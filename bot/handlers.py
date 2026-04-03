"""
Telegram bot message handlers.
"""
import logging
from telegram import Update
from telegram.ext import ContextTypes
from core.analyzer import analyze_script, AnalysisResult
from ai.groq import GroqClient
from bot.formatter import (
    format_analysis,
    format_error_message,
    format_start_message,
    format_help_message,
)

logger = logging.getLogger(__name__)


def get_groq_client(context: ContextTypes.DEFAULT_TYPE) -> GroqClient:
    if "groq_client" not in context.bot_data:
        from config import GROQ_API_KEY
        context.bot_data["groq_client"] = GroqClient(GROQ_API_KEY)
    return context.bot_data["groq_client"]


def get_db(context: ContextTypes.DEFAULT_TYPE):
    """Get or create database instance."""
    if "db" not in context.bot_data:
        from db.models import Database
        context.bot_data["db"] = Database()
    return context.bot_data["db"]


def get_enrichment_clients(context: ContextTypes.DEFAULT_TYPE) -> dict:
    """Get or create enrichment client instances."""
    if "enrichment_clients" not in context.bot_data:
        from enrichment.virustotal import VirusTotalClient
        from enrichment.malwarebazaar import MalwareBazaarClient
        from enrichment.ipinfo import IPInfoClient
        from db.models import Database

        db = get_db(context)

        context.bot_data["enrichment_clients"] = {
            "virustotal": VirusTotalClient(db=db),
            "malwarebazaar": MalwareBazaarClient(db=db),
            "ipinfo": IPInfoClient(db=db),
        }

    return context.bot_data["enrichment_clients"]


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = format_start_message()
    await update.message.reply_text(message, parse_mode="Markdown")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = format_help_message()
    await update.message.reply_text(message, parse_mode="Markdown")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.message.text:
        return

    script = update.message.text.strip()

    if len(script) < 20:
        await update.message.reply_text(
            "Please paste a complete script for analysis. "
            "What you sent looks too short to analyze."
        )
        return

    await update.message.chat.send_action(action="typing")

    groq_client = get_groq_client(context)
    db = get_db(context)
    enrichment_clients = get_enrichment_clients(context)
    user_id = str(update.effective_user.id)

    try:
        result = await analyze_script(
            script, groq_client, user_id, db=db, enrichment_clients=enrichment_clients
        )
        message = format_analysis(result)
        await update.message.reply_text(message, parse_mode="Markdown")

    except Exception as e:
        logger.exception("Analysis failed for user %s", update.effective_user.id)
        error_message = format_error_message(str(e))
        await update.message.reply_text(error_message, parse_mode="Markdown")


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.message.document:
        return

    document = update.message.document
    file = await context.bot.get_file(document.file_id)

    allowed_extensions = {".ps1", ".bat", ".cmd", ".sh", ".py", ".vbs", ".txt"}
    file_ext = "." + document.file_name.split(".")[-1].lower() if "." in document.file_name else ""

    if file_ext not in allowed_extensions:
        await update.message.reply_text(
            f"Sorry, I can't analyze .{file_ext} files. "
            f"Supported formats: {', '.join(allowed_extensions)}"
        )
        return

    try:
        file_bytes = await file.download_as_bytearray()
        script = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        await update.message.reply_text(
            "This file appears to be binary (not a text script). "
            "I can only analyze text-based scripts like PowerShell, Bash, etc."
        )
        return
    except Exception as e:
        logger.exception("File download failed")
        await update.message.reply_text(
            "Failed to download the file. Please try again or paste the script directly."
        )
        return

    await update.message.chat.send_action(action="typing")

    groq_client = get_groq_client(context)
    db = get_db(context)
    enrichment_clients = get_enrichment_clients(context)
    user_id = str(update.effective_user.id)

    try:
        result = await analyze_script(
            script, groq_client, user_id, db=db, enrichment_clients=enrichment_clients
        )
        message = format_analysis(result)
        await update.message.reply_text(message, parse_mode="Markdown")

    except Exception as e:
        logger.exception("File analysis failed for user %s", update.effective_user.id)
        error_message = format_error_message(str(e))
        await update.message.reply_text(error_message, parse_mode="Markdown")


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Update %s caused error %s", update, context.error)
