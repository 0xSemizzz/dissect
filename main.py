"""
Dissect — Telegram Bot Entry Point

A cybersecurity analysis assistant that explains suspicious scripts
in plain English for non-technical users.
"""
import logging
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
)
from config import TELEGRAM_BOT_TOKEN
from bot.handlers import (
    start_command,
    help_command,
    handle_message,
    handle_document,
    error_handler,
)

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


def main() -> None:
    """Start the bot."""
    logger.info("Starting Dissect bot...")
    
    # Build application
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    # Register handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message)
    )
    application.add_handler(
        MessageHandler(filters.Document.ALL, handle_document)
    )
    
    # Register error handler
    application.add_error_handler(error_handler)
    
    # Start polling
    logger.info("Bot started. Polling for updates...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
