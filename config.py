"""
Configuration loader — fails loudly on missing required keys.
"""
import os
from dotenv import load_dotenv

load_dotenv()


def get_required_env(key: str) -> str:
    """Get required environment variable or raise."""
    value = os.getenv(key)
    if not value:
        raise ValueError(f"Missing required environment variable: {key}")
    return value


# Telegram Bot Token (required for Phase 1)
TELEGRAM_BOT_TOKEN = get_required_env("TELEGRAM_BOT_TOKEN")

# Groq API Key (required for Phase 1)
GROQ_API_KEY = get_required_env("GROQ_API_KEY")

# Turso Database (optional for Phase 1, required for Phase 2+)
TURSO_DATABASE_URL = os.getenv("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN")

# Feature flags
USE_TURSO = bool(TURSO_DATABASE_URL and TURSO_AUTH_TOKEN)

# Rate limiting (v1: in-memory if Turso not enabled)
MAX_SUBMISSIONS_PER_USER_PER_DAY = 5
MAX_SUBMISSIONS_PER_HASH_PER_DAY = 10
MAX_SUBMISSIONS_PER_USER_PER_HOUR = 20

# Analysis limits
MAX_SCRIPT_SIZE_KB = 50
