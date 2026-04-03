"""
Database models and schema initialization.
"""
import aiosqlite
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class Database:
    """Manages database connection and schema."""

    def __init__(self, db_path: str = "dissect.db"):
        self.db_path = db_path
        self._connection: Optional[aiosqlite.Connection] = None

    async def connect(self) -> aiosqlite.Connection:
        """Create connection and initialize schema."""
        if self._connection is None:
            self._connection = await aiosqlite.connect(self.db_path)
            self._connection.row_factory = aiosqlite.Row
            await self._create_tables()
            await self._create_indexes()
            logger.info("Database connected and initialized.")
        return self._connection

    async def close(self):
        """Close the database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None
            logger.info("Database connection closed.")

    async def _create_tables(self):
        """Create all required tables."""
        conn = await self.connect()

        # Submissions log
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                script_hash TEXT NOT NULL,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                risk_level TEXT,
                source TEXT DEFAULT 'telegram',
                obfuscation_detected INTEGER DEFAULT 0
            )
        """)

        # Enrichment API cache
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS enrichment_cache (
                cache_key TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)

        # Analysis result cache (cached by script hash)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_cache (
                script_hash TEXT PRIMARY KEY,
                analysis_result TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        """)

        await conn.commit()

    async def _create_indexes(self):
        """Create indexes for fast queries."""
        conn = await self.connect()

        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_submissions_user_time ON submissions(user_id, submitted_at)",
            "CREATE INDEX IF NOT EXISTS idx_submissions_hash ON submissions(script_hash)",
            "CREATE INDEX IF NOT EXISTS idx_analysis_cache_hash ON analysis_cache(script_hash)",
        ]

        for index_sql in indexes:
            await conn.execute(index_sql)

        await conn.commit()
