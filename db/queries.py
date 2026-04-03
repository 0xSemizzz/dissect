"""
Database queries for submissions, caching, and abuse detection.
"""
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from db.models import Database

logger = logging.getLogger(__name__)


async def log_submission(
    db: Database,
    user_id: str,
    script_hash: str,
    risk_level: str,
    obfuscation_detected: bool = False,
    source: str = "telegram",
):
    """Log a script submission."""
    conn = await db.connect()
    await conn.execute(
        """
        INSERT INTO submissions (user_id, script_hash, risk_level, source, obfuscation_detected)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, script_hash, risk_level, source, 1 if obfuscation_detected else 0),
    )
    await conn.commit()


async def count_submissions_per_hash_24h(db: Database, script_hash: str) -> int:
    """Count how many times a specific script hash was submitted in the last 24 hours."""
    conn = await db.connect()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    cursor = await conn.execute(
        "SELECT COUNT(*) FROM submissions WHERE script_hash = ? AND submitted_at > ?",
        (script_hash, cutoff),
    )
    row = await cursor.fetchone()
    return row[0] if row else 0


async def count_submissions_per_user_1h(db: Database, user_id: str) -> int:
    """Count how many submissions a user made in the last hour."""
    conn = await db.connect()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    cursor = await conn.execute(
        "SELECT COUNT(*) FROM submissions WHERE user_id = ? AND submitted_at > ?",
        (user_id, cutoff),
    )
    row = await cursor.fetchone()
    return row[0] if row else 0


# ─── Analysis Cache ───────────────────────────────────────────────────────────


async def get_analysis_cache(db: Database, script_hash: str) -> Optional[Dict[str, Any]]:
    """
    Get cached analysis result for a script hash.
    Returns None if not found or expired.
    """
    conn = await db.connect()
    cursor = await conn.execute(
        "SELECT analysis_result, expires_at FROM analysis_cache WHERE script_hash = ?",
        (script_hash,),
    )
    row = await cursor.fetchone()

    if row is None:
        return None

    expires_at = datetime.fromisoformat(row[1])
    if datetime.now(timezone.utc) > expires_at:
        # Expired — delete it
        await conn.execute("DELETE FROM analysis_cache WHERE script_hash = ?", (script_hash,))
        await conn.commit()
        return None

    return json.loads(row[0])


async def set_analysis_cache(
    db: Database,
    script_hash: str,
    analysis_result: Dict[str, Any],
    ttl_hours: int = 168,
):
    """Store analysis result in cache with TTL."""
    conn = await db.connect()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
    await conn.execute(
        """
        INSERT OR REPLACE INTO analysis_cache (script_hash, analysis_result, expires_at)
        VALUES (?, ?, ?)
        """,
        (script_hash, json.dumps(analysis_result), expires_at),
    )
    await conn.commit()


# ─── Enrichment Cache ─────────────────────────────────────────────────────────


async def get_enrichment_cache(db: Database, cache_key: str) -> Optional[Dict[str, Any]]:
    """Get cached enrichment data. Returns None if not found or expired."""
    conn = await db.connect()
    cursor = await conn.execute(
        "SELECT data, expires_at FROM enrichment_cache WHERE cache_key = ?",
        (cache_key,),
    )
    row = await cursor.fetchone()

    if row is None:
        return None

    expires_at = datetime.fromisoformat(row[1])
    if datetime.now(timezone.utc) > expires_at:
        await conn.execute("DELETE FROM enrichment_cache WHERE cache_key = ?", (cache_key,))
        await conn.commit()
        return None

    return json.loads(row[0])


async def set_enrichment_cache(
    db: Database,
    cache_key: str,
    data: Dict[str, Any],
    ttl_hours: int = 24,
):
    """Store enrichment data in cache with TTL."""
    conn = await db.connect()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
    await conn.execute(
        """
        INSERT OR REPLACE INTO enrichment_cache (cache_key, data, expires_at)
        VALUES (?, ?, ?)
        """,
        (cache_key, json.dumps(data), expires_at),
    )
    await conn.commit()
