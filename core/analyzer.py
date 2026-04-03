"""
Orchestrates the full analysis pipeline.
"""
import asyncio
import logging
from typing import Dict, Any, Optional
from core.extractor import extract_all, detect_script_type, compute_script_hash
from core.obfuscation import detect_obfuscation
from ai.groq import GroqClient
from db.models import Database
from db import queries
from config import (
    ANALYSIS_CACHE_TTL_HOURS,
    MAX_SUBMISSIONS_PER_HASH_PER_DAY,
    MAX_SUBMISSIONS_PER_USER_PER_HOUR,
)

logger = logging.getLogger(__name__)


class AnalysisResult:
    def __init__(
        self,
        script_hash: str,
        script_type: str,
        ai_analysis: Dict[str, Any],
        obfuscation: Dict[str, Any],
        extracted: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None,
        errors: Optional[list] = None,
        cache_hit: bool = False,
        abuse_flags: Optional[list] = None,
    ):
        self.script_hash = script_hash
        self.script_type = script_type
        self.ai_analysis = ai_analysis
        self.obfuscation = obfuscation
        self.extracted = extracted
        self.enrichment = enrichment or {}
        self.errors = errors or []
        self.cache_hit = cache_hit
        self.abuse_flags = abuse_flags or []

    @property
    def risk_level(self) -> str:
        return self.ai_analysis.get("risk_level", "UNKNOWN")

    @property
    def verdict(self) -> str:
        return self.ai_analysis.get("verdict", "Analysis unavailable")

    @property
    def summary(self) -> str:
        return self.ai_analysis.get("summary", "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "script_hash": self.script_hash,
            "script_type": self.script_type,
            "ai_analysis": self.ai_analysis,
            "obfuscation": self.obfuscation,
            "extracted": self.extracted,
            "enrichment": self.enrichment,
            "errors": self.errors,
            "cache_hit": self.cache_hit,
            "abuse_flags": self.abuse_flags,
        }


async def analyze_script(
    script: str,
    groq_client: GroqClient,
    user_id: str,
    db: Optional[Database] = None,
    enrichment_clients: Optional[Dict[str, Any]] = None,
) -> AnalysisResult:
    """
    Full analysis pipeline with caching and enrichment.

    Args:
        script: The script content
        groq_client: GroqClient for AI analysis
        user_id: User identifier (for logging and abuse detection)
        db: Database instance (optional — caching disabled if None)
        enrichment_clients: Dict with 'virustotal', 'malwarebazaar', 'ipinfo' clients
    """
    errors = []
    abuse_flags = []

    # Validate input
    validation_error = _validate_input(script)
    if validation_error:
        return AnalysisResult(
            script_hash="invalid",
            script_type="Unknown",
            ai_analysis={"error": validation_error},
            obfuscation={"obfuscation_detected": False, "flags": []},
            extracted={},
            errors=[validation_error],
        )

    # Compute hash and check analysis cache
    script_hash = compute_script_hash(script)

    if db:
        cached = await queries.get_analysis_cache(db, script_hash)
        if cached:
            logger.info("Analysis cache hit for script %s", script_hash[:12])
            await queries.log_submission(db, user_id, script_hash, cached.get("risk_level", "UNKNOWN"))
            return AnalysisResult(
                script_hash=script_hash,
                script_type=cached.get("script_type", "Unknown"),
                ai_analysis=cached,
                obfuscation={"obfuscation_detected": False, "flags": []},
                extracted={},
                cache_hit=True,
            )

    # Static extraction
    extracted = extract_all(script)
    script_type = detect_script_type(script)
    obfuscation = detect_obfuscation(script)
    obfuscation_flags = [flag["name"] for flag in obfuscation["flags"]]

    # Run enrichment in parallel
    enrichment = {}
    if enrichment_clients:
        enrichment = await _run_enrichment(extracted, enrichment_clients, errors)

    # AI analysis
    try:
        ai_analysis = await groq_client.analyze(
            script=script,
            enrichment=enrichment,
            obfuscation_flags=obfuscation_flags,
        )
    except Exception as e:
        errors.append(f"AI analysis failed: {str(e)}")
        ai_analysis = {
            "script_type": script_type,
            "summary": "AI analysis temporarily unavailable.",
            "what_it_does_steps": [],
            "suspicious_behaviors": [],
            "benign_behaviors": [],
            "obfuscation_detected": obfuscation["obfuscation_detected"],
            "risk_level": "UNKNOWN",
            "risk_reasoning": "Could not complete analysis.",
            "verdict": "INVESTIGATE FURTHER — AI analysis unavailable. Try again or consult a security professional.",
            "confidence": "LOW",
            "confidence_reason": "AI service unavailable.",
        }

    # Build result
    result = AnalysisResult(
        script_hash=script_hash,
        script_type=script_type,
        ai_analysis=ai_analysis,
        obfuscation=obfuscation,
        extracted=extracted,
        enrichment=enrichment,
        errors=errors,
        abuse_flags=abuse_flags,
    )

    # Cache the analysis result
    if db:
        await queries.set_analysis_cache(db, script_hash, ai_analysis, ANALYSIS_CACHE_TTL_HOURS)
        await queries.log_submission(
            db, user_id, script_hash, ai_analysis.get("risk_level", "UNKNOWN"),
            obfuscation_detected=obfuscation["obfuscation_detected"],
        )

        # Abuse detection checks
        abuse_flags = await _check_abuse(db, user_id, script_hash)
        result.abuse_flags = abuse_flags

    return result


async def _run_enrichment(
    extracted: Dict[str, Any],
    clients: Dict[str, Any],
    errors: list,
) -> Dict[str, Any]:
    """Run all enrichment APIs in parallel."""
    urls = extracted.get("urls", [])
    ips = extracted.get("ips", [])
    hashes = extracted.get("hashes", [])

    tasks = []
    task_names = []

    if clients.get("virustotal"):
        vt_client = clients["virustotal"]
        if urls:
            tasks.append(vt_client.lookup_urls(urls))
            task_names.append("vt_urls")
        if hashes:
            tasks.append(vt_client.lookup_hashes(hashes))
            task_names.append("vt_hashes")

    if clients.get("malwarebazaar") and hashes:
        tasks.append(clients["malwarebazaar"].lookup_hashes(hashes))
        task_names.append("mb_hashes")

    if clients.get("ipinfo") and ips:
        tasks.append(clients["ipinfo"].lookup_ips(ips))
        task_names.append("ipinfo")

    if not tasks:
        return {}

    results = await asyncio.gather(*tasks, return_exceptions=True)

    enrichment = {}
    for name, result in zip(task_names, results):
        if isinstance(result, Exception):
            errors.append(f"Enrichment error ({name}): {str(result)}")
            logger.warning("Enrichment failed for %s: %s", name, result)
        elif name == "vt_urls":
            enrichment["urls"] = result
        elif name == "vt_hashes":
            enrichment.setdefault("hashes", []).extend(result)
        elif name == "mb_hashes":
            # Merge MalwareBazaar results into existing hash entries
            for mb_result in result:
                for existing in enrichment.get("hashes", []):
                    if existing.get("hash") == mb_result.get("hash"):
                        existing["malwarebazaar"] = mb_result.get("malwarebazaar", {})
                        break
        elif name == "ipinfo":
            enrichment["ips"] = result

    return enrichment


async def _check_abuse(db: Database, user_id: str, script_hash: str) -> list:
    """Check for abuse patterns. Returns list of abuse flags."""
    flags = []

    # Check if same hash submitted too many times in 24h
    hash_count = await queries.count_submissions_per_hash_24h(db, script_hash)
    if hash_count > MAX_SUBMISSIONS_PER_HASH_PER_DAY:
        flags.append(f"Same script submitted {hash_count} times in 24h (threshold: {MAX_SUBMISSIONS_PER_HASH_PER_DAY})")

    # Check user submission velocity
    user_count = await queries.count_submissions_per_user_1h(db, user_id)
    if user_count > MAX_SUBMISSIONS_PER_USER_PER_HOUR:
        flags.append(f"User submitted {user_count} scripts in 1h (threshold: {MAX_SUBMISSIONS_PER_USER_PER_HOUR})")

    if flags:
        logger.warning("Abuse flags for user %s, script %s: %s", user_id, script_hash[:12], flags)

    return flags


def _validate_input(script: str) -> Optional[str]:
    if not script or not script.strip():
        return "Empty script provided"

    if len(script) > 50 * 1024:
        return "Script too large (max 50KB)"

    try:
        script.encode('utf-8')
    except UnicodeEncodeError:
        return "Script contains invalid characters"

    return None
