"""
Formats analysis results into Telegram messages.
"""
from typing import Dict, Any
from core.analyzer import AnalysisResult


# Risk level emojis
RISK_EMOJIS = {
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
    "UNKNOWN": "⚪",
}

# Confidence indicators
CONFIDENCE_ICONS = {
    "HIGH": "✓✓✓",
    "MEDIUM": "✓✓",
    "LOW": "✓",
}


def format_analysis(result: AnalysisResult) -> str:
    """
    Format analysis result into a Telegram message.

    Args:
        result: AnalysisResult from the analyzer

    Returns:
        Formatted message string
    """
    ai = result.ai_analysis
    risk_emoji = RISK_EMOJIS.get(ai.get("risk_level", "UNKNOWN"), "⚪")
    confidence_icon = CONFIDENCE_ICONS.get(ai.get("confidence", "LOW"), "✓")

    # Build message sections
    sections = []

    # Header with risk level
    header = f"{risk_emoji} *Dissect Analysis Complete*\n"
    header += f"Risk Level: *{ai.get('risk_level', 'UNKNOWN')}*\n"
    header += f"Confidence: {confidence_icon}"

    # Cache hit indicator
    if result.cache_hit:
        header += "\n_Previously analyzed — showing cached result_"

    sections.append(header)

    # Summary
    if ai.get("summary"):
        sections.append(f"*Summary:*\n{ai['summary']}")

    # What it does (steps — strip "Step N:" prefix if present)
    steps = ai.get("what_it_does_steps", [])
    if steps:
        cleaned_steps = []
        for step in steps[:5]:
            # Remove "Step N:" or "Step N —" prefix
            cleaned = step
            for prefix_pattern in ["Step 1:", "Step 2:", "Step 3:", "Step 4:", "Step 5:",
                                   "Step 1 —", "Step 2 —", "Step 3 —", "Step 4 —", "Step 5 —"]:
                if cleaned.startswith(prefix_pattern):
                    cleaned = cleaned[len(prefix_pattern):].strip()
                    break
            cleaned_steps.append(cleaned)

        steps_text = "\n".join(f"• {step}" for step in cleaned_steps)
        if len(steps) > 5:
            steps_text += f"\n• ... and {len(steps) - 5} more"
        sections.append(f"*What it does:*\n{steps_text}")

    # Suspicious behaviors
    suspicious = ai.get("suspicious_behaviors", [])
    if suspicious:
        sus_text = ""
        for behavior in suspicious[:3]:
            severity = behavior.get("severity", "UNKNOWN")
            sus_text += f"• [{severity}] {behavior.get('behavior', 'Unknown')}\n"
        if len(suspicious) > 3:
            sus_text += f"• ... and {len(suspicious) - 3} more"
        sections.append(f"*⚠️ Suspicious behaviors:*\n{sus_text}")

    # Obfuscation notice
    if result.obfuscation.get("obfuscation_detected"):
        flag_count = result.obfuscation.get("flag_count", 0)
        sections.append(
            f"*Obfuscation Detected:* "
            f"{flag_count} technique(s) found"
        )

    # Enrichment highlights (Phase 2)
    enrichment_highlights = _format_enrichment_highlights(result)
    if enrichment_highlights:
        sections.append(enrichment_highlights)

    # Verdict
    verdict = ai.get("verdict", "No verdict available")
    sections.append(f"*Verdict:*\n{verdict}")

    # Abuse flags
    if result.abuse_flags:
        flag_text = "\n".join(f"• {flag}" for flag in result.abuse_flags)
        sections.append(f"*Abuse Detection:*\n{flag_text}")

    # Errors (if any)
    if result.errors:
        error_text = "\n".join(f"• {e}" for e in result.errors)
        sections.append(f"*⚠️ Warnings:*\n{error_text}")

    # Disclaimer
    sections.append(
        "_Disclaimer: This is an automated analysis. "
        "Always verify with a security professional before running unknown scripts._"
    )

    # Join sections with double newlines
    return "\n\n".join(sections)


def _format_enrichment_highlights(result: AnalysisResult) -> str:
    """Format key enrichment findings for the message."""
    highlights = []
    enrichment = result.enrichment

    # VirusTotal URL findings
    for url_data in enrichment.get("urls", []):
        vt = url_data.get("virustotal", {})
        if vt.get("malicious") is not None and vt["malicious"] > 0:
            highlights.append(
                f"VirusTotal: {vt['malicious']}/{vt['total_engines']} engines flagged "
                f"`{url_data['url'][:50]}`"
            )

    # VirusTotal hash findings
    for hash_data in enrichment.get("hashes", []):
        vt = hash_data.get("virustotal", {})
        if vt.get("malicious") is not None and vt["malicious"] > 0:
            highlights.append(
                f"VirusTotal: {vt['malicious']}/{vt['total_engines']} engines flagged "
                f"hash `{hash_data['hash'][:16]}...`"
            )

    # MalwareBazaar findings
    for hash_data in enrichment.get("hashes", []):
        mb = hash_data.get("malwarebazaar", {})
        if mb.get("status") == "found":
            family = mb.get("malware_family", "Unknown")
            highlights.append(f"⚠️ MalwareBazaar: Known malware — {family}")

    # IP reputation findings
    for ip_data in enrichment.get("ips", []):
        ipinfo = ip_data.get("ipinfo", {})
        if ipinfo.get("is_tor"):
            highlights.append(f"`{ip_data['ip']}` is a known Tor exit node")
        if ipinfo.get("is_suspicious_hosting"):
            highlights.append(
                f"`{ip_data['ip']}` — {ipinfo.get('suspicion_reason', 'Suspicious hosting')}"
            )

    if not highlights:
        return ""

    return "*Enrichment Findings:*\n" + "\n".join(highlights)


def format_error_message(error: str) -> str:
    """Format an error message for Telegram."""
    return (
        "❌ *Analysis Failed*\n\n"
        f"{error}\n\n"
        "Please try again or contact support if the issue persists."
    )


def format_start_message() -> str:
    """Format the /start command message."""
    return (
        "🔬 *Welcome to Dissect*\n\n"
        "I analyze suspicious scripts and explain them in plain English.\n\n"
        "*How to use:*\n"
        "• Paste a script directly\n"
        "• Send a file (.ps1, .bat, .sh, .py)\n\n"
        "*What I'll tell you:*\n"
        "• What the script does\n"
        "• Any suspicious behaviors\n"
        "• Whether it's safe to run\n\n"
        "_Note: I'm an AI assistant. Always verify critical findings with a security professional._"
    )


def format_help_message() -> str:
    """Format the /help command message."""
    return (
        "📖 *Dissect Help*\n\n"
        "*Commands:*\n"
        "/start — Start a new analysis\n"
        "/help — Show this help message\n\n"
        "*Supported scripts:*\n"
        "• PowerShell (.ps1)\n"
        "• Batch (.bat, .cmd)\n"
        "• Bash (.sh)\n"
        "• Python (.py)\n"
        "• VBScript (.vbs)\n\n"
        "*Limits:*\n"
        "• Max 50KB per script\n\n"
        "Just paste any script or send a file, and I'll analyze it!"
    )
