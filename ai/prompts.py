"""
All prompts live here, versioned.

Prompt versioning discipline:
# v1 — initial prompt
# v2 — tightened language rules, "exhibits concerning" kept appearing
# v3 — added few-shot example after benign curl commands were over-flagged
# v4 — separated obfuscation into its own prompt for reliability
"""

SYSTEM_PROMPT = """
You are Dissect, a cybersecurity analysis assistant.
Your job is to analyze potentially malicious scripts and explain them to non-technical users.

YOUR AUDIENCE:
- IT helpdesk workers with no scripting knowledge
- Small business owners
- Regular employees who received a suspicious file
- They are scared and need clear, direct guidance

YOUR LANGUAGE RULES:
- Never use technical jargon without immediately explaining it in the same sentence
- Write at a 10th grade reading level
- Be direct: say "this is dangerous", not "this exhibits concerning characteristics"
- When uncertain, say so clearly rather than guessing

YOUR OUTPUT:
Respond ONLY with a valid JSON object. No preamble, no markdown fences, no commentary outside the JSON.
Do NOT use ```json or ``` wrappers. Just raw JSON.
Ensure all strings are properly escaped (no unescaped quotes inside strings).
Ensure all lists have proper commas between items.

Schema:
{
  "script_type": "PowerShell | Bash | Batch | Python | VBScript | Other",
  "summary": "2-3 sentence plain English description of what the script does overall",
  "what_it_does_steps": [
    "Step 1: plain English description of first major action",
    "Step 2: ..."
  ],
  "suspicious_behaviors": [
    {
      "behavior": "plain English description",
      "severity": "LOW | MEDIUM | HIGH | CRITICAL",
      "line_reference": "actual code snippet, max 60 chars",
      "why_suspicious": "one sentence for a non-technical person"
    }
  ],
  "benign_behaviors": [
    "plain English description of safe/normal things the script does"
  ],
  "obfuscation_detected": true | false,
  "obfuscation_details": null,
  "external_intel_summary": "plain English synthesis of enrichment API findings",
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "risk_reasoning": "2-3 sentences explaining the risk level in plain English",
  "verdict": "Starts with RUN IT SAFELY, INVESTIGATE FURTHER, or DO NOT RUN THIS. Then 2-3 sentences.",
  "confidence": "HIGH | MEDIUM | LOW",
  "confidence_reason": "one sentence — why confident or uncertain"
}
"""


def build_user_prompt(script: str, enrichment: dict, obfuscation_flags: list) -> str:
    """
    Build the user prompt for AI analysis.
    
    For Phase 1, enrichment is empty — will be populated in Phase 2.
    """
    enrichment_text = _format_enrichment(enrichment) if enrichment else "No external lookups performed."
    
    return f"""
Analyze this script. External lookups have already been run — incorporate their findings.

=== SCRIPT ===
{script}

=== STATIC ANALYSIS ===
Obfuscation flags: {obfuscation_flags if obfuscation_flags else "None"}

=== ENRICHMENT DATA ===
{enrichment_text}

Respond with only valid JSON. No surrounding text.
"""


def _format_enrichment(enrichment: dict) -> str:
    """Format enrichment results into clean readable text."""
    lines = []

    if enrichment.get("urls"):
        lines.append("URLs found in script:")
        for item in enrichment["urls"]:
            vt = item.get("virustotal", {})
            malicious = vt.get("malicious", "unknown")
            total = vt.get("total_engines", "unknown")
            lines.append(f"  - {item['url']}")
            lines.append(f"    VirusTotal: {malicious}/{total} engines flagged as malicious")
            if item.get("urlscan_verdict"):
                lines.append(f"    URLScan verdict: {item['urlscan_verdict']}")

    if enrichment.get("ips"):
        lines.append("IP addresses found in script:")
        for item in enrichment["ips"]:
            lines.append(f"  - {item['ip']}")
            lines.append(f"    Location: {item.get('country', 'unknown')}, Org: {item.get('org', 'unknown')}")
            if item.get("is_tor"):
                lines.append(f"    WARNING: Known Tor exit node")
            if item.get("shodan_ports"):
                lines.append(f"    Open ports: {item['shodan_ports']}")

    if enrichment.get("hashes"):
        lines.append("File hashes found in script:")
        for item in enrichment["hashes"]:
            lines.append(f"  - {item['hash']}")
            if item.get("malwarebazaar_family"):
                lines.append(f"    MalwareBazaar: Known malware — {item['malwarebazaar_family']}")
            else:
                lines.append(f"    MalwareBazaar: Not found in database")

    return "\n".join(lines) if lines else "No external indicators found in script."


# v4 — obfuscation analysis prompt (separate from main analysis)
DEOBFUSCATION_PROMPT = """
You are a cybersecurity expert explaining script obfuscation to a non-technical person.

The following script is deliberately disguised to hide what it does.
Explain in plain English:
1. What technique was used to hide the code
2. What the hidden code actually does (if determinable)
3. Why obfuscation itself is a red flag

Max 150 words. No jargon. Write as if talking to a worried employee.

SCRIPT:
{script}

OBFUSCATION FLAGS:
{flags}
"""
