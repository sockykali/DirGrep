# DirGrep

```
   ______  __  ______  ______  ______  ______  ______   
  /\  __ \/\ \/\  == \/\  ___\/\  == \/\  ___\/\  == \  
  \ \ \/\ \ \ \ \  __<\ \ \__ \ \  __<\ \  __\\ \  _-/  
   \ \_____\ \_\ \_\ \_\ \_____\ \_\ \_\ \_____\ \_\    
    \/_____/\/_/\/_/ /_/\/_____/\/_/ /_/\/_____/\/_/    
```

**Directory fuzzer + recon toolkit for practice pentesting boxes... or whatever...**
**Use Resonsibly**
Built for Kali Linux. Wraps gobuster, nikto, and sqlmap into a single interactive session with a unified output style.

---

## Features

### Two scan modes at startup
- **Directory scanning** — fuzz paths on a web target using configurable wordlists
- **Subdomain enumeration** — brute-force subdomains using SecLists DNS wordlists

### Directory scanning
- Interactive wordlist picker (dirbuster, dirb, seclists raft — whichever are installed)
- Real-time results with colour-coded status codes
- Automatic juicy file detection — flags `.env`, `.bak`, `.sql`, `.key`, `.pem`, `.config`, `.db` and more with `[★]`
- Recursive scanning — post-scan, pick directories to drill into (up to depth 3)
- Rescan with diff — re-run and highlight only new findings
- Live status code filtering — update ignore list mid-session

### Subdomain enumeration
- Uses SecLists DNS wordlists (top1million, Jhaddix, fierce, namelist)
- Warns if target looks like a bare IP address
- Post-scan commands: RESCAN, HEADERS, NIKTO

### Recon commands (directory mode)
| Command | What it does |
|---|---|
| `HEADERS` | Fingerprinting headers (`Server`, `X-Powered-By`, etc.) + security header audit |
| `ROBOTS` | Fetches `robots.txt` and `sitemap.xml`, auto-adds discovered paths to the scan list |
| `NIKTO` | Runs a vuln scan, reformats output in dirgrep's style |
| `PARAMS` | Fuzz GET parameters on a chosen URL, flags interesting responses |
| `RECURSE` | Pick discovered directories to fuzz recursively |
| `RESCAN` | Re-run the scan and diff against previous results |
| `FILTER` | Update the status code ignore list live |
| `DIRS` | Print all discovered paths across all scan depths |
| `EXIT` | End session, prompt to save results |

### SQLi detection
- Passive probe runs automatically at session end — appends a single quote to every discovered URL and checks responses for SQL error signatures
- Parameter fuzzing also checks responses passively
- If hits are found, prompts to launch sqlmap against flagged targets with configurable risk and level

### Output
- All results saved to a timestamped report on exit
- Full session log written to `/tmp/dirgrep_enumeration.log`
- Proxy support throughout (`-p`)

---

## Requirements

| Tool | Required | Notes |
|---|---|---|
| `gobuster` | ✅ Required | `apt install gobuster` |
| `curl` | ✅ Required | Pre-installed on Kali |
| `nikto` | ⚠ Optional | `apt install nikto` — needed for NIKTO command |
| `sqlmap` | ⚠ Optional | `apt install sqlmap` — needed for SQLi exploitation |
| `SecLists` | ⚠ Optional | `apt install seclists` — needed for subdomain mode and seclists wordlists |

Missing optional tools are flagged at startup but won't prevent directory scanning from running.

---

## Installation

```bash
git clone https://github.com/sockykali/dirgrep
cd dirgrep
chmod +x dirgrep.sh
./dirgrep.sh
```

---

## Usage

```
./dirgrep.sh [flags]
```

| Flag | Description | Example |
|---|---|---|
| `-d` | Target URL | `-d http://10.10.10.10:80` |
| `-u` | Custom User-Agent | `-u "Mozilla/5.0"` |
| `-c` | Session cookie | `-c "session=abc123"` |
| `-p` | Proxy URL | `-p http://127.0.0.1:8080` |
| `-H` | Extra HTTP header | `-H "X-Forwarded-For: 127.0.0.1"` |
| `-r` | Rate limit delay (ms) | `-r 200` |
| `-i` | Status codes to ignore | `-i 404,403` |
| `-h` | Help menu | |

### Example — directory scan with Burp proxy

```bash
./dirgrep.sh -d http://10.10.10.10:80 -p http://127.0.0.1:8080
```

### Example — passing domain and cookie at launch

```bash
./dirgrep.sh -d http://target.com -c "PHPSESSID=abc123"
```

---

## Session flow

```
Launch → Enter target → Select mode
         │
         ├── [1] Directory scanning
         │     └── Pick wordlist → Proxy? → Scan
         │           └── Commands: HEADERS, ROBOTS, NIKTO, PARAMS,
         │                         RECURSE, RESCAN, FILTER, DIRS, EXIT
         │                 └── On EXIT: SQLi probe → sqlmap prompt → Save results
         │
         └── [2] Subdomain enumeration
               └── Pick DNS wordlist → Proxy? → Scan
                     └── Commands: RESCAN, HEADERS, NIKTO, EXIT
```

---

## Output indicators

| Indicator | Meaning |
|---|---|
| `[+]` | Success / match found |
| `[*]` | Info |
| `[!]` | Warning |
| `[✗]` | Error |
| `[★]` | Juicy file extension detected |
| `[‼]` | Critical finding (SQLi indicator, Nikto vuln) |

### Status code colours
| Colour | Codes |
|---|---|
| 🟢 Green | 2xx OK |
| 🔵 Cyan | 3xx Redirect |
| 🟡 Yellow | 401 / 403 Auth |
| 🔴 Red | 4xx Client error |
| 🟣 Magenta | 5xx Server error |

---

## Configuration

Tool paths and defaults are set at the top of the script:

```bash
ENUM_ENGINE="/usr/bin/gobuster"
NIKTO_PATH="/usr/bin/nikto"
SQLMAP_PATH="/usr/bin/sqlmap"
MAX_RECURSE_DEPTH=3
IGNORE_CODES="404"
```

Adjust these if your install paths differ or you're running on a non-Kali distro.

---

## Notes

- Designed for **practice/CTF environments** only. Only use against targets you own or have explicit permission to test.
- Ctrl+C during a scan stops the engine early and continues the session with whatever paths were found before the interrupt.
- The last scanned domain is remembered between sessions — leave the domain prompt blank to reuse it.
- All temp files are written to `/tmp/dirgrep_*` with `600` permissions.

---

## License

Do whatever you want with it. Credit appreciated but not required.
