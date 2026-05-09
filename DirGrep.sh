#!/bin/bash
# DirGrep v4.1 — directory fuzzer + recon toolkit for practice pentesting boxes
# Author: sockykali

# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────
DEFAULT_WORDLIST="/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"
ENUM_ENGINE="/usr/bin/gobuster"
NIKTO_PATH="/usr/bin/nikto"
SQLMAP_PATH="/usr/bin/sqlmap"
OUTPUT_FILE="/tmp/dirgrep_output.txt"
DIRECTORIES_FILE="/tmp/dirgrep_directories.txt"
ALL_DIRECTORIES_FILE="/tmp/dirgrep_all_directories.txt"
LOG_FILE="/tmp/dirgrep_enumeration.log"
LAST_DOMAIN_FILE="/tmp/dirgrep_last_domain.txt"
USER_AGENT="Mozilla/5.0"
export MAX_RETRIES=5
MAX_RECURSE_DEPTH=3
IGNORE_CODES="404"

JUICY_EXTENSIONS="\.bak|\.env|\.sql|\.zip|\.tar|\.gz|\.config|\.conf|\.cfg|\.log|\.old|\.orig|\.swp|\.key|\.pem|\.xml|\.json|\.yml|\.yaml|\.ini|\.db|\.sqlite|\.dump"
SQL_ERRORS="you have an error in your sql|warning: mysql|unclosed quotation mark|quoted string not properly terminated|pg_query|supplied argument is not a valid mysql|ora-[0-9][0-9][0-9][0-9]|microsoft ole db provider for sql|odbc sql server driver|sqlite_error|syntax error.*near"

declare -A KALI_WORDLISTS=(
    [1]="/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"
    [2]="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
    [3]="/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt"
    [4]="/usr/share/wordlists/dirb/common.txt"
    [5]="/usr/share/wordlists/dirb/big.txt"
    [6]="/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    [7]="/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt"
)
declare -A KALI_WORDLIST_LABELS=(
    [1]="dirbuster / directory-list-lowercase-2.3-medium  (default)"
    [2]="dirbuster / directory-list-2.3-small             (fast)"
    [3]="dirbuster / directory-list-2.3-big               (thorough)"
    [4]="dirb / common                                    (quick)"
    [5]="dirb / big"
    [6]="seclists / raft-medium-directories"
    [7]="seclists / raft-large-directories"
)


declare -A DNS_WORDLISTS=(
    [1]="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    [2]="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
    [3]="/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
    [4]="/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt"
    [5]="/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt"
    [6]="/usr/share/seclists/Discovery/DNS/namelist.txt"
)
declare -A DNS_WORDLIST_LABELS=(
    [1]="seclists / subdomains-top1million-5000       (fast, recommended)"
    [2]="seclists / subdomains-top1million-20000      (balanced)"
    [3]="seclists / subdomains-top1million-110000     (thorough, slow)"
    [4]="seclists / dns-Jhaddix                       (comprehensive)"
    [5]="seclists / fierce-hostlist                   (classic)"
    [6]="seclists / namelist                          (broad)"
)
# ─────────────────────────────────────────────
#  COLOURS
# ─────────────────────────────────────────────
R='\e[0;31m'; G='\e[0;32m'; Y='\e[0;33m'; B='\e[0;34m'
M='\e[0;35m'; C='\e[0;36m'; W='\e[0;37m'
BOLD='\e[1m'; DIM='\e[2m'; RESET='\e[0m'

# ─────────────────────────────────────────────
#  OUTPUT HELPERS
# ─────────────────────────────────────────────
log()     { printf "%s  %s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG_FILE"; }
info()    { echo -e "  ${C}[*]${RESET} $1"; }
success() { echo -e "  ${G}[+]${RESET} ${BOLD}$1${RESET}"; }
warn()    { echo -e "  ${Y}[!]${RESET} $1"; }
error()   { echo -e "  ${R}[✗]${RESET} $1" >&2; }
juicy()   { echo -e "  ${M}[★]${RESET} ${BOLD}$1${RESET}"; }
alert()   { echo -e "  ${R}${BOLD}[‼]${RESET}${BOLD} $1${RESET}"; }
divider() { echo -e "  ${DIM}${W}──────────────────────────────────────────────────────${RESET}"; }
section() { echo ""; divider; echo -e "  ${BOLD}${W}$1${RESET}"; divider; }

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
print_banner() {
    # Hacker green gradient effect: bright green -> green -> dim green
    echo -e "\e[1;32m"
    cat << 'EOF'
   ______  __  ______  ______  ______  ______  ______   
  /\  __ \/\ \/\  == \/\  ___\/\  == \/\  ___\/\  == \  
  \ \ \/\ \ \ \ \  __<\ \ \__ \ \  __<\ \  __\\ \  _-/  
   \ \_____\ \_\ \_\ \_\ \_____\ \_\ \_\ \_____\ \_\    
    \/_____/\/_/\/_/ /_/\/_____/\/_/ /_/\/_____/\/_/    
EOF
    echo -e "\e[0;32m"
    printf "  %s\n" "╔══════════════════════════════════════════════════════╗"
    printf "  %s\n" "║  \e[1;32m> directory fuzzer  > recon toolkit  > v4.1\e[0;32m        ║"
    printf "  %s\n" "║  \e[2;32m  author: sockykali  //  use responsibly\e[0;32m            ║"
    printf "  %s\n" "╚══════════════════════════════════════════════════════╝"
    echo -e "\e[0m"
    echo -e "  \e[2;32m⚠  Requires: gobuster  nikto  sqlmap  curl  openssl  SecLists"
    echo -e "     Adjust tool paths at the top of the script if needed.\e[0m"
    echo ""
}

# ─────────────────────────────────────────────
#  HELP MENU
# ─────────────────────────────────────────────
show_help() {
    print_banner
    echo -e "  ${BOLD}${C}USAGE${RESET}"
    echo -e "    ${W}$0${RESET} ${DIM}[flags]${RESET}"
    echo ""
    echo -e "  ${BOLD}${C}FLAGS${RESET}"
    echo -e "    ${B}-d${RESET}  ${W}domain${RESET}       Target URL              ${DIM}e.g. http://10.10.10.10:80${RESET}"
    echo -e "    ${B}-u${RESET}  ${W}user-agent${RESET}   Custom User-Agent       ${DIM}default: Mozilla/5.0${RESET}"
    echo -e "    ${B}-c${RESET}  ${W}cookie${RESET}       Session cookie          ${DIM}NAME=VALUE format${RESET}"
    echo -e "    ${B}-p${RESET}  ${W}proxy${RESET}        Proxy URL               ${DIM}e.g. http://127.0.0.1:8080${RESET}"
    echo -e "    ${B}-H${RESET}  ${W}header${RESET}       Extra HTTP header       ${DIM}e.g. 'X-Forwarded-For: 127.0.0.1'${RESET}"
    echo -e "    ${B}-r${RESET}  ${W}ms${RESET}           Rate limit delay (ms)   ${DIM}e.g. 200${RESET}"
    echo -e "    ${B}-i${RESET}  ${W}codes${RESET}        Status codes to ignore  ${DIM}default: 404${RESET}"
    echo -e "    ${B}-h${RESET}               This help menu"
    echo ""
    divider
    echo -e "  ${BOLD}${C}RUNTIME COMMANDS${RESET}"
    echo ""
    echo -e "    ${C}DIRS${RESET}        List all discovered paths so far"
    echo -e "    ${C}RECURSE${RESET}     Pick directories to fuzz recursively (max depth: ${MAX_RECURSE_DEPTH})"
    echo -e "    ${C}RESCAN${RESET}      Re-run the scan and highlight new findings"
    echo -e "    ${C}FILTER${RESET}      Update the status code ignore list live"
    echo -e "    ${C}HEADERS${RESET}     Inspect HTTP response headers + fingerprint target"
    echo -e "    ${C}NIKTO${RESET}       Run a vulnerability scan against the target"
    echo -e "    ${C}ROBOTS${RESET}      Fetch and parse robots.txt + sitemap.xml"
    echo -e "    ${C}PARAMS${RESET}      Fuzz GET parameters on a chosen URL"
    echo -e "    ${C}BYPASS${RESET}      Try 403/401 bypass techniques on blocked paths"
    echo -e "    ${C}EXT${RESET}         Brute-force file extensions on discovered paths"
    echo -e "    ${C}METHODS${RESET}     Fuzz HTTP methods  ${DIM}(PUT DELETE PATCH TRACE…)${RESET}"
    echo -e "    ${C}BACKUP${RESET}      Probe for backup files  ${DIM}(.bak .old .swp ~…)${RESET}"
    echo -e "    ${C}EXIT${RESET}        End session, prompt to save results"
    echo ""
    divider
    echo -e "  ${BOLD}${C}MODE 2 EXTRA COMMANDS${RESET}"
    echo ""
    echo -e "    ${C}VHOST${RESET}       Enumerate virtual hosts via Host-header fuzzing"
    echo ""
    divider
    echo -e "  ${BOLD}${C}MODE 3 COMMANDS  (passive recon)${RESET}"
    echo ""
    echo -e "    ${C}SSL${RESET}         Inspect TLS certificate + extract SANs"
    echo -e "    ${C}JS${RESET}          Extract endpoints from JavaScript files"
    echo -e "    ${C}CORS${RESET}        Check for CORS misconfigurations"
    echo -e "    ${C}COOKIES${RESET}     Audit cookie security flags"
    echo -e "    ${C}TECH${RESET}        Fingerprint CMS, framework, and frontend libraries"
    echo ""
    divider
    echo -e "  ${BOLD}${C}INDICATORS${RESET}"
    echo ""
    echo -e "    ${G}[+]${RESET}  Success / match found"
    echo -e "    ${C}[*]${RESET}  Info"
    echo -e "    ${Y}[!]${RESET}  Warning"
    echo -e "    ${R}[✗]${RESET}  Error"
    echo -e "    ${M}[★]${RESET}  Juicy file extension detected  ${DIM}(.env .bak .sql .key .pem …)${RESET}"
    echo -e "    ${R}[‼]${RESET}  Critical finding  ${DIM}(SQLi indicator, Nikto vuln)${RESET}"
    echo ""
    divider
    echo -e "  ${BOLD}${C}STATUS CODE COLOURS${RESET}"
    echo ""
    echo -e "    ${G}2xx${RESET}  OK            ${C}3xx${RESET}  Redirect"
    echo -e "    ${Y}401/403${RESET}  Auth     ${R}4xx${RESET}  Client error    ${M}5xx${RESET}  Server error"
    echo ""
    divider
    echo -e "  ${BOLD}${C}TIPS${RESET}"
    echo ""
    echo -e "    • Press ${B}Ctrl+C${RESET} during a scan to stop early and work with what was found"
    echo -e "    • Leave the domain prompt blank to reuse the last scanned domain"
    echo -e "    • Comma-separate multiple search terms:  ${DIM}admin,login,flag,password${RESET}"
    echo -e "    • SQLi probing runs automatically at session end if URLs were found"
    echo -e "    • Subdomain mode uses SecLists DNS wordlists — not directory lists"
    echo -e "    • SecLists install: ${DIM}sudo apt install seclists${RESET}"
    echo ""
    exit 0
}

# ─────────────────────────────────────────────
#  INIT
# ─────────────────────────────────────────────
init_files() {
    touch "$OUTPUT_FILE" "$DIRECTORIES_FILE" "$ALL_DIRECTORIES_FILE" \
          "$LOG_FILE" "$LAST_DOMAIN_FILE" 2>/dev/null
    chmod 600 "$OUTPUT_FILE" "$DIRECTORIES_FILE" "$ALL_DIRECTORIES_FILE" \
              "$LOG_FILE" "$LAST_DOMAIN_FILE" 2>/dev/null
    > "$LOG_FILE"
    > "$ALL_DIRECTORIES_FILE"
}

check_deps() {
    local missing=()
    for app in "$ENUM_ENGINE" curl awk grep sed; do
        command -v "$app" &>/dev/null || missing+=("$app")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing[*]}"; exit 1
    fi
    # Optional — warn but don't exit
    command -v "$NIKTO_PATH"  &>/dev/null || warn "nikto not found  — NIKTO command unavailable"
    command -v "$SQLMAP_PATH" &>/dev/null || warn "sqlmap not found — SQLi exploitation unavailable"
    command -v openssl        &>/dev/null || warn "openssl not found — SSL inspection unavailable"
}

# ─────────────────────────────────────────────
#  URL HELPER
# ─────────────────────────────────────────────
format_url() {
    local url="$1"
    [[ ! "$url" =~ ^https?:// ]] && url="http://$url"
    echo "${url%/}"
}

# ─────────────────────────────────────────────
#  WORDLIST MENU  (sets global $wordlist directly)
# ─────────────────────────────────────────────
wordlist_menu() {
    echo ""
    info "Available wordlists:"
    divider
    for key in $(echo "${!KALI_WORDLISTS[@]}" | tr ' ' '\n' | sort -n); do
        local wl_path="${KALI_WORDLISTS[$key]}" label="${KALI_WORDLIST_LABELS[$key]}"
        if [[ -f "$wl_path" ]]; then
            echo -e "    ${C}[$key]${RESET}  $label"
        else
            echo -e "    ${DIM}[$key]  $label  ${R}(not found)${RESET}"
        fi
    done
    echo -e "    ${C}[c]${RESET}  Custom path"
    divider
    read -rp "  $(echo -e "${C}[?]${RESET}") Select wordlist [1-7 / c]: " wl_choice

    if [[ "$wl_choice" == "c" ]]; then
        read -rp "  $(echo -e "${C}[?]${RESET}") Enter full path: " wordlist
    elif [[ -n "${KALI_WORDLISTS[$wl_choice]}" ]]; then
        wordlist="${KALI_WORDLISTS[$wl_choice]}"
    else
        warn "Invalid selection — using default."
        wordlist="$DEFAULT_WORDLIST"
    fi
}


# ─────────────────────────────────────────────
#  DNS WORDLIST MENU  (sets global $dns_wordlist directly)
# ─────────────────────────────────────────────
dns_wordlist_menu() {
    echo ""
    info "Available subdomain wordlists ${DIM}(SecLists DNS)${RESET}:"
    divider
    for key in $(echo "${!DNS_WORDLISTS[@]}" | tr ' ' '\n' | sort -n); do
        local wl_path="${DNS_WORDLISTS[$key]}" label="${DNS_WORDLIST_LABELS[$key]}"
        if [[ -f "$wl_path" ]]; then
            echo -e "    ${C}[$key]${RESET}  $label"
        else
            echo -e "    ${DIM}[$key]  $label  ${R}(not found)${RESET}"
        fi
    done
    echo -e "    ${C}[c]${RESET}  Custom path"
    divider
    read -rp "  $(echo -e "${C}[?]${RESET}") Select DNS wordlist [1-6 / c]: " dns_wl_choice

    if [[ "$dns_wl_choice" == "c" ]]; then
        read -rp "  $(echo -e "${C}[?]${RESET}") Enter full path: " dns_wordlist
    elif [[ -n "${DNS_WORDLISTS[$dns_wl_choice]}" ]]; then
        dns_wordlist="${DNS_WORDLISTS[$dns_wl_choice]}"
    else
        warn "Invalid selection — using default."
        dns_wordlist="${DNS_WORDLISTS[1]}"
    fi
}

# ─────────────────────────────────────────────
#  CURL WRAPPER
# ─────────────────────────────────────────────
run_curl() {
    local url="$1" ua="$2" cookie="$3" retries=0 result
    while (( retries < MAX_RETRIES )); do
        if result=$(curl -s --max-time 10 -A "$ua" \
                        ${cookie:+-b "$cookie"} \
                        ${proxy:+--proxy "$proxy"} \
                        ${extra_headers:+-H "$extra_headers"} \
                        "$url"); then
            echo "$result"; return 0
        fi
        warn "curl failed for $url — retry $((retries+1))/$MAX_RETRIES"
        (( retries++ )); sleep 1
    done
    error "Failed to fetch $url after $MAX_RETRIES attempts"; return 1
}

# ─────────────────────────────────────────────
#  STATUS CODE COLOURING
# ─────────────────────────────────────────────
colour_status() {
    case "$1" in
        2*)              echo -e "${G}$1${RESET}" ;;
        301|302|307|308) echo -e "${C}$1${RESET}" ;;
        3*)              echo -e "${B}$1${RESET}" ;;
        401|403)         echo -e "${Y}$1${RESET}" ;;
        4*)              echo -e "${R}$1${RESET}" ;;
        5*)              echo -e "${M}$1${RESET}" ;;
        *)               echo -e "${W}$1${RESET}" ;;
    esac
}

# ─────────────────────────────────────────────
#  JUICY FILE DETECTION
# ─────────────────────────────────────────────
check_juicy() {
    local path="$1" base_url="$2"
    if echo "$path" | grep -qiE "($JUICY_EXTENSIONS)$"; then
        juicy "JUICY FILE → ${base_url}${path}"
        results+="[JUICY] ${base_url}${path}\n"
        log "Juicy file: ${base_url}${path}"
    fi
}

# ─────────────────────────────────────────────
#  ENUMERATION ENGINE
# ─────────────────────────────────────────────
run_enum() {
    local target="$1" wl="$2" depth="${3:-0}" depth_label=""
    [[ $depth -gt 0 ]] && depth_label=" ${DIM}(depth $depth)${RESET}"

    info "Starting enumeration against ${BOLD}$target${RESET}${depth_label}"
    info "Wordlist: $(basename "$wl")"
    info "Filtering status codes: $IGNORE_CODES"
    divider
    echo -e "  ${DIM}${W}PATH                                 STATUS   SIZE${RESET}"
    divider

    local scan_flags=("dir" "-q" "-u" "$target" "-w" "$wl" "-o" "$OUTPUT_FILE")
    [[ -n "$IGNORE_CODES" ]] && scan_flags+=("-b" "$IGNORE_CODES")
    [[ -n "$rate_limit"   ]] && scan_flags+=("--delay" "${rate_limit}ms")
    [[ -n "$proxy"        ]] && scan_flags+=("--proxy" "$proxy")
    [[ "$target" =~ ^https:// ]] && scan_flags+=("--no-tls-validation")

    trap 'echo -e "\n${Y}[!]${RESET}  Scan interrupted — using paths found so far."; trap - INT' INT

    "$ENUM_ENGINE" "${scan_flags[@]}" 2>/dev/null | while IFS= read -r line; do
        if [[ "$line" =~ \(Status:\ ([0-9]+)\) ]]; then
            local code="${BASH_REMATCH[1]}"
            local coloured_code path size
            coloured_code=$(colour_status "$code")
            path=$(echo "$line" | awk '{print $1}')
            size=$(echo "$line" | grep -oP '\[Size: \K[0-9]+' || echo "?")
            check_juicy "$path" "$target"
            printf "  \e[0;36m%-36s\e[0m [%s]  \e[2m%s bytes\e[0m\n" "$path" "$coloured_code" "$size"
        fi
    done
    local scan_exit=${PIPESTATUS[0]}
    trap - INT

    divider
    [[ $scan_exit -ne 0 && $scan_exit -ne 130 ]] && {
        error "Scan engine exited with error (code $scan_exit)"; return 1
    }
    return 0
}

extract_directories() {
    local target_file="${1:-$DIRECTORIES_FILE}"
    awk '/^\// {print $1}' "$OUTPUT_FILE" > "$target_file"
    sort -u "$target_file" "$ALL_DIRECTORIES_FILE" > /tmp/dirgrep_dedup.txt
    mv /tmp/dirgrep_dedup.txt "$ALL_DIRECTORIES_FILE"
    local count; count=$(wc -l < "$target_file")
    success "Found $count director$([ "$count" -eq 1 ] && echo 'y' || echo 'ies')"
}

# ─────────────────────────────────────────────
#  RECURSIVE SCANNING
# ─────────────────────────────────────────────
prompt_recursive() {
    local base_url="$1" wl="$2" current_depth="$3"

    (( current_depth >= MAX_RECURSE_DEPTH )) && {
        warn "Max recursion depth ($MAX_RECURSE_DEPTH) reached."; return
    }

    local dirs=()
    while IFS= read -r dir; do [[ -n "$dir" ]] && dirs+=("$dir"); done < "$DIRECTORIES_FILE"
    [[ ${#dirs[@]} -eq 0 ]] && { info "No directories to recurse into."; return; }

    section "RECURSIVE SCAN"
    echo -e "    ${C}[0]${RESET}  ${DIM}Skip${RESET}"
    echo -e "    ${C}[a]${RESET}  ${DIM}All${RESET}"
    local i=1
    for dir in "${dirs[@]}"; do
        echo -e "    ${C}[$i]${RESET}  ${base_url}${C}${dir}${RESET}"; (( i++ ))
    done
    divider
    read -rp "  $(echo -e "${C}[?]${RESET}") Numbers (space-separated), 'a' for all, or 0 to skip: " recurse_input
    [[ "$recurse_input" == "0" || -z "$recurse_input" ]] && return

    local targets=()
    if [[ "$recurse_input" == "a" ]]; then
        targets=("${dirs[@]}")
    else
        for idx in $recurse_input; do
            if [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#dirs[@]} )); then
                targets+=("${dirs[$((idx-1))]}")
            else
                warn "Invalid selection '$idx' — skipping."
            fi
        done
    fi

    local new_depth=$(( current_depth + 1 ))
    local recursive_dirs_file="/tmp/dirgrep_recursive_${new_depth}.txt"

    for target_dir in "${targets[@]}"; do
        local recursive_url="${base_url}${target_dir}"
        echo ""
        info "Recursing into: ${BOLD}$recursive_url${RESET}  ${DIM}(depth $new_depth/$MAX_RECURSE_DEPTH)${RESET}"
        log "Recursive scan: $recursive_url (depth $new_depth)"
        run_enum "$recursive_url" "$wl" "$new_depth"
        extract_directories "$recursive_dirs_file"
        while IFS= read -r subdir; do
            [[ -n "$subdir" ]] && echo "${target_dir}${subdir}" >> "$ALL_DIRECTORIES_FILE"
        done < "$recursive_dirs_file"
        if [[ -s "$recursive_dirs_file" ]]; then
            cp "$recursive_dirs_file" "$DIRECTORIES_FILE"
            prompt_recursive "$recursive_url" "$wl" "$new_depth"
        fi
    done
}

# ─────────────────────────────────────────────
#  RESCAN WITH DIFF
# ─────────────────────────────────────────────
run_rescan() {
    local prev_dirs
    prev_dirs=$(sort "$ALL_DIRECTORIES_FILE" 2>/dev/null)
    info "Rescanning…"; log "Rescan triggered"
    run_enum "$domain" "$wordlist" 0
    extract_directories
    local new_dirs
    new_dirs=$(comm -13 <(echo "$prev_dirs") <(sort "$ALL_DIRECTORIES_FILE"))
    echo ""; divider
    if [[ -n "$new_dirs" ]]; then
        success "New paths since last scan:"
        while IFS= read -r d; do echo -e "    ${G}+${RESET} $d"; done <<< "$new_dirs"
    else
        info "No new paths found."
    fi
    divider
}

# ─────────────────────────────────────────────
#  KEYWORD SEARCH
# ─────────────────────────────────────────────
search_keywords() {
    local search_terms="$1"
    local urls=("$domain")
    while IFS= read -r dir; do [[ -n "$dir" ]] && urls+=("$domain$dir"); done < "$ALL_DIRECTORIES_FILE"

    IFS=',' read -ra raw_terms <<< "$search_terms"
    local terms=()
    for t in "${raw_terms[@]}"; do
        terms+=("$(echo "$t" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')")
    done

    section "KEYWORD SEARCH"
    info "Searching ${#urls[@]} URL(s) for ${#terms[@]} term(s)…"
    divider

    local found=0
    for url in "${urls[@]}"; do
        local page_content
        page_content=$(run_curl "$url" "$user_agent" "$cookie") || continue
        local title
        title=$(echo "$page_content" | grep -oi '<title>[^<]*</title>' | sed 's/<[^>]*>//g' | head -1)
        [[ -n "$title" ]] && echo -e "  ${DIM}  ↳ $url  ${W}«${title}»${RESET}"
        for term in "${terms[@]}"; do
            local matches
            matches=$(echo "$page_content" | grep --color=always -n -i "$term")
            if [[ -n "$matches" ]]; then
                success "MATCH → ${BOLD}$url${RESET}  ${DIM}(term: '$term')${RESET}"
                echo "$matches" | sed 's/^/     /'
                results+="MATCH in $url (term: '$term')\n$matches\n\n"
                log "Match: $url (term: $term)"
                (( found++ ))
            fi
        done
    done
    divider
    (( found == 0 )) && warn "No matches found." || success "$found match(es) found."
}

# ─────────────────────────────────────────────
#  ROBOTS.TXT + SITEMAP
# ─────────────────────────────────────────────
fetch_robots_sitemap() {
    section "ROBOTS.TXT + SITEMAP"

    # robots.txt
    local robots_status
    robots_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                        -A "$user_agent" "$domain/robots.txt" 2>/dev/null)
    if [[ "$robots_status" == "200" ]]; then
        local robots
        robots=$(run_curl "$domain/robots.txt" "$user_agent" "$cookie")
        success "robots.txt found → $domain/robots.txt"
        echo ""
        echo "$robots" | grep -iE "^(disallow|allow|sitemap|user-agent):" | sed 's/^/     /'
        # Pull Disallow paths into our dir list
        while IFS= read -r rline; do
            local rpath
            rpath=$(echo "$rline" | grep -i "^[Dd]isallow:" | sed 's/[Dd]isallow:[[:space:]]*//' | tr -d '[:space:]')
            if [[ -n "$rpath" && "$rpath" != "/" ]]; then
                echo "$rpath" >> "$ALL_DIRECTORIES_FILE"
                info "Added from robots.txt: $rpath"
            fi
        done <<< "$robots"
        sort -u "$ALL_DIRECTORIES_FILE" -o "$ALL_DIRECTORIES_FILE"
        results+="[ROBOTS] $domain/robots.txt\n$robots\n\n"
        log "robots.txt fetched"
    else
        info "robots.txt: not found (HTTP $robots_status)"
    fi

    echo ""

    # sitemap.xml
    local sitemap_status
    sitemap_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                         -A "$user_agent" "$domain/sitemap.xml" 2>/dev/null)
    if [[ "$sitemap_status" == "200" ]]; then
        local sitemap
        sitemap=$(run_curl "$domain/sitemap.xml" "$user_agent" "$cookie")
        success "sitemap.xml found → $domain/sitemap.xml"
        local sitemap_paths
        sitemap_paths=$(echo "$sitemap" | grep -oP '(?<=<loc>)[^<]+' | \
                        sed "s|${domain}||g" | grep "^/" | sort -u)
        if [[ -n "$sitemap_paths" ]]; then
            info "$(echo "$sitemap_paths" | wc -l) path(s) extracted from sitemap:"
            echo "$sitemap_paths" | sed 's/^/     /'
            echo "$sitemap_paths" >> "$ALL_DIRECTORIES_FILE"
            sort -u "$ALL_DIRECTORIES_FILE" -o "$ALL_DIRECTORIES_FILE"
        fi
        results+="[SITEMAP] $domain/sitemap.xml\n$sitemap_paths\n\n"
        log "sitemap.xml fetched"
    else
        info "sitemap.xml: not found (HTTP $sitemap_status)"
    fi
    divider
}

# ─────────────────────────────────────────────
#  HEADER INSPECTOR
# ─────────────────────────────────────────────
inspect_headers() {
    section "HTTP HEADER INSPECTION  —  $domain"

    local headers
    headers=$(curl -s -I --max-time 10 -A "$user_agent" \
                   ${cookie:+-b "$cookie"} \
                   ${proxy:+--proxy "$proxy"} \
                   ${extra_headers:+-H "$extra_headers"} \
                   "$domain" 2>/dev/null)

    if [[ -z "$headers" ]]; then
        warn "No headers received — target may be unreachable."; return
    fi

    local fp_headers=("Server" "X-Powered-By" "X-AspNet-Version" "X-AspNetMvc-Version"
                      "X-Generator" "X-Drupal-Cache" "Via" "X-Backend-Server")
    local sec_headers=("Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options"
                       "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy" "X-XSS-Protection")

    echo -e "\n  ${BOLD}${W}FINGERPRINTING${RESET}"
    local found_fp=false
    for h in "${fp_headers[@]}"; do
        local val
        val=$(echo "$headers" | grep -i "^${h}:" | sed "s/^[^:]*:[[:space:]]*//" | tr -d '\r')
        if [[ -n "$val" ]]; then
            juicy "$h: $val"
            results+="[HEADER:FP] $h: $val\n"
            found_fp=true
        fi
    done
    $found_fp || info "No fingerprinting headers present."

    echo -e "\n  ${BOLD}${W}SECURITY HEADERS${RESET}"
    for h in "${sec_headers[@]}"; do
        local val
        val=$(echo "$headers" | grep -i "^${h}:" | sed "s/^[^:]*:[[:space:]]*//" | tr -d '\r')
        if [[ -n "$val" ]]; then
            echo -e "  ${G}[✓]${RESET} ${BOLD}$h${RESET}: ${DIM}$val${RESET}"
        else
            warn "MISSING: $h"
            results+="[HEADER:MISSING] $h\n"
        fi
    done

    echo -e "\n  ${BOLD}${W}RAW HEADERS${RESET}"
    echo "$headers" | while IFS= read -r hline; do
        [[ -n "$hline" ]] && echo -e "  ${DIM}$hline${RESET}"
    done
    divider
    log "Header inspection done for $domain"
}

# ─────────────────────────────────────────────
#  NIKTO SCAN
# ─────────────────────────────────────────────
run_nikto() {
    if ! command -v "$NIKTO_PATH" &>/dev/null; then
        error "nikto not found at $NIKTO_PATH"; return 1
    fi
    section "VULNERABILITY SCAN  —  $domain"
    info "This may take several minutes…"
    divider

    local nikto_flags=("-h" "$domain" "-nointeractive")
    [[ -n "$proxy" ]] && nikto_flags+=("-useproxy" "$proxy")

    "$NIKTO_PATH" "${nikto_flags[@]}" 2>/dev/null | while IFS= read -r line; do
        [[ "$line" =~ ^-\ Nikto|^\+\ Start|^\+\ End ]] && continue
        if echo "$line" | grep -qiE "OSVDB|^\+ [0-9]"; then
            local clean="${line#+ }"
            alert "$clean"
            results+="[NIKTO] $clean\n"
            log "Nikto: $clean"
        elif [[ -n "${line//[[:space:]]/}" ]]; then
            info "${line#+ }"
        fi
    done
    divider; log "Nikto scan complete for $domain"
}

# ─────────────────────────────────────────────
#  SUBDOMAIN BRUTE-FORCE
# ─────────────────────────────────────────────
run_subdomain_enum() {
    local sub_wordlist="$1"   # uses dns_wordlist, not the directory wordlist
    local hostname
    hostname=$(echo "$domain" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)

    # Warn if target looks like a bare IP — subdomain fuzzing won't be useful
    if echo "$hostname" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        warn "Target appears to be an IP address ($hostname)."
        warn "Subdomain enumeration requires a real domain name (e.g. example.com)."
        read -rp "  $(echo -e "${Y}[!]${RESET}") Continue anyway? [y/N]: " ip_confirm
        [[ ! "$ip_confirm" =~ ^[Yy]$ ]] && return
    fi

    section "SUBDOMAIN ENUMERATION  —  $hostname"
    info "Wordlist: $(basename "$sub_wordlist")"
    info "This may take a while depending on wordlist size…"
    local proto="http"
    [[ "$domain" =~ ^https:// ]] && proto="https"

    divider
    echo -e "  ${DIM}${W}SUBDOMAIN                            STATUS${RESET}"
    divider

    local found_subs=0
    while IFS= read -r word; do
        [[ -z "$word" || "$word" =~ ^# ]] && continue
        local sub="${word}.${hostname}"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
                      -k -A "$user_agent" ${proxy:+--proxy "$proxy"} \
                      "${proto}://$sub" 2>/dev/null)
        if [[ "$status" != "000" && "$status" != "400" ]]; then
            local coloured_code
            coloured_code=$(colour_status "$status")
            printf "  ${C}%-36s${RESET} [%s]\n" "$sub" "$coloured_code"
            results+="[SUBDOMAIN] $sub ($proto:$status)\n"
            log "Subdomain: $sub ($proto:$status)"
            (( found_subs++ ))
        fi
    done < "$sub_wordlist"

    divider
    (( found_subs == 0 )) && info "No live subdomains found." || success "Found $found_subs live subdomain(s)."
}

# ─────────────────────────────────────────────
#  PARAMETER FUZZER
# ─────────────────────────────────────────────
run_param_fuzz() {
    section "PARAMETER FUZZING"

    # Build URL list for user to pick from
    local urls=("$domain")
    while IFS= read -r dir; do [[ -n "$dir" ]] && urls+=("$domain$dir"); done < "$ALL_DIRECTORIES_FILE"

    echo -e "    ${C}[0]${RESET}  ${DIM}Cancel${RESET}"
    local i=1
    for u in "${urls[@]}"; do echo -e "    ${C}[$i]${RESET}  $u"; (( i++ )); done
    divider
    read -rp "  $(echo -e "${C}[?]${RESET}") Select URL to fuzz parameters on: " param_choice

    [[ "$param_choice" == "0" || -z "$param_choice" ]] && return
    local target_url=""
    if [[ "$param_choice" =~ ^[0-9]+$ ]] && (( param_choice >= 1 && param_choice <= ${#urls[@]} )); then
        target_url="${urls[$((param_choice-1))]}"
    else
        warn "Invalid selection."; return
    fi

    info "Fuzzing parameters on: ${BOLD}$target_url${RESET}"
    info "Wordlist: $(basename "$wordlist")"
    divider
    echo -e "  ${DIM}${W}PARAMETER                            STATUS   SIZE${RESET}"
    divider

    # Baseline response size
    local baseline_size
    baseline_size=$(run_curl "$target_url" "$user_agent" "$cookie" 2>/dev/null | wc -c)

    local found_params=0
    while IFS= read -r param; do
        [[ -z "$param" || "$param" =~ ^# ]] && continue
        local fuzz_url="${target_url}?${param}=1"
        local response status size size_diff
        response=$(run_curl "$fuzz_url" "$user_agent" "$cookie" 2>/dev/null)
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                      -A "$user_agent" ${cookie:+-b "$cookie"} "$fuzz_url" 2>/dev/null)
        size=$(echo "$response" | wc -c)
        size_diff=$(( size - baseline_size ))
        [[ $size_diff -lt 0 ]] && size_diff=$(( -size_diff ))

        if [[ "$status" != "404" && "$status" != "000" && ( "$status" == "200" || $size_diff -gt 50 ) ]]; then
            local coloured_code
            coloured_code=$(colour_status "$status")
            printf "  ${C}%-36s${RESET} [%s]  ${DIM}%s bytes${RESET}\n" "?${param}=1" "$coloured_code" "$size"
            # Passive SQLi check on the response
            if echo "$response" | grep -qiE "$SQL_ERRORS"; then
                alert "SQL error signature in response for param: $param"
                sqli_targets+=("${target_url}?${param}=1")
                results+="[PARAM:SQLi] ${target_url}?${param}=1\n"
                log "SQLi indicator in param: $param at $target_url"
            fi
            results+="[PARAM] ${target_url}?${param}=1 (HTTP $status)\n"
            log "Param found: $param at $target_url"
            (( found_params++ ))
        fi
    done < "$wordlist"

    divider
    (( found_params == 0 )) && info "No interesting parameters found." || success "Found $found_params parameter(s)."
}

# ─────────────────────────────────────────────
#  SQLi PASSIVE PROBE
#  Appends a single quote to each discovered URL and watches for DB error strings.
#  Does NOT run sqlmap — just populates sqli_targets[] for the post-session prompt.
# ─────────────────────────────────────────────
sqli_probe() {
    section "PASSIVE SQLi PROBE"
    info "Probing discovered URLs with a single-quote for SQL error signatures…"
    divider

    local urls=("$domain")
    while IFS= read -r dir; do [[ -n "$dir" ]] && urls+=("$domain$dir"); done < "$ALL_DIRECTORIES_FILE"

    for url in "${urls[@]}"; do
        local response
        response=$(curl -s --max-time 10 -A "$user_agent" \
                        ${cookie:+-b "$cookie"} \
                        ${proxy:+--proxy "$proxy"} \
                        "${url}'" 2>/dev/null)
        if echo "$response" | grep -qiE "$SQL_ERRORS"; then
            alert "SQL error signature → ${BOLD}$url${RESET}"
            sqli_targets+=("$url")
            results+="[SQLi PROBE HIT] $url\n"
            log "SQLi probe hit: $url"
        fi
    done

    divider
    if [[ ${#sqli_targets[@]} -eq 0 ]]; then
        info "No SQL error signatures detected."
    else
        success "${#sqli_targets[@]} potential SQLi target(s) flagged."
    fi
}

# ─────────────────────────────────────────────
#  POST-SESSION SQLi PROMPT + SQLMAP LAUNCH
# ─────────────────────────────────────────────
prompt_sqlmap() {
    [[ ${#sqli_targets[@]} -eq 0 ]] && return

    echo ""
    divider
    echo -e "  ${R}${BOLD}  ⚠  POTENTIAL SQL INJECTION DETECTED  ⚠${RESET}"
    divider
    echo -e "  ${Y}The following URL(s) returned SQL error signatures during this"
    echo -e "  session. They may be injectable.${RESET}"
    echo ""
    local i=1
    for t in "${sqli_targets[@]}"; do
        echo -e "    ${R}[$i]${RESET}  $t"; (( i++ ))
    done
    echo ""
    echo -e "  ${DIM}SQLMap can attempt automated exploitation of these targets."
    echo -e "  Additional requests will be sent to the target.${RESET}"
    echo ""
    read -rp "  $(echo -e "${C}[?]${RESET}") Attempt exploitation with SQLMap? [y/N]: " run_sqlmap
    [[ ! "$run_sqlmap" =~ ^[Yy]$ ]] && return

    if ! command -v "$SQLMAP_PATH" &>/dev/null; then
        error "sqlmap not found at $SQLMAP_PATH"; return 1
    fi

    local sqli_choice="1"
    if [[ ${#sqli_targets[@]} -gt 1 ]]; then
        read -rp "  $(echo -e "${C}[?]${RESET}") Target numbers (space-separated) or 'a' for all: " sqli_choice
    fi

    local selected=()
    if [[ "$sqli_choice" == "a" || ${#sqli_targets[@]} -eq 1 ]]; then
        selected=("${sqli_targets[@]}")
    else
        for idx in $sqli_choice; do
            if [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#sqli_targets[@]} )); then
                selected+=("${sqli_targets[$((idx-1))]}")
            else
                warn "Invalid selection '$idx' — skipping."
            fi
        done
    fi
    [[ ${#selected[@]} -eq 0 ]] && return

    read -rp "  $(echo -e "${C}[?]${RESET}") SQLMap risk level [1-3, default 1]: " sqli_risk
    read -rp "  $(echo -e "${C}[?]${RESET}") SQLMap level     [1-5, default 1]: " sqli_level
    sqli_risk="${sqli_risk:-1}"; sqli_level="${sqli_level:-1}"

    for target_url in "${selected[@]}"; do
        section "SQLMAP  —  $target_url"
        log "SQLMap launched: $target_url"

        local sm_flags=("-u" "$target_url" "--risk=$sqli_risk" "--level=$sqli_level" "--batch")
        [[ -n "$cookie"      ]] && sm_flags+=("--cookie=$cookie")
        [[ -n "$proxy"       ]] && sm_flags+=("--proxy=$proxy")
        [[ -n "$user_agent"  ]] && sm_flags+=("--user-agent=$user_agent")

        "$SQLMAP_PATH" "${sm_flags[@]}" 2>&1 | while IFS= read -r line; do
            if echo "$line" | grep -qiE "\[CRITICAL\]|\[ERROR\]"; then
                error "$line"
            elif echo "$line" | grep -qiE "\[WARNING\]"; then
                warn "${line#*WARNING\] }"
            elif echo "$line" | grep -qiE "is vulnerable|parameter.*injectable|identified the following"; then
                alert "$line"
                results+="[SQLMAP] $line\n"
                log "SQLMap finding: $line"
            elif echo "$line" | grep -qiE "\[INFO\]"; then
                info "${line#*INFO\] }"
            elif [[ -n "${line//[[:space:]]/}" ]]; then
                echo -e "  ${DIM}$line${RESET}"
            fi
        done
        divider; log "SQLMap complete: $target_url"
    done
}

# ─────────────────────────────────────────────
#  FILTER CONFIG
# ─────────────────────────────────────────────
configure_filters() {
    echo ""
    info "Current ignored status codes: ${BOLD}$IGNORE_CODES${RESET}"
    read -rp "  $(echo -e "${C}[?]${RESET}") New ignore list (comma-separated, blank to keep): " new_codes
    if [[ -n "$new_codes" ]]; then
        IGNORE_CODES="$new_codes"
        success "Now ignoring: $IGNORE_CODES"
        log "Filter updated: $IGNORE_CODES"
    fi
}

# ─────────────────────────────────────────────
#  SAVE RESULTS
# ─────────────────────────────────────────────
save_results() {
    if [[ -z "$results" ]]; then
        info "No results to save."; return
    fi
    echo ""
    read -rp "  $(echo -e "${C}[?]${RESET}") Save results to a file? [y/N]: " should_save
    [[ ! "$should_save" =~ ^[Yy]$ ]] && return
    read -rp "  $(echo -e "${C}[?]${RESET}") Filename: " results_filename
    {
        printf "DirGrep v4.1 — Results\n"
        printf "Domain : %s\n" "$domain"
        printf "Date   : %s\n" "$(date)"
        printf "================================================================\n\n"
        printf "%b\n" "$results"
    } > "$results_filename"
    if [[ $? -eq 0 ]]; then
        success "Results saved to $results_filename"
        log "Results saved: $results_filename"
    else
        error "Failed to write to $results_filename"
    fi
}

# ─────────────────────────────────────────────
#  PASSIVE RECON — SSL / TLS
# ─────────────────────────────────────────────
inspect_ssl() {
    local hostname port
    hostname=$(echo "$domain" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
    port=$(echo "$domain" | grep -oP '(?<=:)\d+$')
    [[ -z "$port" ]] && { [[ "$domain" =~ ^https:// ]] && port=443 || port=80; }

    section "SSL / TLS CERTIFICATE  —  ${hostname}:${port}"

    if ! command -v openssl &>/dev/null; then
        error "openssl not found — SSL inspection unavailable"; return 1
    fi

    local cert_raw
    cert_raw=$(echo | timeout 10 openssl s_client \
                   -connect "${hostname}:${port}" -servername "$hostname" 2>/dev/null)
    if ! echo "$cert_raw" | grep -q "BEGIN CERTIFICATE"; then
        info "No TLS on port $port — trying 443…"
        cert_raw=$(echo | timeout 10 openssl s_client \
                       -connect "${hostname}:443" -servername "$hostname" 2>/dev/null)
    fi
    if ! echo "$cert_raw" | grep -q "BEGIN CERTIFICATE"; then
        warn "No TLS certificate found."; return
    fi

    local x509
    x509=$(echo "$cert_raw" | openssl x509 -noout -subject -issuer -dates -text 2>/dev/null)

    echo -e "\n  ${BOLD}${W}SUBJECT / ISSUER${RESET}"
    echo "$x509" | grep -E "^subject=|^issuer=" | \
        while IFS= read -r ln; do echo -e "  ${DIM}$ln${RESET}"; done

    echo -e "\n  ${BOLD}${W}VALIDITY${RESET}"
    local not_before not_after
    not_before=$(echo "$x509" | grep "notBefore=" | sed 's/.*notBefore=//')
    not_after=$(echo  "$x509" | grep "notAfter="  | sed 's/.*notAfter=//')
    echo -e "  ${DIM}Not Before : $not_before${RESET}"
    echo -e "  ${DIM}Not After  : $not_after${RESET}"

    local expiry_epoch; expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null)
    local now_epoch;    now_epoch=$(date +%s)
    if [[ -n "$expiry_epoch" ]]; then
        if (( expiry_epoch < now_epoch )); then
            alert "Certificate has EXPIRED"
            results+="[SSL:EXPIRED] $not_after\n"
        elif (( expiry_epoch - now_epoch < 2592000 )); then
            warn "Certificate expires within 30 days: $not_after"
        fi
    fi

    local subj iss
    subj=$(echo "$x509" | grep "^subject=" | sed 's/^subject=//')
    iss=$(echo  "$x509" | grep "^issuer="  | sed 's/^issuer=//')
    [[ "$subj" == "$iss" ]] && {
        alert "Self-signed certificate"
        results+="[SSL:SELF-SIGNED] $hostname\n"
    }

    echo -e "\n  ${BOLD}${W}SUBJECT ALTERNATIVE NAMES${RESET}  ${DIM}(potential vhosts / targets)${RESET}"
    local sans
    sans=$(echo "$x509" | grep -A2 "Subject Alternative Name" | \
           tr ',' '\n' | grep "DNS:" | sed 's/.*DNS://;s/[[:space:]]//g' | sort -u)
    if [[ -n "$sans" ]]; then
        while IFS= read -r san; do
            juicy "SAN → $san"
            results+="[SSL:SAN] $san\n"
            log "SSL SAN: $san"
        done <<< "$sans"
    else
        info "No DNS SANs found."
    fi

    divider
    log "SSL inspection done: $domain"
}

# ─────────────────────────────────────────────
#  PASSIVE RECON — JS ENDPOINT EXTRACTION
# ─────────────────────────────────────────────
run_js_recon() {
    section "JS ENDPOINT EXTRACTION  —  $domain"
    info "Crawling index page for script sources…"

    local page_content
    page_content=$(run_curl "$domain" "$user_agent" "$cookie") || {
        error "Could not fetch target."; return 1
    }

    local -a js_urls=()
    while IFS= read -r src; do
        [[ -z "$src" ]] && continue
        if [[ "$src" =~ ^https?:// ]]; then
            js_urls+=("$src")
        elif [[ "$src" =~ ^// ]]; then
            local proto; proto=$(echo "$domain" | grep -oP '^https?')
            js_urls+=("${proto}:${src}")
        elif [[ "$src" =~ ^/ ]]; then
            js_urls+=("${domain}${src}")
        else
            js_urls+=("${domain}/${src}")
        fi
    done < <(echo "$page_content" | \
             grep -oiP '(?<=src=["\x27])[^"\x27]+\.js[^"\x27]*(?=["\x27])')

    while IFS= read -r dir; do
        [[ "$dir" =~ \.js$ ]] && js_urls+=("${domain}${dir}")
    done < "$ALL_DIRECTORIES_FILE"

    mapfile -t js_urls < <(printf '%s\n' "${js_urls[@]}" | sort -u)

    if [[ ${#js_urls[@]} -eq 0 ]]; then
        info "No JavaScript files discovered."; return
    fi
    success "${#js_urls[@]} JS file(s) to analyse"; divider

    local total_eps=0
    local tmp_js; tmp_js=$(mktemp /tmp/dirgrep_js.XXXXXX)

    for js_url in "${js_urls[@]}"; do
        info "→ $(basename "$js_url")"
        run_curl "$js_url" "$user_agent" "$cookie" > "$tmp_js" 2>/dev/null || continue

        local endpoints
        endpoints=$(grep -oP '["\x27](/[a-zA-Z0-9_/.-]{2,})["\x27]' "$tmp_js" 2>/dev/null | \
                    tr -d "\"'" | grep "^/" | \
                    grep -vE '\.(css|png|jpg|gif|ico|woff2?|ttf|svg|eot|map)$' | sort -u)

        if [[ -n "$endpoints" ]]; then
            local ec; ec=$(echo "$endpoints" | wc -l)
            success "$ec path(s) extracted"
            while IFS= read -r ep; do
                echo -e "    ${C}$ep${RESET}"
                echo "$ep" >> "$ALL_DIRECTORIES_FILE"
                results+="[JS:PATH] $ep\n"
                (( total_eps++ ))
            done <<< "$endpoints"
            sort -u "$ALL_DIRECTORIES_FILE" -o "$ALL_DIRECTORIES_FILE"
        else
            info "No path strings extracted."
        fi

        local ext_urls
        ext_urls=$(grep -oiP '["\x27](https?://[^"\x27]{8,})["\x27]' "$tmp_js" 2>/dev/null | \
                   tr -d "\"'" | grep -v "^${domain}" | sort -u | head -15)
        if [[ -n "$ext_urls" ]]; then
            warn "External URLs found (check for leaked API hosts / keys):"
            while IFS= read -r ext; do
                echo -e "    ${Y}↳ $ext${RESET}"
                results+="[JS:EXT] $ext\n"
            done <<< "$ext_urls"
        fi
    done

    rm -f "$tmp_js"
    divider
    success "$total_eps total endpoint(s) added to discovery pool."
    log "JS recon complete — $total_eps endpoints"
}

# ─────────────────────────────────────────────
#  PASSIVE RECON — CORS CHECK
# ─────────────────────────────────────────────
check_cors() {
    section "CORS MISCONFIGURATION CHECK  —  $domain"

    local -a urls=("$domain")
    while IFS= read -r dir; do [[ -n "$dir" ]] && urls+=("$domain$dir"); done < "$ALL_DIRECTORIES_FILE"
    info "Testing ${#urls[@]} URL(s)…"; divider

    local issues=0
    for url in "${urls[@]}"; do
        local acao acac acao_null
        acao=$(curl -s -I --max-time 8 -A "$user_agent" \
                    -H "Origin: https://evil.com" \
                    ${cookie:+-b "$cookie"} ${proxy:+--proxy "$proxy"} \
                    "$url" 2>/dev/null | \
               grep -i "^access-control-allow-origin:" | \
               sed 's/[^:]*:[[:space:]]*//' | tr -d '\r ')
        acac=$(curl -s -I --max-time 8 -A "$user_agent" \
                    -H "Origin: https://evil.com" \
                    ${cookie:+-b "$cookie"} ${proxy:+--proxy "$proxy"} \
                    "$url" 2>/dev/null | \
               grep -i "^access-control-allow-credentials:" | \
               sed 's/[^:]*:[[:space:]]*//' | tr -d '\r ' | tr '[:upper:]' '[:lower:]')

        if [[ "$acao" == "https://evil.com" && "$acac" == "true" ]]; then
            alert "EXPLOITABLE CORS — reflected origin + credentials: $url"
            results+="[CORS:CRITICAL] $url\n"; log "CORS critical: $url"; (( issues++ ))
        elif [[ "$acao" == "https://evil.com" ]]; then
            warn "CORS: arbitrary origin reflected (no creds): $url"
            results+="[CORS:WARN] reflected origin: $url\n"; (( issues++ ))
        elif [[ "$acao" == "*" && "$acac" == "true" ]]; then
            alert "CORS: wildcard + credentials flag: $url"
            results+="[CORS:WARN] wildcard+creds: $url\n"; (( issues++ ))
        fi

        acao_null=$(curl -s -I --max-time 8 -A "$user_agent" \
                        -H "Origin: null" \
                        ${cookie:+-b "$cookie"} ${proxy:+--proxy "$proxy"} \
                        "$url" 2>/dev/null | \
                    grep -i "^access-control-allow-origin:" | \
                    sed 's/[^:]*:[[:space:]]*//' | tr -d '\r ')
        if [[ "$acao_null" == "null" ]]; then
            alert "CORS: null origin accepted: $url"
            results+="[CORS:WARN] null origin: $url\n"; log "CORS null: $url"; (( issues++ ))
        fi
    done

    divider
    (( issues == 0 )) && info "No CORS misconfigurations detected." || \
        warn "$issues CORS issue(s) found."
    log "CORS check complete: $domain"
}

# ─────────────────────────────────────────────
#  PASSIVE RECON — COOKIE SECURITY
# ─────────────────────────────────────────────
analyze_cookies() {
    section "COOKIE SECURITY ANALYSIS  —  $domain"

    local raw_hdrs
    raw_hdrs=$(curl -s -I -L --max-time 10 -A "$user_agent" \
                   ${cookie:+-b "$cookie"} ${proxy:+--proxy "$proxy"} \
                   "$domain" 2>/dev/null)

    local cookie_lines
    cookie_lines=$(echo "$raw_hdrs" | grep -i "^set-cookie:" | tr -d '\r')
    if [[ -z "$cookie_lines" ]]; then info "No Set-Cookie headers found."; return; fi

    local count; count=$(echo "$cookie_lines" | wc -l)
    info "$count cookie(s) found"; divider

    local issues=0
    while IFS= read -r cline; do
        local name
        name=$(echo "$cline" | sed 's/[Ss]et-[Cc]ookie:[[:space:]]*//' | \
               cut -d'=' -f1 | tr -d ' ')
        echo -e "  ${BOLD}${W}$name${RESET}"

        echo "$cline" | grep -qiE ";[[:space:]]*HttpOnly" \
            && echo -e "    ${G}[✓]${RESET} HttpOnly" \
            || { warn "  Missing HttpOnly"; results+="[COOKIE:MISSING] HttpOnly → $name\n"; (( issues++ )); }

        if [[ "$domain" =~ ^https:// ]]; then
            echo "$cline" | grep -qiE ";[[:space:]]*Secure" \
                && echo -e "    ${G}[✓]${RESET} Secure" \
                || { warn "  Missing Secure"; results+="[COOKIE:MISSING] Secure → $name\n"; (( issues++ )); }
        fi

        local ss; ss=$(echo "$cline" | grep -oiP '(?<=SameSite=)[^\s;,]+' | tr '[:upper:]' '[:lower:]')
        if [[ -z "$ss" ]]; then
            warn "  Missing SameSite"
            results+="[COOKIE:MISSING] SameSite → $name\n"; (( issues++ ))
        elif [[ "$ss" == "none" ]]; then
            warn "  SameSite=None (CSRF risk)"
            results+="[COOKIE:SAMESITE_NONE] $name\n"; (( issues++ ))
        else
            echo -e "    ${G}[✓]${RESET} SameSite=${ss}"
        fi
        echo ""
    done <<< "$cookie_lines"

    divider
    (( issues == 0 )) && success "All cookies look well-configured." || \
        warn "$issues issue(s) found."
    log "Cookie analysis done: $domain"
}

# ─────────────────────────────────────────────
#  PASSIVE RECON — TECH FINGERPRINTING
# ─────────────────────────────────────────────
fingerprint_tech() {
    section "TECHNOLOGY FINGERPRINT  —  $domain"

    local hdrs page_content
    hdrs=$(curl -s -I --max-time 10 -A "$user_agent" \
               ${cookie:+-b "$cookie"} ${proxy:+--proxy "$proxy"} \
               "$domain" 2>/dev/null)
    page_content=$(run_curl "$domain" "$user_agent" "$cookie")

    echo -e "\n  ${BOLD}${W}SERVER STACK${RESET}"
    local server powered gen
    server=$(echo  "$hdrs" | grep -i "^Server:"       | sed 's/[^:]*:[[:space:]]*//' | tr -d '\r')
    powered=$(echo "$hdrs" | grep -i "^X-Powered-By:" | sed 's/[^:]*:[[:space:]]*//' | tr -d '\r')
    gen=$(echo     "$hdrs" | grep -i "^X-Generator:"  | sed 's/[^:]*:[[:space:]]*//' | tr -d '\r')
    [[ -n "$server"  ]] && { juicy "Server: $server";        results+="[TECH] Server: $server\n"; }
    [[ -n "$powered" ]] && { juicy "X-Powered-By: $powered"; results+="[TECH] X-Powered-By: $powered\n"; }
    [[ -n "$gen"     ]] && { juicy "X-Generator: $gen";      results+="[TECH] X-Generator: $gen\n"; }
    [[ -z "${server}${powered}${gen}" ]] && info "No server header fingerprints."

    echo -e "\n  ${BOLD}${W}CMS / FRAMEWORK${RESET}"
    local detected=false
    local body_hdrs="${page_content}${hdrs}"

    echo "$page_content" | grep -qiE "wp-content|wp-includes|wp-json|wordpress"    && { juicy "WordPress detected";        results+="[TECH] WordPress\n";  detected=true; }
    echo "$page_content" | grep -qiE "/components/com_|Joomla!|/media/jui/"        && { juicy "Joomla detected";           results+="[TECH] Joomla\n";     detected=true; }
    echo "$page_content" | grep -qiE "Drupal\.settings|/sites/default/|drupal\.js" && { juicy "Drupal detected";           results+="[TECH] Drupal\n";     detected=true; }
    echo "$body_hdrs"    | grep -qiE "__VIEWSTATE|__EVENTVALIDATION|X-AspNet"       && { juicy "ASP.NET detected";          results+="[TECH] ASP.NET\n";    detected=true; }
    echo "$body_hdrs"    | grep -qiE "laravel_session|XSRF-TOKEN.*[Ll]aravel"       && { juicy "Laravel detected";          results+="[TECH] Laravel\n";    detected=true; }
    echo "$page_content" | grep -qiE "csrfmiddlewaretoken|django"                   && { juicy "Django detected";           results+="[TECH] Django\n";     detected=true; }
    echo "$body_hdrs"    | grep -qiE "authenticity_token|_rails_session"             && { juicy "Ruby on Rails detected";   results+="[TECH] Rails\n";      detected=true; }
    echo "$hdrs"         | grep -qiE "X-Powered-By:.*[Ee]xpress|connect\.sid"       && { juicy "Express/Node.js detected"; results+="[TECH] Express\n";    detected=true; }
    echo "$page_content" | grep -qiE "spring|thymeleaf"                             && { juicy "Spring (Java) detected";   results+="[TECH] Spring\n";     detected=true; }

    $detected || info "No CMS/framework signatures detected."

    echo -e "\n  ${BOLD}${W}FRONTEND LIBRARIES${RESET}"
    local found_fe=false
    if echo "$page_content" | grep -qiE "jquery"; then
        local jq_ver; jq_ver=$(echo "$page_content" | grep -oP 'jquery[._\-]\K[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
        info "jQuery${jq_ver:+ $jq_ver}"; found_fe=true
    fi
    if echo "$page_content" | grep -qiE "bootstrap"; then
        local bs_ver; bs_ver=$(echo "$page_content" | grep -oP 'bootstrap[._\-]\K[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
        info "Bootstrap${bs_ver:+ $bs_ver}"; found_fe=true
    fi
    echo "$page_content" | grep -qiE "react|ReactDOM"   && { info "React";   found_fe=true; }
    echo "$page_content" | grep -qiE "angular|ng-app"   && { info "Angular"; found_fe=true; }
    echo "$page_content" | grep -qiE "vue\.js|new Vue\(" && { info "Vue.js"; found_fe=true; }
    $found_fe || info "No frontend library signatures detected."

    divider
    log "Tech fingerprint complete: $domain"
}

# ─────────────────────────────────────────────
#  FUZZING — VIRTUAL HOST ENUMERATION
# ─────────────────────────────────────────────
run_vhost_enum() {
    local vhost_wl
    if [[ -n "${wordlist:-}" && -f "$wordlist" ]]; then
        vhost_wl="$wordlist"
        info "Using current wordlist: $(basename "$vhost_wl")"
    else
        wordlist_menu; vhost_wl="$wordlist"
    fi
    [[ ! -f "$vhost_wl" ]] && { error "Wordlist not found: $vhost_wl"; return 1; }

    local hostname proto
    hostname=$(echo "$domain" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
    [[ "$domain" =~ ^https:// ]] && proto="https" || proto="http"

    section "VIRTUAL HOST ENUMERATION  —  $hostname"
    info "Wordlist: $(basename "$vhost_wl")"
    info "Fuzzing Host: <word>.${hostname} against $domain  (baseline-filtered)"

    local baseline
    baseline=$(curl -s -o /dev/null -w "%{size_download}" --max-time 10 \
                    -A "$user_agent" ${cookie:+-b "$cookie"} \
                    ${proxy:+--proxy "$proxy"} "$domain" 2>/dev/null)
    info "Baseline response size: ${baseline} bytes"
    divider
    echo -e "  ${DIM}${W}VHOST                                STATUS   SIZE${RESET}"
    divider

    local found=0
    trap 'echo -e "\n${Y}[!]${RESET}  Scan interrupted."; trap - INT' INT
    while IFS= read -r word; do
        [[ -z "$word" || "$word" =~ ^# ]] && continue
        local vhost="${word}.${hostname}"
        local status size
        read -r status size < <(curl -s -o /dev/null \
                                     -w "%{http_code} %{size_download}" \
                                     --max-time 8 -A "$user_agent" \
                                     -H "Host: $vhost" \
                                     ${cookie:+-b "$cookie"} ${proxy:+--proxy "$proxy"} \
                                     "$domain" 2>/dev/null)
        [[ "$status" == "000" ]] && continue
        local diff=$(( size - baseline )); (( diff < 0 )) && diff=$(( -diff ))
        if [[ "$status" =~ ^2 || "$status" =~ ^3 || $diff -gt 100 ]]; then
            local cc; cc=$(colour_status "$status")
            printf "  ${C}%-36s${RESET} [%s]  ${DIM}%s bytes${RESET}\n" "$vhost" "$cc" "$size"
            results+="[VHOST] $vhost (HTTP $status, ${size}b)\n"
            log "VHOST: $vhost ($status)"
            (( found++ ))
        fi
    done < "$vhost_wl"
    trap - INT

    divider
    (( found == 0 )) && info "No virtual hosts found." || success "$found vhost(s) found."
    log "VHOST enumeration complete: $domain"
}

# ─────────────────────────────────────────────
#  FUZZING — 403 / 401 BYPASS
# ─────────────────────────────────────────────
run_403_bypass() {
    section "403 / 401 BYPASS ATTEMPTS"

    local -a all_paths=()
    while IFS= read -r dir; do [[ -n "$dir" ]] && all_paths+=("$dir"); done < "$ALL_DIRECTORIES_FILE"
    [[ ${#all_paths[@]} -eq 0 ]] && { info "No paths found — run a directory scan first."; return; }

    info "Probing ${#all_paths[@]} path(s) for blocked responses…"
    local -a blocked=()
    for path in "${all_paths[@]}"; do
        local st
        st=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 \
                  -A "$user_agent" ${cookie:+-b "$cookie"} \
                  ${proxy:+--proxy "$proxy"} "${domain}${path}" 2>/dev/null)
        [[ "$st" == "401" || "$st" == "403" ]] && blocked+=("$path")
    done

    [[ ${#blocked[@]} -eq 0 ]] && { info "No 401/403 paths to test."; return; }
    success "${#blocked[@]} blocked path(s) — running bypass techniques…"
    divider

    local bypassed=0
    for path in "${blocked[@]}"; do
        local base="${domain}${path}" p="${path#/}"
        info "→ $path"

        local -a try_labels=("double-slash" "dot-prefix" "trailing-dot-slash"
                             "trailing-%20" "trailing-%09" "dot-semi")
        local -a try_urls=("${domain}//${p}" "${domain}/.${path}" "${base}/."
                           "${base}%20" "${base}%09" "${base}..;/")

        local i
        for (( i=0; i<${#try_urls[@]}; i++ )); do
            local st
            st=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 \
                      -A "$user_agent" ${cookie:+-b "$cookie"} \
                      ${proxy:+--proxy "$proxy"} "${try_urls[$i]}" 2>/dev/null)
            if [[ "$st" == "200" || "$st" == "301" || "$st" == "302" ]]; then
                alert "BYPASS [${try_labels[$i]}] → ${try_urls[$i]}  (HTTP $st)"
                results+="[403BYPASS] ${try_labels[$i]}: ${try_urls[$i]} ($st)\n"
                log "403 bypass [${try_labels[$i]}]: ${try_urls[$i]} ($st)"
                (( bypassed++ ))
            fi
        done

        local -a hdr_tests=(
            "X-Original-URL: ${path}"
            "X-Rewrite-URL: ${path}"
            "X-Custom-IP-Authorization: 127.0.0.1"
            "X-Forwarded-For: 127.0.0.1"
            "X-Forwarded-Host: localhost"
        )
        for h in "${hdr_tests[@]}"; do
            local st
            st=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 \
                      -A "$user_agent" ${cookie:+-b "$cookie"} \
                      -H "$h" ${proxy:+--proxy "$proxy"} "$base" 2>/dev/null)
            if [[ "$st" == "200" ]]; then
                alert "BYPASS [header] '$h' → $base"
                results+="[403BYPASS:HDR] $h → $base\n"
                log "403 bypass header: $h → $base"
                (( bypassed++ ))
            fi
        done
    done

    divider
    (( bypassed == 0 )) && info "No bypasses found." || success "$bypassed bypass(es) found."
    log "403 bypass complete"
}

# ─────────────────────────────────────────────
#  FUZZING — EXTENSION BRUTE-FORCE
# ─────────────────────────────────────────────
run_ext_fuzz() {
    section "EXTENSION BRUTE-FORCE"

    local -a paths=()
    while IFS= read -r dir; do [[ -n "$dir" ]] && paths+=("${dir%/}"); done < "$ALL_DIRECTORIES_FILE"
    [[ ${#paths[@]} -eq 0 ]] && { info "No paths to fuzz — run a directory scan first."; return; }

    local default_exts=".php .html .txt .bak .old .backup .asp .aspx .jsp .cfg .config .xml .json .log .sql"
    info "Default extensions: $default_exts"
    read -rp "  $(echo -e "${C}[?]${RESET}") Customise? [y/N]: " cust_ext
    local exts_str="$default_exts"
    [[ "$cust_ext" =~ ^[Yy]$ ]] && \
        read -rp "  $(echo -e "${C}[?]${RESET}") Extensions (space-separated, include dot): " exts_str
    read -ra exts <<< "$exts_str"

    info "Testing ${#paths[@]} path(s) × ${#exts[@]} extension(s)…"
    divider
    echo -e "  ${DIM}${W}PATH+EXT                             STATUS   SIZE${RESET}"
    divider

    local found=0
    trap 'echo -e "\n${Y}[!]${RESET}  Scan interrupted."; trap - INT' INT
    for base_path in "${paths[@]}"; do
        for ext in "${exts[@]}"; do
            local test_url="${domain}${base_path}${ext}"
            local status size
            read -r status size < <(curl -s -o /dev/null \
                                         -w "%{http_code} %{size_download}" \
                                         --max-time 8 -A "$user_agent" \
                                         ${cookie:+-b "$cookie"} \
                                         ${proxy:+--proxy "$proxy"} \
                                         "$test_url" 2>/dev/null)
            if [[ "$status" != "404" && "$status" != "000" && "$status" != "400" ]]; then
                local cc; cc=$(colour_status "$status")
                local rel="${base_path}${ext}"
                printf "  ${C}%-36s${RESET} [%s]  ${DIM}%s bytes${RESET}\n" "$rel" "$cc" "$size"
                check_juicy "$rel" "$domain"
                results+="[EXT] $test_url (HTTP $status)\n"
                log "Ext fuzz: $test_url ($status)"
                (( found++ ))
            fi
        done
    done
    trap - INT

    divider
    (( found == 0 )) && info "No interesting extension hits." || success "$found hit(s) found."
    log "Extension fuzz complete"
}

# ─────────────────────────────────────────────
#  FUZZING — HTTP METHOD FUZZING
# ─────────────────────────────────────────────
run_method_fuzz() {
    section "HTTP METHOD FUZZING"

    local -a urls=("$domain")
    while IFS= read -r dir; do [[ -n "$dir" ]] && urls+=("$domain$dir"); done < "$ALL_DIRECTORIES_FILE"

    local -a methods=("OPTIONS" "PUT" "DELETE" "PATCH" "TRACE" "CONNECT")
    info "Testing ${#urls[@]} URL(s) × ${#methods[@]} method(s)…"
    divider
    echo -e "  ${DIM}${W}METHOD     PATH                         STATUS${RESET}"
    divider

    local found=0
    for url in "${urls[@]}"; do
        for method in "${methods[@]}"; do
            local status
            status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 \
                          -X "$method" -A "$user_agent" \
                          ${cookie:+-b "$cookie"} ${proxy:+--proxy "$proxy"} \
                          "$url" 2>/dev/null)
            if [[ "$status" != "404" && "$status" != "000" && \
                  "$status" != "405" && "$status" != "501" && "$status" != "400" ]]; then
                local cc; cc=$(colour_status "$status")
                local rel="${url#$domain}"; [[ -z "$rel" ]] && rel="/"
                printf "  ${C}%-10s${RESET} ${W}%-28s${RESET} [%s]\n" "$method" "$rel" "$cc"
                results+="[METHOD] $method $url (HTTP $status)\n"
                log "Method: $method $url ($status)"
                (( found++ ))
                if [[ "$method" == "OPTIONS" && "$status" == "200" ]]; then
                    local allow
                    allow=$(curl -s -I --max-time 8 -X OPTIONS -A "$user_agent" \
                                ${cookie:+-b "$cookie"} "$url" 2>/dev/null | \
                            grep -i "^Allow:" | tr -d '\r' | sed 's/[Aa]llow:[[:space:]]*//')
                    [[ -n "$allow" ]] && info "  Allow: $allow"
                fi
            fi
        done
    done

    divider
    (( found == 0 )) && info "No interesting method responses." || \
        success "$found interesting response(s)."
    log "Method fuzz complete"
}

# ─────────────────────────────────────────────
#  FUZZING — BACKUP FILE PROBE
# ─────────────────────────────────────────────
run_backup_probe() {
    section "BACKUP FILE PROBE"

    local -a paths=()
    while IFS= read -r dir; do [[ -n "$dir" ]] && paths+=("$dir"); done < "$ALL_DIRECTORIES_FILE"
    [[ ${#paths[@]} -eq 0 ]] && { info "No paths to probe — run a directory scan first."; return; }

    local -a suffixes=(".bak" "~" ".old" ".orig" ".backup" ".copy" ".swp" ".1" ".save")
    info "Probing ${#paths[@]} path(s)…"
    divider
    echo -e "  ${DIM}${W}PATH                                 STATUS   SIZE${RESET}"
    divider

    local found=0
    trap 'echo -e "\n${Y}[!]${RESET}  Probe interrupted."; trap - INT' INT
    for path in "${paths[@]}"; do
        local -a all_sfx=("${suffixes[@]}")
        [[ "$path" =~ \.php$ ]] && all_sfx+=(".php.bak" ".php~" ".php.old" ".php.swp")
        for sfx in "${all_sfx[@]}"; do
            local test_url="${domain}${path}${sfx}"
            local status size
            read -r status size < <(curl -s -o /dev/null \
                                         -w "%{http_code} %{size_download}" \
                                         --max-time 8 -A "$user_agent" \
                                         ${cookie:+-b "$cookie"} \
                                         ${proxy:+--proxy "$proxy"} \
                                         "$test_url" 2>/dev/null)
            if [[ "$status" != "404" && "$status" != "000" && "$status" != "400" ]]; then
                local cc; cc=$(colour_status "$status")
                local rel="${path}${sfx}"
                printf "  ${C}%-36s${RESET} [%s]  ${DIM}%s bytes${RESET}\n" "$rel" "$cc" "$size"
                juicy "Backup file → ${domain}${rel}"
                results+="[BACKUP] ${domain}${rel} (HTTP $status)\n"
                log "Backup: ${domain}${rel} ($status)"
                (( found++ ))
            fi
        done
    done
    trap - INT

    divider
    (( found == 0 )) && info "No backup files found." || success "$found backup file(s) found."
    log "Backup probe complete"
}

# ─────────────────────────────────────────────
#  ARGUMENT PARSING
# ─────────────────────────────────────────────
domain=""; user_agent="$USER_AGENT"; cookie=""; proxy=""; extra_headers=""; rate_limit=""

while getopts ":u:d:c:p:H:r:i:h" opt; do
    case $opt in
        u) user_agent="$OPTARG" ;;
        d) domain="$OPTARG" ;;
        c) cookie="$OPTARG" ;;
        p) proxy="$OPTARG" ;;
        H) extra_headers="$OPTARG" ;;
        r) rate_limit="$OPTARG" ;;
        i) IGNORE_CODES="$OPTARG" ;;
        h) show_help ;;
        :) error "Option -$OPTARG requires an argument."; exit 1 ;;
        \?) error "Invalid option: -$OPTARG"; exit 1 ;;
    esac
done

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
print_banner
init_files
check_deps

# Domain
if [[ -z "$domain" ]]; then
    if [[ -f "$LAST_DOMAIN_FILE" && -s "$LAST_DOMAIN_FILE" ]]; then
        info "Last scanned domain: ${BOLD}$(cat "$LAST_DOMAIN_FILE")${RESET}"
    fi
    read -rp "  $(echo -e "${C}[?]${RESET}") Target domain (blank to reuse last): " domain
fi
if [[ -z "$domain" ]]; then
    if [[ -f "$LAST_DOMAIN_FILE" && -s "$LAST_DOMAIN_FILE" ]]; then
        domain=$(cat "$LAST_DOMAIN_FILE")
        info "Reusing: ${BOLD}$domain${RESET}"
    else
        error "No domain provided and no previous domain on record."; exit 1
    fi
fi
domain=$(format_url "$domain")
echo "$domain" > "$LAST_DOMAIN_FILE"

# ── MODE SELECT ──────────────────────────────
echo ""
divider
echo -e "  ${BOLD}${W}SELECT MODE${RESET}"
divider
echo -e "    ${C}[1]${RESET}  Directory scanning     ${DIM}— fuzz paths on a web target${RESET}"
echo -e "    ${C}[2]${RESET}  Subdomain enumeration  ${DIM}— brute-force subdomains of a domain${RESET}"
echo -e "    ${C}[3]${RESET}  Passive recon          ${DIM}— SSL, JS endpoints, CORS, cookies, tech fingerprint${RESET}"
divider
read -rp "  $(echo -e "${C}[?]${RESET}") Mode [1/2/3, default 1]: " mode_choice
mode_choice="${mode_choice:-1}"

results=""
sqli_targets=()

# ════════════════════════════════════════════
#  MODE 2 — SUBDOMAIN ENUMERATION
# ════════════════════════════════════════════
if [[ "$mode_choice" == "2" ]]; then
    dns_wordlist=""
    dns_wordlist_menu

    if [[ ! -f "$dns_wordlist" ]]; then
        error "DNS wordlist not found: $dns_wordlist"
        error "Install SecLists (sudo apt install seclists) or set a custom path."
        exit 1
    fi

    if [[ -z "$proxy" ]]; then
        read -rp "  $(echo -e "${C}[?]${RESET}") Proxy URL (blank to skip): " proxy
    fi

    echo ""
    log "Subdomain mode — domain: $domain  wordlist: $dns_wordlist"

    run_subdomain_enum "$dns_wordlist"

    while true; do
        echo ""
        read -rp "  $(echo -e "${C}[?]${RESET}") Command (RESCAN / HEADERS / NIKTO / EXIT): " input
        echo ""
        case "${input^^}" in
            EXIT)    log "Session ended by user"; break ;;
            RESCAN)  info "Rescanning subdomains…"
                     log "Subdomain rescan triggered"
                     run_subdomain_enum "$dns_wordlist" ;;
            HEADERS) inspect_headers ;;
            NIKTO)   run_nikto ;;
            VHOST)   run_vhost_enum ;;
            "")      warn "Available: RESCAN  VHOST  HEADERS  NIKTO  EXIT" ;;
            *)       warn "Unknown command. Available: RESCAN  VHOST  HEADERS  NIKTO  EXIT" ;;
        esac
    done

    save_results
    echo ""
    info "Log written to ${BOLD}$LOG_FILE${RESET}"
    log "Exiting"
    exit 0
fi

# ════════════════════════════════════════════
#  MODE 3 — PASSIVE RECON
# ════════════════════════════════════════════
if [[ "$mode_choice" == "3" ]]; then
    if [[ -z "$proxy" ]]; then
        read -rp "  $(echo -e "${C}[?]${RESET}") Proxy URL (blank to skip): " proxy
    fi

    echo ""
    log "Passive recon mode — domain: $domain"

    fingerprint_tech
    inspect_ssl
    analyze_cookies
    fetch_robots_sitemap
    inspect_headers

    while true; do
        echo ""
        read -rp "  $(echo -e "${C}[?]${RESET}") Command: " input
        echo ""
        case "${input^^}" in
            EXIT)    log "Session ended by user"; break ;;
            SSL)     inspect_ssl ;;
            JS)      run_js_recon ;;
            CORS)    check_cors ;;
            COOKIES) analyze_cookies ;;
            TECH)    fingerprint_tech ;;
            HEADERS) inspect_headers ;;
            ROBOTS)  fetch_robots_sitemap ;;
            NIKTO)   run_nikto ;;
            "")      warn "Commands: SSL  JS  CORS  COOKIES  TECH  HEADERS  ROBOTS  NIKTO  EXIT" ;;
            *)       warn "Unknown. Try: SSL  JS  CORS  COOKIES  TECH  HEADERS  ROBOTS  NIKTO  EXIT" ;;
        esac
    done

    save_results
    echo ""
    info "Log written to ${BOLD}$LOG_FILE${RESET}"
    log "Exiting"
    exit 0
fi

# ════════════════════════════════════════════
#  MODE 1 — DIRECTORY SCANNING  (default)
# ════════════════════════════════════════════
wordlist=""
wordlist_menu
if [[ ! -f "$wordlist" ]]; then
    error "Wordlist not found: $wordlist"; exit 1
fi

if [[ -z "$proxy" ]]; then
    read -rp "  $(echo -e "${C}[?]${RESET}") Proxy URL (blank to skip, e.g. http://127.0.0.1:8080): " proxy
fi

echo ""
log "Directory mode — domain: $domain  wordlist: $wordlist"

first_run=true

while true; do
    if [[ "$first_run" == true ]]; then
        run_enum "$domain" "$wordlist" 0
        extract_directories
        first_run=false
    fi

    echo ""
    read -rp "  $(echo -e "${C}[?]${RESET}") Command or search terms: " input
    echo ""

    case "${input^^}" in
        EXIT)
            log "Session ended by user"; break ;;
        RESCAN)
            run_rescan ;;
        RECURSE)
            awk '/^\// {print $1}' "$OUTPUT_FILE" > "$DIRECTORIES_FILE"
            prompt_recursive "$domain" "$wordlist" 0 ;;
        FILTER)
            configure_filters ;;
        DIRS)
            section "DISCOVERED PATHS"
            total=$(wc -l < "$ALL_DIRECTORIES_FILE")
            info "$total path(s) total:"
            while IFS= read -r d; do
                echo -e "    ${DIM}${W}$domain${RESET}${C}$d${RESET}"
            done < "$ALL_DIRECTORIES_FILE"
            divider ;;
        HEADERS)
            inspect_headers ;;
        NIKTO)
            run_nikto ;;
        ROBOTS)
            fetch_robots_sitemap ;;
        PARAMS)
            run_param_fuzz ;;
        BYPASS)
            run_403_bypass ;;
        EXT)
            run_ext_fuzz ;;
        METHODS)
            run_method_fuzz ;;
        BACKUP)
            run_backup_probe ;;
        "")
            warn "No input — enter a command or comma-separated search terms." ;;
        *)
            log "Search: $input"
            search_keywords "$input" ;;
    esac
done

# ─── POST-SESSION ───────────────────────────
echo ""
sqli_probe
prompt_sqlmap
save_results
echo ""
info "Log written to ${BOLD}$LOG_FILE${RESET}"
log "Exiting"
