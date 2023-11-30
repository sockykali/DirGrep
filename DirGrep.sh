#!/bin/bash

# Constants
DEFAULT_WORDLIST="/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt"
GOBUSTER_PATH="/usr/bin/gobuster"
OUTPUT_FILE="/tmp/output.txt"
DIRECTORIES_FILE="/tmp/directories.txt"
LOG_FILE="/tmp/domain_enumeration.log"
USER_AGENT="Mozilla/5.0"
LAST_DOMAIN_FILE="/tmp/last_domain.txt"
export MAX_RETRIES=5
chmod 600 "$OUTPUT_FILE" "$DIRECTORIES_FILE" "$LOG_FILE" "$LAST_DOMAIN_FILE"

echo -e "\e[1;31m"
cat << "EOF"
 _______   __             ______                                
|       \ |  \           /      \                               
| $$$$$$$\ \$$  ______  |  $$$$$$\  ______    ______    ______  
| $$  | $$|  \ /      \ | $$ __\$$ /      \  /      \  /      \ 
| $$  | $$| $$|  $$$$$$\| $$|    \|  $$$$$$\|  $$$$$$\|  $$$$$$\
| $$  | $$| $$| $$   \$$| $$ \$$$$| $$   \$$| $$    $$| $$  | $$
| $$  | $$| $$| $$      | $$__| $$| $$      | $$$$$$$$| $$__/ $$
| $$__/ $$| $$| $$       \$$    $$| $$       \$$     \| $$    $$
 \$$$$$$$  \$$ \$$        \$$$$$$  \$$        \$$$$$$$| $$$$$$$ 
                                                      | $$      
                                                      | $$      
                                                       \$$                                        
                                                         - sockykali
                                                      
EOF
echo -e "\e[0m"
                                                         
echo -e "\e[31m***Configured for Kali. If you're not running kali, you need to specify the location of DirBuster-1.0-RC1.jar and your wordlist***\e[0m"                            
echo "DirGrep"
echo "Version: 1.0"

## check if we can reach gobuster
for app in "$GOBUSTER_PATH" curl; do
    if ! command -v "$app" &> /dev/null; then
        echo "Error: $app not found" >&2
        exit 1
    fi
done

run_curl() {
    local url="$1"
    local user_agent="$2"
    local cookie="$3"
    local retries=0

    while ((retries < MAX_RETRIES)); do
        result=$(curl -s -A "$user_agent" -b "$cookie" "$url")
        if [[ $? -eq 0 ]]; then
            echo "$result"
            return 0
        else
            echo "Curl command failed. Retrying..."
            ((retries++))
            sleep 1
        fi
    done

    echo "Error: Failed to fetch $url after $retries attempts" >&2
    return 1
}

format_url() {
    local url="$1"
    if [[ ! "$url" =~ ^http:// ]]; then
        url="http://$url"
    fi
    echo "$url"
}

search_keyword_in_file() {
    local domain="$1"
    local file="$2"
    local term="$3"
    local user_agent="$4"
    local cookie="$5"

    echo "Searching $file for '$term'..."
    result=$(run_curl "$domain$file" "$user_agent" "$cookie" | grep --color=always -n -i "$term")
    if [[ $? -eq 0 && ! -z "$result" ]]; then
        echo "KEYWORD FOUND IN $domain$file"
        echo "$result"
        results+="KEYWORD FOUND IN $domain$file\n$result\n"
    fi
}

save_results() {
    read -p "Do you want to save the results to a text file? (Y/N): " should_save_results
    if [[ "$should_save_results" =~ ^[Yy]$ ]]; then
        read -p "Enter the filename to save the results: " results_filename
        printf "%s\n" "$results" > "$results_filename" || { printf "Error: Failed to write to %s\n" "$results_filename" >&2; return 1; }
        printf "Results saved to %s\n" "$results_filename"
    fi
}

> "$LOG_FILE" || { printf "Error: Failed to write to %s\n" "$LOG_FILE" >&2; exit 1; }

run_gobuster() {
    "$GOBUSTER_PATH" dir -u "$1" -w "$2" -o "$OUTPUT_FILE" || exit 1
}

extract_directories() {
    awk '{print $1}' "$OUTPUT_FILE" > "$DIRECTORIES_FILE"
}

search_keywords() {
    local domain="$1"
    local search_terms="$2"
    local user_agent="$3"
    local cookie="$4"

    IFS=',' read -ra terms <<< "$search_terms"
    local urls=("$domain")
    while IFS= read -r directory; do
        urls+=("$domain$directory")
    done < "$DIRECTORIES_FILE"

    for url in "${urls[@]}"; do
        for term in "${terms[@]}"; do
            printf "Searching '%s' for '%s'...\n" "$url" "$term"
            result=$(curl -s -A "$user_agent" -b "$cookie" "$url" | grep --color=always -n -i "$term")
            if [[ ! -z "$result" ]]; then
                printf "\e[1;32mKEYWORD FOUND IN %s\e[0m\n" "$url"
                printf "%s\n" "$result"
                results+="KEYWORD FOUND IN $url\n$result\n"
            fi
        done
    done
}

log() {
    printf "%s %s\n" "$(date +"%Y-%m-%d %H:%M:%S")" "$1" >> "$LOG_FILE"
}

show_help() {
    printf "\e[1;34mUsage:\e[0m %s [-u user_agent] [-d domain] [-c cookie] [-h | -help]\n" "$0"
    printf "\e[1;34m  -u user_agent\e[0m  Specify a custom User-Agent for curl requests (optional).\n"
    printf "\e[1;34m  -d domain\e[0m      Specify the domain to fuzz.\n"
    printf "\e[1;34m  -c cookie\e[0m      Specify a custom cookie to be used with curl requests (optional) (e.g -c NAME:VALUE).\n"
    printf "\e[1;34m  -h, -help\e[0m     Show this help message.\n"
    printf "\n"
    printf "\e[1;34m___________________________________________________\e[0m\n"
    printf "\e[1;34mBELOW COMMANDS ARE AVAILABLE WHILE TOOL IS IN USE.\e[0m\n"
    printf "\n"
    printf "\e[1;34m EXIT\e[0m          Exit the tool.\n"
    printf "\e[1;34m RESCAN\e[0m        Rescan the domain using the same wordlist.\n"
    printf "\n"
    printf "\e[1;34m___________________________________________________\e[0m\n"
    printf "\e[1;34mGeneral Usage\e[0m\n"
    printf "\n"
    printf "Press Ctrl+C to interrupt domain scanning and search with currently found directories.\n"
    printf "Leave URL field blank to proceed with last scanned domain"
    exit 0
}

domain=""
cookie=""
while getopts "u:d:c:h" opt; do
    case $opt in
        u) user_agent="$OPTARG";;
        d) domain="$OPTARG";;
        c) cookie="$OPTARG";;
        h | help) show_help;;
        \?) printf "Invalid option: -%s\n" "$OPTARG" >&2; exit 1;;
    esac
done

read -ep "Enter the domain to fuzz (http://example:80): " domain

if [[ -z "$domain" ]]; then
    if [[ -f "$LAST_DOMAIN_FILE" ]]; then
        domain=$(cat "$LAST_DOMAIN_FILE")
        printf "Using the most recently scanned URL: %s\n" "$domain"
    fi
else
    echo "$domain" > "$LAST_DOMAIN_FILE"
fi

domain=$(format_url "$domain")
read -e -p "Enter the path to your wordlist (blank for default): " wordlist

wordlist="${wordlist:-$DEFAULT_WORDLIST}"

first_run=true
results=""

> "$LOG_FILE"

log "Starting domain enumeration for $domain using wordlist $wordlist"

while true; do
    if [[ "$first_run" = true ]]; then
        log "Running Gobuster..."
        run_gobuster "$domain" "$wordlist"
        extract_directories
        first_run=false
    fi

    readarray -t files < "$DIRECTORIES_FILE"

    read -ep "Enter the terms to search for (comma-separated) or 'EXIT' to quit: " search_terms

    if [[ "$search_terms" = "EXIT" ]]; then
        log "Domain enumeration completed"
        break
    fi

    if [[ "$search_terms" = "RESCAN" ]]; then
        log "Rescanning..."
        run_gobuster "$domain" "$wordlist"
        extract_directories
        continue
    fi

    if [[ -n "$search_terms" ]]; then
        search_keywords "$domain" "$search_terms" "$user_agent" "$cookie"
    else
        printf "No search terms provided. Skipping...\n"
    fi
done

save_results
log "Exiting domain enumeration"
