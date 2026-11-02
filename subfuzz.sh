#!/usr/bin/env bash
#
# subfuzz.sh — DoS-aware subdomain enumeration with optional recursion.
#              Modes: passive | active | full
#
set -uo pipefail

# ---------- defaults ----------
TARGET=""
OUTDIR="./subenum_out"
WORDLIST=""
RESOLVERS=""
MODE="active"
RECURSION_DEPTH=0
PERM_WORDLIST=""
THREADS=20
RATE=20

usage () {
  cat <<EOF
Usage:
  $0 -d <target.com> -w <dns-wordlist.txt> -r <resolvers.txt> [options]

Required:
  -d  <domain>         Root domain to enumerate
  -w  <file>           DNS brute-force wordlist
  -r  <file>           Resolver list file

Options:
  -o  <dir>            Output directory (default: ./subenum_out)
  -t  <n>              Concurrent threads for active steps (default: 20)
  -R  <n>              Requests per second cap (default: 20)
  --mode <m>           passive | active | full  (default: active)
  --depth <n>          Recursion depth for permutation (0=off, 1-3)
  --perm <file>        Permutation wordlist for recursion
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) TARGET="$2"; shift 2 ;;
    -w) WORDLIST="$2"; shift 2 ;;
    -r|--resolvers) RESOLVERS="$2"; shift 2 ;;
    -o) OUTDIR="$2"; shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    -R|--rate) RATE="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --depth) RECURSION_DEPTH="$2"; shift 2 ;;
    --perm) PERM_WORDLIST="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1"; usage; exit 1 ;;
  esac
done

[[ -z "$TARGET" || -z "$WORDLIST" || -z "$RESOLVERS" ]] && { usage; exit 1; }
[[ ! -r "$WORDLIST" ]] && { echo "[-] cannot read wordlist: $WORDLIST"; exit 1; }

if [[ ! -r "$RESOLVERS" ]]; then
  echo "[-] cannot read resolvers file: $RESOLVERS"
  echo "    Note: -r is the RESOLVERS FILE, not rate. Rate is -R."
  echo "    Get one with:  puredns init"
  exit 1
fi

case "$MODE" in
  passive|active|full) ;;
  *) echo "[-] --mode must be passive|active|full"; exit 1 ;;
esac

# ---------- dependency checks ----------
for t in subfinder dnsx httpx puredns jq curl; do
  command -v "$t" >/dev/null || { echo "[-] missing required tool: $t"; exit 1; }
done

for t in amass assetfinder gotator dnsgen; do
  command -v "$t" >/dev/null || echo "[!] optional tool missing: $t (some sources will be skipped)"
done

mkdir -p "$OUTDIR"
TMP="$OUTDIR/.tmp"
mkdir -p "$TMP"

# ---------- helpers ----------
dedupe () {
  if command -v anew >/dev/null 2>&1; then anew "$@"; else sort -u; fi
}

rate_guard () {
  local base_rate=$1; shift
  local rate=$base_rate fails=0
  local logfile="$TMP/rate_guard.log"
  while true; do
    "$@" -rate "$rate" 2>&1 | tee "$logfile"
    if grep -qiE '429|403|REFUSED|SERVFAIL' "$logfile"; then
      rate=$(( rate / 2 )); (( rate < 1 )) && rate=1
      fails=$(( fails + 1 ))
      echo "[!] rate-limit/WAF signal. Backoff to ${rate}/s (strike $fails)" >&2
      sleep $(( 15 * fails ))
      (( fails >= 3 )) && { echo "[X] HARD STOP: sustained blocks." >&2; return 1; }
    else
      break
    fi
  done
}

# ---------- Phase 1: Passive ----------
echo "[*] Phase 1: Passive enumeration for $TARGET"
: > "$TMP/sub_all.txt"

command -v subfinder   >/dev/null && subfinder -d "$TARGET" -all -silent -o "$TMP/sub_subfinder.txt" 2>/dev/null || true
command -v assetfinder >/dev/null && assetfinder --subs-only "$TARGET" > "$TMP/sub_assetfinder.txt" 2>/dev/null || true
command -v amass       >/dev/null && amass enum -passive -d "$TARGET" -o "$TMP/sub_amass.txt" 2>/dev/null || true

curl -s "https://crt.sh/?q=%25.$TARGET&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | tr ',' '\n' \
  | grep -oE "[A-Za-z0-9._-]+\.${TARGET}" \
  | sort -u > "$TMP/sub_crt.txt" 2>/dev/null || true

cat "$TMP"/sub_*.txt 2>/dev/null \
  | sed '/^$/d' \
  | dedupe "$OUTDIR/passive_subs.txt"

echo "[+] Passive: $(wc -l < "$OUTDIR/passive_subs.txt" | tr -d ' ') candidates"

# ---------- Phase 2: Active Bruteforce ----------
cp "$OUTDIR/passive_subs.txt" "$OUTDIR/all_subs_raw.txt"

if [[ "$MODE" != "passive" ]]; then
  echo "[*] Phase 2: Active bruteforce (puredns)"
  timeout 600 puredns bruteforce "$WORDLIST" "$TARGET" \
    -r "$RESOLVERS" \
    -t "$THREADS" \
    -o "$TMP/sub_bruteforce.txt" 2>/dev/null || true

  cat "$OUTDIR/passive_subs.txt" "$TMP/sub_bruteforce.txt" 2>/dev/null \
    | sed '/^$/d' \
    | dedupe "$OUTDIR/all_subs_raw.txt"
fi

echo "[+] Raw merged: $(wc -l < "$OUTDIR/all_subs_raw.txt" | tr -d ' ') candidates"

# ---------- Phase 3: Resolve + wildcard filter ----------
echo "[*] Phase 3: Resolve (dnsx)"

random_name="nonexistent-$(head -c 200 /dev/urandom | tr -dc a-z | head -c 8).$TARGET"
wildcard_ip=$(dig +short "$random_name" A 2>/dev/null | head -n1 || true)

if [[ -n "$wildcard_ip" ]]; then
  echo "[!] Wildcard DNS detected ($random_name -> $wildcard_ip)"
  dnsx -l "$OUTDIR/all_subs_raw.txt" -a -resp -silent -wd "$TARGET" -o "$TMP/resolved.txt" 2>/dev/null || true
else
  dnsx -l "$OUTDIR/all_subs_raw.txt" -a -resp -silent                  -o "$TMP/resolved.txt" 2>/dev/null || true
fi

sed -E 's/[[:space:]].*$//' "$TMP/resolved.txt" 2>/dev/null \
  | sed '/^$/d' \
  | dedupe "$OUTDIR/resolved_subs.txt"

echo "[+] Resolved: $(wc -l < "$OUTDIR/resolved_subs.txt" | tr -d ' ') live subdomains"

# ---------- Phase 4: Recursion (only mode=full + depth>0) ----------
if [[ "$MODE" == "full" && "$RECURSION_DEPTH" -gt 0 ]]; then
  echo "[*] Phase 4: Recursion (depth=$RECURSION_DEPTH)"

  if [[ -z "$PERM_WORDLIST" || ! -r "$PERM_WORDLIST" ]]; then
    echo "[-] --perm wordlist required for recursion. Skipping."
  else
    if command -v gotator >/dev/null 2>&1; then
      gotator -sub "$OUTDIR/resolved_subs.txt" -perm "$PERM_WORDLIST" -depth "$RECURSION_DEPTH" -numbers 10 \
        > "$TMP/permuted_candidates.txt" 2>/dev/null || true
    elif command -v dnsgen >/dev/null 2>&1; then
      input="$OUTDIR/resolved_subs.txt"
      for ((i=1; i<=RECURSION_DEPTH; i++)); do
        dnsgen "$input" > "$TMP/perm_$i.txt" 2>/dev/null || true
        input="$TMP/perm_$i.txt"
      done
      cat "$TMP"/perm_*.txt > "$TMP/permuted_candidates.txt" 2>/dev/null || true
    fi

    if [[ -s "$TMP/permuted_candidates.txt" ]]; then
      echo "[*] Resolving $(wc -l < "$TMP/permuted_candidates.txt" | tr -d ' ') permuted candidates"
      rate_guard "$RATE" puredns resolve "$TMP/permuted_candidates.txt" -r "$RESOLVERS" -t "$THREADS" -o "$TMP/permuted_resolved.txt" 2>/dev/null || true

      if [[ -s "$TMP/permuted_resolved.txt" ]]; then
        cat "$OUTDIR/resolved_subs.txt" "$TMP/permuted_resolved.txt" \
          | sed '/^$/d' \
          | dedupe "$TMP/resolved_with_recursion.txt"
        mv "$TMP/resolved_with_recursion.txt" "$OUTDIR/resolved_subs.txt"
        echo "[+] Recursion added $(wc -l < "$TMP/permuted_resolved.txt" | tr -d ' ') hosts"
      fi
    fi
  fi
fi

# ---------- Phase 5: HTTP probe ----------
echo "[*] Phase 5: HTTP probing (httpx)"

httpx -l "$OUTDIR/resolved_subs.txt" \
  -ports 80,443,8080,8443 \
  -sc -title -tech-detect -cdn -silent \
  -t "$THREADS" -rl "$RATE" -timeout 10 \
  -o "$OUTDIR/live_hosts.txt" 2>/dev/null || true

echo "[+] Live HTTP hosts: $(wc -l < "$OUTDIR/live_hosts.txt" | tr -d ' ')"
echo "[+] Final output   : $OUTDIR/live_hosts.txt"
