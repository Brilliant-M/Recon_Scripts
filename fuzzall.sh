#!/usr/bin/env bash
#
# fuzzall.sh — DoS-aware directory fuzzing (feroxbuster + ffuf).
#
set -uo pipefail

# ---------- defaults ----------
WORDLIST=""
SUBS_FILE=""
SINGLE=""
THREADS=20
RATE=20
OUTDIR="./fuzz_out"
DO_SCHEME_CHECK=1
FEROX_RECURSION=1
FEROX_DEPTH=""

usage () {
  cat <<EOF
Usage:
  $0 -w <wordlist> -l <subs.txt>          # many subdomains
  $0 -w <wordlist> -u <host-or-url>       # single target

Options:
  -w  <file>   wordlist (required)
  -l  <file>   file with subdomains (one per line, scheme optional)
  -u  <host>   single target (host or URL)
  -t  <n>      concurrent threads (default: 20)
  -R  <n>      max requests/sec (default: 20)  ← DoS safety
  -o  <dir>    output dir (default: ./fuzz_out)
  -d  <n>      feroxbuster max recursion depth (default: unlimited)
      --no-scheme-check   skip http/https probing (faster)
      --no-recursion      disable feroxbuster recursion
  -h           show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -w) WORDLIST="$2"; shift 2 ;;
    -l) SUBS_FILE="$2"; shift 2 ;;
    -u) SINGLE="$2"; shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    -R|--rate) RATE="$2"; shift 2 ;;
    -o) OUTDIR="$2"; shift 2 ;;
    -d) FEROX_DEPTH="$2"; shift 2 ;;
    --no-scheme-check) DO_SCHEME_CHECK=0; shift ;;
    --no-recursion)    FEROX_RECURSION=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1"; usage; exit 1 ;;
  esac
done

[[ -z "$WORDLIST" ]] && { echo "[-] -w wordlist required"; usage; exit 1; }
[[ -z "$SUBS_FILE" && -z "$SINGLE" ]] && { echo "[-] provide -l <subs> or -u <host>"; usage; exit 1; }
[[ ! -r "$WORDLIST" ]] && { echo "[-] cannot read wordlist: $WORDLIST"; exit 1; }

command -v ffuf        >/dev/null || { echo "[-] ffuf not installed";        exit 1; }
command -v feroxbuster >/dev/null || { echo "[-] feroxbuster not installed"; exit 1; }
command -v jq          >/dev/null || { echo "[-] jq not installed";          exit 1; }

mkdir -p "$OUTDIR"
TMP="$OUTDIR/.tmp"
mkdir -p "$TMP"

# ---------- helpers ----------
clean_subs () {
  tr -d '\r' < "$1" \
    | sed -E 's/#.*$//; s/^[[:space:]]+//; s/[[:space:]]+$//' \
    | sed -E '/^$/d' \
    | sed -E 's#^([^:/]+)$#https://\1#' \
    | sort -u
}

resolve_scheme () {
  local host="$1" code
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "https://$host" 2>/dev/null || echo 000)
  if [[ "$code" =~ ^(2|3) ]]; then echo "https://$host"; return; fi
  code=$(curl -s  -o /dev/null -w '%{http_code}' --max-time 5 "http://$host"  2>/dev/null || echo 000)
  if [[ "$code" =~ ^(2|3) ]]; then echo "http://$host";  return; fi
  echo ""
}

dedupe () {
  if command -v uro >/dev/null 2>&1; then
    uro | sort -u
  else
    sort -u
  fi
}

# ---------- per-target worker ----------
run_target () {
  local url="$1"
  local safe
  safe=$(printf '%s' "$url" | sed -E 's#https?://##; s#[/:?&=]#_#g; s#_+$##')
  local base="$OUTDIR/$safe"

  local ferox_json="${base}.ferox.jsonl"
  local ffuf_json="${base}.ffuf.json"
  local ferox_urls="${TMP}/${safe}.ferox.urls"
  local ffuf_urls="${TMP}/${safe}.ffuf.urls"
  local combined="${base}.urls.txt"

  echo "[*] target: $url"

  # --- feroxbuster: recursive, rate-limited, auto-bail ---
  local ferox_args=(
    -u "$url"
    -w "$WORDLIST"
    -t "$THREADS"
    --rate-limit "$RATE"     # hard req/s cap
    --scan-limit 2           # max concurrent directory scans
    --auto-tune              # dynamic backoff on 429/timeout
    --auto-bail              # hard stop if error rate too high
    --timeout 10
    --json -o "$ferox_json"
    -q
  )
  [[ "$FEROX_RECURSION" -eq 0 ]] && ferox_args+=( --no-recursion )
  [[ -n "$FEROX_DEPTH" ]]        && ferox_args+=( --depth "$FEROX_DEPTH" )

  feroxbuster "${ferox_args[@]}" >/dev/null 2>&1 || true

  # --- ffuf: non-recursive single-level fuzz, rate-limited ---
  ffuf \
    -w "$WORDLIST" \
    -u "${url%/}/FUZZ" \
    -t "$THREADS" \
    -rate "$RATE"             # hard req/s cap
    -timeout 10 \
    -ac \
    -of json -o "$ffuf_json" \
    -s >/dev/null 2>&1 || true

  # --- extract URLs ---
  : > "$ferox_urls"
  : > "$ffuf_urls"

  [[ -s "$ferox_json" ]] && jq -r '.url // empty' "$ferox_json" 2>/dev/null > "$ferox_urls" || true
  [[ -s "$ffuf_json" ]]  && jq -r '.results[]?.url // empty' "$ffuf_json" 2>/dev/null > "$ffuf_urls" || true

  # --- merge + dedupe into ONE file per target ---
  cat "$ferox_urls" "$ffuf_urls" \
    | sed '/^[[:space:]]*$/d' \
    | dedupe \
    > "$combined"

  local n
  n=$(wc -l < "$combined" | tr -d ' ')
  echo "[+] $url -> $combined ($n unique URLs)"
}

# ---------- main ----------
echo "[*] wordlist   : $WORDLIST"
echo "[*] threads    : $THREADS"
echo "[*] rate limit : $RATE req/s"
echo "[*] outdir     : $OUTDIR"
echo "[*] scheme chk : $([[ $DO_SCHEME_CHECK -eq 1 ]] && echo on || echo off)"
echo "[*] recursion  : $([[ $FEROX_RECURSION -eq 1 ]] && echo on || echo off)"
echo

if [[ -n "$SINGLE" ]]; then
  url="$SINGLE"
  [[ "$url" != http* ]] && url="https://$url"
  run_target "$url"
else
  CLEANED="$OUTDIR/subs.cleaned.txt"
  clean_subs "$SUBS_FILE" > "$CLEANED"
  echo "[*] cleaned subs -> $CLEANED ($(wc -l < "$CLEANED" | tr -d ' ') hosts)"
  echo

  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue

    if [[ "$DO_SCHEME_CHECK" -eq 1 ]]; then
      host="${entry#*://}"
      url=$(resolve_scheme "$host")
      if [[ -z "$url" ]]; then
        echo "[-] skip (dead/unreachable): $host"
        continue
      fi
    else
      url="$entry"
    fi

    run_target "$url"
  done < "$CLEANED"
fi

# ---------- master merge ----------
MASTER="$OUTDIR/ALL_UNIQUE_URLS.txt"
if compgen -G "$OUTDIR/*.urls.txt" >/dev/null; then
  cat "$OUTDIR"/*.urls.txt \
    | sed '/^[[:space:]]*$/d' \
    | dedupe \
    > "$MASTER"
  echo
  echo "[+] master file : $MASTER ($(wc -l < "$MASTER" | tr -d ' ') unique URLs)"
else
  echo "[-] no per-target result files produced"
fi

rm -rf "$TMP"
