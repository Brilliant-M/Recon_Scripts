#!/usr/bin/env bash
#
# filefuzz.sh — DoS-aware file & extension fuzzing.
#
set -uo pipefail

# ---------- defaults ----------
TARGETS_FILE=""
SINGLE=""
WORDLIST=""
OUTDIR="./filefuzz_out"
THREADS=20
RATE=20
EXT_SET="all"
CUSTOM_EXT=""
DO_SCHEME_CHECK=1
DO_TRIAGE=1
FORCE_EXT=0
MAX_TIME=""

# ---------- extension presets ----------
declare -A EXT_SETS
EXT_SETS[web]="php,html,htm,txt,js,json,xml,css,jpg,png,gif,svg,pdf"
EXT_SETS[backup]="bak,backup,old,orig,save,swp,tmp,1,copy,sav,bk,bkp,ghost,dist"
EXT_SETS[config]="env,config,conf,ini,yml,yaml,properties,log,sql,db,sqlite,ds_store"
EXT_SETS[source]="php,php3,php4,php5,phtml,phps,asp,aspx,jsp,jspx,py,rb,pl,sh"
EXT_SETS[archive]="zip,tar,gz,tgz,7z,rar,war,jar"
EXT_SETS[all]="${EXT_SETS[web]},${EXT_SETS[backup]},${EXT_SETS[config]},${EXT_SETS[archive]}"

usage () {
  cat <<EOF
Usage:
  $0 -w <wordlist> -l <subs.txt> [options]     # many targets
  $0 -w <wordlist> -u <host-or-url> [options]  # single target

Required:
  -w  <file>   wordlist (filenames, e.g. raft-large-files.txt)

Target selection:
  -l  <file>   file with hosts/subdomains (scheme optional)
  -u  <host>   single target (host or URL)

Options:
  -o  <dir>    output dir (default: ./filefuzz_out)
  -t  <n>      concurrent threads (default: 20)
  -r  <n>      max req/sec (default: 20)
  -e  <set>    extension preset: web|backup|config|source|archive|all (default: all)
      --ext <list>   custom comma-separated extensions (overrides -e)
      --force-ext    force extensions even when word already has one (noisy)
      --time <dur>   feroxbuster time limit (e.g. 15m, 1h)
      --no-triage    skip the final httpx triage
      --no-scheme-check   skip http/https probing (faster)
  -h           show this help
EOF
}

# ---------- arg parse ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -w) WORDLIST="$2"; shift 2 ;;
    -l) TARGETS_FILE="$2"; shift 2 ;;
    -u) SINGLE="$2"; shift 2 ;;
    -o) OUTDIR="$2"; shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    -r) RATE="$2"; shift 2 ;;
    -e) EXT_SET="$2"; shift 2 ;;
    --ext) CUSTOM_EXT="$2"; shift 2 ;;
    --force-ext) FORCE_EXT=1; shift ;;
    --time) MAX_TIME="$2"; shift 2 ;;
    --no-triage) DO_TRIAGE=0; shift ;;
    --no-scheme-check) DO_SCHEME_CHECK=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1"; usage; exit 1 ;;
  esac
done

[[ -z "$WORDLIST" ]] && { echo "[-] -w wordlist required"; usage; exit 1; }
[[ -z "$TARGETS_FILE" && -z "$SINGLE" ]] && { echo "[-] provide -l <subs> or -u <host>"; usage; exit 1; }
[[ ! -r "$WORDLIST" ]] && { echo "[-] cannot read wordlist: $WORDLIST"; exit 1; }

for t in ffuf feroxbuster jq curl; do
  command -v "$t" >/dev/null || { echo "[-] missing tool: $t"; exit 1; }
done

mkdir -p "$OUTDIR"
TMP="$OUTDIR/.tmp"
mkdir -p "$TMP"

# ---------- extension resolution ----------
resolve_ext () {
  if [[ -n "$CUSTOM_EXT" ]]; then
    echo "$CUSTOM_EXT" | tr -d ' '
  elif [[ -n "${EXT_SETS[$EXT_SET]+x}" ]]; then
    echo "${EXT_SETS[$EXT_SET]}"
  else
    echo "${EXT_SETS[all]}"
  fi
}

EXT_LIST=$(resolve_ext)
FFUF_EXTS=$(echo "$EXT_LIST" | sed 's/[^,]*/\.&/g')
FEROX_EXTS="$EXT_LIST"

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

  local ferox_args=(
    -u "$url"
    -w "$WORDLIST"
    -x "$FEROX_EXTS"
    -t "$THREADS"
    --rate-limit "$RATE"
    --scan-limit 2
    --auto-tune
    --auto-bail
    --timeout 10
    --json -o "$ferox_json"
    -q
  )
  [[ "$FORCE_EXT" -eq 1 ]] && ferox_args+=( --force-extensions )
  [[ -n "$MAX_TIME" ]]     && ferox_args+=( --time-limit "$MAX_TIME" )

  feroxbuster "${ferox_args[@]}" >/dev/null 2>&1 || true

  ffuf \
    -w "$WORDLIST" \
    -u "${url%/}/FUZZ" \
    -e "$FFUF_EXTS" \
    -t "$THREADS" \
    -rate "$RATE" \
    -timeout 10 \
    -ac \
    -of json -o "$ffuf_json" \
    -s >/dev/null 2>&1 || true

  : > "$ferox_urls"
  : > "$ffuf_urls"

  [[ -s "$ferox_json" ]] && jq -r '.url // empty' "$ferox_json" 2>/dev/null > "$ferox_urls" || true
  [[ -s "$ffuf_json" ]]  && jq -r '.results[]?.url // empty' "$ffuf_json" 2>/dev/null > "$ffuf_urls" || true

  cat "$ferox_urls" "$ffuf_urls" \
    | sed '/^[[:space:]]*$/d' \
    | dedupe \
    > "$combined"

  local n
  n=$(wc -l < "$combined" | tr -d ' ')
  echo "[+] $url -> $combined ($n unique URLs)"
}

# ---------- banner ----------
echo "[*] wordlist   : $WORDLIST"
echo "[*] extensions : $EXT_LIST"
echo "[*] threads    : $THREADS"
echo "[*] rate limit : $RATE req/s"
echo "[*] force-ext  : $([[ $FORCE_EXT -eq 1 ]] && echo on || echo off)"
echo "[*] outdir     : $OUTDIR"
echo

# ---------- main ----------
if [[ -n "$SINGLE" ]]; then
  url="$SINGLE"
  [[ "$url" != http* ]] && url="https://$url"
  run_target "$url"
else
  CLEANED="$OUTDIR/subs.cleaned.txt"
  clean_subs "$TARGETS_FILE" > "$CLEANED"
  echo "[*] cleaned targets -> $CLEANED ($(wc -l < "$CLEANED" | tr -d ' ') hosts)"
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
MASTER="$OUTDIR/ALL_UNIQUE_FILES.txt"
if compgen -G "$OUTDIR/*.urls.txt" >/dev/null; then
  cat "$OUTDIR"/*.urls.txt \
    | sed '/^[[:space:]]*$/d' \
    | dedupe \
    > "$MASTER"
  echo
  echo "[+] master file : $MASTER ($(wc -l < "$MASTER" | tr -d ' ') unique URLs)"
else
  echo "[-] no per-target results produced"
fi

# ---------- optional triage ----------
if [[ "$DO_TRIAGE" -eq 1 ]] && command -v httpx >/dev/null 2>&1 && [[ -s "$MASTER" ]]; then
  echo "[*] triage: httpx probing $MASTER"

  httpx -l "$MASTER" \
    -sc -title -tech-detect -content-type -location \
    -t "$THREADS" -rl "$RATE" -timeout 10 \
    -silent -o "$OUTDIR/triage_all.txt" 2>/dev/null || true

  grep -E '\[(200|201|301|302|401|403)\]' "$OUTDIR/triage_all.txt" \
    | sort -u > "$OUTDIR/triage_interesting.txt" 2>/dev/null || true

  grep -iE '\.(bak|backup|old|orig|save|swp|tmp|env|config|conf|ini|yml|yaml|properties|log|sql|db|sqlite|zip|tar|gz|tgz|7z|rar|git|svn)(\?|$|#)' \
    "$OUTDIR/triage_interesting.txt" \
    > "$OUTDIR/triage_sensitive.txt" 2>/dev/null || true

  echo "[+] triage_all        : $(wc -l < "$OUTDIR/triage_all.txt" | tr -d ' ') URLs"
  echo "[+] triage_interesting: $(wc -l < "$OUTDIR/triage_interesting.txt" 2>/dev/null | tr -d ' ') URLs (2xx/3xx/401/403)"
  echo "[+] triage_sensitive  : $(wc -l < "$OUTDIR/triage_sensitive.txt" 2>/dev/null | tr -d ' ') URLs (backups, configs, archives)"
fi

echo
echo "[*] done."
