#!/usr/bin/env bash
#
# triage.sh — turn a raw URL list into a ranked, categorized
#             "worth testing" shortlist.
#
set -uo pipefail

# ---------- defaults ----------
INPUTS=()
SINGLE=""
OUTDIR="./triage_out"
THREADS=20
RATE=20
CUSTOM_HEADERS=()
MC="100-599"
SOFT404_CHECK=1
MIN_SCORE=3

usage () {
  cat <<EOF
Usage:
  $0 -l <urls.txt> [options]
  $0 -u <url> [options]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l) INPUTS+=("$2"); shift 2 ;;
    -u) SINGLE="$2"; shift 2 ;;
    -o) OUTDIR="$2"; shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    -r) RATE="$2"; shift 2 ;;
    -H) CUSTOM_HEADERS+=("$2"); shift 2 ;;
    -mc) MC="$2"; shift 2 ;;
    --soft404) SOFT404_CHECK="$2"; shift 2 ;;
    --min-score) MIN_SCORE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1"; usage; exit 1 ;;
  esac
done

[[ ${#INPUTS[@]} -eq 0 && -z "$SINGLE" ]] && { usage; exit 1; }

# Check for httpx-toolkit (Kali) or fallback to httpx (GitHub Actions)
HTTPX_CMD=""
if command -v httpx-toolkit >/dev/null 2>&1; then
  HTTPX_CMD="httpx-toolkit"
elif command -v httpx >/dev/null 2>&1; then
  HTTPX_CMD="httpx"
else
  echo "[-] httpx-toolkit (or httpx) not installed"
  exit 1
fi

command -v jq >/dev/null || { echo "[-] jq not installed"; exit 1; }

mkdir -p "$OUTDIR"
TMP="$OUTDIR/.tmp"
mkdir -p "$TMP"

HDR_ARGS=()
for h in "${CUSTOM_HEADERS[@]}"; do
  [[ -n "$h" ]] && HDR_ARGS+=(-H "$h")
done

# ---------- collect URLs ----------
URLS="$TMP/all_urls.txt"
: > "$URLS"

for f in "${INPUTS[@]}"; do
  [[ -z "$f" ]] && continue
  [[ ! -r "$f" ]] && { echo "[-] cannot read $f"; continue; }
  tr -d '\r' < "$f" >> "$URLS"
done

if [[ -n "$SINGLE" ]]; then
  echo "$SINGLE" >> "$URLS"
fi

sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d' "$URLS" \
  | sed -E 's#^([^:/]+)$#https://\1#' \
  | sort -u > "$TMP/urls.clean.txt"

TOTAL=$(wc -l < "$TMP/urls.clean.txt" | tr -d ' ')
echo "[*] probing $TOTAL unique URLs (threads=$THREADS, rate=$RATE)"

# ---------- Step 1: baseline 404 per host ----------
declare -A HOST_404_LEN=()

if [[ "$SOFT404_CHECK" -eq 1 ]]; then
  echo "[*] soft-404 baseline: probing a nonexistent path per host"
  awk -F/ '{print $1"//"$3}' "$TMP/urls.clean.txt" | sort -u > "$TMP/hosts.txt"

  while IFS= read -r base; do
    [[ -z "$base" ]] && continue
    rand="nonexistent-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    probe_url="${base}/${rand}"
    clen=$(curl -sk -o /dev/null -w '%{size_download}' --max-time 8 \
           "${HDR_ARGS[@]}" "$probe_url" 2>/dev/null || echo "")
    if [[ "$clen" =~ ^[0-9]+$ ]]; then
      HOST_404_LEN["$base"]="$clen"
      echo "    $base -> soft404 length $clen"
    fi
  done < "$TMP/hosts.txt"
  echo
fi

# ---------- Step 2: full httpx probe ----------
echo "[*] Running $HTTPX_CMD probe"

# Removed the invalid -method flag
$HTTPX_CMD -l "$TMP/urls.clean.txt" \
  -sc -title -tech-detect -content-type -location \
  -cl -wc -server \
  -mc "$MC" \
  -t "$THREADS" -rl "$RATE" -timeout 10 \
  -silent -json -o "$OUTDIR/raw.jsonl" \
  "${HDR_ARGS[@]}" 2>&1 || true

RAW="$OUTDIR/raw.jsonl"
if [[ ! -s "$RAW" ]]; then
  echo "[-] $HTTPX_CMD produced no output (0 live URLs found)"
  echo "Triage summary — $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUTDIR/summary.txt"
  echo "-------------------------------------------" >> "$OUTDIR/summary.txt"
  echo "Input URLs       : $TOTAL" >> "$OUTDIR/summary.txt"
  echo "Probed responses : 0" >> "$OUTDIR/summary.txt"
  echo "Shortlist (>= $MIN_SCORE) : 0" >> "$OUTDIR/summary.txt"
  touch "$OUTDIR/WORTH_TESTING.txt"
  exit 0
fi

jq -r '
  [
    (.url // ""),
    (.status_code // 0 | tostring),
    (.content_length // 0 | tostring),
    (.content_type // "" | split(";")[0]),
    (.title // ""),
    (.webserver // ""),
    ((.tech // []) | join(",")),
    (.location // "")
  ] | @tsv
' "$RAW" > "$TMP/parsed.tsv" 2>/dev/null || true

# ---------- Step 3: classify each URL ----------
CLASSIFIED="$TMP/classified.tsv"
: > "$CLASSIFIED"

while IFS=$'\t' read -r url status clen ct title server tech loc; do
  [[ -z "$url" ]] && continue
  score=0
  tags=""

  case "$status" in
    200)                 score=$((score+2)); tags="$tags,status200" ;;
    201)                 score=$((score+2)); tags="$tags,status201" ;;
    204)                 score=$((score+1)); tags="$tags,status204" ;;
    301|302|303|307|308) score=$((score+1)); tags="$tags,redirect" ;;
    401)                 score=$((score+3)); tags="$tags,auth_bypass" ;;
    403)                 score=$((score+4)); tags="$tags,bypass" ;;
    405)                 score=$((score+2)); tags="$tags,method_bypass" ;;
    500)                 score=$((score+3)); tags="$tags,error_inject" ;;
    502|503|504)         score=$((score+1)); tags="$tags,upstream" ;;
  esac

  lurl=$(echo "$url" | tr '[:upper:]' '[:lower:]')
  for kw in admin administrator dashboard panel console manage \
            internal debug test dev staging beta api graphql swagger \
            login signin auth upload backup config env setup install \
            phpinfo server-status actuator health metrics .git .svn \
            .env .bak .sql .zip .tar web.config; do
    if [[ "$lurl" == *"$kw"* ]]; then
      score=$((score+2)); tags="$tags,$kw"
    fi
  done

  ltitle=$(echo "$title" | tr '[:upper:]' '[:lower:]')
  for kw in admin dashboard login panel phpmyadmin jenkins grafana \
            kibana index\ of directory\ listing welcome\ to swagger \
            api\ docs; do
    if [[ "$ltitle" == *"$kw"* ]]; then
      score=$((score+3)); tags="$tags,title:$kw"
    fi
  done

  ltech=$(echo "$tech" | tr '[:upper:]' '[:lower:]')
  for kw in jenkins grafana kibana phpmyadmin gitlab tomcat spring \
            actuator struts weblogic jboss drupal wordpress joomla; do
    if [[ "$ltech" == *"$kw"* ]]; then
      score=$((score+2)); tags="$tags,tech:$kw"
    fi
  done

  if [[ "$lurl" =~ \.(bak|backup|old|orig|save|swp|tmp|env|config|conf|ini|yml|yaml|properties|log|sql|db|sqlite|zip|tar|gz|tgz|7z|rar)(\?|$|#) ]]; then
    score=$((score+3)); tags="$tags,sensitive_file"
  fi

  if [[ -n "$server" && ! "$server" =~ (nginx|apache|cloudflare|cloudfront|gws|Microsoft-IIS) ]]; then
    score=$((score+1)); tags="$tags,unusual_server"
  fi

  base=$(echo "$url" | awk -F/ '{print $1"//"$3}')
  if [[ -n "${HOST_404_LEN[$base]:-}" && "$clen" == "${HOST_404_LEN[$base]}" ]]; then
    score=$((score-5)); tags="$tags,likely_soft404"
  fi

  (( score < 0 )) && score=0

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$url" "$status" "$clen" "$ct" "$title" "$server" "$tech" "$loc" "$score" "$tags" \
    >> "$CLASSIFIED"
done < "$TMP/parsed.tsv"

# ---------- Step 4: categorized files ----------
emit () {
  local name="$1" pattern="$2" tag="$3"
  local out="$OUTDIR/$name"
  : > "$out"
  if [[ -n "$pattern" ]]; then
    awk -F'\t' -v p="$pattern" '$2 ~ p { print }' "$CLASSIFIED" \
      | sort -t$'\t' -k9,9nr > "$out"
  elif [[ -n "$tag" ]]; then
    awk -F'\t' -v t="$tag" '$10 ~ t { print }' "$CLASSIFIED" \
      | sort -t$'\t' -k9,9nr > "$out"
  fi
  local n
  n=$(wc -l < "$out" | tr -d ' ')
  printf "    %-28s %s entries\n" "$name" "$n"
}

echo "[*] categorizing"

for code in 200 201 204 301 302 307 308 400 401 403 404 405 500 502 503; do
  awk -F'\t' -v c="$code" '$2==c { print }' "$CLASSIFIED" \
    | sort -t$'\t' -k9,9nr > "$OUTDIR/status_${code}.txt"
done

emit "class_bypass_candidates.txt" "^403$|^401$"    ""
emit "class_method_issues.txt"     "^405$"          ""
emit "class_error_inject.txt"      "^500$|^502$|^503$" ""
emit "class_redirects.txt"         "^30[12378]$"    ""
emit "class_direct_hits.txt"       "^200$|^201$"    ""

emit "tag_admin_like.txt"      "" "admin|dashboard|panel|console|manage"
emit "tag_api_like.txt"        "" "api|graphql|swagger|docs"
emit "tag_auth_like.txt"       "" "login|signin|auth"
emit "tag_dev_like.txt"        "" "dev|staging|test|beta|internal|debug"
emit "tag_config_backup.txt"   "" "sensitive_file|\.env|\.bak|\.git|\.svn"
emit "tag_tech_known.txt"      "" "tech:"
emit "tag_soft404.txt"         "" "soft404"

# ---------- Step 5: ranked shortlist ----------
SHORT="$OUTDIR/WORTH_TESTING.txt"
awk -F'\t' -v m="$MIN_SCORE" '$9 >= m { print }' "$CLASSIFIED" \
  | sort -t$'\t' -k9,9nr > "$TMP/shortlist.tsv"

{
  echo "# Worth-testing shortlist — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# min-score=${MIN_SCORE}  total-candidates=$(wc -l < "$TMP/shortlist.tsv" | tr -d ' ')"
  echo "# score | status | clen | title | tech | tags | url"
  printf '#%s\n' "-------------------------------------------------------------"
  awk -F'\t' '{
    printf "%5d | %3s | %7s | %s | %s | %s | %s\n",
      $9, $2, $3, ($5?$5:"-"), ($7?$7:"-"), $10, $1
  }' "$TMP/shortlist.tsv"
} > "$SHORT"

# ---------- Step 6: summary ----------
SUM="$OUTDIR/summary.txt"
{
  echo "Triage summary — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "-------------------------------------------"
  echo "Input URLs       : $TOTAL"
  echo "Probed responses : $(wc -l < "$CLASSIFIED" | tr -d ' ')"
  echo "Shortlist (>= $MIN_SCORE) : $(wc -l < "$TMP/shortlist.tsv" | tr -d ' ')"
  echo
  echo "Top tags by count:"
  tr ',' '\n' < <(cut -f10 "$CLASSIFIED") \
    | sed '/^$/d' \
    | sort | uniq -c | sort -rn | head -20
  echo
  echo "Top 20 ranked URLs:"
  head -20 "$SHORT" | tail -n +5
} > "$SUM"

echo
echo "[+] shortlist : $SHORT"
echo "[+] summary   : $SUM"
echo "[+] categories: $OUTDIR/class_*.txt  $OUTDIR/status_*.txt  $OUTDIR/tag_*.txt"
