name: Subdomain Fuzz

on:
  workflow_dispatch:
    inputs:
      target:
        description: 'Target root domain (e.g. example.com)'
        required: true
        type: string
      mode:
        description: 'Scan mode'
        required: true
        type: choice
        default: 'active'
        options: [passive, active, full]
      depth:
        description: 'Recursion depth (0 = off, only used when mode=full)'
        required: true
        type: choice
        default: '0'
        options: ['0', '1', '2', '3']
      threads:
        description: 'Threads (default 20)'
        required: false
        type: string
        default: '20'
      rate:
        description: 'Rate limit req/s (default 20)'
        required: false
        type: string
        default: '20'

concurrency:
  group: subfuzz-${{ inputs.target }}
  cancel-in-progress: false

jobs:
  enumerate:
    runs-on: ubuntu-latest
    timeout-minutes: 60 # Reduced timeout to prevent runaway jobs
    permissions:
      contents: read

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          ref: ${{ github.ref }}

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          cache: false

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install base packages
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y -qq jq curl dnsutils

      - name: Install massdns
        run: |
          git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns
          cd /tmp/massdns
          make -j
          sudo make install
          massdns --version

      - name: Install Go tools
        run: |
          export PATH="$PATH:$(go env GOPATH)/bin"
          go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
          go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
          go install github.com/projectdiscovery/httpx/cmd/httpx@latest
          go install github.com/tomnomnom/assetfinder@latest
          go install github.com/d3mondev/puredns/v2@latest
          go install github.com/Josue87/gotator@latest
          go install github.com/owasp-amass/amass/v4/...@master || echo "amass install failed (optional)"
          echo "$HOME/go/bin" >> "$GITHUB_PATH"

      - name: Install dnsgen
        run: pip install --quiet dnsgen

      - name: Verify tools
        run: |
          export PATH="$PATH:$HOME/go/bin"
          MISSING=""
          for t in subfinder dnsx httpx puredns massdns jq curl; do
            if ! command -v "$t" >/dev/null 2>&1; then MISSING="$MISSING $t"; fi
          done
          if [ -n "$MISSING" ]; then
            echo "❌ CRITICAL: Missing required tools:$MISSING"
            exit 1
          fi
          echo "✅ All required tools are installed and in PATH."

      - name: Download wordlists
        run: |
          mkdir -p wordlists
          curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -o wordlists/subdomains.txt
          curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt -o wordlists/permutations.txt
          wc -l wordlists/subdomains.txt wordlists/permutations.txt
          test -s wordlists/subdomains.txt
          test -s wordlists/permutations.txt

      - name: Initialize resolvers
        run: |
          export PATH="$PATH:$(go env GOPATH)/bin"
          if ! puredns init; then
            echo "puredns init failed — falling back to trickest/resolvers"
            curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o resolvers.txt
          fi
          test -s resolvers.txt
          echo "resolvers.txt lines: $(wc -l < resolvers.txt)"

      # ==========================================
      # THIS STEP BUILDS AND RUNS THE SCRIPT
      # ==========================================
      - name: Generate and Run subfuzz.sh
        env:
          TARGET:  ${{ inputs.target }}
          MODE:    ${{ inputs.mode }}
          DEPTH:   ${{ inputs.depth }}
          THREADS: ${{ inputs.threads }}
          RATE:    ${{ inputs.rate }}
        run: |
          export PATH="$PATH:$HOME/go/bin"

          # 1. Write the bash script to a file on the runner
          cat > subfuzz.sh << 'SCRIPT_EOF'
          #!/usr/bin/env bash
          set -uo pipefail

          TARGET=""
          OUTDIR="./subenum_out"
          WORDLIST=""
          RESOLVERS=""
          MODE="active"
          RECURSION_DEPTH=0
          PERM_WORDLIST=""
          THREADS=20
          RATE=20

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
              *) shift ;;
            esac
          done

          mkdir -p "$OUTDIR"
          TMP="$OUTDIR/.tmp"
          mkdir -p "$TMP"

          dedupe () { if command -v anew >/dev/null 2>&1; then anew "$@"; else sort -u; fi; }

          rate_guard () {
            local base_rate=$1; shift
            local rate=$base_rate fails=0
            while true; do
              "$@" -rate "$rate" 2>&1 | tee "$TMP/rate_guard.log"
              if grep -qiE '429|403|REFUSED|SERVFAIL' "$TMP/rate_guard.log"; then
                rate=$(( rate / 2 )); (( rate < 1 )) && rate=1
                fails=$(( fails + 1 ))
                sleep $(( 15 * fails ))
                (( fails >= 3 )) && return 1
              else
                break
              fi
            done
          }

          echo "[*] Phase 1: Passive enumeration for $TARGET"
          : > "$TMP/sub_all.txt"
          command -v subfinder   >/dev/null && subfinder -d "$TARGET" -all -silent -o "$TMP/sub_subfinder.txt" 2>/dev/null || true
          command -v assetfinder >/dev/null && assetfinder --subs-only "$TARGET" > "$TMP/sub_assetfinder.txt" 2>/dev/null || true
          command -v amass       >/dev/null && amass enum -passive -d "$TARGET" -o "$TMP/sub_amass.txt" 2>/dev/null || true

          curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | tr ',' '\n' | grep -oE "[A-Za-z0-9._-]+\.${TARGET}" | sort -u > "$TMP/sub_crt.txt" 2>/dev/null || true

          find "$TMP" -maxdepth 1 -name 'sub_*.txt' -exec cat {} + 2>/dev/null | sed '/^$/d' | dedupe "$OUTDIR/passive_subs.txt" || touch "$OUTDIR/passive_subs.txt"
          echo "[+] Passive: $(wc -l < "$OUTDIR/passive_subs.txt" | tr -d ' ') candidates"

          cp "$OUTDIR/passive_subs.txt" "$OUTDIR/all_subs_raw.txt"
          if [[ "$MODE" != "passive" ]]; then
            echo "[*] Phase 2: Active bruteforce (puredns)"
            timeout 600 puredns bruteforce "$WORDLIST" "$TARGET" -r "$RESOLVERS" -t "$THREADS" -o "$TMP/sub_bruteforce.txt" > /dev/null 2>&1 || true
            find "$OUTDIR/passive_subs.txt" "$TMP/sub_bruteforce.txt" -type f -exec cat {} + 2>/dev/null | sed '/^$/d' | dedupe "$OUTDIR/all_subs_raw.txt" || touch "$OUTDIR/all_subs_raw.txt"
          fi
          echo "[+] Raw merged: $(wc -l < "$OUTDIR/all_subs_raw.txt" | tr -d ' ') candidates"

          echo "[*] Phase 3: Resolve (dnsx)"
          random_name="nonexistent-$(head -c 200 /dev/urandom | tr -dc a-z | head -c 8).$TARGET"
          wildcard_ip=$(dig +short "$random_name" A 2>/dev/null | head -n1 || true)
          if [[ -n "$wildcard_ip" ]]; then
            dnsx -l "$OUTDIR/all_subs_raw.txt" -a -resp -silent -wd "$TARGET" -o "$TMP/resolved.txt" > /dev/null 2>&1 || true
          else
            dnsx -l "$OUTDIR/all_subs_raw.txt" -a -resp -silent -o "$TMP/resolved.txt" > /dev/null 2>&1 || true
          fi
          sed -E 's/[[:space:]].*$//' "$TMP/resolved.txt" 2>/dev/null | sed '/^$/d' | dedupe "$OUTDIR/resolved_subs.txt" || touch "$OUTDIR/resolved_subs.txt"
          echo "[+] Resolved: $(wc -l < "$OUTDIR/resolved_subs.txt" | tr -d ' ') live subdomains"

          if [[ "$MODE" == "full" && "$RECURSION_DEPTH" -gt 0 ]]; then
            echo "[*] Phase 4: Recursion (depth=$RECURSION_DEPTH)"
            if [[ -n "$PERM_WORDLIST" && -r "$PERM_WORDLIST" ]]; then
              if command -v gotator >/dev/null 2>&1; then
                gotator -sub "$OUTDIR/resolved_subs.txt" -perm "$PERM_WORDLIST" -depth "$RECURSION_DEPTH" -numbers 10 > "$TMP/permuted_candidates.txt" 2>/dev/null || true
              elif command -v dnsgen >/dev/null 2>&1; then
                input="$OUTDIR/resolved_subs.txt"
                for ((i=1; i<=RECURSION_DEPTH; i++)); do dnsgen "$input" > "$TMP/perm_$i.txt" 2>/dev/null || true; input="$TMP/perm_$i.txt"; done
                cat "$TMP"/perm_*.txt > "$TMP/permuted_candidates.txt" 2>/dev/null || true
              fi
              if [[ -s "$TMP/permuted_candidates.txt" ]]; then
                rate_guard "$RATE" puredns resolve "$TMP/permuted_candidates.txt" -r "$RESOLVERS" -t "$THREADS" -o "$TMP/permuted_resolved.txt" > /dev/null 2>&1 || true
                if [[ -s "$TMP/permuted_resolved.txt" ]]; then
                  find "$OUTDIR/resolved_subs.txt" "$TMP/permuted_resolved.txt" -type f -exec cat {} + 2>/dev/null | sed '/^$/d' | dedupe "$TMP/resolved_with_recursion.txt" || true
                  mv "$TMP/resolved_with_recursion.txt" "$OUTDIR/resolved_subs.txt" 2>/dev/null || true
                fi
              fi
            fi
          fi

          echo "[*] Phase 5: HTTP probing (httpx)"
          httpx -l "$OUTDIR/resolved_subs.txt" -ports 80,443,8080,8443 -sc -title -tech-detect -cdn -silent -t "$THREADS" -rl "$RATE" -timeout 10 -o "$OUTDIR/live_hosts.txt" > /dev/null 2>&1 || true
          echo "[+] Live HTTP hosts: $(wc -l < "$OUTDIR/live_hosts.txt" | tr -d ' ')"
          SCRIPT_EOF

          # 2. Make it executable
          chmod +x subfuzz.sh

          # 3. Run it
          if [ -z "$TARGET" ]; then exit 1; fi
          ARGS=(-d "$TARGET" -w wordlists/subdomains.txt -r resolvers.txt -t "$THREADS" -R "$RATE")
          if [ "$MODE" = "passive" ]; then ARGS+=(--mode passive); fi
          if [ "$MODE" = "full" ] && [ "$DEPTH" != "0" ]; then ARGS+=(--mode full --depth "$DEPTH" --perm wordlists/permutations.txt); fi
          
          echo "▶ ./subfuzz.sh ${ARGS[*]}"
          ./subfuzz.sh "${ARGS[@]}"

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: subfuzz-${{ inputs.target }}-${{ github.run_id }}
          path: subenum_out/
          retention-days: 30
          if-no-files-found: warn

      - name: Notify Telegram
        if: always()
        env:
          TELEGRAM_BOT_TOKEN: ${{ secrets.TELEGRAM_BOT_TOKEN }}
          TELEGRAM_CHAT_ID:   ${{ secrets.TELEGRAM_CHAT_ID }}
          RUN_URL:            ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
          TARGET:             ${{ inputs.target }}
        run: |
          if [ -z "${TELEGRAM_BOT_TOKEN:-}" ] || [ -z "${TELEGRAM_CHAT_ID:-}" ]; then exit 0; fi
          passive=0; resolved=0; live=0
          [ -f subenum_out/passive_subs.txt ]  && passive=$(wc -l < subenum_out/passive_subs.txt)
          [ -f subenum_out/resolved_subs.txt ] && resolved=$(wc -l < subenum_out/resolved_subs.txt)
          [ -f subenum_out/live_hosts.txt ]    && live=$(wc -l < subenum_out/live_hosts.txt)
          
          MSG="🔍 SUBFUZZ — ${TARGET}%0A• Passive: ${passive}%0A• Resolved: ${resolved}%0A• Live: ${live}%0A🔗 ${RUN_URL}"
          curl -sS -o /dev/null -w '[+] Telegram: HTTP %{http_code}\n' \
            -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT_ID}&text=${MSG}" || true

      - name: Write summary
        if: always()
        run: |
          {
            echo "## Subdomain Fuzz — \`${{ inputs.target }}\`"
            echo "| Mode | \`${{ inputs.mode }}\` |"
            echo "| Depth | \`${{ inputs.depth }}\` |"
            echo ""
            if [ -f subenum_out/live_hosts.txt ]; then
              echo "### ✅ Live hosts ($(wc -l < subenum_out/live_hosts.txt))"
              echo '```'; head -50 subenum_out/live_hosts.txt; echo '```'
            else
              echo "### ⚠️ No results produced."
            fi
          } >> "$GITHUB_STEP_SUMMARY" || true
        continue-on-error: true