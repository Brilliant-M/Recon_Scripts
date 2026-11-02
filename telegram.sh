#!/usr/bin/env bash
# telegram.sh — send a plain-text message to a Telegram bot
# Usage: telegram.sh -f <message_file>
# Env:   TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
set -uo pipefail

MSG_FILE=""
TOKEN="${TELEGRAM_BOT_TOKEN:-}"
CHAT="${TELEGRAM_CHAT_ID:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f) MSG_FILE="$2"; shift 2 ;;
    -t) TOKEN="$2"; shift 2 ;;
    -c) CHAT="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 -f <message_file> [-t token] [-c chat_id]"
      exit 0
      ;;
    *) echo "unknown arg: $1"; exit 1 ;;
  esac
done

if [[ -z "$TOKEN" || -z "$CHAT" ]]; then
  echo "[!] TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not configured — skipping"
  exit 0
fi

if [[ -z "$MSG_FILE" || ! -r "$MSG_FILE" ]]; then
  echo "[!] message file required: -f <file>"
  exit 1
fi

MSG=$(cat "$MSG_FILE")
if [[ ${#MSG} -gt 4000 ]]; then
  MSG="${MSG:0:3900}

... [truncated — see artifact for full results]"
fi

RESP=$(curl -s -w "\n%{http_code}" \
  -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
  --data-urlencode "chat_id=${CHAT}" \
  --data-urlencode "text=${MSG}" \
  -d "disable_web_page_preview=true" \
  --max-time 30 2>/dev/null || echo "000")

HTTP_CODE=$(echo "$RESP" | tail -n1)
if [[ "$HTTP_CODE" == "200" ]]; then
  echo "[+] Telegram notification sent (${#MSG} chars)"
else
  echo "[!] Telegram notification failed (HTTP $HTTP_CODE)"
  echo "$RESP" | head -c 300
fi
