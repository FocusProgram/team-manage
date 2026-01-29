#!/bin/bash
set -e

GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
RED="\033[0;31m"
RESET="\033[0m"

log() {
  echo -e "${BLUE}[$(date '+%F %T')]${RESET} $1"
}

ok() {
  echo -e "${GREEN}[$(date '+%F %T')]${RESET} $1"
}

warn() {
  echo -e "${YELLOW}[$(date '+%F %T')]${RESET} $1"
}

err() {
  echo -e "${RED}[$(date '+%F %T')]${RESET} $1"
}

log "🚀 start"

if [ ! -d "venv" ]; then
  warn "📦 create venv"
  python3 -m venv venv
else
  ok "📦 venv exists"
fi

log "✅ activate venv"
source venv/bin/activate

log "📥 install requirements"
pip install -r requirements.txt

log "▶️ run uvicorn"
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8008