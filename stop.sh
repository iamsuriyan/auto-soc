#!/usr/bin/env bash
# ==============================================================================
#  stop.sh — Stop AutoSOC Application and All Docker Containers
#
#  Usage:
#    ./stop.sh
# ==============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo -e "${YELLOW}${BOLD}⏹  Stopping AutoSOC and all Docker containers...${RESET}"

# Stop any running AutoSOC API / server processes
pkill -f "uvicorn src.api.rest.app:app" 2>/dev/null || true
pkill -f "src.api.grpc.server" 2>/dev/null || true

# Tear down Docker Compose containers
echo -e "${CYAN}▶  Bringing down Docker containers...${RESET}"
docker compose down

echo -e "${GREEN}✅ AutoSOC and all Docker containers stopped successfully.${RESET}"
