#!/usr/bin/env bash
# ==============================================================================
#  run.sh — AutoSOC Dev Server
#
#  Usage:
#    ./run.sh          → start all infrastructure + app
#    Ctrl+C            → gracefully stop everything in Docker
# ==============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# ==============================================================================
# TRAP — runs when you press Ctrl+C or kill the script
# ==============================================================================
cleanup() {
    echo ""
    echo -e "${YELLOW}${BOLD}⏹  Shutting down AutoSOC...${RESET}"
    docker compose down
    echo -e "${GREEN}✅ All containers stopped. Bye!${RESET}"
    exit 0
}
trap cleanup SIGINT SIGTERM

# ==============================================================================
# 1. Start infrastructure
# ==============================================================================
echo -e "${CYAN}${BOLD}"
echo "  ___         _          ____  ___   ____"
echo " / _ | __ __/ /____    / __/ / _ \ / __/"
echo "/ __ |/ // / __/ _ \  _\ \  / // // /__ "
echo "/_/ |_/\_,_/\__/\___/ /___/ /___/ \___/ "
echo -e "${RESET}"
echo -e "${BOLD}AutoSOC — Autonomous SOC Co-Pilot${RESET}"
echo -e "Press ${RED}Ctrl+C${RESET} at any time to stop everything.\n"

echo -e "${CYAN}▶  Starting infrastructure containers...${RESET}"
docker compose up -d

# ==============================================================================
# 2. Wait for all services to be healthy
# ==============================================================================
echo -e "\n${CYAN}⏳ Waiting for services to be healthy...${RESET}"

wait_healthy() {
    local name=$1
    local max_retries=30
    local i=0
    while [ $i -lt $max_retries ]; do
        status=$(docker inspect --format='{{.State.Health.Status}}' "$name" 2>/dev/null || echo "none")
        if [ "$status" = "healthy" ]; then
            echo -e "   ${GREEN}✅ $name is healthy${RESET}"
            return 0
        fi
        sleep 2
        i=$((i + 1))
    done
    echo -e "   ${RED}❌ $name did not become healthy in time${RESET}"
    return 1
}

wait_healthy autosoc-redis
wait_healthy autosoc-rabbitmq
wait_healthy autosoc-qdrant
wait_healthy autosoc-phoenix

# ==============================================================================
# 3. Print the dashboard URLs
# ==============================================================================
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}${BOLD}  🟢 AutoSOC Infrastructure is LIVE${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  📦  RabbitMQ Management  →  ${CYAN}http://localhost:15672${RESET}  (guest/guest)"
echo -e "  🧠  Arize Phoenix        →  ${CYAN}http://localhost:6006${RESET}"
echo -e "  🔍  Qdrant Dashboard     →  ${CYAN}http://localhost:6333/dashboard${RESET}"
echo -e "  🗄️   Redis               →  ${CYAN}localhost:6379${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  ${YELLOW}Press Ctrl+C to stop all services${RESET}"
echo ""

# ==============================================================================
# 4. Stream all container logs so you can see what's happening live
# ==============================================================================
docker compose logs -f

