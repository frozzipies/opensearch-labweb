#!/usr/bin/env bash
set -e

echo "=== SOC Lab — OpenSearch Security Events ==="
echo ""

# vm.max_map_count check (required by OpenSearch)
MAPCOUNT=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [ "$MAPCOUNT" -lt 262144 ]; then
  echo "[*] Setting vm.max_map_count=262144 (required by OpenSearch) ..."
  sudo sysctl -w vm.max_map_count=262144 || echo "    WARN: could not set. If OpenSearch crashes, run: sudo sysctl -w vm.max_map_count=262144"
fi

echo "[*] Starting containers ..."
docker compose up -d --build

echo ""
echo "[*] Watching seeder logs (Ctrl+C to stop watching — containers keep running) ..."
echo "    Dashboard will be ready in ~1-2 minutes at http://localhost:5601"
echo ""
docker compose logs -f seeder
