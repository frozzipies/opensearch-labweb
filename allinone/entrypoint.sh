#!/usr/bin/env bash
# =============================================================================
#  SOC Lab entrypoint — OpenSearch + Dashboards + Seeder. No auth.
#  Env vars:
#    EVENT_COUNT          — number of security events to seed (default: 5000)
#    OPENSEARCH_JAVA_OPTS — JVM heap size (default: -Xms512m -Xmx512m)
# =============================================================================
set -uo pipefail
log() { echo "[labweb $(date +%H:%M:%S)] $*"; }

# Alias hostnames to loopback
if ! grep -q 'opensearch' /etc/hosts 2>/dev/null; then
  echo "127.0.0.1 opensearch dashboards" >> /etc/hosts
fi

# Start OpenSearch
log "starting opensearch ..."
su -s /bin/bash opensearch -c "OPENSEARCH_JAVA_OPTS='${OPENSEARCH_JAVA_OPTS:--Xms512m -Xmx512m}' /usr/share/opensearch/bin/opensearch" > /var/log/opensearch.log 2>&1 &
OS_PID=$!

# Wait for OpenSearch
log "waiting for opensearch ..."
up=0
for i in $(seq 1 90); do
  if curl -s http://localhost:9200 >/dev/null 2>&1; then
    up=1; log "opensearch is up."; break
  fi
  if ! kill -0 "$OS_PID" 2>/dev/null; then
    log "ERROR: opensearch died."; tail -n 40 /var/log/opensearch.log || true; exit 1
  fi
  sleep 2
done
[ "$up" = 1 ] || { log "ERROR: opensearch timeout."; tail -n 40 /var/log/opensearch.log || true; exit 1; }

# Start OpenSearch Dashboards
log "starting dashboards ..."
su -s /bin/bash opensearch -c "/opt/opensearch-dashboards/bin/opensearch-dashboards" > /var/log/dashboards.log 2>&1 &

# Seed the dataset + create saved objects
log "seeding ${EVENT_COUNT:-5000} events ..."
OPENSEARCH_URL="http://localhost:9200" DASHBOARDS_URL="http://localhost:5601" \
EVENT_COUNT="${EVENT_COUNT:-5000}" \
  python3 /opt/seeder/seed.py || log "seeder error (check above)."

log "========================================="
log " Ready. Dashboard: port 5601"
log " No login required"
log " Security events dashboard loads by default"
log " Time range: Last 24 hours"
log "========================================="

tail -n +1 -F /var/log/opensearch.log /var/log/dashboards.log 2>/dev/null &
wait "$OS_PID"
