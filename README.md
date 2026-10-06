# SOC Lab — OpenSearch Security Events Dashboard

A self-contained, Dockerized **OpenSearch** training lab. It boots OpenSearch +
OpenSearch Dashboards and **automatically seeds 5,000 realistic security events**
with a pre-built **Security Events dashboard** — metrics, charts, MITRE ATT&CK
breakdown, and a data table — so students can start hunting immediately.

> **Scenario:** a mixed environment (Windows, RHEL7, Amazon Linux, macOS, Debian)
> has been under attack over the last 24 hours. Students analyze the Security
> Events dashboard to identify brute force attempts, web attacks, privilege
> escalation, and defense evasion activity.

| | |
|---|---|
| **Stack** | OpenSearch 2.19.1 + Dashboards + one-shot seeder |
| **Dataset** | ~5,000 events, deterministic, last 24h |
| **Attacks** | SSH brute force, SQLi, XSS, path traversal, PowerShell, rootkit, web shell |
| **MITRE** | Credential Access, Initial Access, Defense Evasion, Execution, Privilege Escalation, Discovery |
| **Deploy** | `docker compose` or single-container Dockerfile |

---

## Requirements

- **Docker** + **Docker Compose v2**
- **~1 GB RAM** (OpenSearch 512 MB heap + Dashboards ~400 MB)
- **~1.5 GB disk** (2 Docker images)
- Linux kernel: `vm.max_map_count >= 262144` (handled by `setup.sh`)

## Quick start

```bash
chmod +x setup.sh
./setup.sh
```

Then open **http://localhost:5601** — the Security Events dashboard loads
automatically. Set time range to **Last 24 hours**.

No login required (security plugin disabled for simplicity).

## Who does what

| Service | Image | Role |
|---|---|---|
| `opensearch` | `opensearchproject/opensearch:2.19.1` | Data store (512 MB heap) |
| `dashboards` | `opensearchproject/opensearch-dashboards:2.19.1` | UI (HTTP, port 5601) |
| `seeder` | built from `./seeder` | One-shot: loads events + creates dashboard, then exits |

## Dashboard contents

| Panel | Type | Description |
|---|---|---|
| Total alerts | Metric | Total event count |
| Level 12+ alerts | Metric | High-severity events (SQLi, XSS, rootkit, web shell) |
| Authentication failure | Metric | Brute force attempts |
| Authentication success | Metric | Successful logins |
| Alert level evolution | Area chart | Event severity over time |
| Top MITRE ATT&CK tactics | Pie chart | Attack category breakdown |
| Top 5 agents | Donut chart | Events by host |
| Alerts evolution | Stacked bar | Events over time by agent |
| Security alerts | Data table | Raw events with MITRE mapping |

## Reset

```bash
docker compose down -v
./setup.sh
```

## Deploying on a PaaS (Dockerfile)

1. Point the PaaS at this repo, branch `main`, use the root `Dockerfile`.
2. Container port: **5601**. Backend protocol: **HTTP**.
3. Give it **~1.5 GB RAM**.
4. Open the URL — the Security Events dashboard loads automatically.

## Troubleshooting

| Symptom | Fix |
|---|---|
| OpenSearch crashes / `max virtual memory areas` | `sudo sysctl -w vm.max_map_count=262144` |
| Dashboard shows "no results" | Set time range to *Last 24 hours* |
| Saved objects missing | Restart the seeder: `docker compose restart seeder` |

## Credits

Built on [OpenSearch](https://opensearch.org/) 2.19.1.
Security events dataset and dashboard are original to this lab.
