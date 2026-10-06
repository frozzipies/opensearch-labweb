#!/usr/bin/env python3
"""
SOC Lab — OpenSearch Security Events Seeder
Generates realistic security events and pre-builds a Security Events dashboard
with visualizations (metrics, charts, pie charts, data table).
No external dependencies — stdlib only.
"""

import json
import random
import time
import os
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://opensearch:9200")
DASHBOARDS_URL = os.environ.get("DASHBOARDS_URL", "http://dashboards:5601")
EVENT_COUNT = int(os.environ.get("EVENT_COUNT", "5000"))
INDEX_PREFIX = "security-events"

# ---------------------------------------------------------------------------
# Agents (matching Wazuh-style names from the screenshots)
# ---------------------------------------------------------------------------
AGENTS = [
    {"id": "001", "name": "Windows",  "ip": "10.0.0.5"},
    {"id": "002", "name": "RHEL7",    "ip": "10.0.0.10"},
    {"id": "003", "name": "Amazon",   "ip": "10.0.0.15"},
    {"id": "004", "name": "macOS",    "ip": "10.0.0.20"},
    {"id": "005", "name": "Debian",   "ip": "10.0.0.25"},
]
AGENT_WEIGHTS = [35, 25, 20, 10, 10]

# ---------------------------------------------------------------------------
# Rule catalog — each rule maps to MITRE ATT&CK
# ---------------------------------------------------------------------------
RULES = [
    # --- Credential Access (high volume) ---
    {"id": "5710",  "level": 5,  "desc": "sshd: Attempt to login using a non-existent user",
     "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
     "groups": ["syslog","sshd"], "agent_idx": [1,2,4], "weight": 20, "cat": "auth_failure"},
    {"id": "5503",  "level": 5,  "desc": "PAM: User login failed",
     "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
     "groups": ["pam","syslog"], "agent_idx": [1,2,4], "weight": 12, "cat": "auth_failure"},
    {"id": "5715",  "level": 10, "desc": "sshd: Multiple authentication failures",
     "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
     "groups": ["syslog","sshd"], "agent_idx": [1,2], "weight": 4, "cat": "auth_failure"},
    {"id": "5720",  "level": 10, "desc": "sshd: Multiple access attempts using a denied user",
     "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
     "groups": ["syslog","sshd"], "agent_idx": [1,2,4], "weight": 3, "cat": "auth_failure"},
    {"id": "18104", "level": 8,  "desc": "Windows: Logon failure - Unknown user or bad password",
     "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
     "groups": ["windows","security_event"], "agent_idx": [0], "weight": 6, "cat": "auth_failure"},

    # --- Authentication success ---
    {"id": "5501",  "level": 3, "desc": "PAM: Login session opened",
     "mitre": {"id": ["T1078"], "tactic": ["Initial Access"], "technique": ["Valid Accounts"]},
     "groups": ["pam","syslog"], "agent_idx": [1,2,3,4], "weight": 2, "cat": "auth_success"},
    {"id": "5502",  "level": 3, "desc": "sshd: Authentication success",
     "mitre": {"id": ["T1078"], "tactic": ["Initial Access"], "technique": ["Valid Accounts"]},
     "groups": ["syslog","sshd"], "agent_idx": [1,2], "weight": 1, "cat": "auth_success"},
    {"id": "18100", "level": 3, "desc": "Windows: Logon success",
     "mitre": {"id": ["T1078"], "tactic": ["Initial Access"], "technique": ["Valid Accounts"]},
     "groups": ["windows","security_event"], "agent_idx": [0], "weight": 1, "cat": "auth_success"},

    # --- Initial Access (web attacks) ---
    {"id": "31101", "level": 6,  "desc": "Apache: Attempt to access forbidden directory index",
     "mitre": {"id": ["T1190"], "tactic": ["Initial Access"], "technique": ["Exploit Public-Facing Application"]},
     "groups": ["apache","web"], "agent_idx": [2,4], "weight": 7},
    {"id": "31104", "level": 6,  "desc": "Apache: Invalid URI in request",
     "mitre": {"id": ["T1190"], "tactic": ["Initial Access"], "technique": ["Exploit Public-Facing Application"]},
     "groups": ["apache","web"], "agent_idx": [2], "weight": 5},
    {"id": "31105", "level": 6,  "desc": "Apache: Attempt to access a forbidden resource",
     "mitre": {"id": ["T1190"], "tactic": ["Initial Access"], "technique": ["Exploit Public-Facing Application"]},
     "groups": ["apache","web"], "agent_idx": [2,4], "weight": 4},
    {"id": "31106", "level": 12, "desc": "Apache: SQL injection attempt detected",
     "mitre": {"id": ["T1190"], "tactic": ["Initial Access"], "technique": ["Exploit Public-Facing Application"]},
     "groups": ["apache","web","attack"], "agent_idx": [2], "weight": 2},
    {"id": "31110", "level": 12, "desc": "Apache: XSS (Cross-Site Scripting) attempt",
     "mitre": {"id": ["T1190"], "tactic": ["Initial Access"], "technique": ["Exploit Public-Facing Application"]},
     "groups": ["apache","web","attack"], "agent_idx": [2,4], "weight": 1},
    {"id": "31115", "level": 10, "desc": "Apache: Path traversal attempt detected",
     "mitre": {"id": ["T1190"], "tactic": ["Initial Access"], "technique": ["Exploit Public-Facing Application"]},
     "groups": ["apache","web","attack"], "agent_idx": [2], "weight": 2},

    # --- Defense Evasion ---
    {"id": "255563","level": 10, "desc": "Signed Script Proxy Execution: C:\\Windows\\System32\\svchost.exe",
     "mitre": {"id": ["T1218"], "tactic": ["Defense Evasion","Execution"], "technique": ["System Binary Proxy Execution"]},
     "groups": ["windows","sysmon"], "agent_idx": [0], "weight": 4},
    {"id": "255546","level": 5,  "desc": "Install Root Certificate: C:\\Windows\\sysmon64.exe",
     "mitre": {"id": ["T1553"], "tactic": ["Defense Evasion"], "technique": ["Subvert Trust Controls"]},
     "groups": ["windows","sysmon"], "agent_idx": [0], "weight": 3},
    {"id": "750",   "level": 7,  "desc": "Service startup type was changed",
     "mitre": {"id": ["T1543"], "tactic": ["Defense Evasion"], "technique": ["Create or Modify System Process"]},
     "groups": ["windows","system"], "agent_idx": [0], "weight": 3},
    {"id": "550",   "level": 7,  "desc": "Integrity checksum changed",
     "mitre": {"id": ["T1565"], "tactic": ["Defense Evasion"], "technique": ["Data Manipulation"]},
     "groups": ["syscheck"], "agent_idx": [0,1,2,3,4], "weight": 4},

    # --- Execution ---
    {"id": "91005", "level": 8,  "desc": "PowerShell: Script block logging - suspicious content",
     "mitre": {"id": ["T1059"], "tactic": ["Execution"], "technique": ["Command and Scripting Interpreter"]},
     "groups": ["windows","powershell"], "agent_idx": [0], "weight": 3},
    {"id": "92000", "level": 6,  "desc": "Sysmon: Process creation detected",
     "mitre": {"id": ["T1059"], "tactic": ["Execution"], "technique": ["Command and Scripting Interpreter"]},
     "groups": ["windows","sysmon"], "agent_idx": [0], "weight": 5},
    {"id": "80700", "level": 6,  "desc": "Sysmon: Network connection detected",
     "mitre": {"id": ["T1071"], "tactic": ["Execution"], "technique": ["Application Layer Protocol"]},
     "groups": ["windows","sysmon"], "agent_idx": [0], "weight": 3},

    # --- Privilege Escalation ---
    {"id": "5303",  "level": 8,  "desc": "User successfully changed UID to root",
     "mitre": {"id": ["T1068"], "tactic": ["Privilege Escalation"], "technique": ["Exploitation for Privilege Escalation"]},
     "groups": ["syslog","su"], "agent_idx": [1,2,3,4], "weight": 2},
    {"id": "5401",  "level": 10, "desc": "sudo: User ran command as root",
     "mitre": {"id": ["T1548"], "tactic": ["Privilege Escalation"], "technique": ["Abuse Elevation Control Mechanism"]},
     "groups": ["syslog","sudo"], "agent_idx": [1,2,3], "weight": 3},

    # --- Discovery ---
    {"id": "80710", "level": 5,  "desc": "Firewall: Dropped inbound connection",
     "mitre": {"id": ["T1046"], "tactic": ["Discovery"], "technique": ["Network Service Discovery"]},
     "groups": ["firewall"], "agent_idx": [0,1,2], "weight": 3},

    # --- High severity ---
    {"id": "510",   "level": 13, "desc": "Rootkit detection: Hidden process found",
     "mitre": {"id": ["T1014"], "tactic": ["Defense Evasion"], "technique": ["Rootkit"]},
     "groups": ["rootcheck"], "agent_idx": [1,2], "weight": 0.5},
    {"id": "31120", "level": 13, "desc": "Web shell detected: Suspicious file upload",
     "mitre": {"id": ["T1505"], "tactic": ["Execution"], "technique": ["Server Software Component"]},
     "groups": ["apache","web","attack"], "agent_idx": [2], "weight": 0.3},
    {"id": "100100","level": 13, "desc": "Malware detected: Trojan.GenericKD found in memory",
     "mitre": {"id": ["T1204"], "tactic": ["Execution"], "technique": ["User Execution"]},
     "groups": ["antivirus"], "agent_idx": [0], "weight": 0.2},
]

ATTACKER_IPS = [
    "185.220.101.34","45.155.205.233","194.26.135.89","23.129.64.190",
    "162.247.74.27","198.98.51.189","91.240.118.172","103.251.167.20",
    "195.54.160.149","5.188.206.14","80.82.77.139","71.6.135.131",
    "209.141.40.193","185.56.80.65","45.129.56.200",
]
TARGET_USERS = ["admin","root","test","user","deploy","backup","www-data","postgres","mysql"]

# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------
def http(method, url, body=None, headers=None):
    hdrs = headers or {}
    data = None
    if body is not None:
        if isinstance(body, str):
            data = body.encode()
        elif isinstance(body, bytes):
            data = body
        else:
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
    req = Request(url, data=data, headers=hdrs, method=method)
    with urlopen(req) as resp:
        return resp.status, json.loads(resp.read())

def wait_for(name, url, path="/", timeout=120):
    print(f"[*] Waiting for {name} at {url}{path} ...")
    for _ in range(timeout):
        try:
            req = Request(f"{url}{path}")
            with urlopen(req, timeout=5) as r:
                if r.status < 500:
                    print(f"[+] {name} is up.")
                    return True
        except Exception:
            pass
        time.sleep(1)
    print(f"[-] ERROR: {name} timeout after {timeout}s")
    return False

# ---------------------------------------------------------------------------
# Event generation
# ---------------------------------------------------------------------------
def build_events(count):
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=24)

    rule_weights = [r["weight"] for r in RULES]
    events = []

    for _ in range(count):
        rule = random.choices(RULES, weights=rule_weights, k=1)[0]
        agent_idx = random.choice(rule["agent_idx"])
        agent = AGENTS[agent_idx]

        secs_offset = random.random() * 86400
        hour = secs_offset / 3600
        # More events during business hours (8-18)
        if 8 <= hour <= 18:
            pass  # keep
        elif random.random() < 0.4:
            secs_offset = random.uniform(8*3600, 18*3600)

        ts = start + timedelta(seconds=secs_offset)

        event = {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{random.randint(0,999):03d}Z",
            "agent": {"id": agent["id"], "name": agent["name"], "ip": agent["ip"]},
            "rule": {
                "id": rule["id"],
                "level": rule["level"],
                "description": rule["desc"],
                "groups": rule["groups"],
                "mitre": rule["mitre"],
            },
            "manager": {"name": "opensearch-lab"},
            "cluster": {"name": "opensearch-lab"},
            "data": {
                "srcip": random.choice(ATTACKER_IPS),
                "dstuser": random.choice(TARGET_USERS),
            },
            "location": random.choice(["/var/log/auth.log","/var/log/syslog","/var/log/apache2/access.log",
                                        "EventChannel","WinEvtLog"]) if "windows" not in rule["groups"]
                       else random.choice(["EventChannel","WinEvtLog","Microsoft-Windows-Sysmon/Operational"]),
        }
        events.append((ts, event))

    events.sort(key=lambda x: x[0])
    return events

# ---------------------------------------------------------------------------
# Bulk indexing
# ---------------------------------------------------------------------------
def bulk_index(events):
    print(f"[*] Loading {len(events)} events into OpenSearch ...")
    batch_size = 500
    indexed = 0

    for i in range(0, len(events), batch_size):
        batch = events[i:i+batch_size]
        lines = []
        for ts, event in batch:
            idx = f"{INDEX_PREFIX}-{ts.strftime('%Y.%m.%d')}"
            lines.append(json.dumps({"index": {"_index": idx}}))
            lines.append(json.dumps(event))
        body = "\n".join(lines) + "\n"

        req = Request(
            f"{OPENSEARCH_URL}/_bulk",
            data=body.encode(),
            headers={"Content-Type": "application/x-ndjson"},
            method="POST",
        )
        with urlopen(req) as resp:
            result = json.loads(resp.read())
            if result.get("errors"):
                errs = [i for i in result["items"] if "error" in i.get("index",{})]
                print(f"    WARN: {len(errs)} errors in batch")

        indexed += len(batch)
        print(f"     indexed {indexed}/{len(events)} events")

    print(f"[+] Done. {indexed} events loaded.")

# ---------------------------------------------------------------------------
# Saved objects — index pattern + visualizations + dashboard
# ---------------------------------------------------------------------------
def vis_ref(idx_id="security-events-*"):
    return [{"id": idx_id, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]

def search_source(query="", filters=None):
    ss = {"query": {"query": query, "language": "kuery"}, "filter": filters or [],
          "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"}
    return json.dumps(ss)

def metric_vis(title, label, query="", filters=None, font_size=60, color="#1BA9F5"):
    vis_state = {
        "title": title, "type": "metric",
        "aggs": [{"id":"1","enabled":True,"type":"count","params":{"customLabel":label},"schema":"metric"}],
        "params": {
            "addTooltip":True,"addLegend":False,"type":"metric",
            "metric":{"percentageMode":False,"useRanges":False,"colorSchema":"Green to Red",
                      "metricColorMode":"Labels","colorsRange":[{"from":0,"to":999999}],
                      "labels":{"show":True},"invertColors":False,
                      "style":{"bgFill":"#000","bgColor":False,"labelColor":True,
                               "subText":"","fontSize":font_size}},
        },
    }
    return {
        "type":"visualization","id":title.lower().replace(" ","-"),
        "attributes":{
            "title":title,"visState":json.dumps(vis_state),
            "uiStateJSON":json.dumps({"vis":{"defaultColors":{"0 - 999999":color}}}),
            "description":"",
            "kibanaSavedObjectMeta":{"searchSourceJSON":search_source(query, filters)},
        },
        "references": vis_ref(),
    }

def area_chart_vis():
    vis_state = {
        "title":"Alert level evolution","type":"area",
        "aggs":[
            {"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
            {"id":"2","enabled":True,"type":"date_histogram","params":{
                "field":"timestamp","useNormalizedOpenSearchInterval":True,
                "scaleMetricValues":False,"interval":"auto",
                "drop_partials":False,"min_doc_count":1,"extended_bounds":{}},"schema":"segment"},
            {"id":"3","enabled":True,"type":"terms","params":{
                "field":"rule.level","orderBy":"1","order":"desc","size":10,
                "otherBucket":False,"missingBucket":False},"schema":"group"},
        ],
        "params":{
            "type":"area","grid":{"categoryLines":False},
            "categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"bottom",
                             "show":True,"style":{},"scale":{"type":"linear"},
                             "labels":{"show":True,"filter":True,"truncate":100},"title":{}}],
            "valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"left",
                          "show":True,"style":{},"scale":{"type":"linear","mode":"normal"},
                          "labels":{"show":True,"rotate":0,"filter":False,"truncate":100},
                          "title":{"text":"Count"}}],
            "seriesParams":[{"show":True,"type":"area","mode":"stacked",
                             "data":{"label":"Count","id":"1"},"drawLinesBetweenPoints":True,
                             "lineWidth":2,"showCircles":True,"interpolate":"linear",
                             "valueAxis":"ValueAxis-1"}],
            "addTooltip":True,"addLegend":True,"legendPosition":"right",
            "times":[],"addTimeMarker":False,
            "thresholdLine":{"show":False,"value":10,"width":1,"style":"full","color":"#E7664C"},
        },
    }
    return {
        "type":"visualization","id":"alert-level-evolution",
        "attributes":{
            "title":"Alert level evolution","visState":json.dumps(vis_state),
            "uiStateJSON":"{}","description":"",
            "kibanaSavedObjectMeta":{"searchSourceJSON":search_source()},
        },
        "references": vis_ref(),
    }

def pie_vis(vis_id, title, field, size=10, is_donut=False):
    vis_state = {
        "title":title,"type":"pie",
        "aggs":[
            {"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
            {"id":"2","enabled":True,"type":"terms","params":{
                "field":field,"orderBy":"1","order":"desc","size":size,
                "otherBucket":False,"missingBucket":False},"schema":"segment"},
        ],
        "params":{
            "type":"pie","addTooltip":True,"addLegend":True,"legendPosition":"right",
            "isDonut":is_donut,
            "labels":{"show":False,"values":True,"last_level":True,"truncate":100},
        },
    }
    return {
        "type":"visualization","id":vis_id,
        "attributes":{
            "title":title,"visState":json.dumps(vis_state),
            "uiStateJSON":"{}","description":"",
            "kibanaSavedObjectMeta":{"searchSourceJSON":search_source()},
        },
        "references": vis_ref(),
    }

def bar_chart_vis():
    vis_state = {
        "title":"Alerts evolution - Top 5 agents","type":"histogram",
        "aggs":[
            {"id":"1","enabled":True,"type":"count","params":{},"schema":"metric"},
            {"id":"2","enabled":True,"type":"date_histogram","params":{
                "field":"timestamp","useNormalizedOpenSearchInterval":True,
                "scaleMetricValues":False,"interval":"auto",
                "drop_partials":False,"min_doc_count":1,"extended_bounds":{}},"schema":"segment"},
            {"id":"3","enabled":True,"type":"terms","params":{
                "field":"agent.name","orderBy":"1","order":"desc","size":5,
                "otherBucket":False,"missingBucket":False},"schema":"group"},
        ],
        "params":{
            "type":"histogram","grid":{"categoryLines":False},
            "categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"bottom",
                             "show":True,"style":{},"scale":{"type":"linear"},
                             "labels":{"show":True,"filter":True,"truncate":100},"title":{}}],
            "valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"left",
                          "show":True,"style":{},"scale":{"type":"linear","mode":"normal"},
                          "labels":{"show":True,"rotate":0,"filter":False,"truncate":100},
                          "title":{"text":"Count"}}],
            "seriesParams":[{"show":True,"type":"histogram","mode":"stacked",
                             "data":{"label":"Count","id":"1"},"drawLinesBetweenPoints":True,
                             "lineWidth":2,"showCircles":True,"valueAxis":"ValueAxis-1"}],
            "addTooltip":True,"addLegend":True,"legendPosition":"right",
            "times":[],"addTimeMarker":False,
        },
    }
    return {
        "type":"visualization","id":"agents-evolution",
        "attributes":{
            "title":"Alerts evolution - Top 5 agents","visState":json.dumps(vis_state),
            "uiStateJSON":"{}","description":"",
            "kibanaSavedObjectMeta":{"searchSourceJSON":search_source()},
        },
        "references": vis_ref(),
    }

def saved_search():
    return {
        "type":"search","id":"security-alerts-table",
        "attributes":{
            "title":"Security alerts","description":"",
            "columns":["agent.name","rule.mitre.id","rule.mitre.tactic","rule.description","rule.level","rule.id"],
            "sort":[["timestamp","desc"]],
            "kibanaSavedObjectMeta":{"searchSourceJSON":search_source()},
        },
        "references": vis_ref(),
    }

def build_dashboard():
    panels = [
        {"gridData":{"x":0, "y":0, "w":12,"h":6, "i":"1"},"panelIndex":"1","embeddableConfig":{},"panelRefName":"panel_0"},
        {"gridData":{"x":12,"y":0, "w":12,"h":6, "i":"2"},"panelIndex":"2","embeddableConfig":{},"panelRefName":"panel_1"},
        {"gridData":{"x":24,"y":0, "w":12,"h":6, "i":"3"},"panelIndex":"3","embeddableConfig":{},"panelRefName":"panel_2"},
        {"gridData":{"x":36,"y":0, "w":12,"h":6, "i":"4"},"panelIndex":"4","embeddableConfig":{},"panelRefName":"panel_3"},
        {"gridData":{"x":0, "y":6, "w":30,"h":16,"i":"5"},"panelIndex":"5","embeddableConfig":{},"panelRefName":"panel_4"},
        {"gridData":{"x":30,"y":6, "w":18,"h":16,"i":"6"},"panelIndex":"6","embeddableConfig":{},"panelRefName":"panel_5"},
        {"gridData":{"x":0, "y":22,"w":16,"h":16,"i":"7"},"panelIndex":"7","embeddableConfig":{},"panelRefName":"panel_6"},
        {"gridData":{"x":16,"y":22,"w":32,"h":16,"i":"8"},"panelIndex":"8","embeddableConfig":{},"panelRefName":"panel_7"},
        {"gridData":{"x":0, "y":38,"w":48,"h":20,"i":"9"},"panelIndex":"9","embeddableConfig":{},"panelRefName":"panel_8"},
    ]
    refs = [
        {"name":"panel_0","type":"visualization","id":"total-alerts"},
        {"name":"panel_1","type":"visualization","id":"level-12+-alerts"},
        {"name":"panel_2","type":"visualization","id":"authentication-failure"},
        {"name":"panel_3","type":"visualization","id":"authentication-success"},
        {"name":"panel_4","type":"visualization","id":"alert-level-evolution"},
        {"name":"panel_5","type":"visualization","id":"mitre-tactics"},
        {"name":"panel_6","type":"visualization","id":"top-agents"},
        {"name":"panel_7","type":"visualization","id":"agents-evolution"},
        {"name":"panel_8","type":"search","id":"security-alerts-table"},
    ]
    return {
        "type":"dashboard","id":"security-events",
        "attributes":{
            "title":"Security events","hits":0,"description":"SOC Lab — Security Events Dashboard",
            "panelsJSON":json.dumps(panels),
            "optionsJSON":json.dumps({"hidePanelTitles":False,"useMargins":True}),
            "kibanaSavedObjectMeta":{"searchSourceJSON":json.dumps(
                {"query":{"query":"","language":"kuery"},"filter":[]})},
        },
        "references": refs,
    }

def create_saved_objects():
    print("[*] Creating saved objects (index pattern + visualizations + dashboard) ...")

    level12_filter = [{"meta":{"index":"security-events-*","negate":False,"disabled":False,
                               "alias":None,"type":"range","key":"rule.level","params":{"gte":12}},
                       "range":{"rule.level":{"gte":12}}}]
    auth_fail_filter = [{"meta":{"index":"security-events-*","negate":False,"disabled":False,
                                 "alias":None,"type":"phrase","key":"rule.mitre.technique",
                                 "params":{"query":"Brute Force"}},
                         "query":{"match_phrase":{"rule.mitre.technique":"Brute Force"}}}]
    auth_succ_filter = [{"meta":{"index":"security-events-*","negate":False,"disabled":False,
                                 "alias":None,"type":"phrase","key":"rule.mitre.technique",
                                 "params":{"query":"Valid Accounts"}},
                         "query":{"match_phrase":{"rule.mitre.technique":"Valid Accounts"}}}]

    objects = [
        # Index pattern
        {"type":"index-pattern","id":"security-events-*",
         "attributes":{"title":"security-events-*","timeFieldName":"timestamp"},
         "references":[]},
        # Set as default index pattern
        {"type":"config","id":"2.19.1",
         "attributes":{"defaultIndex":"security-events-*"},
         "references":[]},
        # Metric visualizations
        metric_vis("Total alerts","Total", color="#1BA9F5"),
        metric_vis("Level 12+ alerts","Level 12 or above", filters=level12_filter, color="#F5A700"),
        metric_vis("Authentication failure","Auth failure", filters=auth_fail_filter, color="#BD271E"),
        metric_vis("Authentication success","Auth success", filters=auth_succ_filter, color="#017D73"),
        # Charts
        area_chart_vis(),
        pie_vis("mitre-tactics","Top Mitre ATT&CK tactics","rule.mitre.tactic"),
        pie_vis("top-agents","Top 5 agents","agent.name", size=5, is_donut=True),
        bar_chart_vis(),
        # Data table (saved search)
        saved_search(),
        # Dashboard
        build_dashboard(),
    ]

    body = json.dumps(objects).encode()
    req = Request(
        f"{DASHBOARDS_URL}/api/saved_objects/_bulk_create?overwrite=true",
        data=body,
        headers={"Content-Type":"application/json","osd-xsrf":"true"},
        method="POST",
    )
    with urlopen(req) as resp:
        result = json.loads(resp.read())
        errors = [o for o in result.get("saved_objects",[]) if o.get("error")]
        if errors:
            for e in errors:
                print(f"    WARN: {e['type']}/{e['id']}: {e['error']}")
        else:
            print(f"[+] Created {len(objects)} saved objects successfully.")

# ---------------------------------------------------------------------------
# Index template
# ---------------------------------------------------------------------------
def create_template():
    template = {
        "index_patterns": [f"{INDEX_PREFIX}-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "timestamp": {"type":"date"},
                    "agent": {"properties":{
                        "id":{"type":"keyword"},"name":{"type":"keyword"},"ip":{"type":"ip"}}},
                    "rule": {"properties":{
                        "id":{"type":"keyword"},"level":{"type":"integer"},
                        "description":{"type":"text","fields":{"keyword":{"type":"keyword","ignore_above":512}}},
                        "groups":{"type":"keyword"},
                        "mitre":{"properties":{
                            "id":{"type":"keyword"},"tactic":{"type":"keyword"},
                            "technique":{"type":"keyword"}}}}},
                    "data": {"properties":{
                        "srcip":{"type":"ip"},"dstuser":{"type":"keyword"},
                        "url":{"type":"text","fields":{"keyword":{"type":"keyword"}}}}},
                    "location": {"type":"keyword"},
                    "full_log": {"type":"text"},
                    "manager": {"properties":{"name":{"type":"keyword"}}},
                    "cluster": {"properties":{"name":{"type":"keyword"}}},
                }
            }
        }
    }
    http("PUT", f"{OPENSEARCH_URL}/_index_template/security-events", template)
    print("[+] Index template created.")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    random.seed(42)

    # Phase 1: OpenSearch — template + events
    if not wait_for("OpenSearch", OPENSEARCH_URL):
        raise SystemExit(1)

    # Check if already seeded
    try:
        _, info = http("GET", f"{OPENSEARCH_URL}/soc-lab-seed-marker/_doc/seeded")
        if info.get("found"):
            print("[*] Already seeded. Skipping.")
            # Still try to create saved objects in case dashboards wasn't ready last time
            if wait_for("OpenSearch Dashboards", DASHBOARDS_URL, "/api/status", timeout=180):
                try:
                    create_saved_objects()
                except Exception as e:
                    print(f"    WARN: saved objects: {e}")
            return
    except Exception:
        pass

    create_template()

    print("[*] Generating security events dataset ...")
    events = build_events(EVENT_COUNT)
    bulk_index(events)

    # Mark as seeded
    http("PUT", f"{OPENSEARCH_URL}/soc-lab-seed-marker/_doc/seeded",
         {"seeded": True, "count": len(events), "timestamp": datetime.now(timezone.utc).isoformat()})

    # Phase 2: Dashboards — saved objects
    if wait_for("OpenSearch Dashboards", DASHBOARDS_URL, "/api/status", timeout=180):
        try:
            create_saved_objects()
        except Exception as e:
            print(f"[-] Failed to create saved objects: {e}")
            print("    You can still use Discover manually.")

    print("=" * 50)
    print(" Ready! Open Dashboards on port 5601")
    print(" Go to: Security events dashboard")
    print(" Time range: Last 24 hours")
    print("=" * 50)

if __name__ == "__main__":
    main()
