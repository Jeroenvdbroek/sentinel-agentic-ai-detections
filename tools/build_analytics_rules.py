"""Builds an ARM template from the ThreatDefence Sentinel analytics rules
(usage: python build_analytics_rules.py <path-to-artex-detections-clone> [output.json]).

Rules are deployed disabled, with an optional name prefix, a deploy switch per rule and a
switch per optional table inside union queries (Sentinel refuses to save a rule that names a
table missing from the workspace, even inside union isfuzzy=true)."""
import glob, json, re, sys, yaml

REPO = sys.argv[1]
OUT = sys.argv[2] if len(sys.argv) > 2 else "azuredeploy-analytics-rules.json"

DEFAULT_OFF = {  # rules that only read tables many workspaces don't have; deploy switch defaults to false
    "artex-cloudwatch-secret-search.yaml": "AWSCloudTrail",
    "artex-ec2-dryrun-burst.yaml": "AWSCloudTrail",
    "config-backup-file-served.yaml": "W3CIISLog",
}
# Optional union sources: (default, description). Verified present tables are never toggled.
OPTIONAL = {
    "AADNonInteractiveUserSignInLogs": True,
    "DeviceRegistryEvents": True,
    "DnsEvents": False,
    "MicrosoftGraphActivityLogs": False,
    "W3CIISLog": False,
    "AWSCloudTrail": False,
}


# MITRE ATT&CK Enterprise: technique -> tactics (first = the one added if none listed)
MITRE = {
    "T1036": ["DefenseEvasion"], "T1041": ["Exfiltration"], "T1046": ["Discovery"],
    "T1053": ["Execution", "Persistence", "PrivilegeEscalation"], "T1059": ["Execution"],
    "T1071": ["CommandAndControl"], "T1078": ["InitialAccess", "DefenseEvasion", "Persistence", "PrivilegeEscalation"],
    "T1098": ["Persistence", "PrivilegeEscalation"], "T1110": ["CredentialAccess"],
    "T1190": ["InitialAccess"], "T1219": ["CommandAndControl"], "T1505": ["Persistence"],
    "T1543": ["Persistence", "PrivilegeEscalation"], "T1546": ["Persistence", "PrivilegeEscalation"],
    "T1547": ["Persistence", "PrivilegeEscalation"], "T1562": ["DefenseEvasion"],
    "T1213": ["Collection"], "T1552": ["CredentialAccess"], "T1580": ["Discovery"],
    "T1592": ["Reconnaissance"], "T1595": ["Reconnaissance"], "T1611": ["PrivilegeEscalation"],
}
FIXES = []


def iso(d):
    n, u = int(d[:-1]), d[-1]
    return {"m": f"PT{n}M", "h": f"PT{n}H", "d": f"P{n}D"}[u]


def scan_legs(q, start):
    """From the text after 'union isfuzzy=true', return [(begin, end, table)] for each
    top-level '( ... )' leg, honouring KQL string literals, and the index where the legs end."""
    legs, i, n = [], start, len(q)
    while True:
        while i < n and q[i] in " \t\r\n,":
            i += 1
        if i >= n or q[i] != "(":
            return legs, i
        b, depth = i, 0
        while i < n:
            c = q[i]
            if c == "@" and i + 1 < n and q[i + 1] in "'\"":  # verbatim string
                qc = q[i + 1]; i += 2
                while i < n:
                    if q[i] == qc and i + 1 < n and q[i + 1] == qc: i += 2; continue
                    if q[i] == qc: break
                    i += 1
            elif c in "'\"":
                qc = c; i += 1
                while i < n and q[i] != qc:
                    i += 2 if q[i] == "\\" else 1
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    i += 1; break
            i += 1
        table = re.match(r"\(\s*([A-Za-z0-9_]+)", q[b:]).group(1)
        legs.append((b, i, table))


def split_query(q):
    """Return list of (text, table_or_None). Optional-table legs become separately switchable parts."""
    m = re.search(r"union isfuzzy=true\s*\n", q)
    if not m:
        # simple form: "union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs"
        m2 = re.search(r"union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs", q)
        if m2:
            a = q[: m2.start()] + "union isfuzzy=true SigninLogs"
            return [(a, None), (", AADNonInteractiveUserSignInLogs", "AADNonInteractiveUserSignInLogs"), (q[m2.end():], None)]
        return [(q, None)]
    legs, end = scan_legs(q, m.end())
    parts, pos = [], 0
    first_done = False
    for b, e, t in legs:
        if t in OPTIONAL:
            assert first_done, f"first union leg is optional table {t}"
            parts.append((q[pos:b].rstrip().rstrip(","), None))  # drop the separator before this leg
            parts.append((",\n    " + q[b:e], t))
            pos = e
        else:
            if first_done:
                parts.append((q[pos:b].rstrip().rstrip(",") + ",\n    ", None))
                pos = b
            first_done = True
    parts.append((q[pos:], None))
    return [(t, tb) for t, tb in parts if t or tb]


def arm_escape(v):
    if isinstance(v, str):
        return "[" + v if v.startswith("[") else v
    if isinstance(v, list):
        return [arm_escape(x) for x in v]
    if isinstance(v, dict):
        return {k: arm_escape(x) for k, x in v.items()}
    return v


files = sorted(glob.glob(f"{REPO}/frameworks/*/sentinel/analytics/*.yaml") + glob.glob(f"{REPO}/behaviors/sentinel/analytics/*.yaml"))
params = {
    "workspaceName": {"type": "string", "metadata": {"description": "Sentinel Log Analytics workspace (in the resource group you deploy to)."}},
    "rulePrefix": {"type": "string", "defaultValue": "",
        "metadata": {"description": "Optional text put in front of every rule name, e.g. 'CONTOSO - '."}},
    "rulesEnabled": {"type": "bool", "defaultValue": False,
        "metadata": {"description": "Deploy the rules switched on. Default off: baseline them on your own data first, as ThreatDefence advises."}},
}
for t, d in OPTIONAL.items():
    params[f"source{t}"] = {"type": "bool", "defaultValue": d,
        "metadata": {"description": f"Rules also read {t} where they support it. Set to true only if this table exists in your workspace."}}

variables, resources, summary = {}, [], []
for f in files:
    base = f.split("/analytics/")[1]
    fw = f.split("/frameworks/")[1].split("/")[0] if "/frameworks/" in f else "behaviors"
    d = yaml.safe_load(open(f))
    key = re.sub(r"[^A-Za-z0-9]", "", base[:-5].title())
    parts = split_query(d["query"])
    pieces = []
    for i, (text, table) in enumerate(parts):
        vn = f"q_{key}_{i}"
        variables[vn] = text
        pieces.append(f"if(parameters('source{table}'), variables('{vn}'), '')" if table else f"variables('{vn}')")
    query_expr = "[concat(" + ", ".join(pieces) + ")]" if len(pieces) > 1 else f"[variables('q_{key}_0')]"
    dp = f"deploy{key}"
    params[dp] = {"type": "bool", "defaultValue": base not in DEFAULT_OFF,
        "metadata": {"description": f"Deploy: {d['name']}" + (f" (needs {DEFAULT_OFF[base]})" if base in DEFAULT_OFF else "")}}

    tech = d.get("relevantTechniques") or []
    tactics = list(d.get("tactics", []))
    for t in sorted({x.split(".")[0] for x in tech}):  # Sentinel rejects a technique whose tactic isn't listed
        if t not in MITRE:
            sys.exit(f"{base}: technique {t} missing from the MITRE table in this script; add it with its tactics")
        if not set(MITRE[t]) & set(tactics):
            tactics.append(MITRE[t][0]); FIXES.append((d["name"], t, MITRE[t][0]))
    props = {
        "displayName": d["name"],
        "description": d.get("description", "").strip() + "\n\nSource: ThreatDefence/artex-detections (" + base + ").",
        "severity": d["severity"],
        "queryFrequency": iso(d["queryFrequency"]),
        "queryPeriod": iso(d["queryPeriod"]),
        "triggerOperator": {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal"}[d.get("triggerOperator", "gt")],
        "triggerThreshold": d.get("triggerThreshold", 0),
        "suppressionEnabled": False, "suppressionDuration": "PT5H",
        "tactics": tactics,
        "techniques": sorted({t.split(".")[0] for t in tech}),
        "subTechniques": sorted({t for t in tech if "." in t}),
        "entityMappings": d.get("entityMappings"),
        "customDetails": d.get("customDetails"),
        "alertDetailsOverride": d.get("alertDetailsOverride"),
        "eventGroupingSettings": d.get("eventGroupingSettings") or {"aggregationKind": "SingleAlert"},
        "incidentConfiguration": {"createIncident": True, "groupingConfiguration": {
            "enabled": False, "reopenClosedIncident": False, "lookbackDuration": "PT5H",
            "matchingMethod": "AllEntities", "groupByEntities": [], "groupByAlertDetails": [], "groupByCustomDetails": []}},
    }
    if d.get("alertDetailsOverride", {}) and d["alertDetailsOverride"].get("alertDisplayNameFormat"):
        props["alertDetailsOverride"] = dict(d["alertDetailsOverride"])
    props = {k: v for k, v in props.items() if v not in (None, [], {})}
    props = arm_escape(props)
    props["query"] = query_expr
    props["enabled"] = "[parameters('rulesEnabled')]"
    props["displayName"] = "[concat(parameters('rulePrefix'), variables('n_%s'))]" % key
    variables["n_" + key] = arm_escape(d["name"])
    resources.append({
        "condition": f"[parameters('{dp}')]",
        "type": "Microsoft.SecurityInsights/alertRules", "apiVersion": "2024-03-01", "kind": "Scheduled",
        "scope": "[format('Microsoft.OperationalInsights/workspaces/{0}', parameters('workspaceName'))]",
        "name": d["id"],
        "properties": props,
    })
    opt = sorted({t for _, t in parts if t})
    summary.append(("RULE", fw, d["name"], ", ".join(opt)))

for v in variables:  # variable values are literals; protect any that happen to start with '['
    variables[v] = arm_escape(variables[v])
tpl = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "metadata": {"description": "The ThreatDefence agentic AI attack framework analytics rules for Microsoft Sentinel / Defender."},
    "parameters": params, "variables": variables, "resources": resources,
}
json.dump(tpl, open(OUT, "w"), indent=2)
for s in summary: print(" | ".join(s))
print(len(resources), "rules; tactic fixes:", FIXES, "->", OUT)
