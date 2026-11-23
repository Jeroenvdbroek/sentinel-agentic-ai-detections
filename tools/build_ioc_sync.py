"""Generates azuredeploy-ioc-sync.json (usage: python build_ioc_sync.py [output.json]): a Logic App that keeps a Sentinel watchlist in sync
with ThreatDefence/artex-detections feeds/sentinel-watchlist.csv, plus an optional
scheduled analytics rule that alerts on watchlist matches."""
import json
import sys

API = "2024-03-01"
MSI = {"type": "ManagedServiceIdentity", "audience": "https://management.azure.com/"}
RETRY = {"type": "exponential", "count": 4, "interval": "PT30S"}
STATUS = "outputs('Get_existing_watchlist')['statusCode']"

actions = {
    "Init_WatchlistUrl": {
        "type": "InitializeVariable", "runAfter": {},
        "inputs": {"variables": [{"name": "WatchlistUrl", "type": "string",
            "value": "https://management.azure.com/subscriptions/@{parameters('subscriptionId')}/resourceGroups/@{parameters('resourceGroup')}/providers/Microsoft.OperationalInsights/workspaces/@{parameters('workspace')}/providers/Microsoft.SecurityInsights/watchlists/@{parameters('alias')}?api-version=" + API}]},
    },
    "Get_latest_commit": {
        "type": "Http", "runAfter": {"Init_WatchlistUrl": ["Succeeded"]},
        "inputs": {"method": "GET",
            "uri": "https://api.github.com/repositories/@{parameters('repoId')}/commits?sha=@{parameters('branch')}&path=feeds/sentinel-watchlist.csv&per_page=1",
            "headers": {"User-Agent": "sentinel-agentic-ioc-sync", "Accept": "application/vnd.github+json"},
            "retryPolicy": RETRY},
    },
    "Init_CommitSha": {
        "type": "InitializeVariable", "runAfter": {"Get_latest_commit": ["Succeeded"]},
        "inputs": {"variables": [{"name": "CommitSha", "type": "string",
            "value": "@{body('Get_latest_commit')[0]['sha']}"}]},
    },
    "Get_existing_watchlist": {
        "type": "Http", "runAfter": {"Init_CommitSha": ["Succeeded"]},
        "inputs": {"method": "GET", "uri": "@variables('WatchlistUrl')", "authentication": MSI},
    },
    # 404 = first run, fine. Anything else (403 = missing role) stops the run before it deletes anything.
    "Stop_if_lookup_failed": {
        "type": "If", "runAfter": {"Get_existing_watchlist": ["Succeeded", "Failed"]},
        "expression": {"and": [{"not": {"equals": [f"@{STATUS}", 200]}},
                               {"not": {"equals": [f"@{STATUS}", 404]}}]},
        "actions": {"Terminate_lookup_failed": {"type": "Terminate", "runAfter": {},
            "inputs": {"runStatus": "Failed", "runError": {"code": f"@{{string({STATUS})}}",
                "message": "Could not read the watchlist. Check the Logic App identity has Microsoft Sentinel Contributor on the workspace."}}}},
        "else": {"actions": {}},
    },
    # The commit SHA is stored in the watchlist description, so unchanged upstream = no-op.
    "Skip_if_already_current": {
        "type": "If", "runAfter": {"Stop_if_lookup_failed": ["Succeeded"]},
        "expression": {"and": [{"equals": [f"@{STATUS}", 200]},
            {"contains": ["@coalesce(body('Get_existing_watchlist')?['properties']?['description'], '')", "@variables('CommitSha')"]}]},
        "actions": {"Terminate_no_change": {"type": "Terminate", "runAfter": {}, "inputs": {"runStatus": "Succeeded"}}},
        "else": {"actions": {}},
    },
    # Pinned to the exact commit so the content matches the SHA recorded in the description.
    "Download_CSV": {
        "type": "Http", "runAfter": {"Skip_if_already_current": ["Succeeded"]},
        "inputs": {"method": "GET",
            "uri": "https://api.github.com/repositories/@{parameters('repoId')}/contents/feeds/sentinel-watchlist.csv?ref=@{variables('CommitSha')}",
            "headers": {"User-Agent": "sentinel-agentic-ioc-sync", "Accept": "application/vnd.github+json"},
            "retryPolicy": RETRY},
    },
    "Init_Csv": {
        "type": "InitializeVariable", "runAfter": {"Download_CSV": ["Succeeded"]},
        "inputs": {"variables": [{"name": "Csv", "type": "string",
            "value": "@{base64ToString(replace(coalesce(body('Download_CSV')?['content'], ''), decodeUriComponent('%0A'), ''))}"}]},
    },
    # Sanity checks before the old watchlist is deleted: expected header, plausible size, under the 3.8 MB rawContent limit.
    "Stop_if_CSV_invalid": {
        "type": "If", "runAfter": {"Init_Csv": ["Succeeded"]},
        "expression": {"or": [
            {"not": {"startsWith": ["@variables('Csv')", "value,type,confidence,"]}},
            {"less": ["@length(variables('Csv'))", "@parameters('minCsvBytes')"]},
            {"greater": ["@length(variables('Csv'))", 3800000]}]},
        "actions": {"Terminate_bad_csv": {"type": "Terminate", "runAfter": {},
            "inputs": {"runStatus": "Failed", "runError": {"code": "InvalidCsv",
                "message": "Downloaded CSV failed validation (header, minimum size or 3.8 MB limit). Existing watchlist left untouched."}}}},
        "else": {"actions": {}},
    },
    # Re-PUTting rawContent onto an existing watchlist appends rows instead of replacing them,
    # so stale or changed indicators would linger. Delete and recreate for a clean replace.
    "Remove_old_version": {
        "type": "If", "runAfter": {"Stop_if_CSV_invalid": ["Succeeded"]},
        "expression": {"and": [{"equals": [f"@{STATUS}", 200]}]},
        "actions": {
            "Delete_watchlist": {"type": "Http", "runAfter": {},
                "inputs": {"method": "DELETE", "uri": "@variables('WatchlistUrl')", "authentication": MSI, "retryPolicy": RETRY}},
            "Wait_until_deleted": {
                "type": "Until", "runAfter": {"Delete_watchlist": ["Succeeded"]},
                "expression": "@equals(outputs('Deleted_status'), 404)",
                "limit": {"count": 40, "timeout": "PT20M"},
                "actions": {
                    "Delay_30s": {"type": "Wait", "runAfter": {}, "inputs": {"interval": {"count": 30, "unit": "Second"}}},
                    "Check_deleted": {"type": "Http", "runAfter": {"Delay_30s": ["Succeeded"]},
                        "inputs": {"method": "GET", "uri": "@variables('WatchlistUrl')", "authentication": MSI}},
                    # Runs on success or failure so the expected 404 doesn't fail the loop.
                    "Deleted_status": {"type": "Compose", "runAfter": {"Check_deleted": ["Succeeded", "Failed"]},
                        "inputs": "@outputs('Check_deleted')['statusCode']"},
                },
            },
            "Fail_if_delete_timed_out": {
                "type": "If", "runAfter": {"Wait_until_deleted": ["Succeeded", "Failed", "TimedOut"]},
                "expression": {"and": [{"not": {"equals": ["@outputs('Deleted_status')", 404]}}]},
                "actions": {"Terminate_delete_timeout": {"type": "Terminate", "runAfter": {},
                    "inputs": {"runStatus": "Failed", "runError": {"code": "DeleteTimeout", "message": "Watchlist was not deleted within 20 minutes."}}}},
                "else": {"actions": {}},
            },
            "Settle_60s": {"type": "Wait", "runAfter": {"Fail_if_delete_timed_out": ["Succeeded"]},
                "inputs": {"interval": {"count": 60, "unit": "Second"}}},
        },
        "else": {"actions": {}},
    },
    "Create_watchlist": {
        "type": "Http", "runAfter": {"Remove_old_version": ["Succeeded"]},
        "inputs": {"method": "PUT", "uri": "@variables('WatchlistUrl')", "authentication": MSI, "retryPolicy": RETRY,
            "headers": {"Content-Type": "application/json"},
            "body": {"properties": {
                "displayName": "@parameters('displayName')",
                "provider": "ThreatDefence",
                "source": "sentinel-watchlist.csv",
                "sourceType": "Local",
                "itemsSearchKey": "value",
                "contentType": "text/csv",
                "numberOfLinesToSkip": 0,
                "rawContent": "@variables('Csv')",
                "description": "Synced from github.com/@{parameters('repo')} commit @{variables('CommitSha')} at @{utcNow()}",
            }}},
    },
}

wf_params = {k: {"type": t, "defaultValue": d} for k, t, d in [
    ("subscriptionId", "String", ""), ("resourceGroup", "String", ""), ("workspace", "String", ""),
    ("alias", "String", ""), ("displayName", "String", ""), ("repoId", "String", ""), ("repo", "String", ""), ("branch", "String", ""), ("minCsvBytes", "Int", 0)]}

definition = {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "parameters": wf_params,
    "triggers": {"Daily": {"type": "Recurrence", "recurrence": {
        "frequency": "Day", "interval": 1, "timeZone": "UTC",
        "schedule": {"hours": ["[parameters('syncHourUtc')]"], "minutes": [17]}}}},
    "actions": actions,
    "outputs": {},
}

# Scheduled rule: same logic as the repo's watchlist sweep hunt, but across all frameworks,
# medium/high confidence only, 1h window, on Sentinel's TimeGenerated.
KQL_HEAD = r"""let IOC = _GetWatchlist('__ALIAS__')
    | where confidence in ("high", "medium")
    | project value = tostring(SearchKey), type, confidence, framework, actor, source;
let IPList = toscalar(IOC | where type == "ipv4" | summarize make_list(value));
let UAs = toscalar(IOC | where type == "user_agent" | summarize make_list(value));
let Domains = toscalar(IOC | where type == "domain" | summarize make_list(value));
let Hashes = toscalar(IOC | where type in ("sha256", "md5") | summarize make_list(value));
union isfuzzy=true
    (datatable(TimeGenerated: datetime, Table: string, Account: string, IP: string, UA: string, Host: string)[])"""

# Sentinel rejects a rule that names a table missing from the workspace, even inside
# union isfuzzy, so each table is a separate leg switched on by a template parameter.
LEGS = [
    ("SigninLogs", "includeSigninLogs", r""",
    (SigninLogs
        | where ipv4_is_in_any_range(IPAddress, IPList) or UserAgent has_any (UAs)
        | extend Table = "SigninLogs", Account = UserPrincipalName, IP = IPAddress, UA = UserAgent, Host = "")"""),
    ("AADServicePrincipalSignInLogs", "includeAADServicePrincipalSignInLogs", r""",
    (AADServicePrincipalSignInLogs
        | where ipv4_is_in_any_range(IPAddress, IPList)
        | extend Table = "AADServicePrincipalSignInLogs", Account = ServicePrincipalName, IP = IPAddress, UA = "", Host = "")"""),
    ("AWSCloudTrail", "includeAWSCloudTrail", r""",
    (AWSCloudTrail
        | where ipv4_is_in_any_range(SourceIpAddress, IPList) or UserAgent has_any (UAs)
        | extend Table = "AWSCloudTrail", Account = UserIdentityArn, IP = SourceIpAddress, UA = UserAgent, Host = "")"""),
    ("CommonSecurityLog", "includeCommonSecurityLog", r""",
    (CommonSecurityLog
        | where ipv4_is_in_any_range(SourceIP, IPList) or ipv4_is_in_any_range(DestinationIP, IPList)
            or RequestClientApplication has_any (UAs) or DestinationHostName in~ (Domains)
        | extend Table = "CommonSecurityLog", Account = SourceUserName, IP = iff(ipv4_is_in_any_range(DestinationIP, IPList), DestinationIP, SourceIP),
            UA = RequestClientApplication, Host = DestinationHostName)"""),
    ("DeviceNetworkEvents", "includeDeviceNetworkEvents", r""",
    (DeviceNetworkEvents
        | where ipv4_is_in_any_range(RemoteIP, IPList) or RemoteUrl has_any (Domains)
        | extend Table = "DeviceNetworkEvents", Account = InitiatingProcessAccountName, IP = RemoteIP, UA = "", Host = DeviceName)"""),
    ("DeviceFileEvents", "includeDeviceFileEvents", r""",
    (DeviceFileEvents
        | where SHA256 in~ (Hashes) or MD5 in~ (Hashes)
        | extend Table = "DeviceFileEvents", Account = InitiatingProcessAccountName, IP = "", UA = "", Host = DeviceName)"""),
]

KQL_TAIL = r"""
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Events = count()
    by Table, Account = tostring(Account), IP = tostring(IP), UA = tostring(UA), Host = tostring(Host)"""

template = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "metadata": {"description": "Daily sync of the ThreatDefence agentic-framework IOC watchlist into Microsoft Sentinel, plus an optional IOC-match analytics rule."},
    "parameters": {
        "workspaceName": {"type": "string", "metadata": {"description": "Sentinel Log Analytics workspace. Must be in the resource group you deploy to."}},
        "logicAppName": {"type": "string", "defaultValue": "Sync-AgenticAI-IOC-Watchlist"},
        "watchlistAlias": {"type": "string", "defaultValue": "AGENTIC_IOCs",
            "metadata": {"description": "Name used in KQL (_GetWatchlist). The repo's hunting queries expect AGENTIC_IOCs, so only change it if you also edit those."}},
        "watchlistDisplayName": {"type": "string", "defaultValue": "Agentic AI Attack Frameworks - IOCs"},
        "sourceRepo": {"type": "string", "defaultValue": "ThreatDefence/artex-detections", "metadata": {"description": "Label only, written into the watchlist description."}},
        "sourceRepoId": {"type": "string", "defaultValue": "1464795219", "metadata": {"description": "GitHub's permanent numeric ID for the repo; keeps working if it is renamed or moved."}},
        "sourceBranch": {"type": "string", "defaultValue": "main"},
        "syncHourUtc": {"type": "int", "defaultValue": 3, "minValue": 0, "maxValue": 23},
        "minCsvBytes": {"type": "int", "defaultValue": 20000,
            "metadata": {"description": "Refuse to replace the watchlist if the download is smaller than this (truncated or emptied upstream file)."}},
        "assignSentinelRole": {"type": "bool", "defaultValue": True,
            "metadata": {"description": "Grant the Logic App identity Microsoft Sentinel Contributor on the workspace. Needs Owner or User Access Administrator."}},
        "deployAnalyticsRule": {"type": "bool", "defaultValue": True},
        "rulePrefix": {"type": "string", "defaultValue": "",
            "metadata": {"description": "Optional text put in front of the analytics rule name, e.g. 'CONTOSO - '."}},
        **{p: {"type": "bool", "defaultValue": True, "metadata": {"description": f"Include the {t} table in the analytics rule. Set to false if the table does not exist in your workspace."}} for t, p, _ in LEGS},
        "includeAWSCloudTrail": {"type": "bool", "defaultValue": False, "metadata": {"description": "Include the AWSCloudTrail table in the analytics rule. Set to false if the table does not exist in your workspace."}},
        "analyticsRuleEnabled": {"type": "bool", "defaultValue": True},
    },
    "variables": {
        "sentinelContributor": "ab8e14d6-4a74-4a29-9ba8-549422addade",
        "qHead": KQL_HEAD, "qTail": KQL_TAIL,
        **{f"q{t}": leg for t, _, leg in LEGS},
        "ruleId": "[guid(resourceGroup().id, parameters('workspaceName'), 'agentic-ioc-watchlist-match')]",
    },
    "resources": [
        {
            "type": "Microsoft.Logic/workflows", "apiVersion": "2019-05-01",
            "name": "[parameters('logicAppName')]", "location": "[resourceGroup().location]",
            "identity": {"type": "SystemAssigned"},
            "properties": {
                "state": "Enabled",
                "definition": definition,
                "parameters": {
                    "subscriptionId": {"value": "[subscription().subscriptionId]"},
                    "resourceGroup": {"value": "[resourceGroup().name]"},
                    "workspace": {"value": "[parameters('workspaceName')]"},
                    "alias": {"value": "[parameters('watchlistAlias')]"},
                    "displayName": {"value": "[parameters('watchlistDisplayName')]"},
                    "repo": {"value": "[parameters('sourceRepo')]"},
                    "repoId": {"value": "[parameters('sourceRepoId')]"},
                    "branch": {"value": "[parameters('sourceBranch')]"},
                    "minCsvBytes": {"value": "[parameters('minCsvBytes')]"},
                },
            },
        },
        {
            "condition": "[parameters('assignSentinelRole')]",
            "type": "Microsoft.Authorization/roleAssignments", "apiVersion": "2022-04-01",
            "scope": "[format('Microsoft.OperationalInsights/workspaces/{0}', parameters('workspaceName'))]",
            "name": "[guid(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName')), resourceId('Microsoft.Logic/workflows', parameters('logicAppName')), variables('sentinelContributor'))]",
            "dependsOn": ["[resourceId('Microsoft.Logic/workflows', parameters('logicAppName'))]"],
            "properties": {
                "roleDefinitionId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', variables('sentinelContributor'))]",
                "principalId": "[reference(resourceId('Microsoft.Logic/workflows', parameters('logicAppName')), '2019-05-01', 'full').identity.principalId]",
                "principalType": "ServicePrincipal",
            },
        },
        {
            "condition": "[parameters('deployAnalyticsRule')]",
            "type": "Microsoft.SecurityInsights/alertRules", "apiVersion": API, "kind": "Scheduled",
            "scope": "[format('Microsoft.OperationalInsights/workspaces/{0}', parameters('workspaceName'))]",
            "name": "[variables('ruleId')]",
            "properties": {
                "displayName": "[concat(parameters('rulePrefix'), 'Agentic AI attack framework - IOC match')]",
                "description": "Matches sign-in, cloud, proxy/firewall and endpoint telemetry against the medium/high-confidence indicators in the ThreatDefence agentic-framework watchlist (ARTEX, CyberStrikeAI, Hermes, Cairn, PentAGI, HexStrike, Strix, Agent Zero). The watchlist is refreshed daily by a Logic App. IP addresses get reassigned: check the indicator's reported and review_by dates before acting.",
                "severity": "Medium",
                "enabled": "[parameters('analyticsRuleEnabled')]",
                "query": "[replace(concat(variables('qHead'), " + ", ".join(f"if(parameters('{p}'), variables('q{t}'), '')" for t, p, _ in LEGS) + ", variables('qTail')), '__ALIAS__', parameters('watchlistAlias'))]",
                "queryFrequency": "PT1H", "queryPeriod": "PT1H",
                "triggerOperator": "GreaterThan", "triggerThreshold": 0,
                "suppressionEnabled": False, "suppressionDuration": "PT5H",
                "tactics": ["InitialAccess", "CredentialAccess", "CommandAndControl"],
                "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
                "alertDetailsOverride": {
                    "alertDisplayNameFormat": "Agentic AI attack framework IOC match in {{Table}}",
                    "alertDescriptionFormat": "Indicator match for account {{Account}} / IP {{IP}} in {{Table}}.",
                },
                "entityMappings": [
                    {"entityType": "Account", "fieldMappings": [{"identifier": "Name", "columnName": "Account"}]},
                    {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "IP"}]},
                    {"entityType": "Host", "fieldMappings": [{"identifier": "HostName", "columnName": "Host"}]},
                ],
                "incidentConfiguration": {"createIncident": True, "groupingConfiguration": {
                    "enabled": True, "reopenClosedIncident": False, "lookbackDuration": "PT24H",
                    "matchingMethod": "AnyAlert", "groupByEntities": [], "groupByAlertDetails": [], "groupByCustomDetails": []}},
            },
        },
    ],
    "outputs": {
        "logicAppPrincipalId": {"type": "string",
            "value": "[reference(resourceId('Microsoft.Logic/workflows', parameters('logicAppName')), '2019-05-01', 'full').identity.principalId]"},
    },
}

s = json.dumps(template, indent=2)
out = sys.argv[1] if len(sys.argv) > 1 else "azuredeploy-ioc-sync.json"
open(out, "w").write(s + "\n")
print("wrote", out)
