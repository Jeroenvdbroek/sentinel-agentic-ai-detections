# Sentinel detections for agentic AI attack frameworks

Deploy-ready Microsoft Sentinel content for detecting agentic AI attack frameworks
(ARTEX, Cairn, CyberStrikeAI, Hermes, HexStrike, PentAGI, Strix and Agent Zero), built on the
open-source detections published by [ThreatDefence/artex-detections](https://github.com/ThreatDefence/artex-detections).

The upstream repo ships KQL rules and an IOC CSV. This repo adds the plumbing to run them in
Sentinel with little effort:

| Template | What it deploys |
|---|---|
| `azuredeploy-ioc-sync.json` | A Logic App that keeps a Sentinel watchlist in sync with the upstream IOC list every day, its role assignment, and an hourly analytics rule that matches your logs against the watchlist |
| `azuredeploy-analytics-rules.json` | The 20 upstream Sentinel analytics rules as one template, with a switch per rule and per optional log source |

## 1. IOC watchlist sync (`azuredeploy-ioc-sync.json`)

**The Logic App** runs once a day:

1. Asks GitHub for the latest commit that changed `feeds/sentinel-watchlist.csv`. If that commit is
   already recorded in the watchlist description, it stops.
2. Downloads the CSV at exactly that commit and validates it: expected header, a minimum size, and
   under Sentinel's 3.8 MB inline limit. If validation fails, the existing watchlist is left untouched.
3. Deletes the watchlist, waits until the delete has finished, and recreates it with the new content.
   Re-uploading content onto an existing watchlist appends rows instead of replacing them, so
   removed or changed indicators would otherwise stay behind.

The repo is looked up by its permanent numeric GitHub ID (`sourceRepoId`), because Logic Apps don't
follow GitHub's 301 redirects when a repo is renamed or moved.

**The analytics rule** ("Agentic AI attack framework - IOC match") runs hourly against the
medium- and high-confidence indicators: IPs and CIDRs, user agents, domains and file hashes. It can read
`SigninLogs`, `AADServicePrincipalSignInLogs`, `AWSCloudTrail`, `CommonSecurityLog`,
`DeviceNetworkEvents` and `DeviceFileEvents`, and each table has an `include...` switch. Low-confidence
indicators are skipped because they include legitimate AI services.

**Parameters you'll usually set**

| Parameter | Default | Notes |
|---|---|---|
| `workspaceName` | | Sentinel workspace, in the resource group you deploy to |
| `watchlistAlias` | `AGENTIC_IOCs` | The upstream hunting queries expect this alias |
| `syncHourUtc` | `3` | Hour of the daily sync |
| `rulePrefix` | empty | Optional prefix for the rule name, e.g. `CONTOSO - ` |
| `include<Table>` | true, except AWSCloudTrail | Set to false for every table your workspace doesn't have |
| `assignSentinelRole` | true | Grants the Logic App identity *Microsoft Sentinel Contributor* on the workspace. This needs Owner or User Access Administrator |

After deploying, open the Logic App and click **Run** once to fill the watchlist straight away.

## 2. Analytics rules (`azuredeploy-analytics-rules.json`)

All 20 upstream Sentinel rules, converted to ARM:

- **Deployed disabled** (`rulesEnabled` = false). Upstream is experimental and advises baselining every
  rule on your own data before alerting.
- **`rulePrefix`** puts optional text in front of every rule name.
- **`deploy<Rule>`** switches each rule on or off. The two AWS-only rules and the IIS-only rule default
  to off.
- **`source<Table>`** switches optional tables inside union queries. Sentinel refuses to save a rule that
  names a table missing from your workspace, even inside `union isfuzzy=true`, so each optional source
  can be turned off. With every source on, the queries are identical to upstream.
- **MITRE fix:** a technique whose tactic is missing from the rule's tactics is rejected by Sentinel, so
  the build adds the missing tactic. Currently that's one rule: Carbonato, with T1036 and Defense Evasion.

Most rules need `DeviceProcessEvents`. One needs `AuditLogs`.

### Which tables do I have?

```kql
Usage
| where TimeGenerated > ago(30d)
| where DataType in ("SigninLogs", "AADNonInteractiveUserSignInLogs", "AADServicePrincipalSignInLogs",
    "AuditLogs", "AWSCloudTrail", "CommonSecurityLog", "DeviceFileEvents", "DeviceNetworkEvents",
    "DeviceProcessEvents", "DeviceRegistryEvents", "DnsEvents", "MicrosoftGraphActivityLogs", "W3CIISLog")
| distinct DataType
```

## Deploying

In the Azure portal, go to **Deploy a custom template**, then **Build your own template in the editor**,
then **Load file**. Pick the resource group that holds your Sentinel workspace and fill in the
parameters. Redeploying is safe: existing resources are updated in place.

Don't use the portal's **Redeploy** button on a failed deployment after updating a template. It reuses
the old template.

## Rebuilding from upstream

The analytics rules template is a snapshot. Rules don't update themselves, and some of them carry
indicators inside the query. To pick up upstream changes:

```bash
git clone https://github.com/ThreatDefence/artex-detections.git upstream
pip install pyyaml
python tools/build_analytics_rules.py upstream azuredeploy-analytics-rules.json
python tools/build_ioc_sync.py azuredeploy-ioc-sync.json
```

If upstream adds a MITRE technique the script doesn't know yet, it stops and tells you which one to add.

## Things to know

- **Short gap during updates.** While the watchlist is being replaced (a few minutes), it's empty.
  Schedule the sync at a quiet hour.
- **You're trusting upstream.** Whatever lands in the upstream CSV reaches your watchlist the next day.
  The worst case is noise, not damage. If you'd rather review changes first, point `sourceRepoId` at
  your own fork.
- **IP addresses get reassigned.** Check an indicator's `reported` and `review_by` dates before acting
  on a match.
- **No entity mappings.** The upstream rules don't ship them, so incidents won't link users or hosts
  automatically.
- **Testing so far.** The templates have been deployed and run in a real Sentinel workspace.
  The detections themselves come from upstream, which describes them as tested against a synthetic pcap,
  not a real intrusion.

## Credits and license

The detection logic and indicators are by [ThreatDefence](https://github.com/ThreatDefence/artex-detections),
under the MIT license. The deployment templates and build scripts in this repo are also MIT; see
[LICENSE](LICENSE).
