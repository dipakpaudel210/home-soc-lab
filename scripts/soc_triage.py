#!/usr/bin/env python3
"""
soc_triage.py — AI-assisted alert triage for a Wazuh home SOC lab.

Pulls recent alerts directly from the Wazuh indexer (OpenSearch) REST API
and sends each one to an LLM (Groq, free tier) for a plain-English
triage summary, a sanity-check of the auto-tagged MITRE ATT&CK mapping, a
severity assessment, and a recommended next step for an analyst.

Setup:
    Get a free API key at https://console.groq.com/keys (no credit card needed)

    export WAZUH_INDEXER_URL="https://192.168.50.10:9200"
    export WAZUH_USER="admin"
    export WAZUH_PASS="your-indexer-password"
    export GROQ_API_KEY="your-groq-api-key"

    python3 soc_triage.py --minutes 60 --agent window11

Output: a timestamped Markdown report in ./triage_reports/
"""

import argparse
import json
import os
import sys
import time
import urllib3
from datetime import datetime

import requests

# The Wazuh indexer uses a self-signed cert by default (from the install script),
# so we disable the verification warning rather than failing every request.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GROQ_MODEL = "llama-3.3-70b-versatile"  # generous free tier, strong quality for short triage summaries
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def get_env(name, required=True):
    val = os.environ.get(name)
    if required and not val:
        print(f"ERROR: environment variable {name} is not set. See the script header for setup.")
        sys.exit(1)
    return val


def fetch_alerts(indexer_url, user, password, minutes, agent_name=None, size=20, min_level=5):
    """Query the Wazuh indexer's OpenSearch API for recent alerts, filtered by
    minimum severity so routine low-level noise (service checks, benchmark scans,
    etc.) doesn't crowd out the alerts actually worth an analyst's attention."""
    query = {
        "size": size,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"timestamp": {"gte": f"now-{minutes}m"}}},
                    {"range": {"rule.level": {"gte": min_level}}},
                ]
            }
        },
    }
    if agent_name:
        query["query"]["bool"]["filter"].append({"term": {"agent.name": agent_name}})

    resp = requests.post(
        f"{indexer_url}/wazuh-alerts-*/_search",
        json=query,
        auth=(user, password),
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    hits = resp.json().get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]


def summarize_alert(api_key, alert):
    """Ask the LLM (Groq) to triage a single alert."""
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    context = {
        "timestamp": alert.get("timestamp"),
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "rule_description": rule.get("description"),
        "rule_level": rule.get("level"),
        "rule_id": rule.get("id"),
        "rule_groups": rule.get("groups"),
        "mitre_id": rule.get("mitre", {}).get("id"),
        "mitre_tactic": rule.get("mitre", {}).get("tactic"),
        "mitre_technique": rule.get("mitre", {}).get("technique"),
        "source_ip": alert.get("data", {}).get("win", {}).get("eventdata", {}).get("ipAddress")
                     or alert.get("data", {}).get("srcip"),
        "full_log": (alert.get("full_log") or "")[:1200],  # cap length to keep prompts small/cheap
    }

    prompt = f"""You are assisting a SOC analyst by triaging one Wazuh SIEM alert. Here is the alert data:

{json.dumps(context, indent=2, default=str)}

Respond in this exact structure, plain text, no markdown headers:

SUMMARY: One or two sentences, plain English, what happened.
MITRE CHECK: State whether the alert's own MITRE tag (if present) actually matches what the raw log shows happened. If it's wrong or missing, give the correct ATT&CK technique ID and name.
SEVERITY: Low, Medium, or High, with a one-sentence reason based on the actual data (not just the rule's default level).
NEXT STEP: One concrete action a SOC analyst should take next.
"""

    resp = requests.post(
        GROQ_URL,
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": GROQ_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 400,
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def main():
    parser = argparse.ArgumentParser(description="AI-assisted Wazuh alert triage")
    parser.add_argument("--minutes", type=int, default=60, help="How far back to look for alerts")
    parser.add_argument("--agent", type=str, default=None, help="Filter to a single agent name")
    parser.add_argument("--limit", type=int, default=10, help="Max number of alerts to triage")
    parser.add_argument("--min-level", type=int, default=5, help="Minimum Wazuh rule level to include (filters out routine noise)")
    args = parser.parse_args()

    indexer_url = get_env("WAZUH_INDEXER_URL")
    user = get_env("WAZUH_USER")
    password = get_env("WAZUH_PASS")
    api_key = get_env("GROQ_API_KEY")

    print(f"Fetching alerts from the last {args.minutes} minute(s)"
          + (f" for agent '{args.agent}'" if args.agent else "")
          + f" at level >= {args.min_level}...")
    alerts = fetch_alerts(indexer_url, user, password, args.minutes, args.agent,
                           size=args.limit, min_level=args.min_level)

    if not alerts:
        print("No alerts found in that window.")
        return

    print(f"Found {len(alerts)} alert(s). Sending each to the LLM for triage...\n")

    os.makedirs("triage_reports", exist_ok=True)
    report_path = f"triage_reports/triage_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

    with open(report_path, "w") as f:
        f.write(f"# AI Triage Report — {datetime.now().isoformat()}\n\n")
        f.write(f"Window: last {args.minutes} minute(s)"
                + (f" | Agent: {args.agent}" if args.agent else "") + "\n\n")

        for i, alert in enumerate(alerts, 1):
            rule = alert.get("rule", {})
            print(f"[{i}/{len(alerts)}] Rule {rule.get('id')} — {rule.get('description', '')[:60]}...")

            try:
                triage = summarize_alert(api_key, alert)
            except Exception as e:
                triage = f"(LLM call failed: {e})"

            time.sleep(4)  # stay well under free-tier per-minute rate limits

            f.write(f"## Alert {i}: {rule.get('description', 'Unknown')}\n\n")
            f.write(f"- **Timestamp**: {alert.get('timestamp')}\n")
            f.write(f"- **Agent**: {alert.get('agent', {}).get('name')}\n")
            f.write(f"- **Wazuh Rule**: {rule.get('id')} (level {rule.get('level')})\n\n")
            f.write("**AI Triage:**\n\n")
            f.write(triage.strip() + "\n\n")
            f.write("---\n\n")

    print(f"\nDone. Report saved to: {report_path}")


if __name__ == "__main__":
    main()
