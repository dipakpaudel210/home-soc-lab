# AI-Assisted Alert Triage (`soc_triage.py`)

A small Python tool that pulls recent alerts directly from the Wazuh indexer (OpenSearch) and sends each one to an LLM (Groq, free tier — `llama-3.3-70b-versatile`) for a plain-English summary, a MITRE ATT&CK sanity-check, a severity assessment, and a suggested next step. Output is a timestamped Markdown report.

The goal isn't to replace analyst judgment — it's to speed up the first pass through a noisy alert queue, the same way a junior analyst uses a SIEM's own tagging as a starting point, not a final answer.

## Setup

```bash
pip install requests --break-system-packages

export WAZUH_INDEXER_URL="https://127.0.0.1:9200"   # run on the Wazuh manager itself
export WAZUH_USER="admin"
export WAZUH_PASS="your-indexer-password"
export GROQ_API_KEY="your-groq-key"                 # free at console.groq.com/keys
```

## Usage

```bash
python3 soc_triage.py --minutes 1440 --agent window11 --min-level 5
```

- `--minutes` — how far back to look
- `--agent` — filter to a single Wazuh agent (optional)
- `--min-level` — minimum Wazuh rule severity to include (default 5). This exists because unfiltered "most recent N alerts" gets flooded by routine background noise (service checks, CIS benchmark scans) that crowds out anything actually worth reviewing — filtering by severity at the query level, not just sorting by recency, is what makes the tool usable against a real (noisy) log stream.
- `--limit` — max alerts to triage in one run

## Finding: the AI trusts the SIEM's own tags more than it should

Tested against the SMB enumeration alert from Detection Report #1 (Wazuh rule 92657 — anonymous NTLM logon), the model's "MITRE CHECK" step simply restated Wazuh's own auto-tagged techniques (T1550.002 Pass the Hash, T1021.001 RDP) as correct, rather than catching what a manual review found: the actual technique performed was SMB/network share enumeration (T1046, T1135), not pass-the-hash or RDP.

This happens because the LLM only sees the isolated alert record — it has no access to the actual attacker timeline (what command was run, from where, why). A human analyst who executed or observed the attack has ground-truth context that isolated log review doesn't provide.

**Conclusion:** this tool is useful for fast first-pass triage and for surfacing alerts worth a closer look, but it inherits and can amplify a SIEM's own mis-tagging rather than independently verifying it. It is not a substitute for an analyst correlating an alert against known attacker activity — it's a filter, not a verdict.
