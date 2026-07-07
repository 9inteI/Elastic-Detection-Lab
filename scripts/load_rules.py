#!/usr/bin/env python3
"""Import the detection rules in detections/ into Kibana Security.

Bundles every detections/*.json rule into a single NDJSON payload and posts
it to Kibana's detection-engine import API (overwriting existing copies, so
the script is idempotent).

Usage: python scripts/load_rules.py [--kibana-url http://localhost:5601]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests

RULES_DIR = Path(__file__).resolve().parent.parent / "detections"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kibana-url",
                        default=os.environ.get("KIBANA_URL", "http://localhost:5601"))
    parser.add_argument("--user", default=os.environ.get("ES_USER", "elastic"))
    parser.add_argument("--password", default=os.environ.get("ELASTIC_PASSWORD", "changeme"))
    args = parser.parse_args()

    rule_files = sorted(RULES_DIR.glob("*.json"))
    if not rule_files:
        print(f"No rules found in {RULES_DIR}", file=sys.stderr)
        return 1

    ndjson = "\n".join(
        json.dumps(json.loads(f.read_text())) for f in rule_files
    ) + "\n"

    resp = requests.post(
        f"{args.kibana_url}/api/detection_engine/rules/_import",
        params={"overwrite": "true"},
        headers={"kbn-xsrf": "true"},
        auth=(args.user, args.password),
        files={"file": ("rules.ndjson", ndjson, "application/x-ndjson")},
        timeout=60,
    )
    resp.raise_for_status()
    result = resp.json()

    if result.get("success"):
        print(f"Imported {result.get('success_count', len(rule_files))} rules:")
        for f in rule_files:
            print(f"  - {json.loads(f.read_text())['name']}")
        return 0

    print("Import reported errors:", file=sys.stderr)
    for err in result.get("errors", []):
        print(f"  {err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
