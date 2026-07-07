#!/usr/bin/env python3
"""Capture the README screenshots automatically (headless Chromium).

Produces docs/screenshots/{triage-cli,alerts-overview,rule-detail}.png:
  - triage-cli.png       the `make alerts` rich table, exported via SVG
  - alerts-overview.png  Kibana Security -> Alerts
  - rule-detail.png      Kibana rule page with the MITRE ATT&CK block

Requires the stack up and seeded, plus: pip install playwright &&
playwright install chromium.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import requests
from elasticsearch import Elasticsearch
from playwright.sync_api import sync_playwright
from rich.console import Console

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from alert_consumer.consumer import build_table, fetch_alerts  # noqa: E402
from alert_consumer.enrich import enrich_alert, sort_for_triage  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
KIBANA = os.environ.get("KIBANA_URL", "http://localhost:5601")
USER = os.environ.get("ES_USER", "elastic")
PASSWORD = os.environ.get("ELASTIC_PASSWORD", "changeme")


def capture_cli_table(page) -> None:
    es = Elasticsearch(ES_URL, basic_auth=(USER, PASSWORD))
    alerts = sort_for_triage([enrich_alert(d) for d in fetch_alerts(es)])[:12]
    console = Console(record=True, width=148)
    console.print(build_table(alerts))
    svg_path = OUT / "triage-cli.svg"
    svg_path.write_text(console.export_svg(title="make alerts"))

    page.set_viewport_size({"width": 1500, "height": 900})
    page.goto(f"file://{svg_path}")
    svg = page.locator("svg")
    svg.screenshot(path=str(OUT / "triage-cli.png"), scale="device")
    svg_path.unlink()
    print("triage-cli.png")


def kibana_login(page) -> None:
    page.goto(f"{KIBANA}/login", wait_until="networkidle")
    if "/login" not in page.url:
        return  # already authenticated
    page.fill('input[name="username"]', USER)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(lambda url: "/login" not in url, timeout=30_000)


def capture_kibana(page) -> None:
    page.set_viewport_size({"width": 1720, "height": 980})
    kibana_login(page)

    # Alerts overview
    page.goto(f"{KIBANA}/app/security/alerts", wait_until="networkidle")
    time.sleep(12)  # charts + alert table render after network settles
    page.screenshot(path=str(OUT / "alerts-overview.png"))
    print("alerts-overview.png")

    # Rule detail (EDL-006, the EQL sequence rule) - resolve its internal id
    resp = requests.get(
        f"{KIBANA}/api/detection_engine/rules",
        params={"rule_id": "edl-006-new-admin-account"},
        headers={"kbn-xsrf": "true"},
        auth=(USER, PASSWORD),
        timeout=30,
    )
    resp.raise_for_status()
    page.goto(f"{KIBANA}/app/security/rules/id/{resp.json()['id']}",
              wait_until="networkidle")
    time.sleep(10)
    page.screenshot(path=str(OUT / "rule-detail.png"))
    print("rule-detail.png")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page()
        capture_cli_table(page)
        capture_kibana(page)
        browser.close()
    print(f"Saved to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
