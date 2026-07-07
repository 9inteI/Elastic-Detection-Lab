"""Query Elastic for triggered security alerts and print a triage table.

Usage:
    python -m alert_consumer [--es-url http://localhost:9200] [--since 24h]
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any

from elasticsearch import Elasticsearch
from rich.console import Console
from rich.table import Table

from alert_consumer.enrich import EnrichedAlert, enrich_alert, sort_for_triage

ALERTS_INDEX = ".alerts-security.alerts-default"

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "green",
}


def fetch_alerts(es: Elasticsearch, since: str = "24h", size: int = 200) -> list[dict[str, Any]]:
    """Return raw alert _source docs from the security alerts index."""
    resp = es.search(
        index=ALERTS_INDEX,
        size=size,
        query={
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{since}"}}},
                    {"term": {"kibana.alert.workflow_status": "open"}},
                ]
            }
        },
        sort=[{"@timestamp": {"order": "desc"}}],
        ignore_unavailable=True,
    )
    return [hit["_source"] for hit in resp["hits"]["hits"]]


def build_table(alerts: list[EnrichedAlert]) -> Table:
    table = Table(
        title="🚨 Elastic Detection Lab - Alert Triage",
        caption=f"{len(alerts)} open alert(s), sorted by severity",
        show_lines=False,
        header_style="bold cyan",
    )
    table.add_column("Severity", justify="center")
    table.add_column("Rule")
    table.add_column("ATT&CK", justify="center")
    table.add_column("Technique")
    table.add_column("Tactic")
    table.add_column("Entity")
    table.add_column("Risk", justify="right")
    table.add_column("Time (UTC)")

    for alert in alerts:
        style = SEVERITY_STYLE.get(alert.severity, "")
        table.add_row(
            f"[{style}]{alert.severity.upper()}[/]" if style else alert.severity.upper(),
            alert.rule_name,
            f"[link=https://attack.mitre.org/techniques/{alert.technique_id.replace('.', '/')}/]"
            f"{alert.technique_id}[/link]",
            alert.technique,
            alert.tactic,
            alert.entity,
            str(alert.risk_score),
            alert.timestamp[:19].replace("T", " "),
        )
    return table


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="alert_consumer", description=__doc__)
    parser.add_argument("--es-url", default=os.environ.get("ES_URL", "http://localhost:9200"))
    parser.add_argument("--user", default=os.environ.get("ES_USER", "elastic"))
    parser.add_argument("--password", default=os.environ.get("ELASTIC_PASSWORD", "changeme"))
    parser.add_argument("--since", default="24h", help="lookback window, e.g. 1h, 24h, 7d")
    args = parser.parse_args(argv)

    console = Console()
    es = Elasticsearch(args.es_url, basic_auth=(args.user, args.password),
                       request_timeout=30)
    if not es.ping():
        console.print(f"[red]Cannot reach Elasticsearch at {args.es_url} - "
                      f"is the stack up? (make up)[/red]")
        return 1

    raw = fetch_alerts(es, since=args.since)
    if not raw:
        console.print(
            "[yellow]No open alerts found.[/yellow] Run [bold]make seed[/bold] and wait "
            "~1 minute for the rules to execute, or check Kibana → Security → Alerts."
        )
        return 0

    enriched = sort_for_triage([enrich_alert(doc) for doc in raw])
    console.print(build_table(enriched))
    return 0


if __name__ == "__main__":
    sys.exit(main())
