#!/usr/bin/env python3
"""Parse the sample logs into ECS documents and bulk-index them.

Filebeat ships the raw lines; this script indexes the *structured* view the
detection rules query:

  logs-edl.auth     <- sample-logs/auth.log
  logs-edl.nginx    <- sample-logs/nginx-access.log
  logs-edl.windows  <- sample-logs/windows-security.json

Timestamps in the samples are rebased so the newest event is "now" — this
keeps the rules (which look back a few hours) firing no matter when you run
the lab.

Usage: python scripts/seed.py [--es-url http://localhost:9200]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from elasticsearch import Elasticsearch, helpers

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample-logs"
YEAR = 2026  # syslog timestamps carry no year; the generator uses 2026

SSH_FAIL = re.compile(
    r"sshd\[\d+\]: Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
SSH_OK = re.compile(
    r"sshd\[\d+\]: Accepted \w+ for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
SUDO = re.compile(
    r"sudo:\s+(?P<user>\S+) :(?P<denied> user NOT in sudoers ;)?\s*TTY=(?P<tty>\S+) ; "
    r"PWD=(?P<pwd>\S+) ; USER=(?P<runas>\S+) ; COMMAND=(?P<cmd>.+)$"
)
USER_MGMT = re.compile(r"(useradd|usermod)\[\d+\]: (?P<msg>.+)$")
SYSLOG_TS = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d+) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+)")
NGINX = re.compile(
    r'(?P<ip>\S+) - - \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+) "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)


def parse_syslog_ts(line: str) -> tuple[datetime, str] | None:
    m = SYSLOG_TS.match(line)
    if not m:
        return None
    dt = datetime.strptime(
        f"{YEAR} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
    ).replace(tzinfo=timezone.utc)
    return dt, m["host"]


def parse_auth() -> list[dict]:
    docs = []
    for line in (SAMPLE_DIR / "auth.log").read_text().splitlines():
        parsed = parse_syslog_ts(line)
        if not parsed:
            continue
        ts, host = parsed
        doc = {
            "@timestamp": ts,
            "host": {"name": host},
            "event": {"dataset": "system.auth"},
            "message": line,
        }
        if m := SSH_FAIL.search(line):
            doc["event"].update(category=["authentication"], action="ssh_login",
                                outcome="failure")
            doc["user"] = {"name": m["user"]}
            doc["source"] = {"ip": m["ip"], "port": int(m["port"])}
        elif m := SSH_OK.search(line):
            doc["event"].update(category=["authentication"], action="ssh_login",
                                outcome="success")
            doc["user"] = {"name": m["user"]}
            doc["source"] = {"ip": m["ip"], "port": int(m["port"])}
        elif m := SUDO.search(line):
            doc["event"].update(category=["process"], action="sudo_command",
                                outcome="failure" if m["denied"] else "success")
            doc["user"] = {"name": m["user"], "effective": {"name": m["runas"]}}
            doc["process"] = {"command_line": m["cmd"]}
        elif m := USER_MGMT.search(line):
            doc["event"].update(category=["iam"], action="user_management",
                                outcome="success")
        else:
            continue
        docs.append(doc)
    return docs


def parse_nginx() -> list[dict]:
    docs = []
    for line in (SAMPLE_DIR / "nginx-access.log").read_text().splitlines():
        m = NGINX.match(line)
        if not m:
            continue
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
        path, _, query = m["path"].partition("?")
        docs.append({
            "@timestamp": ts,
            "event": {"dataset": "nginx.access", "category": ["web"]},
            "source": {"ip": m["ip"]},
            "http": {
                "request": {"method": m["method"]},
                "response": {"status_code": int(m["status"]),
                             "bytes": int(m["bytes"])},
            },
            "url": {"path": path, "query": query, "original": m["path"]},
            "user_agent": {"original": m["agent"]},
            "message": line,
        })
    return docs


def parse_windows() -> list[dict]:
    docs = []
    for line in (SAMPLE_DIR / "windows-security.json").read_text().splitlines():
        if line.strip():
            doc = json.loads(line)
            doc["@timestamp"] = datetime.fromisoformat(doc["@timestamp"])
            doc.setdefault("event", {})["dataset"] = "windows.security"
            docs.append(doc)
    return docs


def rebase_timestamps(docs: list[dict]) -> None:
    """Shift all docs so the newest one lands a minute ago."""
    newest = max(d["@timestamp"] for d in docs)
    shift = datetime.now(timezone.utc) - timedelta(minutes=1) - newest
    for d in docs:
        d["@timestamp"] = (d["@timestamp"] + shift).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--es-url", default=os.environ.get("ES_URL", "http://localhost:9200"))
    parser.add_argument("--user", default=os.environ.get("ES_USER", "elastic"))
    parser.add_argument("--password", default=os.environ.get("ELASTIC_PASSWORD", "changeme"))
    args = parser.parse_args()

    es = Elasticsearch(args.es_url, basic_auth=(args.user, args.password),
                       request_timeout=60)
    if not es.ping():
        print(f"Cannot reach Elasticsearch at {args.es_url} — is the stack up?",
              file=sys.stderr)
        return 1

    batches = {
        "logs-edl.auth": parse_auth(),
        "logs-edl.nginx": parse_nginx(),
        "logs-edl.windows": parse_windows(),
    }
    all_docs = [d for docs in batches.values() for d in docs]
    rebase_timestamps(all_docs)

    for index, docs in batches.items():
        if es.indices.exists(index=index):
            es.indices.delete(index=index)
        ok, _ = helpers.bulk(
            es, ({"_index": index, "_source": d} for d in docs)
        )
        print(f"{index}: indexed {ok} docs")

    es.indices.refresh(index="logs-edl.*")
    print("Seed complete. Rules run on their next interval (~1 min).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
