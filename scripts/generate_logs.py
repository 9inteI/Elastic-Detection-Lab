#!/usr/bin/env python3
"""Generate synthetic-but-realistic log samples for the detection lab.

Produces three files under sample-logs/:
  - auth.log              Linux syslog auth events (sshd, sudo, useradd)
  - nginx-access.log      Nginx combined-format access logs
  - windows-security.json Windows Security events as NDJSON (ECS-ish)

Each file contains mostly-benign background noise plus the specific attack
patterns the six detection rules are designed to catch. Deterministic
(seeded) so the repo stays reproducible.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(1337)

OUT_DIR = Path(__file__).resolve().parent.parent / "sample-logs"
BASE = datetime(2026, 7, 6, 8, 0, 0, tzinfo=timezone.utc)

USERS = ["alice", "bob", "carol", "dave", "svc_backup"]
INTERNAL_IPS = [f"10.20.30.{i}" for i in range(10, 40)]
ATTACKER_IP = "203.0.113.66"
EXFIL_IP = "198.51.100.99"
WEBSHELL_IP = "192.0.2.77"


def syslog_ts(dt: datetime) -> str:
    return dt.strftime("%b %e %H:%M:%S")


# --------------------------------------------------------------------------
# 1. Linux auth.log
# --------------------------------------------------------------------------
def gen_auth_log() -> list[str]:
    lines: list[tuple[datetime, str]] = []
    host = "web-01"

    def ssh_ok(dt, user, ip, port):
        return (
            dt,
            f"{syslog_ts(dt)} {host} sshd[{random.randint(1000, 9999)}]: "
            f"Accepted publickey for {user} from {ip} port {port} ssh2: RSA "
            f"SHA256:{''.join(random.choices('abcdef0123456789', k=16))}",
        )

    def ssh_fail(dt, user, ip, port):
        return (
            dt,
            f"{syslog_ts(dt)} {host} sshd[{random.randint(1000, 9999)}]: "
            f"Failed password for {'invalid user ' if user in ('admin', 'test', 'oracle') else ''}"
            f"{user} from {ip} port {port} ssh2",
        )

    # Benign background: successful logins + occasional typo'd password
    t = BASE
    for _ in range(60):
        t += timedelta(seconds=random.randint(60, 600))
        user = random.choice(USERS)
        ip = random.choice(INTERNAL_IPS)
        lines.append(ssh_ok(t, user, ip, random.randint(40000, 65000)))
        if random.random() < 0.1:
            lines.append(ssh_fail(t + timedelta(seconds=5), user, ip, random.randint(40000, 65000)))

    # Benign sudo usage by admins
    t = BASE
    for _ in range(25):
        t += timedelta(seconds=random.randint(120, 900))
        user = random.choice(["alice", "bob"])
        cmd = random.choice(
            ["/usr/bin/systemctl restart nginx", "/usr/bin/apt update", "/usr/bin/journalctl -u nginx"]
        )
        lines.append(
            (
                t,
                f"{syslog_ts(t)} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; "
                f"USER=root ; COMMAND={cmd}",
            )
        )

    # ATTACK 1: SSH brute force from ATTACKER_IP (rapid failures, then success)
    t = BASE + timedelta(hours=2)
    for i in range(40):
        t += timedelta(seconds=random.randint(1, 4))
        user = random.choice(["root", "admin", "test", "oracle", "svc_backup"])
        lines.append(ssh_fail(t, user, ATTACKER_IP, 50000 + i))
    t += timedelta(seconds=3)
    lines.append(ssh_ok(t, "svc_backup", ATTACKER_IP, 50101))

    # ATTACK 3: suspicious sudo escalation by compromised service account
    t += timedelta(seconds=45)
    for cmd in ["/bin/bash", "/usr/bin/cat /etc/shadow", "/usr/bin/su - root"]:
        t += timedelta(seconds=random.randint(10, 60))
        lines.append(
            (
                t,
                f"{syslog_ts(t)} {host} sudo: svc_backup : TTY=pts/2 ; PWD=/tmp ; "
                f"USER=root ; COMMAND={cmd}",
            )
        )
    t += timedelta(seconds=20)
    lines.append(
        (
            t,
            f"{syslog_ts(t)} {host} sudo: dave : user NOT in sudoers ; TTY=pts/3 ; "
            f"PWD=/home/dave ; USER=root ; COMMAND=/bin/bash",
        )
    )

    # ATTACK 6 (Linux flavor): new account added to sudo group
    t += timedelta(minutes=2)
    lines.append(
        (t, f"{syslog_ts(t)} {host} useradd[7811]: new user: name=sysadm1n, UID=1099, GID=1099, "
            f"home=/home/sysadm1n, shell=/bin/bash")
    )
    t += timedelta(seconds=8)
    lines.append(
        (t, f"{syslog_ts(t)} {host} usermod[7820]: add 'sysadm1n' to group 'sudo'")
    )

    lines.sort(key=lambda pair: pair[0])
    return [line for _, line in lines]


# --------------------------------------------------------------------------
# 2. Nginx access log (combined format)
# --------------------------------------------------------------------------
def gen_nginx_log() -> list[str]:
    lines: list[tuple[datetime, str]] = []
    pages = ["/", "/about", "/products", "/blog/post-1", "/api/v1/items", "/login",
             "/static/app.js", "/static/style.css", "/images/logo.png"]
    agents = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    ]

    def entry(dt, ip, method, path, status, size, agent, referer="-"):
        ts = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        return (dt, f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{agent}"')

    # Benign traffic
    t = BASE
    for _ in range(300):
        t += timedelta(seconds=random.randint(2, 45))
        ip = f"172.16.{random.randint(0, 8)}.{random.randint(2, 250)}"
        path = random.choice(pages)
        status = random.choices([200, 304, 404, 302], weights=[80, 10, 5, 5])[0]
        lines.append(entry(t, ip, "GET", path, status, random.randint(300, 15000), random.choice(agents)))

    # ATTACK 4: web shell probing and interaction
    t = BASE + timedelta(hours=3)
    probes = [
        ("GET", "/uploads/shell.php?cmd=id", 404),
        ("GET", "/images/c99.php", 404),
        ("GET", "/wp-content/uploads/wso.php", 404),
        ("POST", "/uploads/avatar.php", 200),
        ("GET", "/uploads/avatar.php?cmd=whoami", 200),
        ("GET", "/uploads/avatar.php?cmd=cat+/etc/passwd", 200),
        ("GET", "/uploads/avatar.php?cmd=uname+-a&dir=/var/www", 200),
        ("POST", "/uploads/avatar.php?action=eval&code=base64_decode", 200),
    ]
    for method, path, status in probes:
        t += timedelta(seconds=random.randint(5, 40))
        lines.append(entry(t, WEBSHELL_IP, method, path, status, random.randint(200, 2000),
                           "python-requests/2.32.0"))

    # ATTACK 5: data exfiltration - huge responses pulled to one external IP
    t = BASE + timedelta(hours=4)
    for i in range(12):
        t += timedelta(seconds=random.randint(10, 30))
        lines.append(entry(t, EXFIL_IP, "GET", f"/api/v1/export?batch={i}", 200,
                           random.randint(45_000_000, 95_000_000), "curl/8.6.0"))

    lines.sort(key=lambda pair: pair[0])
    return [line for _, line in lines]


# --------------------------------------------------------------------------
# 3. Windows Security events (NDJSON, ECS-flavored)
# --------------------------------------------------------------------------
def gen_windows_log() -> list[dict]:
    events: list[dict] = []
    host = "DC-01"
    domain = "CORP"

    def base_event(dt, code, action, user, extra=None):
        doc = {
            "@timestamp": dt.isoformat(),
            "host": {"name": host},
            "event": {
                "code": str(code),
                "provider": "Microsoft-Windows-Security-Auditing",
                "action": action,
                "category": ["iam" if code in (4720, 4722, 4732, 4728) else "authentication"],
                "outcome": "success",
            },
            "winlog": {"channel": "Security", "event_id": code},
            "user": {"name": user, "domain": domain},
        }
        if extra:
            doc.update(extra)
        return doc

    # Benign logons (4624) and a few logoffs (4634)
    t = BASE
    for _ in range(50):
        t += timedelta(seconds=random.randint(60, 500))
        user = random.choice(USERS)
        events.append(
            base_event(
                t, 4624, "logged-in", user,
                {"source": {"ip": random.choice(INTERNAL_IPS),
                            "geo": {"country_name": "Spain", "city_name": "Madrid"}},
                 "winlog_logon_type": 3},
            )
        )
        if random.random() < 0.3:
            events.append(base_event(t + timedelta(minutes=20), 4634, "logged-off", user))

    # ATTACK 2: impossible travel - alice logs in from Madrid, then Singapore 9 min later
    t = BASE + timedelta(hours=1)
    events.append(
        base_event(t, 4624, "logged-in", "alice",
                   {"source": {"ip": "10.20.30.15",
                               "geo": {"country_name": "Spain", "city_name": "Madrid"}}})
    )
    events.append(
        base_event(t + timedelta(minutes=9), 4624, "logged-in", "alice",
                   {"source": {"ip": "203.0.113.200",
                               "geo": {"country_name": "Singapore", "city_name": "Singapore"}}})
    )

    # ATTACK 6: new account created (4720) then added to Administrators (4732)
    t = BASE + timedelta(hours=5)
    events.append(
        base_event(t, 4720, "added-user-account", "attacker_admin",
                   {"winlog_event_data": {"TargetUserName": "attacker_admin",
                                          "SubjectUserName": "svc_backup"}})
    )
    events.append(
        base_event(t + timedelta(seconds=42), 4732, "added-member-to-group", "attacker_admin",
                   {"group": {"name": "Administrators"},
                    "winlog_event_data": {"TargetUserName": "attacker_admin",
                                          "SubjectUserName": "svc_backup",
                                          "GroupName": "Administrators"}})
    )

    events.sort(key=lambda e: e["@timestamp"])
    return events


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)

    auth = gen_auth_log()
    (OUT_DIR / "auth.log").write_text("\n".join(auth) + "\n")

    nginx = gen_nginx_log()
    (OUT_DIR / "nginx-access.log").write_text("\n".join(nginx) + "\n")

    windows = gen_windows_log()
    (OUT_DIR / "windows-security.json").write_text(
        "\n".join(json.dumps(e) for e in windows) + "\n"
    )

    print(f"auth.log:              {len(auth)} lines")
    print(f"nginx-access.log:      {len(nginx)} lines")
    print(f"windows-security.json: {len(windows)} events")
    print(f"Written to {OUT_DIR}")


if __name__ == "__main__":
    main()
