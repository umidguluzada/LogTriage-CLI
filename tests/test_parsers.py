"""Tests for the streaming Linux and Windows parsers."""

from __future__ import annotations

import gzip
from datetime import datetime
from pathlib import Path

from parsers import (
    EventCategory,
    LinuxLogParser,
    WindowsEventParser,
    detect_log_type,
    extract_message_fields,
    parse_iso_timestamp,
)

AUTH_LOG = """\
Oct 21 02:13:01 web01 sshd[1201]: Failed password for invalid user admin from 203.0.113.45 port 50122 ssh2
Oct 21 02:13:05 web01 sshd[1201]: message repeated 4 times: [ Failed password for root from 203.0.113.45 port 50122 ssh2]
Oct 21 02:14:00 web01 sshd[1202]: Accepted password for deploy from 203.0.113.45 port 50200 ssh2
Oct 21 02:15:00 web01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
Oct 21 02:16:00 web01 sudo:    carol : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/carol ; USER=root ; COMMAND=/bin/cat /etc/shadow
Oct 21 02:17:00 web01 su[900]: pam_unix(su:session): session opened for user root(uid=0) by bob(uid=1001)
Oct 21 02:18:00 web01 useradd[901]: new user: name=sysbackup, UID=0, GID=0, home=/root, shell=/bin/bash
Oct 21 02:19:00 web01 CRON[902]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
2026-10-21T02:20:00.123456+00:00 web01 sshd[1203]: Failed password for alice from 10.0.0.5 port 4000 ssh2
this line is not syslog at all
"""


def _write(tmp_path: Path, name: str, content: str, encoding: str = "utf-8") -> Path:
    path = tmp_path / name
    path.write_text(content, encoding=encoding)
    return path


def test_linux_parser_classifies_auth_log(tmp_path, config, normalizer):
    parser = LinuxLogParser(config, normalizer, year=2026)
    events = list(parser.parse_files([_write(tmp_path, "auth.log", AUTH_LOG)]))

    assert [e.category for e in events] == [
        EventCategory.AUTH_FAILURE,
        EventCategory.AUTH_FAILURE,
        EventCategory.AUTH_SUCCESS,
        EventCategory.PRIV_COMMAND,
        EventCategory.PRIV_FAILURE,
        EventCategory.PRIV_SWITCH,
        EventCategory.ACCOUNT_CREATED,
        EventCategory.AUTH_FAILURE,
    ]
    failed, repeated, accepted, sudo, denied, su, created, iso = events
    assert (failed.user, failed.src_ip, failed.timestamp) == ("admin", "203.0.113.45", datetime(2026, 10, 21, 2, 13, 1))
    assert repeated.count == 4 and repeated.user == "root"
    assert accepted.user == "deploy"
    assert (sudo.user, sudo.target_user, sudo.command) == ("deploy", "root", "/bin/bash")
    assert denied.severity_hint == "high" and denied.command == "/bin/cat /etc/shadow"
    assert (su.user, su.target_user) == ("bob", "root")
    assert created.fields["uid"] == "0"
    assert iso.timestamp == datetime(2026, 10, 21, 2, 20, 0, 123456)
    assert failed.origin == "auth.log:1"

    assert parser.stats.records_read == 10
    assert parser.stats.malformed == 1
    assert parser.stats.unmatched == 1


def test_linux_parser_handles_year_rollover_and_gzip(tmp_path, config, normalizer):
    path = tmp_path / "auth.log.1.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write("Dec 31 23:59:59 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\n")
        handle.write("Jan  1 00:00:01 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2\n")
    events = list(LinuxLogParser(config, normalizer, year=2025).parse_files([path]))
    assert [e.timestamp.year for e in events] == [2025, 2026]


def test_parse_iso_timestamp_variants():
    assert parse_iso_timestamp("2026-10-23T05:14:00.1234567Z").microsecond == 123456
    assert parse_iso_timestamp("2026-10-23 05:14:00.5 UTC").tzinfo is not None
    assert parse_iso_timestamp("2026-10-23T05:14:00+0400").utcoffset().total_seconds() == 4 * 3600


WEVTUTIL_XML = """\
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-10-21T01:05:00.1234567Z'/><Computer>WS01</Computer></System><EventData><Data Name='SubjectUserName'>-</Data><Data Name='TargetUserName'>Administrator</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>::ffff:203.0.113.77</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5156</EventID><TimeCreated SystemTime='2026-10-21T01:05:01Z'/><Computer>WS01</Computer></System><EventData/></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><TimeCreated SystemTime='2026-10-21T01:10:00Z'/><Computer>WS01</Computer></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserName>Administrator</SubjectUserName></LogFileCleared></UserData></Event>
"""


def test_windows_xml_stream_without_root(tmp_path, config, normalizer):
    parser = WindowsEventParser(config, normalizer)
    events = list(parser.parse_files([_write(tmp_path, "security.xml", WEVTUTIL_XML)]))

    assert [e.event_id for e in events] == [4625, 1102]
    failure, cleared = events
    assert failure.category == EventCategory.AUTH_FAILURE
    assert (failure.user, failure.src_ip, failure.fields["logon_type"]) == ("Administrator", "203.0.113.77", "3")
    assert failure.timestamp == datetime(2026, 10, 21, 1, 5, 0, 123456)
    assert cleared.category == EventCategory.LOG_CLEARED and cleared.user == "Administrator"
    assert parser.stats.unmatched == 1


FAILED_LOGON_MESSAGE = (
    "An account failed to log on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\t-\r\n"
    "\r\nLogon Type:\t\t\t3\r\n\r\nAccount For Which Logon Failed:\r\n\tSecurity ID:\t\tS-1-0-0\r\n"
    "\tAccount Name:\t\tbackup\r\n\tAccount Domain:\t\tCORP\r\n\r\nNetwork Information:\r\n"
    "\tWorkstation Name:\tKALI\r\n\tSource Network Address:\t198.51.100.9\r\n\tSource Port:\t\t0\r\n"
)


def test_extract_message_fields_maps_sections():
    fields = extract_message_fields(FAILED_LOGON_MESSAGE)
    assert fields["TargetUserName"] == "backup"
    assert fields["IpAddress"] == "198.51.100.9"
    assert fields["LogonType"] == "3"
    assert fields["WorkstationName"] == "KALI"
    assert "SubjectUserName" in fields  # "-" is kept here and cleaned during normalization


def test_windows_event_viewer_csv_utf16(tmp_path, config, normalizer):
    message = FAILED_LOGON_MESSAGE.replace("\r\n", "\n").replace('"', '""')
    content = (
        "Level,Date and Time,Source,Event ID,Task Category\n"
        f'Information,10/21/2026 1:05:00 AM,Microsoft-Windows-Security-Auditing,4625,Logon,"{message}"\n'
        'Information,10/21/2026 1:06:00 AM,Microsoft-Windows-Security-Auditing,4634,Logoff,"An account was logged off."\n'
    )
    path = _write(tmp_path, "security.csv", content, encoding="utf-16")
    parser = WindowsEventParser(config, normalizer)
    events = list(parser.parse_files([path]))

    assert len(events) == 1
    event = events[0]
    assert event.timestamp == datetime(2026, 10, 21, 1, 5)
    assert (event.user, event.src_ip) == ("backup", "198.51.100.9")
    assert event.message == "An account failed to log on."


def test_windows_wevtutil_text(tmp_path, config, normalizer):
    content = (
        "Event[0]:\n  Log Name: Security\n  Source: Microsoft-Windows-Security-Auditing\n"
        "  Date: 2026-10-21T01:05:00.0000000Z\n  Event ID: 4732\n  Task: Security Group Management\n"
        "  Computer: WS01\n  Description: \nA member was added to a security-enabled local group.\n\n"
        "Subject:\n\tSecurity ID:\t\tS-1-5-21-1-2-3-500\n\tAccount Name:\t\tAdministrator\n\n"
        "Member:\n\tSecurity ID:\t\tS-1-5-21-1-2-3-1104\n\tAccount Name:\t\t-\n\n"
        "Group:\n\tSecurity ID:\t\tS-1-5-32-544\n\tGroup Name:\t\tAdministrators\n\tGroup Domain:\t\tBuiltin\n"
        "Event[1]:\n  Log Name: Security\n  Source: Microsoft-Windows-Security-Auditing\n"
        "  Date: 2026-10-21T01:06:00.0000000Z\n  Event ID: 4634\n  Description: \nAn account was logged off.\n"
    )
    parser = WindowsEventParser(config, normalizer)
    events = list(parser.parse_files([_write(tmp_path, "security.txt", content)]))

    assert len(events) == 1
    event = events[0]
    assert event.category == EventCategory.GROUP_CHANGE
    assert event.group == "Administrators"
    assert event.user == "S-1-5-21-1-2-3-1104"
    assert event.fields["actor"] == "Administrator"


def test_detect_log_type(tmp_path):
    assert detect_log_type(_write(tmp_path, "auth.log", AUTH_LOG)) == "linux"
    assert detect_log_type(_write(tmp_path, "export.csv", "a,b\n")) == "windows"
    assert detect_log_type(_write(tmp_path, "events.txt", "Event[0]:\n  Event ID: 4624\n")) == "windows"
