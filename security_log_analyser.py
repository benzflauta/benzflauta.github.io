#!/usr/bin/env python3
"""
security_log_analyzer.py

Parses authentication/security logs to detect:
- Repeated failed login attempts
- Potential brute-force attacks
- Suspicious successful logins after multiple failures

"""

import re
import argparse
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional


# ----------------------------
# Data model
# ----------------------------
@dataclass
class LogEvent:
    timestamp: datetime
    hostname: str
    service: str
    pid: Optional[int]
    event_type: str   # "failed", "success", "invalid_user", "other"
    username: Optional[str]
    ip_address: Optional[str]
    raw_line: str


# ----------------------------
# Parser
# ----------------------------
class AuthLogParser:
    """
    Parses Linux auth log lines like:
    Mar 23 14:22:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 53422 ssh2
    Mar 23 14:25:12 server sshd[1235]: Accepted password for benz from 192.168.1.10 port 53430 ssh2
    """

    FAILED_REGEX = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<service>\w+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"Failed password for(?: invalid user)?\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    )

    INVALID_USER_REGEX = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<service>\w+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    )

    SUCCESS_REGEX = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<service>\w+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"Accepted \S+ for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    )

    MONTHS = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
        "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
        "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }

    def __init__(self, year: Optional[int] = None):
        self.year = year or datetime.now().year

    def parse_timestamp(self, month: str, day: str, time_str: str) -> datetime:
        month_num = self.MONTHS[month]
        hour, minute, second = map(int, time_str.split(":"))
        return datetime(self.year, month_num, int(day), hour, minute, second)

    def parse_line(self, line: str) -> Optional[LogEvent]:
        line = line.strip()
        if not line:
            return None

        for regex, event_type in [
            (self.FAILED_REGEX, "failed"),
            (self.INVALID_USER_REGEX, "invalid_user"),
            (self.SUCCESS_REGEX, "success"),
        ]:
            match = regex.match(line)
            if match:
                data = match.groupdict()
                return LogEvent(
                    timestamp=self.parse_timestamp(data["month"], data["day"], data["time"]),
                    hostname=data["host"],
                    service=data["service"],
                    pid=int(data["pid"]) if data.get("pid") else None,
                    event_type=event_type,
                    username=data.get("user"),
                    ip_address=data.get("ip"),
                    raw_line=line,
                )

        return None

    def parse_file(self, filepath: str) -> List[LogEvent]:
        events = []
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                event = self.parse_line(line)
                if event:
                    events.append(event)
        return events


# ----------------------------
# Analyzer
# ----------------------------
class SecurityAnalyzer:
    def __init__(self, events: List[LogEvent], threshold: int = 5, window_minutes: int = 10):
        self.events = sorted(events, key=lambda e: e.timestamp)
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def failed_attempts_by_ip(self):
        counts = defaultdict(int)
        for event in self.events:
            if event.event_type in ("failed", "invalid_user") and event.ip_address:
                counts[event.ip_address] += 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    def failed_attempts_by_user(self):
        counts = defaultdict(int)
        for event in self.events:
            if event.event_type in ("failed", "invalid_user") and event.username:
                counts[event.username] += 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    def detect_bruteforce_by_ip(self):
        """
        Detect N failed attempts from same IP within a rolling time window.
        """
        suspicious = []
        by_ip = defaultdict(list)

        for event in self.events:
            if event.event_type in ("failed", "invalid_user") and event.ip_address:
                by_ip[event.ip_address].append(event)

        for ip, ip_events in by_ip.items():
            start = 0
            for end in range(len(ip_events)):
                while ip_events[end].timestamp - ip_events[start].timestamp > self.window:
                    start += 1

                window_events = ip_events[start:end + 1]
                if len(window_events) >= self.threshold:
                    suspicious.append({
                        "ip": ip,
                        "count": len(window_events),
                        "start": window_events[0].timestamp,
                        "end": window_events[-1].timestamp,
                        "users_targeted": sorted({e.username for e in window_events if e.username}),
                    })
                    break  # avoid duplicate alerts for same IP

        return suspicious

    def suspicious_success_after_failures(self):
        """
        Detect successful logins shortly after repeated failures from the same IP.
        """
        alerts = []
        failures_by_ip = defaultdict(list)

        for event in self.events:
            if event.event_type in ("failed", "invalid_user") and event.ip_address:
                failures_by_ip[event.ip_address].append(event)

        for event in self.events:
            if event.event_type == "success" and event.ip_address:
                recent_failures = [
                    f for f in failures_by_ip[event.ip_address]
                    if timedelta(0) <= (event.timestamp - f.timestamp) <= self.window
                ]
                if len(recent_failures) >= self.threshold:
                    alerts.append({
                        "ip": event.ip_address,
                        "username": event.username,
                        "success_time": event.timestamp,
                        "recent_failures": len(recent_failures),
                    })

        return alerts

    def summary(self):
        total_events = len(self.events)
        total_failed = sum(1 for e in self.events if e.event_type in ("failed", "invalid_user"))
        total_success = sum(1 for e in self.events if e.event_type == "success")
        unique_ips = len({e.ip_address for e in self.events if e.ip_address})

        return {
            "total_parsed_events": total_events,
            "failed_logins": total_failed,
            "successful_logins": total_success,
            "unique_ips": unique_ips,
        }


# ----------------------------
# Reporting
# ----------------------------
def print_report(summary, failed_by_ip, failed_by_user, brute_force_alerts, success_alerts):
    print("=" * 70)
    print("SECURITY LOG ANALYSIS REPORT")
    print("=" * 70)

    print("\n[SUMMARY]")
    for key, value in summary.items():
        print(f"- {key.replace('_', ' ').title()}: {value}")

    print("\n[TOP FAILED ATTEMPTS BY IP]")
    if failed_by_ip:
        for ip, count in list(failed_by_ip.items())[:10]:
            print(f"- {ip}: {count} failed attempts")
    else:
        print("- None found")

    print("\n[TOP FAILED ATTEMPTS BY USERNAME]")
    if failed_by_user:
        for user, count in list(failed_by_user.items())[:10]:
            print(f"- {user}: {count} failed attempts")
    else:
        print("- None found")

    print("\n[POTENTIAL BRUTE-FORCE ATTACKS]")
    if brute_force_alerts:
        for alert in brute_force_alerts:
            print(
                f"- IP {alert['ip']} triggered {alert['count']} failures "
                f"between {alert['start']} and {alert['end']} "
                f"(users targeted: {', '.join(alert['users_targeted']) if alert['users_targeted'] else 'unknown'})"
            )
    else:
        print("- No brute-force patterns detected")

    print("\n[SUSPICIOUS SUCCESSFUL LOGINS AFTER FAILURES]")
    if success_alerts:
        for alert in success_alerts:
            print(
                f"- IP {alert['ip']} successfully logged in as {alert['username']} "
                f"at {alert['success_time']} after {alert['recent_failures']} recent failures"
            )
    else:
        print("- No suspicious success-after-failure events detected")

    print("\n" + "=" * 70)


# ----------------------------
# CLI
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="Analyze security/authentication logs for suspicious login activity.")
    parser.add_argument("logfile", help="Path to the auth/security log file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed attempts threshold for brute-force detection")
    parser.add_argument("--window", type=int, default=10, help="Time window in minutes")
    parser.add_argument("--year", type=int, default=None, help="Year of the log file (default: current year)")
    args = parser.parse_args()

    log_parser = AuthLogParser(year=args.year)
    events = log_parser.parse_file(args.logfile)

    if not events:
        print("No supported authentication events found in the log.")
        return

    analyzer = SecurityAnalyzer(
        events=events,
        threshold=args.threshold,
        window_minutes=args.window
    )

    summary = analyzer.summary()
    failed_by_ip = analyzer.failed_attempts_by_ip()
    failed_by_user = analyzer.failed_attempts_by_user()
    brute_force_alerts = analyzer.detect_bruteforce_by_ip()
    success_alerts = analyzer.suspicious_success_after_failures()

    print_report(summary, failed_by_ip, failed_by_user, brute_force_alerts, success_alerts)


if __name__ == "__main__":
    main()