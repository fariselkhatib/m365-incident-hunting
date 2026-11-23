"""Checks that keep the query collection honest.

These tests can't execute KQL. They verify that every query is documented, that MITRE
references are well-formed, that lab files are current, and that the synthetic data actually
contains the scenario each query's "Expected lab results" claims. Run the lab files in a
Kusto query window for end-to-end verification.
"""
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import build_labs  # noqa: E402

QUERIES = sorted((ROOT / "queries").glob("*.kql"))
REQUIRED_HEADERS = ["Title", "Description", "Tables", "MITRE", "False positives", "Tuning",
                    "Expected lab results"]
# Techniques referenced in this repo. Adding one here forces a deliberate review.
KNOWN_TECHNIQUES = {
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1110.003": "Brute Force: Password Spraying",
    "T1564.008": "Hide Artifacts: Email Hiding Rules",
    "T1114.003": "Email Collection: Email Forwarding Rule",
    "T1528": "Steal Application Access Token",
    "T1550.001": "Use Alternate Authentication Material: Application Access Token",
    "T1556.006": "Modify Authentication Process: Multi-Factor Authentication",
    "T1098.005": "Account Manipulation: Device Registration",
}
SCHEMA = json.loads((ROOT / "samples" / "schema.json").read_text())
DATA = {t: json.loads((ROOT / "samples" / f"{t}.json").read_text()) for t in SCHEMA}
LAB_NOW = datetime.fromisoformat("2026-03-11T00:00:00+00:00")


def headers(path):
    found = {}
    for line in path.read_text().splitlines():
        m = re.match(r"^// ([A-Za-z ]+): (.*)", line)
        if m:
            found[m.group(1)] = m.group(2)
    return found


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


@pytest.mark.parametrize("q", QUERIES, ids=lambda p: p.name)
def test_query_has_required_headers(q):
    h = headers(q)
    for key in REQUIRED_HEADERS:
        assert h.get(key, "").strip(), f"{q.name} missing '{key}' header"


@pytest.mark.parametrize("q", QUERIES, ids=lambda p: p.name)
def test_mitre_ids_known(q):
    ids = [i.strip() for i in headers(q)["MITRE"].split(",")]
    for i in ids:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", i), i
        assert i in KNOWN_TECHNIQUES, f"{i} not in KNOWN_TECHNIQUES"


@pytest.mark.parametrize("q", QUERIES, ids=lambda p: p.name)
def test_declared_tables_match_body(q):
    declared = {t.strip() for t in headers(q)["Tables"].split(",")}
    body = "\n".join(l for l in q.read_text().splitlines() if not l.startswith("//"))
    assert declared == set(build_labs.tables_used(body, SCHEMA))


@pytest.mark.parametrize("q", QUERIES, ids=lambda p: p.name)
def test_query_uses_parameterized_time_window(q):
    body = q.read_text()
    assert "let query_end = now();" in body
    assert "ago(" not in body, "use query_end/lookback so labs can pin time"


def test_balanced_brackets():
    for q in QUERIES:
        body = re.sub(r'@"[^"]*"|"(?:\\.|[^"\\])*"', '""', q.read_text())
        for a, b in ["()", "[]", "{}"]:
            assert body.count(a) == body.count(b), f"{q.name}: unbalanced {a}{b}"


def test_labs_are_current():
    assert build_labs.main(["--check"]) == 0


def test_sample_rows_match_schema():
    for table, cols in SCHEMA.items():
        names = [c for c, _ in cols]
        for row in DATA[table]:
            assert list(row.keys()) == names, f"{table} row keys drift from schema"
            for c, t in cols:
                if t == "datetime":
                    ts(row[c])
            if table == "OfficeActivity":
                json.loads(row["Parameters"])


# --- Scenario checks: Python re-statements of each query's core logic ---------

def window(rows, days=1):
    return [r for r in rows if LAB_NOW - timedelta(days=days) <= ts(r["TimeGenerated"]) <= LAB_NOW]


def test_scenario_password_spray():
    rows = window(DATA["SigninLogs"])
    fails, succ = defaultdict(set), defaultdict(set)
    for r in rows:
        if r["ResultType"] in ("50126", "50053"):
            fails[r["IPAddress"]].add(r["UserPrincipalName"])
        elif r["ResultType"] == "0":
            succ[r["IPAddress"]].add(r["UserPrincipalName"])
    hits = {ip: u for ip, u in fails.items() if len(u) >= 5}
    assert list(hits) == ["198.51.100.77"] and len(hits["198.51.100.77"]) == 8
    assert succ["198.51.100.77"] == {"dana@lab.example"}


def test_scenario_impossible_travel():
    rows = sorted((r for r in window(DATA["SigninLogs"]) if r["ResultType"] == "0"),
                  key=lambda r: (r["UserPrincipalName"], r["TimeGenerated"]))
    hits = []
    for prev, cur in zip(rows, rows[1:]):
        if prev["UserPrincipalName"] == cur["UserPrincipalName"] and \
           prev["LocationDetails"]["countryOrRegion"] != cur["LocationDetails"]["countryOrRegion"]:
            hrs = (ts(cur["TimeGenerated"]) - ts(prev["TimeGenerated"])).total_seconds() / 3600
            if hrs <= 4:
                hits.append((cur["UserPrincipalName"], round(hrs, 2)))
    assert hits == [("dana@lab.example", 1.37)]


def test_scenario_inbox_rules():
    lure = {"invoice", "payment", "wire", "bank", "ach", "remit", "password", "security",
            "phish", "hack", "compromise", "fraud"}
    scores = {}
    for r in window(DATA["OfficeActivity"]):
        p = {x["Name"]: x["Value"] for x in json.loads(r["Parameters"])}
        fwd = ";".join(p.get(k, "") for k in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo"))
        external = set(re.findall(r"@([a-z0-9.\-]+)", fwd.lower())) - {"lab.example"}
        hides = p.get("DeleteMessage") == "True" or bool(
            re.search(r"(?i)(rss|conversation history|archive|junk|deleted items)", p.get("MoveToFolder", "")))
        words = set(re.split(r"\W+", ";".join(p.get(k, "") for k in
                    ("SubjectContainsWords", "SubjectOrBodyContainsWords", "BodyContainsWords")).lower()))
        name = p.get("Name", "")
        obscure = len(name.strip()) <= 2 or bool(re.fullmatch(r"[\W_]+", name))
        score = 3 * bool(external) + 2 * hides + 2 * bool(words & lure) + obscure + (p.get("MarkAsRead") == "True")
        scores[r["UserId"]] = score
    assert scores == {"dana@lab.example": 6, "mlee@lab.example": 3, "ravi@lab.example": 0}


def test_scenario_oauth_consent():
    risky = {"Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite", "Files.Read.All",
             "Files.ReadWrite.All", "Sites.ReadWrite.All", "Contacts.Read", "EWS.AccessAsUser.All",
             "full_access_as_user", "offline_access"}
    hits = {}
    for r in DATA["AuditLogs"]:
        if r["OperationName"] != "Consent to application":
            continue
        props = {m["displayName"]: m["newValue"] for m in r["TargetResources"][0]["modifiedProperties"]}
        scopes = set(re.findall(r"(offline_access|full_access_as_user|[A-Za-z]+\.[A-Za-z.]+)",
                                props["ConsentAction.Permissions"]))
        if scopes & risky:
            hits[r["TargetResources"][0]["displayName"]] = scopes & risky
    assert hits == {"Mail Sync Pro": {"Mail.ReadWrite", "offline_access"}}


def test_scenario_recovery_from_new_ip():
    known = {(r["UserPrincipalName"].lower(), r["IPAddress"]) for r in DATA["SigninLogs"]
             if r["ResultType"] == "0" and ts(r["TimeGenerated"]) < LAB_NOW - timedelta(days=1)}
    hits = [r["TargetResources"][0]["userPrincipalName"] for r in window(DATA["AuditLogs"])
            if "security info" in r["OperationName"]
            and (r["TargetResources"][0]["userPrincipalName"].lower(), r["InitiatedBy"]["user"]["ipAddress"]) not in known]
    assert hits == ["dana@lab.example"]
