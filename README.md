# m365-incident-hunting

![tests](https://github.com/fariselkhatib/m365-incident-hunting/actions/workflows/tests.yml/badge.svg)

KQL hunts for Microsoft 365 / Entra ID account takeover, written the way you'd want them in an actual investigation: readable, documented, with the false positives called out up front. Every query ships with a lab version you can run against synthetic data without a tenant.

## The problem

Most M365 compromises follow the same arc: get a valid session, hide the evidence in the mailbox, set up persistence that survives a password reset. The signals exist in `SigninLogs`, `OfficeActivity`, and `AuditLogs`, but individually they're noisy. Analysts need queries they can trust, tune, and explain to a client.

## The hunts

| # | Query | What it catches | ATT&CK |
|---|---|---|---|
| 01 | [Password spray + success](queries/01-password-spray.kql) | One IP failing against many accounts, then getting in | T1110.003, T1078.004 |
| 02 | [Impossible travel (lite)](queries/02-impossible-travel-lite.kql) | Country change between successful sign-ins faster than travel allows | T1078.004 |
| 03 | [Suspicious inbox rules](queries/03-suspicious-inbox-rules.kql) | Scored rules: external forwarding, hiding folders, finance keywords, junk names | T1564.008, T1114.003 |
| 04 | [Risky OAuth consent](queries/04-risky-oauth-consent.kql) | Consent grants with mailbox/file scopes and refresh-token persistence | T1528, T1550.001 |
| 05 | [Recovery change from new IP](queries/05-recovery-change-from-new-ip.kql) | MFA method or password changes from an IP the user never used | T1556.006, T1098.005 |
| 06 | [BEC sequence](queries/06-bec-sequence.kql) | Correlates 01-05 style signals per user into one takeover lead | T1078.004, T1564.008, T1528, T1556.006 |

Each query file has a standard header: description, tables, ATT&CK mapping, **false positives**, tuning advice, and the exact result you should see in the lab.

## Data source

`samples/` holds synthetic `SigninLogs`, `OfficeActivity`, and `AuditLogs` rows modeled on the real schemas. Domain is `lab.example`, IPs are RFC 5737 documentation ranges.

The scenario: a spray from `198.51.100.77` hits 8 accounts and lands on `dana`. Within 45 minutes the attacker creates a hiding inbox rule, consents to a mail-reading app with `offline_access`, and registers a new authenticator. Two other users generate benign look-alike activity (a newsletter rule, a Zoom consent, a phone registration from a known IP, and a forward-to-personal rule) so you can see what the queries correctly ignore and where they produce a defensible false positive.

## How to run

**In Sentinel / Log Analytics:** paste any file from `queries/` into Logs. Adjust `lookback` and the tuning lists at the top.

**Without a tenant:** paste any file from `labs/` into a Kusto query window, such as a free Azure Data Explorer cluster. Lab files shadow the real tables with `datatable()` built from `samples/` and pin `now()` to the scenario date. Compare output to the query's `Expected lab results` header.

**Rebuild labs after editing a query or sample:**

```bash
python tools/build_labs.py
```

**Tests** (Python 3.10+, `pip install pytest`):

```bash
python -m pytest -q
```

The test suite checks that every query is fully documented, ATT&CK IDs are valid and reviewed, declared tables match what the query uses, lab files are current, and that the synthetic data actually contains the scenario each query claims to find (via small Python re-statements of each query's core logic).

## Sample output

Lab run of `06-bec-sequence.kql`:

| User | SignalCount | SpanMinutes | Signals |
|---|---|---|---|
| dana@lab.example | 4 | 43 | new-ip-signin, inbox-rule, oauth-consent, security-info-change |

`ravi@lab.example` also has an inbox rule, a consent, and a security info change in the window, but all from his known IP with no new-IP sign-in, so he's excluded. That's the point of anchoring the sequence on the sign-in.

## Limitations

- **The tests don't execute KQL.** They validate structure and the dataset. Run the lab files in a Kusto window to verify query behavior end to end.
- **Schemas are simplified.** Sample rows include only the columns these queries use. Real tables have many more, and field formats (especially `ConsentAction.Permissions` and inbox rule `Parameters`) vary between tenants and over time. Check against your own data before relying on string parsing.
- **Geo-IP is unreliable.** Query 02 trusts `LocationDetails`. VPNs and mobile carriers will generate false positives.
- **No risk signals.** These work on E3-level logging. If you have Entra ID P2, add `RiskLevelDuringSignIn` and `RiskEventTypes` for better precision.
- **Unified Audit Log latency.** `OfficeActivity` can lag 30+ minutes behind sign-ins. Keep correlation windows wide enough.
- **Baseline length matters.** "New IP" logic (05, 06) depends on the 14-day baseline actually containing the user's normal activity. Infrequent users will look new.

## License

MIT. See [LICENSE](LICENSE).
