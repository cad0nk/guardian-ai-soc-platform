# Demo material

A 2-4 minute screen recording is the best way to show guardian_ai. Use **only synthetic data** - the screenshots in
`docs/screenshots/` are generated with `python tools/generate_screenshots.py` and use RFC 5737 documentation IPs and `.example` domains.

## Preparation
- Clean desktop, 1920x1080, 100 % or 125 % display scale, hide notifications.
- Use a **throw-away `.env`** (or none) - never record while real keys, internal hostnames or customer data are visible.
- Open `tests/fixtures/` files for the demo; they are inert. Do not run any sample.
- Delete `soc_history.db` first so the history starts empty.

## Suggested storyboard (about 3 minutes)
| Time | Scene | Talking point |
|---|---|---|
| 0:00 | Dashboard | "One workspace for CTI, malware and forensics. The header states honestly what is configured." |
| 0:20 | CTI lookup | Enter `198.51.100.23` -> risk meter, per-source cards, AbuseIPDB tab (with keys: real data; without: *Not configured* cards) |
| 0:55 | Malware (local) | Upload `sample_malware.txt` -> `LOCAL ANALYSIS` badge, strings/network/behaviour tabs; point out the Hybrid card explaining what is *not* available |
| 1:30 | Forensics (WAF) | Upload a WAF JSON -> findings, IOCs, statistics |
| 2:00 | Timeline + Attack Graph | Show the sequence and IOC relationships; panel folds away to give the graph room |
| 2:25 | AI SOC Analyst | Ask "why is this malicious?" -> structured answer with risk level and recommendations |
| 2:45 | History + PDF | Select an entry, *Export PDF* |
| 3:00 | Close | Limitations: keys optional, TShark for PCAP, not an EDR |

## Per-feature checklist
- [ ] Dashboard walkthrough
- [ ] CTI lookup
- [ ] AbuseIPDB intelligence
- [ ] Malware local analysis
- [ ] WAF investigation
- [ ] PCAP analysis (needs TShark and a **synthetic** capture you created yourself)
- [ ] Attack Graph
- [ ] AI SOC Analyst
- [ ] PDF report

Do not use screenshots or recordings of company monitoring, customer data or real incidents without written permission.
