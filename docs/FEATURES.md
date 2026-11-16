# Features

Status legend: **Local** = works without any external service. **Key** = needs the user's own API key.
**System** = needs a system program.

> **How these were verified.** The offline paths below are covered by the automated tests (`tests/`) on Linux / Python 3.12.
> Features that call third-party services (VirusTotal, AbuseIPDB, Shodan, Hybrid Analysis, Groq, WHOIS servers) are implemented,
> but live calls are deliberately **not** made by the test-suite and were not exercised against production services while preparing this repository.

## Cyber Threat Intelligence
| Feature | Needs | Notes |
|---|---|---|
| IOC type detection (IP, domain, URL, MD5/SHA1/SHA256) | Local | Shown live under the input field |
| VirusTotal reputation | Key | |
| AbuseIPDB reputation + report list | Key | IP addresses only |
| Shodan host lookup | Key | |
| WHOIS enrichment | Local library (network) | Domains only; needs outbound network |
| Per-source status (OK / NO DATA / ERROR / NOT CONFIGURED) | Local | Real errors (e.g. rate limit) are displayed |
| Risk score, severity, raw JSON, AI summary | Local (AI: Key) | |

## Malware Analysis
| Feature | Needs | Notes |
|---|---|---|
| File upload, size/extension/SHA-256 preview | Local | Supported: `.exe .dll .pdf .doc .ps1 .cmd .txt .com .bat` |
| String extraction and suspicious-pattern detection | Local | |
| Base64 / PowerShell `-EncodedCommand` inspection | Local | |
| Network-indicator extraction (URLs, IPs, domains) | Local | |
| YARA-style pattern scan | Local | Pattern-based, **not** the YARA engine |
| EICAR test-signature recognition | Local | |
| Hybrid Analysis report lookup / URL submission | Key | |
| Local fallback verdict | Local | Static analysis only - never presented as a sandbox run |
| Source labelling: LOCAL / HYBRID ENRICHMENT / CORRELATED | Local | `CORRELATED` appears only if both sources contributed |

## Forensics
| Feature | Needs | Notes |
|---|---|---|
| WAF log analysis (JSON, CSV, text) | Local | SQLi, XSS, LFI, suspicious user-agents, blocked traffic, sensitive endpoints, ... |
| NGFW log analysis (CSV) | Local | |
| Wireshark PCAP / PCAPNG | System (TShark) + PyShark | Not covered by the CI test-suite |
| IOC extraction | Local | |
| Findings, statistics | Local | Lower-severity findings are listed, not hidden |
| Attack Timeline | Local | |
| Attack Graph | Local | NumPy (optional) accelerates layout |
| Paginated raw log view | Local | SQLite-backed |
| Paste logs directly | Local | JSON arrays, NDJSON and CSV are detected |

## AI SOC Analyst
| Feature | Needs | Notes |
|---|---|---|
| Context-aware chat (CTI / Malware / Forensics) | Key (Groq) | Receives the result of the analysis that was just run |
| Quick actions (explain, recommended action, is it malicious?, executive summary) | Key (Groq) | |
| Rule-based fallback summaries | Local | |
| Output formatting (headings, risk level highlight) | Local | |

## Investigation management
| Feature | Needs | Notes |
|---|---|---|
| SQLite analysis history | Local | Created next to the application |
| History filters, search, preview | Local | |
| Investigate / Explain / Timeline actions | Local (Explain: Key) | |
| Dashboard statistics | Local | |
| PDF incident report | Local | ReportLab |

## Desktop UX
Collapsible sidebar, global header with honest system status, dark design system, resizable/collapsible side panels (state remembered),
high-DPI aware layout (audited at 100 %, 125 %, 150 % and 200 % scale on Linux with `tools/ui_audit.py`).
