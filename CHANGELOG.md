# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Only items that were verified are listed.

## v1.0.0 - first portfolio release

### Added
- Cyber Threat Intelligence page: IOC type detection, VirusTotal / AbuseIPDB / Shodan / WHOIS sources, per-source status cards, risk meter, raw JSON, AI summary.
- Malware Analysis page: local static analysis (strings, suspicious patterns, encoded PowerShell, network indicators, pattern scan, EICAR recognition), optional Hybrid Analysis enrichment, honest source labelling.
- Forensics page: WAF / NGFW log analysis, optional PCAP/PCAPNG via PyShark + TShark, IOC extraction, findings, statistics, Attack Timeline, Attack Graph, paginated raw logs.
- AI SOC Analyst (Groq) with context from the open analysis, quick actions and rule-based fallbacks.
- SQLite analysis history, dashboard statistics and PDF incident report.
- guardian_ai branding: shield + lightning icon (ICO with 16-256 px sizes, PNG, SVG), Windows AppUserModelID, PyInstaller spec and `build_windows.bat`.
- Design system (`ui/styles`, `ui/widgets.py`): consistent palette, typography, spacing and reusable components.
- Hermetic pytest suite (`tests/`), headless UI audit (`tools/ui_audit.py`), screenshot and banner generators, GitHub Actions workflow.

### Improved
- UI/UX: collapsible sidebar, global header with honest system status, redesigned pages and panels, responsive layouts, remembered panel state.
- Worker lifecycle: duplicate-run protection and clean shutdown of background threads.
- Log parsing and IOC classification; large logs are paginated.
- Source code and configuration prepared for publication: no hardcoded keys, runtime files kept next to the executable, synthetic inert test fixtures.

### Fixed
- Pasted JSON arrays / CSV logs were parsed as a single text record (now identical to uploading the file).
- AI SOC Analyst never received Forensics context (a type error on the IOC totals and mismatched field names).
- Analysis History preview showed "-" for Malware and Forensics fields.
- Attack Graph force layout pushed unconnected nodes ~2000 px away (graph looked empty when zoomed out).
- Hybrid Analysis requests were sent even when no API key was configured (disclosing file hashes to a third party for a lookup that could not succeed); no request is made without a key now and the UI reports "Not configured".
- The sidebar footer claimed "Powered by Anthropic & Groq" although no Anthropic service is used; it now says "AI analysis powered by Groq".
- Legacy translucent colours (`#RRGGBBAA`) were misread by Qt, producing wrong tints.
- Re-rendering a page left stale widgets from nested layouts.

### Verification notes
- Automated tests: 26 passed, 1 skipped (PCAP test needs TShark) on Ubuntu / Python 3.12, with dependencies pinned in `requirements*.txt`.
- UI audit (no clipped or squeezed widgets) at 100 %, 125 %, 150 % and 200 % scale and four window sizes, on Linux.
- The PyInstaller build was exercised on Linux; the Windows executable still has to be built and tested on Windows (see `docs/RELEASE.md`).
- Third-party API calls are not made by the test-suite.
