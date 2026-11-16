# Building and releasing the Windows executable

GitHub Pages cannot run a PyQt5 desktop application. Use the **repository** for source and documentation and
**GitHub Releases** for the Windows executable. Never commit `dist/`, `build/` or the `.exe` to the repository.

> **Status of the build.** `guardian_ai.spec` and `build_windows.bat` have been exercised with PyInstaller on **Linux**
> (the bundle was inspected and the binary started). **The Windows `.exe` must be built and tested on a Windows machine
> before it is published** - do not describe it as verified until you have done that.

## 1. Prerequisites
- Windows 10/11, Python 3.12 on `PATH`.
- Optional: Wireshark/TShark on the *target* PC if the build will be used for PCAP analysis.

## 2. Build
From the repository root:
```powershell
.\build_windows.bat
```
The script creates `.venv-build`, installs the **pinned** `requirements-build.txt`, regenerates the icon assets,
runs `pyinstaller guardian_ai.spec --noconfirm --clean` and prints the SHA-256 checksum.
Result: `dist\guardian_ai.exe`.

What the spec guarantees:
- `assets/` (guardian_ai icons) are bundled; the `.exe` carries the guardian_ai icon (`assets/icons/guardian_ai.ico`).
- `.env`, `soc_history.db` and `debug.log` are **not** bundled - no API key can be embedded in the executable.
- At run time the executable reads `.env` and writes the database/log **next to the `.exe`** (not into PyInstaller's temporary folder).
- UPX is disabled (it can corrupt Qt DLLs and triggers antivirus false positives).

## 3. Test the executable on a clean Windows machine
- [ ] Starts without Python installed and shows the guardian_ai icon in the title bar and the taskbar.
- [ ] Opens with no `.env` (console-less build: confirm the window appears; features without keys show "not configured").
- [ ] With a `.env` next to the `.exe`, the header status changes from `LOCAL ONLY` and the CTI/AI features work.
- [ ] Upload `tests/fixtures/sample_malware.txt` -> local analysis completes (it is inert text; it is never executed).
- [ ] `soc_history.db` and `debug.log` appear next to the `.exe`.
- [ ] PDF export works.
- [ ] PCAP: works only after installing Wireshark/TShark.
- [ ] Antivirus / SmartScreen behaviour noted in the release notes.

## 4. Checksum
```powershell
Get-FileHash .\dist\guardian_ai.exe -Algorithm SHA256
```
Paste the hash into the release notes. **Do not** call the file "signed" - it is not code-signed unless you obtain a certificate.

## 5. Publish a GitHub Release
1. Make sure `main` is green in GitHub Actions and the version/CHANGELOG are final.
2. Create the tag:
   ```bash
   git tag -a v1.0.0 -m "guardian_ai v1.0.0"
   git push origin v1.0.0
   ```
3. GitHub -> **Releases** -> *Draft a new release* -> choose tag `v1.0.0`.
4. Title: `guardian_ai v1.0.0 — AI-Powered SOC Platform`
5. Attach `guardian_ai.exe` (optionally zip it together with `.env.example` and a short README).
6. Paste the release notes below, fill in the checksum, publish.

### Release notes template
```markdown
## guardian_ai v1.0.0 - AI-Powered SOC Platform

### Overview
Desktop SOC investigation workspace: Cyber Threat Intelligence, malware analysis, WAF/NGFW/PCAP forensics, AI-assisted analysis.

### Major features
- CTI enrichment (VirusTotal, AbuseIPDB, Shodan, WHOIS)
- Malware analysis: local static analysis + optional Hybrid Analysis enrichment
- Forensics: WAF/NGFW/PCAP, IOC extraction, attack timeline and graph
- AI SOC Analyst (Groq), SQLite history, dashboard, PDF reports

### Installation
Download `guardian_ai.exe`, optionally create a `.env` next to it (see docs/CONFIGURATION.md), double-click to run.

### API configuration
All API keys are optional and user-supplied. Nothing is bundled in the executable.

### Known limitations
- Not code-signed (SmartScreen may warn).
- PCAP analysis needs Wireshark/TShark installed.
- Local malware analysis is static heuristics, not a sandbox.
- External services need your own keys and an internet connection.

### Requirements
Windows 10/11 x64. TShark only for PCAP.

### SHA-256
`<paste Get-FileHash output>`
```

## 6. Before the repository is made public
Confirm publication rights and choose a license - see the checklist in the deployment guide. Keep the repository **private**
until that is settled.
