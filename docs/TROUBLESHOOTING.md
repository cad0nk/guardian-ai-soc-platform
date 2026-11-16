# Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Console says `API keys MISSING (feature disabled)` | No `.env`, or the key is empty | Expected. Add your key to `.env` next to the app, or ignore it - local features still work |
| `.env` is ignored | File is in the wrong folder | Put it next to `guardian_ai_v4_fixed.py` / `guardian_ai.exe`. The start-up log prints the exact path that was searched |
| "PCAP analysis unavailable" / PyShark errors | TShark not installed or not on `PATH` | Install Wireshark (TShark component) and check `tshark --version` in a new terminal |
| `ModuleNotFoundError: PyQt5` | Virtual environment not activated / dependencies not installed | `.\.venv\Scripts\Activate.ps1` then `pip install -r requirements.txt` |
| PowerShell refuses to activate the venv | Execution policy | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| Windows SmartScreen warns about `guardian_ai.exe` | The executable is not code-signed | Verify the SHA-256 from the release notes, then choose *More info -> Run anyway* only if it matches |
| Antivirus flags the executable | PyInstaller one-file bundles are sometimes flagged heuristically | Verify the checksum; build from source yourself if in doubt (`build_windows.bat`) |
| Taskbar shows the Python icon | Pinned shortcut created before the app set its identity | Unpin, then start the application again and re-pin |
| Text is too small / blurry on a high-DPI display | OS scaling | The app enables Qt high-DPI scaling; check Windows *Display scale*, restart the app after changing it |
| Hybrid Analysis card shows `ERROR` | No key, no network, or provider limit | The message shows the real reason. Local analysis results are still valid and labelled `LOCAL ANALYSIS` |
| AI SOC Analyst says it is unavailable | No `GROQ_API_KEY` or no internet | Set the key, or use the rule-based summaries |
| Forensics list is slow with a huge file | Very large log | The preview is capped and the raw view is paginated; adjust `GUARDIAN_CSV_WARN_MB` / `GUARDIAN_CSV_MAX_MB` if needed |
| `soc_history.db` / `debug.log` appear in the project folder | Normal when running from source | Both are git-ignored |
| Tests fail on `QT_QPA_PLATFORM` / display errors (Linux) | Missing Qt system libraries | `sudo apt-get install libegl1 libgl1 libxkbcommon0 libdbus-1-3 libfontconfig1 libglib2.0-0` |
| `test_pcap_engine_available` is `skipped` | TShark is not installed | Expected; install TShark to run it |

Still stuck? Open an issue using the *Bug report* template - and **redact `debug.log`** before attaching it.
