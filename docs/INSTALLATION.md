# Installation

This guide assumes **Windows 10/11** (the primary target) and no prior Python experience.
Linux and macOS can run the application from source in the same way; only the shell commands differ.

> **Verification note.** The automated test-suite has been verified on Ubuntu with **Python 3.12**.
> Python 3.12 is the version this guide recommends. Other Python versions are untested.

## Option A - run the Windows executable

1. Open the repository's **Releases** page and download `guardian_ai.exe` from the latest release.
2. Compare the file's SHA-256 with the value in the release notes:
   ```powershell
   Get-FileHash .\guardian_ai.exe -Algorithm SHA256
   ```
3. (Optional) create a `.env` file **next to** `guardian_ai.exe` with your own API keys - see [CONFIGURATION.md](CONFIGURATION.md).
4. Double-click `guardian_ai.exe`.

The executable is **not code-signed**, so Windows SmartScreen may warn on first launch. The history database
(`soc_history.db`) and `debug.log` are created next to the executable.

## Option B - run from source

### Step 1 - Install Git and Python
- Git: <https://git-scm.com/download/win> (or use GitHub Desktop).
- Python 3.12: <https://www.python.org/downloads/> - tick **"Add python.exe to PATH"** in the installer.

### Step 2 - Clone the repository
```bash
git clone https://github.com/USERNAME/guardian-ai-soc-platform.git
cd guardian-ai-soc-platform
```

### Step 3 - Check Python
```bash
python --version
```
Expected: `Python 3.12.x`. (If you have several versions, use `py -3.12` in the next step.)

### Step 4 - Create a virtual environment
```powershell
py -3.12 -m venv .venv
```

### Step 5 - Activate it
```powershell
.\.venv\Scripts\Activate.ps1
```
If PowerShell refuses to run the script, run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, then retry.
You should now see `(.venv)` in front of your prompt.

### Step 6 - Install dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-optional.txt   # optional: PCAP parsing (PyShark) and faster graph layout (NumPy)
```
For development and tests also run `pip install -r requirements-dev.txt`.

### Step 7 - Configure API keys (optional)
```powershell
Copy-Item .env.example .env
notepad .env
```
Paste **your own** keys. Every key is optional; leave unused ones empty. The file must sit next to
`guardian_ai_v4_fixed.py` (the application looks for it in its own folder - `app_base_dir()`).
Never commit `.env`; it is git-ignored.

### Step 8 - Start the application
```bash
python guardian_ai_v4_fixed.py
```
On first start the console prints which API keys were found and which features are disabled. Missing keys are not an error.

### Optional: TShark for PCAP analysis
PCAP / PCAPNG parsing uses PyShark, which drives **TShark** - a *system program* installed with Wireshark, not a pip package.

1. Install Wireshark from <https://www.wireshark.org/download.html>; keep the **TShark** component selected.
2. Make sure `tshark` is on your `PATH`, then verify in a **new** terminal:
   ```bash
   tshark --version
   ```
Without TShark the application still runs - CTI, Malware and WAF/NGFW log analysis are unaffected; only PCAP files cannot be parsed.

### Run the tests
```bash
pip install -r requirements-dev.txt
python -m pytest
```
- Tests run headless and never contact the network or use real API keys.
- The PCAP test is **skipped** automatically when TShark is not installed (it is reported as `skipped`, not as passed).
- Windows is the primary target, but the test-suite has so far only been verified on Linux; a failure on Windows is worth reporting.

## Build the executable yourself
See [RELEASE.md](RELEASE.md).
