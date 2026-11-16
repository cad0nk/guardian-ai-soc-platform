# Configuration

guardian_ai is configured **only** through environment variables, normally via a local `.env` file.
No API key is stored in the source code, and none is required to open the application.

## Where the `.env` file goes

| How you run it | `.env` location |
|---|---|
| `python guardian_ai_v4_fixed.py` | next to `guardian_ai_v4_fixed.py` |
| `guardian_ai.exe` | next to `guardian_ai.exe` |

(This is the folder returned by `app_base_dir()` in the source.) Real environment variables take precedence over `.env`.
At start-up the console shows which file was looked up and which keys were found.

## Variables

| Variable | Purpose | Required? | Effect when missing |
|---|---|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal enrichment | Optional (feature-dependent) | CTI shows "API key not configured" for VirusTotal |
| `ABUSEIPDB_API_KEY` | AbuseIPDB reputation and reports | Optional (feature-dependent) | AbuseIPDB source disabled |
| `SHODAN_API_KEY` | Shodan host lookup | Optional (feature-dependent) | Shodan source disabled |
| `HYBRID_API_KEY` | Hybrid Analysis reports | Optional (feature-dependent) | **No request is sent** to Hybrid Analysis; malware analysis uses the local fallback and says so |
| `GROQ_API_KEY` | AI SOC Analyst chat and AI summaries | Optional (feature-dependent) | AI features fall back to rule-based summaries |
| `GROQ_MODEL` | Override the Groq model | Optional | Built-in default is used |
| `GUARDIAN_CSV_WARN_MB` | Size (MB) above which a tabular log asks for confirmation | Optional | `150` |
| `GUARDIAN_CSV_MAX_MB` | Maximum tabular log size (MB) | Optional | `500` |

**Nothing is strictly required.** The desktop application always opens, and the local/offline features
(local malware analysis, WAF/NGFW log forensics, history, dashboard, PDF export) keep working without any key.

## Security rules
- Never commit `.env`. `.gitignore` already excludes `.env` and `.env.*` (but keeps `.env.example`).
- Never paste keys into issues, screenshots, logs or pull requests.
- The executable never contains your keys; it reads `.env` at run time.
- If a key was ever committed or shared, **revoke/rotate it at the provider**. Deleting it from the latest commit does not remove it from Git history.

## Runtime files
Created next to the application (both are git-ignored):

| File | Content |
|---|---|
| `soc_history.db` | SQLite analysis history |
| `debug.log` | Application log - may contain indicators from your analyses; review before sharing |
