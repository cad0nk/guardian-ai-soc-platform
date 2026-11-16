# Architecture

This document describes the code **as it actually is**, not an idealised design.

## At a glance

guardian_ai is a single-process PyQt5 desktop application. The application logic lives in **one large module**,
`guardian_ai_v4_fixed.py` (~14,000 lines, organised into numbered sections), supported by a small `ui/` package that holds the
design system and reusable widgets. It is **not yet split into separate packages per feature** - that refactor is future work.

```text
guardian-ai-soc-platform/
├── guardian_ai_v4_fixed.py      # entry point + application logic (sections 1-14 below)
├── guardian_ai.spec             # PyInstaller build configuration
├── build_windows.bat            # one-command Windows build
├── ui/
│   ├── widgets.py               # reusable components (SidebarButton, HeaderBar, StatCard, RiskMeter, SourceCard, ...)
│   ├── icons.py                 # vector icons painted with QPainter
│   └── styles/                  # colors, typography, spacing, QSS helpers (single source of truth)
├── assets/icons/                # guardian_ai.ico / .png / .svg
├── tests/                       # pytest suite + inert fixtures (tests/fixtures/)
├── tools/                       # icon, banner, screenshot generators and a headless UI audit
└── docs/                        # documentation and screenshots
```

## Entry point and runtime paths

`python guardian_ai_v4_fixed.py` -> `main()`:

1. Sets the Windows *AppUserModelID* (so the taskbar shows the guardian_ai icon) - a no-op on other platforms.
2. Enables high-DPI scaling, creates `QApplication`, applies the global stylesheet and the application icon.
3. Shows a splash screen, builds `MainWindow`, restores window/splitter state from `QSettings`.

`resource_path()` resolves bundled read-only assets (works from source and from a PyInstaller bundle via `sys._MEIPASS`).
`app_base_dir()` resolves the writable folder for `.env`, `soc_history.db` and `debug.log` (next to the script, or next to the `.exe`).

## Sections of `guardian_ai_v4_fixed.py`

| Section | Content |
|---|---|
| 1-2 | Imports, optional-dependency guards, configuration (`.env`), logging, constants, `IOCParser`, input normalisation |
| 3 | **CTI module** - `CTIService` (VirusTotal, AbuseIPDB, Shodan, WHOIS) and result aggregation / risk scoring |
| 4 | **Malware module** - hash/URL lookups, Hybrid Analysis client, local static analysis, string extraction, pattern scan, EICAR handling |
| 5 | **Forensics module** - log/PCAP parsers, WAF/NGFW detection engine, IOC extraction, timeline, statistics |
| 6 | **AI module** - Groq client (`AISummary`) with rule-based fallbacks |
| 7-8 | UI palette, global stylesheet, reusable UI helpers |
| 9 / 9b / 9c | `Worker` / `LogParseWorker` QThreads, SQLite manager, PDF export engine |
| 9d | Analysis History panel |
| 10-13 | Pages: Dashboard, CTI, Malware, Attack Graph components, Forensics, AI SOC Analyst chat panel |
| 14 | `SmoothSplitter`, `MainWindow` (navigation, header, sidebar, panel state) |

## Data flow

```text
user input (IOC / file / log)
        │
        ▼
   Page (UI thread)  ──starts──▶  Worker / LogParseWorker (QThread)
                                         │  calls analysis function
                                         ▼
                              CTIService │ malware engine │ log parser + detection engine
                                         │
                              result dict (never raises into the UI thread)
        ▲                                │
        │            signals             ▼
   Page renders  ◀───────────────  SQLite (save_to_db) ──▶ History panel / Dashboard / PDF
        │
        ▼
 context_ready signal ──▶ AI SOC Analyst panel ──▶ Groq (optional)
```

### Threading
Network calls and heavy parsing run in `QThread` workers. Pages keep a reference to the running worker, ignore a second click while
one is running, and workers are stopped on shutdown. Results travel back to the UI thread as Qt signals.

### Degradation rules (by design)
- Missing API key -> that source is shown as **NOT CONFIGURED**; the rest keep working.
- Hybrid Analysis unreachable -> **local fallback**, labelled `LOCAL ANALYSIS`, and the Hybrid card shows the real error.
- `python-whois`, `pyshark`, `numpy` are optional imports; the application runs without them.
- TShark missing -> PCAP parsing is unavailable, everything else is unaffected.

## UI layer
- `ui/styles/colors.py` is the single source of truth for the palette (the legacy `P` dict is built from it).
- `ui/styles/qss_compat.py` rewrites legacy `#RRGGBBAA` colours (Qt reads 8-digit hex as `#AARRGGBB`) for stylesheets set from Python.
- `ui/widgets.py` holds components reused by every page; `ui/icons.py` paints vector icons so they stay sharp on high-DPI screens.

## Persistence
- **SQLite history** (`soc_history.db`): table `analysis_history(id, timestamp, module, severity, ioc, summary, raw_json)`.
- **Per-analysis SQLite files**: large log analyses are streamed into a temporary SQLite database (`logs`, `timeline_events`, aggregate tables) so the raw-log view can be paginated and memory stays bounded.
- **QSettings**: window geometry, splitter sizes, sidebar and side-panel visibility.

## Build
`guardian_ai.spec` bundles `assets/` and the `ui` package; it does **not** bundle `.env`, the database or logs.
See [RELEASE.md](RELEASE.md).

## Known structural limitations
- Single large module; no package boundaries between CTI, malware and forensics yet.
- No dependency injection for the network layer - tests block `requests` globally instead (`tests/conftest.py`).
- PCAP analysis is not exercised by the CI test-suite (it needs TShark).
