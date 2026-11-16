"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║  guardian_ai — AI-Powered Security Operations Center                             ║
║                                                                                  ║
║  Modules:                                                                        ║
║    1. CTI        — VirusTotal, AbuseIPDB, Shodan, WHOIS enrichment               ║
║    2. Malware    — Hybrid Analysis enrichment + local static analysis + strings  ║
║    3. Forensics  — WAF / NGFW / PCAP analysis, IOC extraction, timeline, graph   ║
║    4. AI Analyst — Groq API (context-aware) + rule-based fallback summaries      ║
║                                                                                  ║
║  Run:   python guardian_ai_v4_fixed.py                                           ║
║  Deps:  pip install -r requirements.txt   (see docs/INSTALLATION.md)             ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

# ========================
# IMPORTS
# ========================

import sys
import os
import re
import json
import calendar
import csv
import io
import math
import string
import datetime
import threading
import hashlib
import time
import base64
import logging
import asyncio
import sqlite3
import tempfile
import ipaddress
from urllib.parse import urlparse, urlsplit, urlunsplit

# ========================
# BRANDING / ASSET PATHS / WINDOWS APP IDENTITY
# ========================
APP_NAME = "guardian_ai"
APP_USER_MODEL_ID = "guardian_ai.desktop"
ICON_REL_PATH = os.path.join("assets", "icons", "guardian_ai.ico")
PNG_REL_PATH = os.path.join("assets", "icons", "guardian_ai_256.png")


def resource_path(relative_path: str) -> str:
    """Locate a bundled read-only asset in source mode and in PyInstaller builds.

    PyInstaller (onefile) unpacks to sys._MEIPASS; in source mode we use the
    directory of this file. Never returns a developer-machine absolute path.
    """
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative_path)


def app_base_dir() -> str:
    """Writable, persistent directory for .env / DB / logs.

    Source mode: next to this script (unchanged behaviour).
    Frozen exe : next to the .exe (NOT sys._MEIPASS, which is wiped on exit).
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def set_windows_app_id(app_id: str = APP_USER_MODEL_ID) -> bool:
    """Give the process its own Windows AppUserModelID so the taskbar shows our
    icon (not python.exe's) and groups windows correctly. Safe no-op elsewhere.
    Must run BEFORE QApplication / any window is created."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
        return True
    except Exception as exc:  # pragma: no cover - Windows only
        print(f"[WARN] AppUserModelID not set: {exc}", flush=True)
        return False


# Make the sibling `ui/` package importable regardless of the launch directory.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from collections import defaultdict, Counter, deque
from typing import Optional

import requests

try:
    import pyshark
except Exception:
    pyshark = None

# ── python-whois (WHOIS enrichment) ──────────────────────────────────────────
try:
    import whois as _whois_lib
    WHOIS_OK = True
except ImportError:
    _whois_lib = None
    WHOIS_OK = False

# ── ReportLab (PDF export) ────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether
    )
    from reportlab.platypus import PageBreak
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False

# ── PyQt5 ─────────────────────────────────────────────────────────────────────
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QLineEdit, QTextEdit, QFileDialog,
        QStackedWidget, QScrollArea, QFrame, QSplitter, QSplitterHandle,
        QComboBox, QProgressBar, QTabWidget, QTableWidget, QTableWidgetItem,
        QHeaderView, QSizePolicy, QTextBrowser, QMessageBox,
        QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
        QGraphicsLineItem, QGraphicsTextItem, QGraphicsItem,
        QGraphicsRectItem, QCheckBox, QGraphicsObject,
        QStyleOptionGraphicsItem, QMenu, QAction, QButtonGroup, QDialog, QGridLayout,
        QShortcut, QBoxLayout, QAbstractItemView,
    )
    from PyQt5.QtCore import (
        Qt, QThread, pyqtSignal, QPointF, QRectF, QTimer, pyqtProperty,
        QSize, QRect, QPropertyAnimation, QVariantAnimation, QEasingCurve,
        QSettings, QEvent, QPoint,
    )
    from PyQt5.QtGui import (
        QColor, QPalette, QPainter, QPen, QBrush, QFont,
        QRadialGradient, QLinearGradient, QTransform, QPolygonF,
        QPainterPath, QPainterPathStroker, QCursor, QIcon, QPixmap, QKeySequence,
    )
except ImportError:
    print("ERROR: PyQt5 not found.\nInstall with:  pip install PyQt5 requests")
    sys.exit(1)


# ========================
# CONFIG (API KEYS)
# ========================
#
# API keys are never hardcoded in this file. Provide them one of two ways:
#
#   1) Local ".env" file (recommended for dev/demo — quickest, no shell setup):
#      Create a file named ".env" next to this script (see ".env.example")
#      containing lines like:
#          VIRUSTOTAL_API_KEY=your_key_here
#          ABUSEIPDB_API_KEY=your_key_here
#          SHODAN_API_KEY=your_key_here
#          HYBRID_API_KEY=your_key_here
#          GROQ_API_KEY=your_key_here
#      Requires: pip install python-dotenv   (optional — app still runs
#      without it, it just won't auto-load ".env"; falls back to (2) below).
#      IMPORTANT: add ".env" to .gitignore so it's never committed.
#
#   2) OS environment variables (works with or without python-dotenv):
#      Windows (PowerShell):   $env:GROQ_API_KEY = "your_key_here"
#      Windows (cmd):          set GROQ_API_KEY=your_key_here
#      Linux / macOS (bash):   export GROQ_API_KEY="your_key_here"
#      Then run `python guardian_ai_v4_fixed.py` in the same terminal session.
#
try:
    from dotenv import load_dotenv
    _env_path = os.path.join(app_base_dir(), ".env")
    _dotenv_found = os.path.isfile(_env_path)
    load_dotenv(_env_path)
    print(f"[dotenv] Looking for .env at: {_env_path}")
    print(f"[dotenv] File found: {_dotenv_found}")
except ImportError:
    print("[dotenv] python-dotenv is NOT installed — run: pip install python-dotenv")
    print("[dotenv] (OS-level environment variables set via 'export'/'set' still work without it)")

_LOGGER = None
_CONFIG = None


def _default_config():
    # SECURITY: no API keys are hardcoded anywhere in this project.
    # Keys come only from environment variables (see ENV_MAP below) or a local,
    # untracked ".env" file. If a key is missing, the corresponding service is
    # treated as "not configured" and its feature is disabled; the application
    # still starts and the local/offline features keep working.
    return {
        "api_keys": {
            "virustotal": "",
            "abuseipdb": "",
            "shodan": "",
            "hybrid_analysis": "",
            "groq": "",
        }
    }


ENV_MAP = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "hybrid_analysis": "HYBRID_API_KEY",
    "groq": "GROQ_API_KEY",
}


def load_config():
    global _CONFIG
    if _CONFIG is not None:
        return _CONFIG

    cfg = _default_config()
    for key, env_name in ENV_MAP.items():
        env_val = os.getenv(env_name)
        if env_val:
            cfg["api_keys"][key] = env_val

    _CONFIG = cfg

    loaded = [env_name for key, env_name in ENV_MAP.items() if cfg["api_keys"][key]]
    missing = [env_name for key, env_name in ENV_MAP.items() if not cfg["api_keys"][key]]
    print(f"[config] API keys loaded: {loaded if loaded else '(none)'}")
    if missing:
        print(f"[config] API keys MISSING (feature disabled): {missing}")
        try:
            get_logger().warning(
                "Missing API key(s), related features will be disabled: %s",
                ", ".join(missing),
            )
        except Exception:
            pass

    return cfg


def get_config():
    return load_config()


def is_api_key_configured(service: str) -> bool:
    """Returns False if the given service's API key is empty/unset."""
    return bool(get_config().get("api_keys", {}).get(service, "").strip())


def get_logger():
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER

    logger = logging.getLogger("soc_platform")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        log_path = os.path.join(app_base_dir(), "debug.log")
        handler = logging.FileHandler(log_path, encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    _LOGGER = logger
    return logger


try:
    from PyQt5 import sip as _sip
except ImportError:                       # pragma: no cover - very old PyQt5
    import sip as _sip


def safe_single_shot(owner, delay_ms: int, fn):
    """QTimer.singleShot that is skipped when *owner* (a QObject) has been
    destroyed before the timer fires. A plain singleShot on a bound method or
    lambda raises "wrapped C/C++ object has been deleted" inside the Qt event
    loop if the widget is closed/destroyed in the meantime."""
    from PyQt5.QtCore import QTimer as _QT

    def _run():
        try:
            if _sip.isdeleted(owner):
                return
        except TypeError:
            return
        fn()
    _QT.singleShot(delay_ms, _run)


def log_event(message: str):
    try:
        get_logger().info(message)
    except Exception as exc:      # logging must never crash the app, but never fail silently either
        stream = getattr(sys, "stderr", None)      # None under pythonw / frozen GUI builds
        if stream is not None:
            try:
                stream.write(f"[log_event failed: {type(exc).__name__}: {exc}] {message}\n")
            except (OSError, ValueError):
                pass


_SECRET_LIKE = re.compile(r"[A-Za-z0-9_\-]{32,}")


# ── External API failures: one vocabulary for every integration ─────────────────────
API_AUTH_FAILED, API_PLAN_RESTRICTED, API_RATE_LIMITED = "auth_failed", "plan_restricted", "rate_limited"
API_NOT_FOUND, API_BAD_REQUEST, API_SERVICE_ERROR = "not_found", "bad_request", "service_error"
API_TIMEOUT, API_NETWORK_ERROR, API_INVALID_RESPONSE = "timeout", "network_error", "invalid_response"
API_UNEXPECTED = "unexpected_status"
API_INTERNAL = "unexpected_error"

_API_MESSAGES = {
    API_AUTH_FAILED:      "Authentication failed — check the API key",
    API_PLAN_RESTRICTED:  "Access denied — plan or permission restriction",
    API_RATE_LIMITED:     "Rate limit exceeded — retry later",
    API_NOT_FOUND:        "No intelligence found",
    API_BAD_REQUEST:      "Skipped (not valid IOC)",
    API_SERVICE_ERROR:    "Service unavailable",
    API_TIMEOUT:          "Request timed out",
    API_NETWORK_ERROR:    "Network error — service unreachable",
    API_INVALID_RESPONSE: "Unexpected response from service",
    API_UNEXPECTED:       "Unexpected response from service",
    API_INTERNAL:         "Unexpected error — see debug.log",
}
_AUTH_HINTS = ("invalid api key", "invalid key", "wrong api key", "incorrect api key", "unauthorized",
               "invalid authentication", "invalid_api_key", "api key is invalid", "authentication")


def _parse_retry_after(headers) -> int:
    try:
        val = (headers or {}).get("Retry-After")
        return max(0, int(float(val))) if val not in (None, "") else None
    except (TypeError, ValueError, AttributeError):
        return None


def classify_api_failure(service: str, status_code=None, body: str = "", headers=None, exc=None) -> dict:
    """Map an HTTP status / exception to ``{error_code, error, status, retry_after}``.
    401 -> auth_failed · 402/403 -> plan_restricted (unless the body says the key is invalid)
    429 -> rate_limited (+Retry-After) · 404 -> not_found · 400/422 -> bad_request
    5xx -> service_error · timeout / connection / bad JSON have their own codes.
    The raw body is never returned (only logged, sanitised)."""
    retry_after = None
    if exc is not None:
        name = type(exc).__name__
        if isinstance(exc, requests.exceptions.Timeout):
            code = API_TIMEOUT
        elif isinstance(exc, requests.exceptions.RequestException):
            code = API_NETWORK_ERROR
        elif isinstance(exc, (ValueError, KeyError, TypeError, AttributeError, IndexError)):
            code = API_INVALID_RESPONSE
        else:
            code = API_INTERNAL          # not a transport/parse problem: an internal error, logged in full
            import traceback
            log_event(f"{service} unexpected {name}: {exc}\n{traceback.format_exc()}")
        log_event(f"{service} API failure code={code} exc={name}")
    else:
        sc = int(status_code) if status_code is not None else 0
        low = (body or "").lower()
        if sc == 401:
            code = API_AUTH_FAILED
        elif sc in (402, 403):
            code = API_AUTH_FAILED if (sc == 403 and any(h in low for h in _AUTH_HINTS)) else API_PLAN_RESTRICTED
        elif sc == 429:
            code, retry_after = API_RATE_LIMITED, _parse_retry_after(headers)
        elif sc == 404:
            code = API_NOT_FOUND
        elif sc in (400, 422):
            code = API_BAD_REQUEST
        elif 500 <= sc <= 599:
            code = API_SERVICE_ERROR
        else:
            code = API_UNEXPECTED
        log_event(f"{service} API failure code={code} status={sc} body={_sanitize_snippet(body)}")
    msg = _API_MESSAGES[code]
    if code == API_RATE_LIMITED and retry_after:
        msg += f" ({retry_after}s)"
    return {"error_code": code, "error": msg, "retry_after": retry_after,
            "status": int(status_code) if status_code is not None else None}


class ExternalAPIError(RuntimeError):
    """Raised by LLM helpers; keeps RuntimeError compatibility, adds a stable ``code``."""
    def __init__(self, service: str, info: dict):
        super().__init__(f"{service}: {info['error']}")
        self.service, self.code, self.info = service, info["error_code"], info


def _api_failure_result(service: str, resp=None, exc=None) -> dict:
    """CTI-style failure record: {source, score:0, error, error_code[, retry_after]}."""
    info = classify_api_failure(service, getattr(resp, "status_code", None),
                                getattr(resp, "text", "") if resp is not None else "",
                                getattr(resp, "headers", None) if resp is not None else None, exc)
    out = {"source": service, "score": 0, "error": info["error"], "error_code": info["error_code"]}
    if info["retry_after"] is not None:
        out["retry_after"] = info["retry_after"]
    return out


def _sanitize_snippet(text, limit: int = 120) -> str:
    """Short, single-line, secret-scrubbed excerpt of an external response for logs.
    Never log full response bodies, API keys or authorization headers."""
    t = " ".join(str(text if text is not None else "").split())
    t = _SECRET_LIKE.sub("[redacted]", t)
    return t[:limit] + ("…" if len(t) > limit else "")


CONFIG = get_config()
LOGGER = get_logger()

VIRUSTOTAL_API_KEY = (CONFIG.get("api_keys", {}).get("virustotal") or "").strip()
ABUSEIPDB_API_KEY = (CONFIG.get("api_keys", {}).get("abuseipdb") or "").strip()
SHODAN_API_KEY = (CONFIG.get("api_keys", {}).get("shodan") or "").strip()
HYBRID_API_KEY = (CONFIG.get("api_keys", {}).get("hybrid_analysis") or "").strip()
GROQ_API_KEY = (CONFIG.get("api_keys", {}).get("groq") or "").strip()

# ─── API base URLs ────────────────────────────────────────────────────────────
HYBRID_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
# llama-3.3-70b-versatile was retired by Groq on 2026-08-16 (404 model_not_found).
# Override without editing code via GROQ_MODEL in .env / environment.
GROQ_MODEL = (os.getenv("GROQ_MODEL") or "openai/gpt-oss-120b").strip()
REQUEST_TIMEOUT = 15
MAX_PREVIEW_RECORDS = 10000
MAX_PREVIEW_PACKETS = 10000
DASHBOARD_POLL_MS = 5000      # dashboard SQLite polling interval (milliseconds)
MAX_TABLE_ROWS = 50
STREAM_CHUNK_SIZE = 2000


def _env_mb(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        val = int(float(raw))
        if val <= 0:
            raise ValueError("must be positive")
        return val
    except ValueError as exc:
        log_event(f"Ignoring invalid {name}={raw!r} ({exc}); using {default}")
        return default


# CSV/TXT (Wireshark-style) files are loaded into memory as a list of records before analysis,
# so their RAM use grows ~7 MB per MB of file (measured: 10 MB -> 155 MB peak, 100 MB -> 763 MB,
# 150 MB -> 1,049 MB). Above TABULAR_WARN_MB the user must confirm; above TABULAR_MAX_MB it is refused.
# Override with GUARDIAN_CSV_WARN_MB / GUARDIAN_CSV_MAX_MB (e.g. on a machine with less RAM).
TABULAR_WARN_MB = _env_mb("GUARDIAN_CSV_WARN_MB", 150)
TABULAR_MAX_MB = max(_env_mb("GUARDIAN_CSV_MAX_MB", 500), TABULAR_WARN_MB)
TABULAR_RAM_FACTOR = 7.0          # estimated peak RAM (MB) per MB of CSV/TXT
TABULAR_EXTENSIONS = (".csv", ".txt")


def check_tabular_size(file_path: str) -> dict:
    """Pre-flight size check for the in-memory CSV/TXT path.
    Returns {"level": "ok"|"warn"|"blocked", "size_mb", "est_ram_gb", "message"}.
    Other formats (JSONL/log/PCAP) are streamed or handled elsewhere and are always "ok"."""
    ext = os.path.splitext(str(file_path))[1].lower()
    info = {"level": "ok", "size_mb": 0.0, "est_ram_gb": 0.0, "message": "",
            "warn_mb": TABULAR_WARN_MB, "max_mb": TABULAR_MAX_MB}
    if ext not in TABULAR_EXTENSIONS:
        return info
    try:
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
    except OSError as exc:
        log_event(f"check_tabular_size: cannot stat {file_path!r}: {exc}")
        return info                              # the normal input validation reports the real problem
    est_gb = size_mb * TABULAR_RAM_FACTOR / 1024
    info.update(size_mb=round(size_mb, 1), est_ram_gb=round(est_gb, 1))
    if size_mb > TABULAR_MAX_MB:
        info["level"] = "blocked"
        info["message"] = (f"File {ext.upper().lstrip('.')} terlalu besar ({size_mb:.0f} MB; batas {TABULAR_MAX_MB} MB). "
                           f"Analisis butuh sekitar {est_gb:.1f} GB RAM (perkiraan). "
                           "Pisahkan file menjadi bagian lebih kecil atau gunakan format JSONL/log.")
    elif size_mb > TABULAR_WARN_MB:
        info["level"] = "warn"
        info["message"] = (f"File besar ({size_mb:.0f} MB). Analisis memuat seluruh data ke memori dan butuh "
                           f"sekitar {est_gb:.1f} GB RAM (perkiraan). Lanjutkan?")
    return info
DEFAULT_PAGE_SIZE = 50
MAX_FINDINGS_STORE = 5000
MAX_TIMELINE_EVENTS = 5000
TIMELINE_PAGE_SIZE = 50
SUPPORTED_FILES = {".pcap", ".pcapng", ".csv", ".txt", ".json", ".log"}


# ========================
# IOC PARSER CLASS
# ========================


class IOCParser:
    FILE_EXTENSIONS = {
        # images / web assets
        "ico", "png", "jpg", "jpeg", "gif", "svg", "webp", "bmp",
        "css", "js", "woff", "woff2", "ttf", "html", "htm",
        # server-side / scripts
        "php", "asp", "aspx", "jsp", "py", "rb", "sh", "ps1", "psm1",
        "bat", "cmd", "vbs", "vbe", "wsf", "hta", "lnk",
        # executables / installers / libraries
        "exe", "dll", "scr", "msi", "jar", "apk", "bin", "iso", "dmg",
        "sys", "elf",
        # NOTE: "com", "pl", "so" are intentionally NOT listed — they are real TLDs
        # (example.com / example.pl) and would turn legitimate domains into files.
        # data / logs / docs
        "json", "xml", "txt", "log", "yml", "yaml", "ini", "conf", "bak", "tmp",
        "csv", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "owner",
        # archives / databases
        "gz", "tar", "bz2", "xz", "zip", "rar", "7z", "tgz",
        "sql", "db", "sqlite", "pcap", "pcapng",
        # extra script / office-macro / disk-image / misc payload types
        "md", "jse", "wsh", "wsc", "reg", "cab", "vhd", "vhdx", "img", "pif",
        "docm", "xlsm", "pptm", "dotm", "eml", "msg", "cpl", "msc", "ps1xml",
        "pyc", "class", "gz", "lzma", "zst", "7zip", "dat", "dmp", "evtx",
    }
    # Trailing punctuation that commonly sticks to IOCs copied from text/chat.
    _TRAILING_PUNCT = ".,;:'\")]}>!?"
    _LABEL_REGEX = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
    DOMAIN_REGEX = re.compile(r"^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")

    def is_valid_url(self, url: str) -> bool:
        try:
            result = urlparse(url)
            return result.scheme in ("http", "https") and result.netloc != ""
        except Exception:
            return False

    def extract_domain_from_url(self, url: str) -> str:
        try:
            result = urlparse(url)
            return (result.hostname or "").lower()
        except Exception:
            return ""

    @staticmethod
    def parse_ip(value: str):
        """Return an ipaddress object for a *strictly* valid IPv4/IPv6 literal, else None.
        Uses ipaddress (rejects 999.999.999.999 and ambiguous leading zeros)."""
        v = (value or "").strip()
        if not v:
            return None
        try:
            return ipaddress.ip_address(v)
        except ValueError:
            return None

    @classmethod
    def is_valid_ip(cls, value: str) -> bool:
        return cls.parse_ip(value) is not None

    @staticmethod
    def _looks_numeric_dotted(v: str) -> bool:
        """'999.999.999.999', '1.2.3' ... — digits-and-dots only; never a domain/file."""
        return bool(re.match(r"^\d+(\.\d+)+$", v))

    @staticmethod
    def _basename(v: str) -> str:
        """Last path component, with query string / fragment removed."""
        v = re.split(r"[?#]", v, maxsplit=1)[0]
        return re.split(r"[\\/]", v)[-1]

    def is_file_like(self, value: str) -> bool:
        """True when the last path component ends in a known file extension.
        Handles double extensions (admin.sql.gz, invoice.pdf.exe), Windows/POSIX
        separators and query strings (evil.exe?x=1)."""
        v = (value or "").strip().lower()
        if not v:
            return False
        base = self._basename(v).rstrip(".")
        if not base or "." not in base:
            return False
        ext = base.rsplit(".", 1)[-1]
        return ext in self.FILE_EXTENSIONS

    def _strip_trailing_punct(self, v: str) -> str:
        return v.rstrip(self._TRAILING_PUNCT) if v else v

    def normalize_input(self, value: str) -> dict:
        raw = (value or "").strip()
        if raw.endswith("/") and len(raw) > 1:
            raw = raw.rstrip("/")
        normalized = raw.lower()
        info = self.classify_ioc(normalized)
        info["original"] = raw
        log_event(f"IOC classify: raw='{raw}' type='{info['type']}' value='{info['value']}'")
        return info

    def is_valid_domain(self, value: str) -> bool:
        """Structural domain validation (RFC 1035-ish) + not file-like.
        The extension list is only one guard; labels, length and TLD shape are
        validated independently."""
        v = (value or "").strip().lower()
        if v.endswith("/") and len(v) > 1:
            v = v.rstrip("/")
        if not v or "/" in v or "\\" in v or " " in v:
            return False
        if v.startswith("http://") or v.startswith("https://"):
            return False
        if len(v) > 253 or self._looks_numeric_dotted(v):
            return False
        labels = v.split(".")
        if len(labels) < 2 or not all(self._LABEL_REGEX.match(l) for l in labels):
            return False
        tld = labels[-1]
        if len(tld) < 2 or tld in self.FILE_EXTENSIONS:
            return False
        if not (tld.isalpha() or tld.startswith("xn--")):
            return False
        return True

    def classify_ioc(self, value: str) -> dict:
        """Order: URL -> IP -> hash -> file/path -> domain -> unknown."""
        v = (value or "").strip().lower()
        if v.endswith("/") and len(v) > 1:
            v = v.rstrip("/")
        if not v:
            return {"type": "unknown", "value": v}
        # 1. full URL
        if self.is_valid_url(v):
            return {"type": "url", "value": v}
        # Remove trailing punctuation copied with the IOC ("cmd.exe," / "evil.com.")
        v = self._strip_trailing_punct(v) or v
        # 2. IP (ipaddress, not regex); dotted-numeric junk is never a domain/file
        ip = self.parse_ip(v)
        if ip is not None:
            return {"type": "ip", "value": str(ip)}
        if self._looks_numeric_dotted(v):
            return {"type": "unknown", "value": v}
        # 3. hashes
        if re.match(r"^[a-f0-9]{32}$", v):
            return {"type": "hash_md5", "value": v}
        if re.match(r"^[a-f0-9]{40}$", v):
            return {"type": "hash_sha1", "value": v}
        if re.match(r"^[a-f0-9]{64}$", v):
            return {"type": "hash_sha256", "value": v}
        # 4. file / path (must come before domain: 'payload.ps1' matches the domain regex)
        if self.is_file_like(v):
            return {"type": "file_path", "value": v}
        # 5. domain
        if self.is_valid_domain(v):
            return {"type": "domain", "value": v}
        # Remaining path-ish / dotted tokens are never sent to domain endpoints.
        if "/" in v or "\\" in v:
            return {"type": "file_path", "value": v}
        if re.match(r"^[a-z0-9._-]+$", v) and "." in v:
            return {"type": "file_path", "value": v}
        return {"type": "unknown", "value": v}

    def _clean_ioc_value(self, value: str) -> str:
        return (value or "").strip().strip(".,;:'\"()[]{}<>")

    def extract_iocs(self, text: str) -> dict:
        patterns = [
            r"https?://[^\s\"'<>]+",
            r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b",
            r"\b[A-Za-z0-9._-]+\.(?:" + "|".join(sorted(self.FILE_EXTENSIONS, key=len, reverse=True)) + r")\b",
            r"/[A-Za-z0-9._/-]+",
        ]
        candidates = set()
        for pat in patterns:
            candidates.update(re.findall(pat, text or ""))

        results = {
            "ips": set(),
            "urls": set(),
            "domains": set(),
            "hashes": set(),
            "files": set(),
        }
        for cand in candidates:
            val = self._clean_ioc_value(cand)
            if not val:
                continue
            cls = self.classify_ioc(val)
            ctype = cls["type"]
            if ctype == "ip":
                results["ips"].add(cls["value"])
            elif ctype == "url":
                results["urls"].add(cls["value"])
            elif ctype == "domain":
                results["domains"].add(cls["value"])
            elif ctype in ("hash_md5", "hash_sha1", "hash_sha256"):
                results["hashes"].add(cls["value"])
            elif ctype == "file_path":
                results["files"].add(cls["value"])

        return {k: sorted(v) for k, v in results.items()}


# ========================
# CTI SERVICE CLASS
# ========================


class CTIService:
    def __init__(self, config: dict, parser: IOCParser):
        self.config = config or {}
        self.parser = parser

    def _get_key(self, name: str) -> str:
        return (self.config.get("api_keys", {}).get(name) or "").strip()

    def _friendly_error(self, status_code: int) -> str:
        if status_code == 400:
            return "Skipped (not valid IOC)"
        if status_code == 404:
            return "No intelligence found"
        return "Service unavailable"

    def fetch_virustotal(self, ioc: str, ioc_type: str) -> dict:
        base = "https://www.virustotal.com/api/v3"
        # Validate first: invalid IPs, files and malformed domains must never reach the network.
        if ioc_type == "domain" and not self.parser.is_valid_domain(ioc):
            return {"source": "VirusTotal", "score": 0, "error": "Skipped (not valid IOC)"}
        if ioc_type == "ip" and not self.parser.is_valid_ip(ioc):
            return {"source": "VirusTotal", "score": 0, "error": "Skipped (not valid IOC)"}
        api_key = self._get_key("virustotal")
        if not api_key:
            return {"source": "VirusTotal", "score": 0, "error": "API key not configured"}

        headers = {"x-apikey": api_key}
        ep_map = {
            "ip": f"{base}/ip_addresses/{ioc}",
            "domain": f"{base}/domains/{ioc}",
            "hash_md5": f"{base}/files/{ioc}",
            "hash_sha1": f"{base}/files/{ioc}",
            "hash_sha256": f"{base}/files/{ioc}",
        }
        url = ep_map.get(ioc_type)
        if not url:
            return {"source": "VirusTotal", "score": 0, "error": "Unsupported IOC type"}

        try:
            resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                return {
                    "source": "VirusTotal",
                    "malicious_count": malicious,
                    "total_engines": total,
                    "score": int((malicious / total) * 100),
                    "verdict": "malicious" if malicious > 0 else "clean",
                    "country": data.get("country", "N/A"),
                    "as_owner": data.get("as_owner", "N/A"),
                    "tags": data.get("tags", []),
                }
            return _api_failure_result("VirusTotal", resp=resp)
        except Exception as e:      # classified + logged; a worker thread must never die silently
            return _api_failure_result("VirusTotal", exc=e)

    def fetch_abuseipdb(self, ip: str) -> dict:
        if not self.parser.is_valid_ip(ip):
            return {"source": "AbuseIPDB", "score": 0, "error": "Skipped (not valid IOC)"}
        api_key = self._get_key("abuseipdb")
        if not api_key:
            return {"source": "AbuseIPDB", "score": 0, "error": "API key not configured"}

        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                score = d.get("abuseConfidenceScore", 0)

                # Parse verbose reports list (cap at 50 for performance)
                reports_raw = d.get("reports", []) or []
                reports = []
                for rpt in reports_raw[:50]:
                    reports.append({
                        "reportedAt": rpt.get("reportedAt", ""),
                        "comment": (rpt.get("comment") or "").strip()[:200],
                        "categories": rpt.get("categories", []),
                        "reporterCountryCode": rpt.get("reporterCountryCode", ""),
                        "reporterCountryName": rpt.get("reporterCountryName", ""),
                    })

                return {
                    "source": "AbuseIPDB",
                    "score": score,
                    "verdict": "malicious" if score > 50 else ("suspicious" if score > 20 else "clean"),
                    "country_code": d.get("countryCode", "N/A"),
                    "country_name": d.get("countryName", "N/A"),
                    "isp": d.get("isp", "N/A"),
                    "domain": d.get("domain", "N/A"),
                    "hostnames": d.get("hostnames", []),
                    "total_reports": d.get("totalReports", 0),
                    "num_distinct_users": d.get("numDistinctUsers", 0),
                    "last_reported_at": d.get("lastReportedAt", "N/A"),
                    "usage_type": d.get("usageType", "N/A"),
                    "is_tor": d.get("isTor", False),
                    "is_public": d.get("isPublic", True),
                    "reports": reports,
                }
            return _api_failure_result("AbuseIPDB", resp=resp)
        except Exception as e:      # classified + logged; a worker thread must never die silently
            return _api_failure_result("AbuseIPDB", exc=e)

    # ── per-session WHOIS cache ───────────────────────────────────────────────
    _whois_cache: dict = {}

    def fetch_whois(self, domain: str) -> dict:
        """WHOIS enrichment for a domain. Cached per session. Non-blocking when
        called from a Worker thread."""
        domain = (domain or "").strip().lower()
        if not domain or not self.parser.is_valid_domain(domain):
            return {"error": "Domain tidak valid — WHOIS dilewati"}
        if not WHOIS_OK:
            return {"error": "python-whois not installed. Run: pip install python-whois"}

        # Cache hit: skip network call
        if domain in CTIService._whois_cache:
            cached = dict(CTIService._whois_cache[domain])
            cached["cached"] = True
            return cached

        try:
            data = _whois_lib.whois(domain)
        except Exception as e:      # python-whois raises many library-specific types
            low = str(e).lower()
            if "no match" in low or "not found" in low or "no whois" in low:
                code = API_NOT_FOUND
            elif isinstance(e, (TimeoutError, OSError)) and "timed out" in low:
                code = API_TIMEOUT
            elif isinstance(e, (ConnectionError, OSError)):
                code = API_NETWORK_ERROR
            else:
                code = API_SERVICE_ERROR
            log_event(f"WHOIS failure code={code} domain={domain} exc={type(e).__name__}")
            return {"error": f"WHOIS data tidak tersedia ({type(e).__name__})", "error_code": code}

        # ── Safe date extractor: handles list / aware / naive / None ──────
        def _extract(raw):
            """Return (formatted_str, datetime_or_None).
            Strips timezone info so all arithmetic stays naive-UTC-safe."""
            v = raw
            if isinstance(v, list):
                v = v[0] if v else None
            if not isinstance(v, datetime.datetime):
                return (str(v) if v else "N/A"), None
            # Normalise to naive UTC to avoid offset-aware vs offset-naive clash
            if v.tzinfo is not None:
                v = v.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            return v.strftime("%Y-%m-%d"), v

        creation_str,   creation_dt   = _extract(data.creation_date)
        expiration_str, _             = _extract(data.expiration_date)
        updated_str,    _             = _extract(data.updated_date)

        log_event(f"WHOIS dates: creation={creation_str} creation_dt={creation_dt}")

        # ── Domain age (always naive arithmetic after _extract) ───────────
        domain_age_days = None
        domain_age_label = "Unknown"
        is_new_domain = False
        if creation_dt is not None:
            try:
                now_naive = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)  # naive UTC
                domain_age_days = (now_naive - creation_dt).days
                is_new_domain = domain_age_days < 30
                # Human-readable label
                if domain_age_days < 1:
                    domain_age_label = "kurang dari 1 hari"
                elif domain_age_days < 30:
                    domain_age_label = f"{domain_age_days} hari"
                elif domain_age_days < 365:
                    months = domain_age_days // 30
                    domain_age_label = f"{months} bulan ({domain_age_days} hari)"
                else:
                    years  = domain_age_days // 365
                    months = (domain_age_days % 365) // 30
                    parts  = [f"{years} tahun"]
                    if months:
                        parts.append(f"{months} bulan")
                    domain_age_label = " ".join(parts)
            except Exception as age_err:
                log_event(f"WHOIS domain age calc error: {age_err}")
                domain_age_days = None
                domain_age_label = "Unavailable"

        # ── Name servers ──────────────────────────────────────────────────
        ns = data.name_servers or []
        if isinstance(ns, set):
            ns = sorted(ns)
        elif not isinstance(ns, list):
            ns = [str(ns)] if ns else []
        ns = sorted({n.lower().rstrip(".") for n in ns if n})[:6]

        # ── Emails ────────────────────────────────────────────────────────
        emails = data.emails or []
        if not isinstance(emails, list):
            emails = [emails] if emails else []
        emails = [str(e) for e in emails[:3]]

        # ── Risk heuristics ───────────────────────────────────────────────
        tld = domain.rsplit(".", 1)[-1].lower()
        SUSPICIOUS_TLDS = {
            "xyz", "top", "ru", "cn", "tk", "ml", "ga", "cf", "gq",
            "pw", "cc", "su", "ws", "biz", "online", "site", "website",
            "space", "club", "win", "download", "click",
        }
        suspicious_tld = tld in SUSPICIOUS_TLDS

        registrar = (data.registrar or "").strip()
        LOW_REP_REGISTRARS = {
            "namecheap", "namesilo", "porkbun", "epik", "internetbs",
            "publicdomainregistry", "1api", "dynadot",
        }
        registrar_low_rep = any(r in registrar.lower() for r in LOW_REP_REGISTRARS)

        FREE_HOSTING_MARKERS = {"freenom", "afraid.org", "netlify", "vercel", "pages.dev"}
        uses_free_hosting = any(m in " ".join(ns) for m in FREE_HOSTING_MARKERS)

        risk_flags = []
        if is_new_domain:
            risk_flags.append(
                f"🚨 HIGH RISK: Domain baru ({domain_age_label}) — "
                "berpotensi digunakan untuk phishing/malware infrastructure"
            )
        if suspicious_tld:
            risk_flags.append(f"⚠️ TLD mencurigakan: .{tld}")
        if registrar_low_rep:
            risk_flags.append(f"⚠️ Registrar reputasi rendah: {registrar}")
        if uses_free_hosting:
            risk_flags.append("⚠️ Menggunakan free/shared hosting DNS")

        if len(risk_flags) >= 3 or is_new_domain:
            whois_risk = "HIGH"
        elif len(risk_flags) >= 1:
            whois_risk = "MEDIUM"
        else:
            whois_risk = "LOW"

        result = {
            "domain":            domain,
            "registrar":         registrar or "N/A",
            "creation_date":     creation_str,
            "expiration_date":   expiration_str,
            "updated_date":      updated_str,
            "name_servers":      ns,
            "country":           str(data.country or "N/A"),
            "emails":            emails,
            "domain_age_days":   domain_age_days,
            "domain_age_label":  domain_age_label,
            "is_new_domain":     is_new_domain,
            "suspicious_tld":    suspicious_tld,
            "registrar_low_rep": registrar_low_rep,
            "uses_free_hosting": uses_free_hosting,
            "risk_flags":        risk_flags,
            "whois_risk":        whois_risk,
            "cached":            False,
        }

        CTIService._whois_cache[domain] = result
        log_event(f"WHOIS OK: {domain} age={domain_age_days}d risk={whois_risk}")
        return result

    def fetch_shodan(self, ip: str) -> dict:
        if not self.parser.is_valid_ip(ip):
            return {"source": "Shodan", "score": 0, "error": "Skipped (not valid IOC)"}
        api_key = self._get_key("shodan")
        if not api_key:
            return {"source": "Shodan", "score": 0, "error": "API key not configured"}

        try:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key},
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                d = resp.json()
                return {
                    "source": "Shodan",
                    "score": 0,
                    "country": d.get("country_name", "N/A"),
                    "city": d.get("city", "N/A"),
                    "org": d.get("org", "N/A"),
                    "isp": d.get("isp", "N/A"),
                    "os": d.get("os", "N/A"),
                    "open_ports": d.get("ports", []),
                    "hostnames": d.get("hostnames", []),
                    "services": [
                        {
                            "port": item.get("port"),
                            "transport": item.get("transport", "tcp"),
                            "product": item.get("product", ""),
                            "banner_snippet": (item.get("banner") or "")[:100],
                        }
                        for item in d.get("data", [])[:5]
                    ],
                    "tags": d.get("tags", []),
                    "vulns": list(d.get("vulns", {}).keys()),
                }
            return _api_failure_result("Shodan", resp=resp)
        except Exception as e:      # classified + logged; a worker thread must never die silently
            return _api_failure_result("Shodan", exc=e)

    def aggregate(self, ioc: str) -> dict:
        n = self.parser.normalize_input(ioc)
        ioc_type = n["type"]
        ioc_val = n["value"]
        lookup_type = ioc_type
        lookup_val = ioc_val

        result = {
            "ioc": ioc_val,
            "type": ioc_type,
            "sources": {},
            "risk_score": 0,
            "severity": "unknown",
            "summary": {},
        }

        if ioc_type in ("file_path", "unknown"):
            result["summary"]["note"] = "Skipped (not valid IOC)"
            return result
        if ioc_type == "url":
            domain = self.parser.extract_domain_from_url(ioc_val)
            if not domain or not self.parser.is_valid_domain(domain):
                result["summary"]["note"] = "Skipped (not valid IOC)"
                return result
            result["summary"]["resolved_domain"] = domain
            lookup_type = "domain"
            lookup_val = domain

        result["sources"]["virustotal"] = self.fetch_virustotal(lookup_val, lookup_type)
        if lookup_type == "ip":
            result["sources"]["abuseipdb"] = self.fetch_abuseipdb(lookup_val)
            result["sources"]["shodan"] = self.fetch_shodan(lookup_val)
        if lookup_type == "domain":
            result["whois"] = self.fetch_whois(lookup_val)

        scores = [s.get("score", 0) for s in result["sources"].values() if "error" not in s]
        result["risk_score"] = int(sum(scores) / len(scores)) if scores else 0
        result["severity"] = score_to_severity(result["risk_score"])

        vt = result["sources"].get("virustotal", {})
        ab = result["sources"].get("abuseipdb", {})
        sh = result["sources"].get("shodan", {})
        result["summary"] = {
            "verdict": vt.get("verdict", "unknown"),
            "country": sh.get("country") or vt.get("country") or ab.get("country_code", "N/A"),
            "isp": sh.get("isp") or ab.get("isp", "N/A"),
            "org": sh.get("org", "N/A"),
            "hostnames": sh.get("hostnames", []),
            "open_ports": sh.get("open_ports", []),
            "services": sh.get("services", []),
            "vulns": sh.get("vulns", []),
            "is_tor": ab.get("is_tor", False),
            "abuse_score": ab.get("score", 0),
            "vt_malicious": vt.get("malicious_count", 0),
        }

        if result["sources"] and all("error" in s for s in result["sources"].values()):
            log_event(f"CTI lookup failed for IOC: {ioc_val}")
            result["summary"]["note"] = "No intelligence found"
        return result


# ========================
# AI SUMMARY CLASS
# ========================


class AISummary:
    def __init__(self, config: dict):
        self.config = config or {}

    def _get_groq_key(self) -> str:
        return (self.config.get("api_keys", {}).get("groq") or "").strip()

    def _format_sections(self, overview: str, findings: list, risk_level: str,
                         risk_reason: str, insight: str, recommendations: list,
                         confidence: str) -> str:
        lines = []
        lines.append("**[THREAT OVERVIEW]**")
        lines.append(overview)
        lines.append("")
        lines.append("**[KEY FINDINGS]**")
        if findings:
            lines.extend([f"- {t}" for t in findings[:5]])
        else:
            lines.append("- Tidak ada temuan signifikan.")
        lines.append("")
        lines.append("**[RISK ASSESSMENT]**")
        lines.append(f"Severity: **{risk_level}**")
        lines.append(risk_reason)
        lines.append("")
        lines.append("**[INSIGHT]**")
        lines.append(insight)
        lines.append("")
        lines.append("**[RECOMMENDATION]**")
        if recommendations:
            lines.extend([f"- {r}" for r in recommendations[:5]])
        else:
            lines.append("- Tidak diperlukan tindakan langsung.")
        lines.append("")
        lines.append("**[CONFIDENCE LEVEL]**")
        lines.append(confidence)
        return "\n".join(lines)

    def _risk_from_score(self, score: int) -> str:
        if score >= 80:
            return "HIGH"
        if score >= 50:
            return "MEDIUM"
        return "LOW"

    def _call_groq(self, prompt: str) -> str:
        api_key = self._get_groq_key()
        resp = requests.post(
            GROQ_API_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": GROQ_MODEL,
                "messages": [
                    {"role": "system", "content": "You are a SOC analyst."},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": 2000,   # headroom: gpt-oss spends tokens on reasoning
                "reasoning_effort": "low",
                "temperature": 0.3,
            },
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            try:
                return resp.json()["choices"][0]["message"]["content"]
            except (ValueError, KeyError, IndexError, TypeError) as e:
                raise ExternalAPIError("Groq", classify_api_failure("Groq", exc=e)) from e
        raise ExternalAPIError("Groq", classify_api_failure("Groq", resp.status_code, resp.text, resp.headers))

    def _severity_to_level(self, sev: str) -> str:
        s = (sev or "").lower()
        if s in ("critical", "high"):
            return "HIGH"
        if s in ("medium",):
            return "MEDIUM"
        return "LOW"

    def _action_for_ioc(self, ioc_type: str) -> str:
        if ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
            return "Blokir file hash di endpoint/XDR dan lakukan hunting."
        if ioc_type == "ip":
            return "Blokir IP di firewall/WAF dan investigasi traffic terkait."
        if ioc_type == "domain":
            return "Blokir domain di DNS/WAF dan investigasi host terkait."
        if ioc_type == "url":
            return "Blokir URL di proxy/WAF dan review access log."
        return "Validasi IOC dan lakukan enrichment tambahan."

    def _rb_cti(self, data: dict) -> str:
        summ = data.get("summary", {})
        ioc = data.get("ioc")
        verdict = summ.get("verdict", "unknown")
        risk_score = data.get("risk_score", 0)
        risiko = self._risk_from_score(_safe_score(risk_score))
        note = summ.get("note") or ""
        overview = f"IOC {ioc} terdeteksi dengan status {verdict}. {note}".strip()
        findings = [
            f"Skor risiko {risk_score}/100",
            f"Negara/ISP: {summ.get('country','N/A')} / {summ.get('isp','N/A')}",
            f"VT malicious: {summ.get('vt_malicious',0)} engine(s)",
            f"Abuse score: {summ.get('abuse_score',0)}",
        ]
        # Inject WHOIS findings into rule-based summary
        whois = data.get("whois", {})
        if whois and not whois.get("error"):
            age = whois.get("domain_age_days")
            age_label = whois.get("domain_age_label", "")
            if age is not None:
                age_info = age_label or f"{age} hari"
                findings.append(f"Domain age: {age_info} — {'⚠️ BARU, potensi phishing infrastructure' if age < 30 else 'sudah lama terdaftar'}")
            if whois.get("risk_flags"):
                for fl in whois["risk_flags"][:2]:
                    findings.append(fl)
        if verdict == "clean" or note.startswith("Skipped"):
            risk_reason = "Tidak ada intelijen yang kuat atau IOC tidak valid."
            insight = "Tidak ada indikasi reputasi buruk yang konsisten; data dapat jadi baseline monitoring."
            rekom = ["Lanjutkan monitoring bila IOC muncul kembali."]
        else:
            risk_reason = "Ada indikasi reputasi buruk pada IOC."
            insight = "IOC berpotensi terkait komunikasi berbahaya; validasi konteks penggunaan sangat disarankan."
            rekom = [self._action_for_ioc(data.get("type")), "Lakukan verifikasi konteks dan scope exposure."]
            if whois.get("is_new_domain"):
                rekom.append("Domain baru dibuat — blokir segera di DNS filter dan investigasi registrasi.")
        keyakinan = "MEDIUM" if risk_score else "LOW"
        return self._format_sections(overview, findings, risiko, risk_reason, insight, rekom, keyakinan)

    def _rb_malware(self, data: dict) -> str:
        score = _safe_score(data.get("threat_score", 0))
        verdict = data.get("verdict", "unknown")
        risiko = self._risk_from_score(score)
        overview = f"Analisis malware menunjukkan status {verdict} dengan skor {score}/100."
        findings = [
            f"Verdict: {verdict}",
            f"Threat score: {score}/100",
        ]
        risk_reason = "Indikator malware terdeteksi." if score >= 50 else "Indikasi terbatas atau tidak signifikan."
        insight = "Perlu validasi konteks eksekusi dan asal sampel." if score >= 50 else "Belum ada sinyal kuat; tetap pantau bila sampel muncul kembali."
        rekom = [
            "Isolasi endpoint terkait dan lakukan pemeriksaan EDR.",
            "Blokir hash/file jika dikonfirmasi malicious.",
        ] if score >= 50 else ["Lanjutkan monitoring dan validasi manual sampel."]
        keyakinan = "HIGH" if score >= 80 else "MEDIUM" if score >= 50 else "LOW"
        return self._format_sections(overview, findings, risiko, risk_reason, insight, rekom, keyakinan)

    def _rb_forensics(self, data: dict) -> str:
        sc = data.get("severity_counts", {})
        total = data.get("total_findings", 0)
        risiko = "HIGH" if sc.get("critical") else "MEDIUM" if sc.get("high") else "LOW"
        traffic = data.get("traffic_summary", {})
        anomalies = data.get("anomalies", [])
        if total:
            overview = f"Analisis forensics menemukan {total} kejadian dari {data.get('total_records',0)} record."
        else:
            overview = "Tidak ditemukan indikasi ancaman. Pola traffic normal teramati dan dapat dijadikan baseline monitoring."
        top_ips = [ip.get("value") for ip in data.get("top_attacker_ips", [])[:3]]
        top_domains = [d.get("value") for d in data.get("top_domains", [])[:3]]
        findings = []
        if top_ips:
            findings.append(f"Top source IP: {', '.join(top_ips)}")
        if top_domains:
            findings.append(f"Top domain: {', '.join(top_domains)}")
        if sc:
            findings.append(f"Severity breakdown: {sc}")
        if not total and traffic:
            top_src = traffic.get("top_src_ips", [])
            top_url = traffic.get("top_urls", [])
            if top_src:
                findings.append(f"Top source IP: {top_src[0]['value']} ({top_src[0]['count']})")
            if top_url:
                findings.append(f"Top URL: {top_url[0]['value']}")

        risk_reason = "Aktivitas mencurigakan terdeteksi." if total else "Pola traffic konsisten dengan aktivitas normal."
        if anomalies:
            insight = "Terdapat anomali ringan yang perlu dipantau sebagai early warning."
        else:
            insight = "Traffic menunjukkan pola investigasi yang perlu ditindaklanjuti." if total else "Traffic stabil dan dapat digunakan sebagai baseline monitoring."
        if risiko == "HIGH" and total:
            rekom = ["Blokir sumber berulang dan eskalasi ke tim IR.", "Tuning WAF/IDS untuk pola serangan."]
        elif risiko == "MEDIUM" and total:
            rekom = ["Lakukan monitoring lanjutan dan rate limiting jika perlu."]
        else:
            rekom = ["Tidak perlu tindakan langsung, lanjutkan monitoring rutin."]
        keyakinan = "MEDIUM" if total else "LOW"
        return self._format_sections(overview, findings, risiko, risk_reason, insight, rekom, keyakinan)

    def generate_summary(self, data: dict, mode: str = "cti") -> dict:
        api_key = self._get_groq_key()
        prompt = ""

        if mode == "cti":
            ioc_type = data.get("type")
            ioc = data.get("ioc")
            summary = data.get("summary", {})
            action_hint = self._action_for_ioc(ioc_type)
            # Build AbuseIPDB detail block for richer AI context
            ab = data.get("sources", {}).get("abuseipdb", {})
            abuse_detail = ""
            if ab and "error" not in ab:
                reports = ab.get("reports", []) or []
                abuse_detail = (
                    f"\n\nAbuseIPDB Detail:\n"
                    f"  Abuse Score: {ab.get('score', 0)}/100\n"
                    f"  Total Reports: {ab.get('total_reports', 0)}\n"
                    f"  Distinct Reporters: {ab.get('num_distinct_users', 0)}\n"
                    f"  Last Reported: {ab.get('last_reported_at', 'N/A')}\n"
                    f"  Country: {ab.get('country_code','N/A')} {ab.get('country_name','')}\n"
                    f"  ISP: {ab.get('isp','N/A')}\n"
                    f"  Usage Type: {ab.get('usage_type','N/A')}\n"
                    f"  Is TOR: {ab.get('is_tor', False)}\n"
                )
                if reports:
                    abuse_detail += "  Last 5 Reports:\n"
                    CMAP = {1:"DNS Compromise",2:"DNS Poisoning",3:"Fraud Orders",4:"DDoS",5:"FTP Brute-Force",
                            6:"Ping of Death",7:"Phishing",8:"Fraud VoIP",9:"Open Proxy",10:"Web Spam",
                            11:"Email Spam",12:"Blog Spam",13:"VPN IP",14:"Port Scan",15:"Hacking",
                            16:"SQL Injection",17:"Spoofing",18:"Brute-Force",19:"Bad Web Bot",
                            20:"Exploited Host",21:"Web App Attack",22:"SSH",23:"IoT Targeted"}
                    for rpt in reports[:5]:
                        cats = ", ".join(CMAP.get(c, f"#{c}") for c in (rpt.get("categories") or []))
                        ts = (rpt.get("reportedAt") or "")[:10]
                        cmt = (rpt.get("comment") or "—")[:100]
                        abuse_detail += f"    [{ts}] {cats} — {cmt}\n"
            prompt = (
                "Anda adalah Senior SOC Analyst. Gunakan Bahasa Indonesia profesional, boleh campur istilah Inggris "
                "(severity, risk, baseline). Jangan kontradiktif dan jangan overreact. Jika tidak ada threat, tetap beri insight.\n\n"
                "Format wajib:\n"
                "**[THREAT OVERVIEW]**\n...\n\n"
                "**[KEY FINDINGS]**\n- ...\n\n"
                "**[RISK ASSESSMENT]**\nSeverity: **LOW/MEDIUM/HIGH**\n...\n\n"
                "**[INSIGHT]**\n...\n\n"
                "**[RECOMMENDATION]**\n- ...\n\n"
                "**[CONFIDENCE LEVEL]**\nLOW / MEDIUM / HIGH\n\n"
                f"IOC: {ioc} ({ioc_type})\n"
                f"Summary: {json.dumps(summary, indent=2)}\n"
                f"WHOIS: {json.dumps(data.get('whois', {}), indent=2)}"
                f"{abuse_detail}\n"
                f"Rekomendasi harus mempertimbangkan: {action_hint}"
            )
        elif mode == "malware":
            report = data.get("report", {})
            prompt = (
                "Anda adalah Senior SOC Analyst. Gunakan Bahasa Indonesia profesional, boleh campur istilah Inggris "
                "(severity, risk, baseline). Jangan kontradiktif dan jangan overreact. Jika tidak ada threat, tetap beri insight.\n\n"
                "Format wajib:\n"
                "**[THREAT OVERVIEW]**\n...\n\n"
                "**[KEY FINDINGS]**\n- ...\n\n"
                "**[RISK ASSESSMENT]**\nSeverity: **LOW/MEDIUM/HIGH**\n...\n\n"
                "**[INSIGHT]**\n...\n\n"
                "**[RECOMMENDATION]**\n- ...\n\n"
                "**[CONFIDENCE LEVEL]**\nLOW / MEDIUM / HIGH\n\n"
                f"Verdict: {data.get('verdict','unknown')}\n"
                f"Score: {data.get('threat_score',0)}\n"
                f"Report: {json.dumps(report, indent=2)}"
            )
        elif mode == "forensics":
            prompt = (
                "Anda adalah Senior SOC Analyst. Analisis attack timeline berikut secara berurutan. Gunakan Bahasa Indonesia profesional, boleh campur istilah Inggris "
                "(severity, risk, baseline). Jangan kontradiktif dan jangan overreact. Jika tidak ada threat, tetap beri insight.\n\n"
                "Format wajib:\n"
                "**[THREAT OVERVIEW]**\n...\n\n"
                "**[KEY FINDINGS]**\n- ...\n\n"
                "**[RISK ASSESSMENT]**\nSeverity: **LOW/MEDIUM/HIGH**\n...\n\n"
                "**[INSIGHT]**\n...\n\n"
                "**[RECOMMENDATION]**\n- ...\n\n"
                "**[CONFIDENCE LEVEL]**\nLOW / MEDIUM / HIGH\n\n"
                "Jelaskan attacker behavior, attack stages, severity progression, dan recommended action.\n\n"
                f"Data: {json.dumps(data, indent=2)}"
            )
        else:
            prompt = (
                "Anda adalah Senior SOC Analyst. Gunakan Bahasa Indonesia profesional, boleh campur istilah Inggris "
                "(severity, risk, baseline). Jangan kontradiktif dan jangan overreact. Jika tidak ada threat, tetap beri insight.\n\n"
                "Format wajib:\n"
                "**[THREAT OVERVIEW]**\n...\n\n"
                "**[KEY FINDINGS]**\n- ...\n\n"
                "**[RISK ASSESSMENT]**\nSeverity: **LOW/MEDIUM/HIGH**\n...\n\n"
                "**[INSIGHT]**\n...\n\n"
                "**[RECOMMENDATION]**\n- ...\n\n"
                "**[CONFIDENCE LEVEL]**\nLOW / MEDIUM / HIGH\n\n"
                f"Data: {json.dumps(data, indent=2)}"
            )

        groq_error = None
        try:
            if api_key:
                return {"summary": self._call_groq(prompt), "source": "groq", "error": None}
        except ExternalAPIError as e:
            groq_error = {"code": e.code, "message": e.info["error"]}
            log_event(f"Groq API error: {e}")
        except Exception as e:      # any other failure still falls back to the rule-based summary
            info = classify_api_failure("Groq", exc=e)
            groq_error = {"code": info["error_code"], "message": info["error"]}

        fallbacks = {"cti": self._rb_cti, "malware": self._rb_malware, "forensics": self._rb_forensics}
        fb = fallbacks.get(mode, lambda d: self._format_sections(
            "Tidak ada data yang cukup untuk analisis.",
            ["Data terbatas atau kosong."],
            "LOW",
            "Keterbatasan data.",
            "Tidak ada insight yang kuat karena data minim.",
            ["Kumpulkan data tambahan jika diperlukan."],
            "LOW",
        ))
        return {"summary": fb(data), "source": "rule_based", "error": None, "llm_error": groq_error}

    def generate_local_summary(self, local_result: dict) -> dict:
        if local_result.get("is_test_artifact"):
            # Deterministic, accurate wording — never let an LLM call a test file real malware.
            summary = self._format_sections(
                "EICAR test signature detected. File ini adalah anti-malware test file standar "
                "(bukan malware aktif dan bukan confirmed real-world malware).",
                [f"Detection: {local_result.get('detection_name', 'EICAR-Test-File')}",
                 f"Evidence: {local_result.get('evidence', 'EICAR standard signature')}",
                 f"Source: {local_result.get('analysis_source', 'Local Signature Detection')}"],
                "LOW",
                "Test artifact: tidak berbahaya, namun membuktikan scanner/EDR mendeteksi signature.",
                "Jika file ini tidak sengaja dibuat sebagai uji deteksi, selidiki asal file tersebut.",
                ["Konfirmasi file berasal dari uji coba yang disengaja.",
                 "Hapus file jika tidak diperlukan."],
                "HIGH")
            return {"summary": summary, "source": "rule_based", "error": None}
        prompt = (
            "Anda adalah Senior SOC Analyst. Gunakan Bahasa Indonesia profesional, boleh campur istilah Inggris "
            "(severity, risk, baseline). Jangan kontradiktif dan jangan overreact.\n\n"
            f"Analisis data berdasarkan:\n- behaviors: {json.dumps(local_result.get('findings',[]), indent=2)}\n"
            f"- network: {json.dumps(local_result.get('network',{}), indent=2)}\n"
            f"- decoded payload: {json.dumps(local_result.get('decoded_payload',[]), indent=2)}\n\n"
            "Return output in this exact format:\n"
            "**[THREAT OVERVIEW]**\n...\n"
            "**[KEY FINDINGS]**\n- ...\n"
            "**[RISK ASSESSMENT]**\nSeverity: **LOW/MEDIUM/HIGH**\n...\n"
            "**[INSIGHT]**\n...\n"
            "**[RECOMMENDATION]**\n- ...\n"
            "**[CONFIDENCE LEVEL]**\nLOW / MEDIUM / HIGH"
        )

        try:
            if self._get_groq_key():
                return {"summary": self._call_groq(prompt), "source": "groq", "error": None}
        except Exception as e:
            log_event(f"Groq API error (local): {e}")

        score = _safe_score(local_result.get("score", 0))
        risiko = self._risk_from_score(score)
        overview = f"Analisis lokal menunjukkan skor {score}/100 dengan indikasi terbatas."
        findings = [f"Threat level: {local_result.get('threat_level','LOW')}"]
        risk_reason = "Indikasi berdasarkan analisis lokal."
        insight = "Tidak ada sinyal kuat dari perilaku maupun network, perlu verifikasi konteks eksekusi."
        rekom = ["Isolasi sampel dan lakukan validasi manual sebelum eksekusi."]
        keyakinan = "MEDIUM" if score >= 50 else "LOW"
        summary = self._format_sections(overview, findings, risiko, risk_reason, insight, rekom, keyakinan)
        return {"summary": summary, "source": "rule_based", "error": None}


IOC = IOCParser()
CTI = CTIService(CONFIG, IOC)
AI = AISummary(CONFIG)


# ========================
# HELPER FUNCTIONS (optional)
# ========================

SEVERITY_COLORS = {
    "critical": "#FF3B3B",
    "high":     "#FF8C00",
    "medium":   "#FFD700",
    "low":      "#00C896",
    "info":     "#4FC3F7",
    "unknown":  "#888888",
    "clean":    "#00C896",
}

SEVERITY_SOFT_STYLE = {
    "high":   {"bg": "#ffcccc", "text": "#990000"},
    "medium": {"bg": "#ffe5cc", "text": "#cc6600"},
    "low":    {"bg": "#e6ffe6", "text": "#006600"},
}

def is_valid_domain(value: str) -> bool:
    return IOC.is_valid_domain(value)


def classify_ioc(value: str) -> dict:
    return IOC.classify_ioc(value)


def normalize_input(value: str) -> dict:
    return IOC.normalize_input(value)


def extract_iocs(text: str) -> dict:
    return IOC.extract_iocs(text)


def is_valid_ip(ip: str) -> bool:
    """Strict IPv4/IPv6 validation via the ipaddress module."""
    return IOCParser.is_valid_ip(ip)


_LABELLED_SRC_PATTERNS = (
    re.compile(r"src[=: ]+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
    re.compile(r"source[=: ]+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
    re.compile(r"client_ip[=: ]+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
)
_ANY_IP_PATTERN = re.compile(r"(\d+\.\d+\.\d+\.\d+)")


def extract_src_ip(log_line: str, labelled_only: bool = False) -> str:
    """Best-effort source IP from free text. With labelled_only=True only an
    explicit src=/source=/client_ip= label is accepted; the "first IP in the
    line" heuristic is for unstructured text lines only, because in a
    structured record it would pick the destination IP."""
    patterns = _LABELLED_SRC_PATTERNS if labelled_only else _LABELLED_SRC_PATTERNS + (_ANY_IP_PATTERN,)
    for pat in patterns:
        m = pat.search(log_line or "")
        if m and is_valid_ip(m.group(1)):
            return m.group(1)
    return ""


def _safe_score(value) -> int:
    if value is None:
        return 0
    v = str(value).strip()
    if not v:
        return 0
    try:
        return int(float(v))
    except (ValueError, TypeError):
        return 0


def score_to_severity(score: int) -> str:
    score = _safe_score(score)
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 40: return "medium"
    if score >= 20: return "low"
    return "info"


def malware_score_to_severity(score: int) -> str:
    score = _safe_score(score)
    if score >= 80: return "high"
    if score >= 50: return "medium"
    return "low"


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — CTI MODULE
# ══════════════════════════════════════════════════════════════════════════════

def fetch_virustotal(ioc: str, ioc_type: str) -> dict:
    """Query VirusTotal for an IP, domain, URL or file hash."""
    return CTI.fetch_virustotal(ioc, ioc_type)


def fetch_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB for an IP address reputation."""
    return CTI.fetch_abuseipdb(ip)


def fetch_shodan(ip: str) -> dict:
    """Query Shodan for open ports, banners, and location."""
    return CTI.fetch_shodan(ip)


def aggregate_cti_result(ioc: str) -> dict:
    """Main CTI entry point. Normalize IOC, query all sources, aggregate."""
    return CTI.aggregate(ioc)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — MALWARE ANALYSIS MODULE
# ══════════════════════════════════════════════════════════════════════════════

# ─── Suspicious string patterns ───────────────────────────────────────────────
SUSPICIOUS_PATTERNS = {
    "powershell":   re.compile(r"powershell", re.IGNORECASE),
    "cmd.exe":      re.compile(r"cmd\.exe",   re.IGNORECASE),
    "http/https":   re.compile(r"https?://[^\s\"']+"),
    "base64":       re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    "registry":     re.compile(r"HKEY_[A-Z_]+\\[^\s\"']+", re.IGNORECASE),
    "temp_path":    re.compile(r"%TEMP%|%APPDATA%|C:\\Windows\\Temp", re.IGNORECASE),
    "net_command":  re.compile(r"\bnet\s+(user|group|localgroup|share|use)\b", re.IGNORECASE),
    "wscript":      re.compile(r"wscript|cscript|mshta|regsvr32|rundll32", re.IGNORECASE),
    "recon":        re.compile(r"\bwhoami\b|\bipconfig\b|\bnetstat\b", re.IGNORECASE),
}

# ─── YARA Mock Rules (regex-based) ───────────────────────────────────────────
YARA_MOCK_RULES = [
    {"rule_name": "Suspicious_PowerShell_Encoded",
     "description": "Detects encoded PowerShell commands",
     "pattern": re.compile(r"powershell.*-[eE]nc", re.IGNORECASE), "severity": "high"},
    {"rule_name": "Meterpreter_Shellcode",
     "description": "Detects Meterpreter-style markers (text repr)",
     "pattern": re.compile(r"\\xfc\\xe8\\x8[0-9a-fA-F]"), "severity": "critical"},
    {"rule_name": "Base64_Payload",
     "description": "Detects large base64 encoded payloads",
     "pattern": re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"), "severity": "medium"},
    {"rule_name": "Suspicious_URL_Download",
     "description": "Detects download cradle patterns",
     "pattern": re.compile(r"(WebClient|wget|curl|bitsadmin).*https?://", re.IGNORECASE), "severity": "high"},
    {"rule_name": "Ransomware_Extensions",
     "description": "Common ransomware file extension lists",
     "pattern": re.compile(r"\.(docx|xlsx|pdf|jpg|png|db)\s*→", re.IGNORECASE), "severity": "critical"},
    {"rule_name": "UAC_Bypass",
     "description": "Detects common UAC bypass techniques",
     "pattern": re.compile(r"fodhelper|eventvwr|sdclt|computerdefaults", re.IGNORECASE), "severity": "high"},
]

ALLOWED_MALWARE_EXTENSIONS = {".exe", ".dll", ".pdf", ".doc", ".ps1", ".cmd", ".txt", ".com", ".bat"}
LOCAL_ANALYSIS_CACHE = {}


def get_file_hash(file_path: str) -> str:
    """Generate SHA256 file hash using streaming reads."""
    LOGGER.debug("get_file_hash: %s", os.path.basename(str(file_path)))
    if not file_path or not os.path.isfile(file_path):
        LOGGER.warning("ERROR: File path kosong atau tidak ditemukan")
        return ""
    try:
        size = os.path.getsize(file_path)
        LOGGER.debug("get_file_hash: size=%s", size)
        if size <= 0:
            LOGGER.warning("ERROR: File size 0")
            return ""
    except Exception as e:
        LOGGER.error(f"ERROR: Cannot read file size: {e}")
        return ""

    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256.update(chunk)
    except Exception as e:
        LOGGER.error(f"ERROR: Hash generation failed: {e}")
        return ""

    hash_value = sha256.hexdigest()
    LOGGER.debug("get_file_hash: sha256=%s", hash_value)
    return hash_value


def _normalize_hash(hash_value) -> str:
    if isinstance(hash_value, bytes):
        hash_value = hash_value.decode("utf-8", errors="replace")
    if hash_value is None:
        hash_value = ""
    return str(hash_value).strip()


HYBRID_NO_KEY = "no_api_key"


def _hybrid_unconfigured():
    """Hybrid Analysis needs the user's own key. Without one NO request is sent at all:
    it could not succeed, and it would disclose the file hash to a third party for nothing."""
    if HYBRID_API_KEY:
        return None
    return {"found": False, "submitted": False, "error": "API key not configured",
            "error_code": HYBRID_NO_KEY, "message": "Hybrid Analysis API key not configured"}


def fetch_overview(sha256: str) -> dict:
    """Check Hybrid Analysis overview by sha256."""
    _g = _hybrid_unconfigured()
    if _g:
        return _g
    try:
        sha256 = _normalize_hash(sha256)
        LOGGER.debug("fetch_overview: sha256=%r", sha256)
        if not sha256:
            log_event("Hybrid Analysis overview: empty hash")
            LOGGER.warning("ERROR: Hash kosong")
            return {"found": False, "error": "Hash kosong"}

        url = f"{HYBRID_BASE_URL}/overview/{sha256}"
        resp = requests.get(
            url,
            headers={
                "api-key": HYBRID_API_KEY,
                "user-agent": "Falcon Sandbox",
                "Accept": "application/json",
            },
            timeout=REQUEST_TIMEOUT,
        )
        LOGGER.debug(f"OVERVIEW STATUS: {resp.status_code} | {_sanitize_snippet(resp.text)}")
        if resp.status_code == 200:
            try:
                data = resp.json() or {}
            except ValueError as e:
                log_event(f"Hybrid Analysis overview JSON error: {e} | {_sanitize_snippet(resp.text)}")
                LOGGER.warning(f"Hybrid Analysis overview JSON error: {e} | {_sanitize_snippet(resp.text)}")
                return {"found": False, "error": "Invalid JSON response"}

            if isinstance(data, list):
                data = data[0] if data else {}
            if not data:
                return {"found": False, "error": None}

            verdict = data.get("verdict") or "unknown"
            threat_score = _safe_score(data.get("threat_score") or data.get("score"))
            classification = data.get("classification") or data.get("classification_tag") or ""
            analysis_summary = data.get("analysis_summary") or data.get("summary") or ""
            LOGGER.debug("threat_score=%s", threat_score)
            LOGGER.debug("verdict=%s", verdict)
            return {
                "found": True,
                "verdict": verdict,
                "threat_score": threat_score,
                "classification": classification,
                "analysis_summary": analysis_summary,
            }
        if resp.status_code == 404:
            return {"found": False, "error": None, "error_code": API_NOT_FOUND}     # no report for this hash
        f = _api_failure_result("Hybrid Analysis", resp=resp)
        return {"found": False, "error": f["error"], "error_code": f["error_code"],
                **({"retry_after": f["retry_after"]} if "retry_after" in f else {})}
    except Exception as e:      # classified + logged; a worker thread must never die silently
        f = _api_failure_result("Hybrid Analysis", exc=e)
        return {"found": False, "error": f["error"], "error_code": f["error_code"]}


def _parse_quick_scan_result(data: dict) -> dict:
    verdict = data.get("verdict") or "unknown"
    threat_score = _safe_score(data.get("threat_score") or data.get("score"))
    detected = data.get("detected") if data.get("detected") is not None else data.get("malicious", None)
    classification = data.get("classification") or data.get("classification_tag") or ""
    LOGGER.debug("threat_score=%s", threat_score)
    LOGGER.debug("verdict=%s", verdict)
    return {
        "verdict": verdict,
        "threat_score": threat_score,
        "detected": detected,
        "classification": classification,
    }


def poll_quick_scan(scan_id: str, poll_interval: int = 5, max_attempts: int = 10) -> dict:
    """Poll quick scan status until available or timeout."""
    _g = _hybrid_unconfigured()
    if _g:
        return _g
    scan_id = _normalize_hash(scan_id)
    if not scan_id:
        log_event("Hybrid Analysis quick-scan: empty scan id")
        return {"found": False, "error": "Scan ID kosong"}
    for i in range(max_attempts):
        LOGGER.debug(f"POLLING {i + 1}/{max_attempts} for scan_id={scan_id}")
        resp = requests.get(
            f"{HYBRID_BASE_URL}/quick-scan/{scan_id}",
            headers={
                "api-key": HYBRID_API_KEY,
                "user-agent": "Falcon Sandbox",
                "Accept": "application/json",
            },
            timeout=REQUEST_TIMEOUT,
        )
        LOGGER.debug(f"QUICK SCAN STATUS: {resp.status_code} | {_sanitize_snippet(resp.text)}")
        if resp.status_code == 200:
            try:
                data = resp.json() or {}
            except ValueError as e:
                log_event(f"Hybrid Analysis quick-scan JSON error: {e} | {_sanitize_snippet(resp.text)}")
                LOGGER.warning(f"Hybrid Analysis quick-scan JSON error: {e} | {_sanitize_snippet(resp.text)}")
                return {"found": False, "error": "Invalid JSON response"}
            status = str(data.get("status", data.get("state", ""))).lower()
            is_done = data.get("finished") is True or status in ("done", "finished", "completed", "success", "succeeded")
            has_result = any(k in data for k in ("verdict", "score", "threat_score", "detected"))
            if is_done or has_result:
                parsed = _parse_quick_scan_result(data)
                return {"found": True, **parsed}
        elif resp.status_code in (202, 204):
            pass
        elif resp.status_code == 404:
            log_event(f"Hybrid Analysis quick-scan not found: {scan_id}")
            return {"found": False, "error": "No report found for this scan", "error_code": API_NOT_FOUND}
        else:
            f = _api_failure_result("Hybrid Analysis", resp=resp)
            return {"found": False, "error": f["error"], "error_code": f["error_code"]}
        time.sleep(poll_interval)
    return {"found": False, "error": None, "pending": True}


def test_hash_request():
    test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    res = requests.get(
        f"{HYBRID_BASE_URL}/overview/{test_hash}",
        headers={
            "api-key": HYBRID_API_KEY,
            "user-agent": "Falcon Sandbox",
            "Accept": "application/json",
        },
        timeout=REQUEST_TIMEOUT,
    )
    LOGGER.debug("Hybrid Analysis key check: status=%s body=%s", res.status_code, _sanitize_snippet(res.text))


def test_api():
    url = f"{HYBRID_BASE_URL}/key/current"
    res = requests.get(
        url,
        headers={
            "api-key": HYBRID_API_KEY,
            "user-agent": "Falcon Sandbox",
        },
        timeout=REQUEST_TIMEOUT,
    )
    LOGGER.debug("Hybrid Analysis key check: status=%s body=%s", res.status_code, _sanitize_snippet(res.text))


def poll_analysis_result(hash_value: str, poll_interval: int = 5, max_attempts: int = 12) -> dict:
    """Poll Hybrid Analysis quick scan until available or timeout reached."""
    return poll_quick_scan(hash_value, poll_interval=poll_interval, max_attempts=max_attempts)


def search_report(hash_value: str) -> dict:
    """Search Hybrid Analysis overview by hash."""
    return fetch_overview(hash_value)


def quick_scan_file(file_path: str) -> dict:
    """Quick scan a file with Hybrid Analysis."""
    _g = _hybrid_unconfigured()
    if _g:
        return _g
    try:
        url = f"{HYBRID_BASE_URL}/quick-scan/file"
        with open(file_path, "rb") as f:
            resp = requests.post(
                url,
                headers={"api-key": HYBRID_API_KEY, "user-agent": "Falcon Sandbox", "Accept": "application/json"},
                files={"file": (os.path.basename(file_path), f)},
                timeout=REQUEST_TIMEOUT,
            )
        LOGGER.debug("quick-scan url=%s", _sanitize_snippet(url, 200))
        LOGGER.debug(f"QUICK SCAN STATUS: {resp.status_code} | {_sanitize_snippet(resp.text)}")
        if resp.status_code in (200, 201):
            data = resp.json()
            scan_id = data.get("scan_id") or data.get("id") or data.get("job_id")
            LOGGER.debug("quick-scan scan_id=%s", scan_id)
            return {"submitted": True, "scan_id": scan_id, "message": "Quick scan submitted. Analysis pending."}
        if resp.status_code == 404:
            log_event("Hybrid Analysis quick-scan unavailable: HTTP 404")
            return {"submitted": False, "error": "Submission not available in current API plan",
                    "error_code": API_PLAN_RESTRICTED,
                    "message": "Submission not available in current API plan"}
        f = _api_failure_result("Hybrid Analysis", resp=resp)
        return {"submitted": False, "error": f["error"], "error_code": f["error_code"]}
    except Exception as e:      # classified + logged; a worker thread must never die silently
        f = _api_failure_result("Hybrid Analysis", exc=e)
        return {"submitted": False, "error": f["error"], "error_code": f["error_code"]}


def submit_url_sample(url_to_scan: str) -> dict:
    """Submit a URL for analysis."""
    _g = _hybrid_unconfigured()
    if _g:
        return _g
    try:
        resp = requests.post(
            f"{HYBRID_BASE_URL}/submit/url-for-analysis",
            headers={"api-key": HYBRID_API_KEY, "User-Agent": "Falcon Sandbox", "Accept": "application/json"},
            data={"url": url_to_scan, "environment_id": 110},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code in (200, 201):
            data = resp.json()
            return {"submitted": True, "job_id": data.get("job_id", ""),
                    "message": "URL submitted. Analysis pending."}
        f = _api_failure_result("Hybrid Analysis", resp=resp)
        return {"submitted": False, "error": f["error"], "error_code": f["error_code"]}
    except Exception as e:      # classified + logged; a worker thread must never die silently
        f = _api_failure_result("Hybrid Analysis", exc=e)
        return {"submitted": False, "error": f["error"], "error_code": f["error_code"]}


def extract_strings(file_path: str, min_len: int = 4, max_strings: int = 500) -> dict:
    """Extract printable strings from a binary file (like Unix `strings`)."""
    try:
        printable = set(string.printable)
        strings_found, current = [], []
        stop = False
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                for byte in chunk:
                    char = chr(byte)
                    if char in printable and char not in ('\r', '\n'):
                        current.append(char)
                    else:
                        if len(current) >= min_len:
                            strings_found.append("".join(current))
                            if len(strings_found) >= max_strings:
                                stop = True
                                break
                        current = []
                if stop:
                    break
        if not stop and len(current) >= min_len:
            strings_found.append("".join(current))
    except Exception as e:
        return {"error": str(e), "strings": [], "suspicious": {}}

    strings_found = list(dict.fromkeys(strings_found))[:max_strings]
    text_blob = "\n".join(strings_found)
    suspicious = {
        label: list(set(pattern.findall(text_blob)))[:10]
        for label, pattern in SUSPICIOUS_PATTERNS.items()
        if pattern.findall(text_blob)
    }
    return {"total_strings": len(strings_found), "strings": strings_found[:200],
            "suspicious": suspicious, "has_suspicious": bool(suspicious)}


def yara_scan_mock(file_path: str) -> dict:
    """Scan file with mock YARA rules (regex-based)."""
    try:
        with open(file_path, "rb") as f:
            text = f.read(10 * 1024 * 1024).decode("utf-8", errors="replace")
    except Exception as e:
        return {"error": str(e), "matches": [], "risk": "unknown"}

    matches = [
        {"rule": r["rule_name"], "description": r["description"], "severity": r["severity"]}
        for r in YARA_MOCK_RULES if r["pattern"].search(text)
    ]
    sevs = {m["severity"] for m in matches}
    risk = "critical" if "critical" in sevs else "high" if "high" in sevs else \
           "medium" if "medium" in sevs else "low" if matches else "clean"
    return {"matches": matches, "total_matches": len(matches), "risk": risk,
            "note": "Mock YARA scan (regex-based)."}


def normalize_content(text: str) -> str:
    if not text:
        return ""
    cleaned = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    try:
        cleaned = bytes(cleaned, "utf-8", errors="ignore").decode("unicode_escape", errors="ignore")
    except Exception:
        pass
    cleaned = cleaned.lower()
    cleaned = re.sub(r"\s+", " ", cleaned)
    cleaned = cleaned.replace("powershell.exe", "powershell")
    cleaned = cleaned.replace("cmd.exe", "cmd")
    return cleaned.strip()


def detect_base64_strings(text: str) -> list:
    if not text:
        return []
    matches = re.findall(r"[A-Za-z0-9+/=]{20,}", text)
    return list(dict.fromkeys(matches))[:200]


def _decode_base64_candidate(candidate: str) -> Optional[str]:
    s = candidate.strip()
    if len(s) < 20:
        return None
    pad = "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s + pad)
    except Exception:
        return None
    decoded = raw.decode("utf-8", errors="replace")
    if not decoded:
        return None
    printable = sum(1 for c in decoded if c in string.printable)
    ratio = printable / max(1, len(decoded))
    if ratio < 0.6:
        return None
    return decoded


def decode_base64_strings(matches: list, max_decoded: int = 20) -> list:
    decoded = []
    for m in matches:
        d = _decode_base64_candidate(m)
        if d:
            decoded.append(d)
            if len(decoded) >= max_decoded:
                break
    return list(dict.fromkeys(decoded))


def decode_powershell_encoded_commands(text: str, max_decoded: int = 10) -> list:
    decoded = []
    for m in re.findall(r"-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE):
        pad = "=" * (-len(m) % 4)
        try:
            raw = base64.b64decode(m + pad)
            d = raw.decode("utf-16le", errors="replace")
        except Exception:
            continue
        if d.strip():
            decoded.append(d)
        if len(decoded) >= max_decoded:
            break
    return list(dict.fromkeys(decoded))


def detect_behaviors(content: str) -> list:
    findings = []

    def add(technique, evidence, severity):
        findings.append({"technique": technique, "evidence": evidence, "severity": severity})

    c = content
    if "iex" in c and "downloadstring" in c:
        add("RCE via IEX DownloadString", "iex + downloadstring", "HIGH")
    if "invoke-expression" in c and "http" in c:
        add("RCE via Invoke-Expression", "invoke-expression + http", "HIGH")

    if "downloadfile" in c:
        add("Download and Execute", "downloadfile", "HIGH")
    if "wget" in c and "chmod" in c and ("./" in c or "bash" in c or "sh " in c):
        add("Download and Execute", "wget + chmod + execute", "HIGH")
    if "curl" in c and ("| sh" in c or "|bash" in c or "| powershell" in c):
        add("Download and Execute", "curl + pipe to shell", "HIGH")

    if "schtasks" in c or "reg add" in c or "startup" in c:
        add("Persistence", "schtasks/reg add/startup", "MEDIUM")

    if "net user" in c or "whoami" in c or "systeminfo" in c:
        add("Privilege/Discovery", "net user/whoami/systeminfo", "MEDIUM")

    if "-enc" in c or "encodedcommand" in c:
        add("Obfuscation", "powershell -enc", "MEDIUM")
    if re.search(r"[A-Za-z0-9+/=]{60,}", c):
        add("Obfuscation", "long base64 string", "MEDIUM")

    if "nc " in c or "netcat" in c:
        add("Reverse Shell", "nc/netcat", "HIGH")
    if "bash -i" in c:
        add("Reverse Shell", "bash -i", "HIGH")
    if "tcpclient" in c and "powershell" in c:
        add("Reverse Shell", "powershell tcpclient", "HIGH")

    return findings


def extract_network(content: str) -> dict:
    urls = list(dict.fromkeys(re.findall(r"https?://[^\s]+", content)))
    ips = list(dict.fromkeys(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", content)))
    suspicious_domains = ["pastebin", "ngrok", "raw.githubusercontent"]
    suspicious = []
    for url in urls:
        try:
            host = urlparse(url).netloc.lower()
        except Exception:
            host = ""
        if host and any(s in host for s in suspicious_domains):
            suspicious.append(host)
    for s in suspicious_domains:
        if s in content:
            suspicious.append(s)
    return {
        "urls": urls,
        "ips": ips,
        "suspicious": list(dict.fromkeys(suspicious)),
    }


def calculate_score(findings: list, network: dict, decoded: list) -> int:
    score = 0
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev == "HIGH":
            score += 40
        elif sev == "MEDIUM":
            score += 20
        else:
            score += 10
    if network.get("suspicious"):
        score += 20
    if network.get("urls") or network.get("ips"):
        score += 10
    if decoded:
        score += 15
    return min(100, score)


def verdict_from_score(score: int) -> tuple:
    if score >= 70:
        return "MALICIOUS", "HIGH"
    if score >= 30:
        return "SUSPICIOUS", "MEDIUM"
    return "CLEAN", "LOW"


EICAR_MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
# Full 68-byte standard EICAR test string (https://www.eicar.org).
EICAR_SIGNATURE = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_MAX_FILE_SIZE = 128   # per the EICAR spec: file must not exceed 128 bytes


def is_eicar_test_file(file_path: str) -> bool:
    """True only for a *valid* EICAR test file: the full 68-byte signature at the
    start of the file, optionally followed by whitespace/CR/LF/Ctrl-Z, <=128 bytes.
    Binary-safe, extension-independent, offline. A file that merely *mentions* the
    marker (docs, rules, partial/altered strings) does not match."""
    try:
        with open(file_path, "rb") as fh:
            data = fh.read(EICAR_MAX_FILE_SIZE + 1)
    except OSError as exc:
        log_event(f"EICAR check could not read {file_path}: {exc}")
        return False
    if len(data) > EICAR_MAX_FILE_SIZE or not data.startswith(EICAR_SIGNATURE):
        return False
    return data[len(EICAR_SIGNATURE):].strip(b" \t\r\n\x1a") == b""


def _has_static_signature(file_path: str, marker: bytes, max_bytes: int = 1024 * 1024) -> bool:
    """Return True if *marker* appears in the first *max_bytes* of the file."""
    try:
        with open(file_path, "rb") as fh:
            return marker in fh.read(max_bytes)
    except OSError as exc:
        log_event(f"static signature scan could not read {file_path}: {exc}")
        return False


def run_local_analysis(file_path: str) -> dict:
    file_hash = get_file_hash(file_path)
    if file_hash in LOCAL_ANALYSIS_CACHE:
        return LOCAL_ANALYSIS_CACHE[file_hash]

    # Static signature layer (works fully offline, independent of behavioural
    # heuristics): the EICAR anti-malware test string is the universal "is the
    # scanner actually scanning?" check and must always be detected.
    eicar_hit = is_eicar_test_file(file_path)

    strings_data = extract_strings(file_path, min_len=4)
    strings_sample = strings_data.get("strings", [])
    text_blob = "\n".join(strings_sample)
    normalized = normalize_content(text_blob)

    base64_matches = detect_base64_strings(normalized)
    decoded_payload = decode_base64_strings(base64_matches)
    decoded_payload += decode_powershell_encoded_commands(normalized)
    decoded_payload = list(dict.fromkeys(decoded_payload))[:20]

    combined = normalized + "\n" + "\n".join(decoded_payload)
    findings = detect_behaviors(combined)
    network = extract_network(combined)
    if eicar_hit:
        findings.insert(0, {
            "technique": "EICAR Anti-Malware Test File",
            "evidence": "Full 68-byte EICAR standard test signature found at start of file "
                        "(harmless test artifact, not active malware)",
            "severity": "HIGH",
        })
    score = calculate_score(findings, network, decoded_payload)
    if eicar_hit:
        score = 100   # signature match is definitive (non-clean)
    verdict, threat_level = verdict_from_score(score)
    if eicar_hit:
        verdict = "TEST_SIGNATURE"   # NOT "MALICIOUS": a test artifact is not real malware

    result = {
        "verdict": verdict,
        "threat_level": threat_level,
        "score": score,
        "findings": findings,
        "strings_sample": strings_sample[:200],
        "decoded_payload": decoded_payload,
        "network": network,
        "analysis_source": "Local Signature Detection" if eicar_hit else "Local Static Heuristics",
        "is_test_artifact": bool(eicar_hit),
    }
    if eicar_hit:
        result.update({
            "detection_name": "EICAR-Test-File",
            "detection_type": "test_signature",
            "evidence": "EICAR test signature detected (standard 68-byte string)",
            "severity": "high",
            "note": "EICAR test signature detected — this is a standard anti-malware test "
                    "file, not confirmed real-world malware.",
        })
    LOCAL_ANALYSIS_CACHE[file_hash] = result
    return result


def analyze_malware(input_value: str, file_path: str = None) -> dict:
    """Main malware analysis entry point."""
    result = {"input": input_value, "report": {}, "strings": {}, "yara": {},
               "verdict": "unknown", "threat_score": 0, "severity": "unknown"}
    api_failed = False

    if file_path:
        if not os.path.isfile(file_path):
            return {"input": input_value or str(file_path),
                    "report": {"error": "File path tidak ditemukan"},
                    "strings": {}, "yara": {},
                    "verdict": "unknown", "threat_score": 0, "severity": "unknown"}
        try:
            size = os.path.getsize(file_path)
        except Exception as e:
            return {"input": input_value or os.path.basename(file_path),
                    "report": {"error": f"Tidak bisa membaca ukuran file: {e}"},
                    "strings": {}, "yara": {},
                    "verdict": "unknown", "threat_score": 0, "severity": "unknown"}
        if size <= 0:
            return {"input": input_value or os.path.basename(file_path),
                    "report": {"error": "File size 0"},
                    "strings": {}, "yara": {},
                    "verdict": "unknown", "threat_score": 0, "severity": "unknown"}

        ext = os.path.splitext(file_path)[1].lower()
        if ext not in ALLOWED_MALWARE_EXTENSIONS:
            return {"input": input_value or os.path.basename(file_path),
                    "report": {"error": f"Unsupported file type: {ext}"},
                    "strings": {}, "yara": {},
                    "verdict": "unknown", "threat_score": 0, "severity": "unknown"}

        result["input"] = input_value or os.path.basename(file_path)
        result["strings"] = extract_strings(file_path)
        result["yara"]    = yara_scan_mock(file_path)

        file_hash = get_file_hash(file_path)
        if not file_hash or not file_hash.strip():
            LOGGER.warning("empty hash")
            return {"input": input_value or os.path.basename(file_path),
                    "report": {"error": "Hash kosong"},
                    "strings": {}, "yara": {},
                    "verdict": "unknown", "threat_score": 0, "severity": "unknown"}
        overview = fetch_overview(file_hash)
        result["enrichment"] = {
            "source": "Hybrid Analysis",
            "status": ("found" if overview.get("found")
                       else (overview.get("error_code") or ("not_found" if not overview.get("error") else "error"))),
            "error": overview.get("error"),
        }
        if overview.get("found"):
            result["report"] = {
                "found": True,
                "sha256": file_hash,
                "verdict": overview.get("verdict") or "unknown",
                "threat_score": _safe_score(overview.get("threat_score")),
                "analysis_summary": overview.get("analysis_summary") or "",
                "classification": overview.get("classification") or "",
            }
        else:
            local = run_local_analysis(file_path)
            result["local_analysis"] = local
            verdict = local.get("verdict", "UNKNOWN").lower()
            score = _safe_score(local.get("score"))
            threat_level = local.get("threat_level", "LOW")
            result["report"] = {
                "found": True,
                "local_analysis": True,
                "sha256": file_hash,
                "verdict": verdict,
                "threat_score": score,
                "analysis_summary": f"Local analysis score {score}/100 | Threat {threat_level}",
                "classification": threat_level,
                "findings": local.get("findings", []),
                "decoded_payload": local.get("decoded_payload", []),
                "network_connections": {
                    "urls": local.get("network", {}).get("urls", []),
                    "ips": local.get("network", {}).get("ips", []),
                    "suspicious": local.get("network", {}).get("suspicious", []),
                },
                "note": local.get("note") or "Local analysis fallback",
                "analysis_source": local.get("analysis_source", "Local Static Heuristics"),
                "is_test_artifact": bool(local.get("is_test_artifact")),
                **({"detection_name": local["detection_name"],
                    "evidence": local["evidence"]} if local.get("is_test_artifact") else {}),
            }

        if result["report"].get("found"):
            result["threat_score"] = _safe_score(result["report"].get("threat_score"))
            result["verdict"]      = result["report"].get("verdict") or "unknown"
            result["severity"]     = malware_score_to_severity(result["threat_score"])
    else:
        n = normalize_input(input_value)
        if n["type"] in ("hash_md5", "hash_sha1", "hash_sha256"):
            report = search_report(input_value)
            result["report"] = report
            if report.get("found"):
                result["report"] = {
                    "found": True,
                    "sha256": n.get("value"),
                    "verdict": report.get("verdict") or "unknown",
                    "threat_score": _safe_score(report.get("threat_score")),
                    "analysis_summary": report.get("analysis_summary") or "",
                    "classification": report.get("classification") or "",
                }
                result["threat_score"] = _safe_score(result["report"].get("threat_score"))
                result["verdict"]      = result["report"].get("verdict") or "unknown"
                result["severity"]     = malware_score_to_severity(result["threat_score"])
            elif report.get("error"):
                api_failed = True
            else:
                result["report"]["message"] = "No result found."
        elif n["type"] == "url":
            report = submit_url_sample(input_value)
            result["report"] = report
            if report.get("error"):
                api_failed = True
        else:
            result["report"] = {"error": "Input must be a hash, URL, or file path"}

    if api_failed:
        result["report"].setdefault("error", "API unavailable or no data")
        return result

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — FORENSICS MODULE
# ══════════════════════════════════════════════════════════════════════════════

STANDARD_SCHEMA = [
    "timestamp", "src_ip", "dst_ip", "url", "method",
    "status_code", "action", "user", "device_type", "user_agent", "bytes", "port", "protocol",
    "src_port", "dst_port",
]

# ─── Detection patterns ───────────────────────────────────────────────────────
RE_SQLI   = re.compile(r"('|\%27)\s*(OR|AND)\s*\d*\s*=\s*\d+|UNION\s+(ALL\s+)?SELECT|;\s*(DROP|ALTER|INSERT|DELETE)\s+|SLEEP\s*\(\d+\)", re.IGNORECASE)
RE_XSS    = re.compile(r"<script[\s>]|javascript:|on\w+\s*=|<iframe|document\.(cookie|write)|eval\s*\(|alert\s*\(", re.IGNORECASE)
RE_LFI    = re.compile(r"\.\./|\.\.\\|/etc/(passwd|shadow|hosts)|boot\.ini|win\.ini|%2e%2e[/%]", re.IGNORECASE)
RE_CMDI   = re.compile(r";\s*(ls|cat|id|whoami|uname|wget|curl|nc|bash|sh)\b|&&\s*\w+|\|\s*\w+|\$\([^)]+\)", re.IGNORECASE)
RE_UA_BAD = re.compile(r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|medusa|python-requests/|libwww-perl|scanner|exploit|metasploit|havij", re.IGNORECASE)
RE_SENS   = re.compile(r"/(admin|login|wp-admin|wp-login|phpmyadmin|cpanel|xmlrpc|config|setup|install|backup|\.env|\.git|shell|webshell|eval)", re.IGNORECASE)

BENIGN_PATHS = [
    "favicon.ico",
    "robots.txt",
    "sitemap.xml",
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".svg",
]

STATIC_EXTENSIONS = {"ico", "png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "woff", "woff2", "ttf"}
SUSPICIOUS_DOMAIN_KEYWORDS = {"c2", "malware", "bot", "panel", "steal", "phish", "update", "gate", "command", "control"}

APACHE_LOG_RE = re.compile(
    r'(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status_code>\d+)\s+(?P<bytes>\S+)'
    r'(?:\s+"[^"]*"\s+"(?P<user_agent>[^"]*)")?'
)


def _parse_plain_text_line(line: str) -> dict:
    m = APACHE_LOG_RE.match(line)
    if m:
        d = m.groupdict()
        d["action"] = "allow" if int(d.get("status_code", 200)) < 400 else "block"
        return d
    src_ip = extract_src_ip(line)
    return {"raw": line, "timestamp": "", "src_ip": src_ip or "unknown", "url": line[:200]}


def parse_log(raw: str) -> list:
    """Parse JSON, NDJSON, CSV, or plain-text logs."""
    s = raw.strip()
    if s.startswith("["):
        try:
            r = json.loads(s)
            if isinstance(r, list):
                return [x for x in r if isinstance(x, dict)]
        except json.JSONDecodeError as e:
            LOGGER.warning(f"Parsing error: JSON array parse failed: {e}")
    if s.startswith("{"):
        records = []
        for line in s.splitlines():
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        if records:
            return records
    try:
        rows = [dict(r) for r in csv.DictReader(io.StringIO(s))]
        if rows: return rows
    except Exception as e:
        LOGGER.warning(f"Parsing error: CSV parse failed: {e}")
    # Plain text (Apache/Nginx CLF)
    records = []
    for line in s.splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        records.append(_parse_plain_text_line(line))
    return records


ALT_FIELD_MAP = {
    "time": "timestamp", "datetime": "timestamp", "@timestamp": "timestamp", "date": "timestamp",
    "source_ip": "src_ip", "sourceip": "src_ip", "src": "src_ip", "client_ip": "src_ip",
    "clientip": "src_ip", "remote_addr": "src_ip",
    "destination_ip": "dst_ip", "dst": "dst_ip", "dest_ip": "dst_ip",
    "request_uri": "url", "uri": "url", "path": "url", "request": "url",
    "http_method": "method", "request_method": "method", "verb": "method",
    "status": "status_code", "http_status": "status_code", "response_code": "status_code",
    "decision": "action", "result": "action", "disposition": "action",
    "useragent": "user_agent", "http_user_agent": "user_agent", "agent": "user_agent",
    # common firewall / NGFW exports (field names are mapped, never guessed from IP order)
    "srcip": "src_ip", "src_address": "src_ip", "source_address": "src_ip", "sourceaddress": "src_ip",
    "dstip": "dst_ip", "dst_address": "dst_ip", "destination_address": "dst_ip", "destinationaddress": "dst_ip",
    "receive_time": "timestamp", "log_time": "timestamp", "eventtime": "timestamp",
    "proto": "protocol", "ip_protocol": "protocol",
    "srcport": "src_port", "sport": "src_port", "source_port": "src_port",
    "dstport": "dst_port", "dport": "dst_port", "destination_port": "dst_port",
    # Check Point / SonicWall / Sophos style spellings
    "s_port": "src_port", "sourceport": "src_port", "src_prt": "src_port",
    "d_port": "dst_port", "destport": "dst_port", "dest_port": "dst_port", "destinationport": "dst_port",
    "src_addr": "src_ip", "dst_addr": "dst_ip", "dest_addr": "dst_ip",
}


def normalize_record(rec: dict, field_mapping: dict = None) -> dict:
    """Normalize a single record to standard schema."""
    norm = {f: "" for f in STANDARD_SCHEMA}
    mapping = field_mapping or {}
    for key, value in rec.items():
        kl = str(key).lower().replace("-", "_").replace(" ", "_")
        # Field names are matched case-/space-/hyphen-insensitively ("Protocol", "Source IP",
        # "ACTION"); previously only the exact lower-case schema names matched, so a
        # SonicWall-style "Action: Deny" was lost and a blocked event looked like a plain request.
        std = mapping.get(key) or (key if key in STANDARD_SCHEMA else (kl if kl in STANDARD_SCHEMA else ALT_FIELD_MAP.get(kl)))
        if std and std in STANDARD_SCHEMA:
            if norm[std] and (value is None or str(value) == ""):
                continue                    # never overwrite a real value with an empty duplicate
            norm[std] = str(value)
    # Fortinet-style exports carry the date and the time of day as separate fields.
    lower = {str(k).lower(): v for k, v in rec.items()}
    if "date" in lower and "time" in lower and re.match(r"^\d{1,2}:\d{2}", str(lower["time"])):
        norm["timestamp"] = f"{lower['date']} {lower['time']}"
    if not norm.get("port") and norm.get("dst_port"):
        norm["port"] = norm["dst_port"]
    if not is_valid_ip(norm.get("src_ip", "")):
        # Structured record: accept only an explicitly labelled source, never
        # "the first IP found" (that is usually the destination).
        src_candidate = extract_src_ip(json.dumps(rec, default=str), labelled_only=True)
        if src_candidate:
            norm["src_ip"] = src_candidate
    if not norm.get("src_ip"):
        norm["src_ip"] = "unknown"
    if not norm.get("dst_ip"):
        norm["dst_ip"] = "unknown"
    norm["_raw"] = rec
    return norm


def normalize_log(records: list, field_mapping: dict = None) -> list:
    """Normalize records to standard schema."""
    normalized = []
    for rec in records:
        normalized.append(normalize_record(rec, field_mapping))
    return normalized


def classify_severity(attack_type: str) -> str:
    if attack_type in {"brute_force", "ddos", "beaconing", "rfi"}:     return "critical"
    if attack_type in {"sqli", "xss", "command_injection", "port_scan"}: return "high"
    if attack_type in {"lfi", "sensitive_endpoint", "blocked_traffic"}: return "medium"
    return "low"


def _extract_path(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = urlparse(value)
        if parsed.scheme and parsed.netloc:
            return parsed.path or ""
    except Exception:
        pass
    return value


def is_benign_path(value: str) -> bool:
    v = (value or "").lower()
    if not v:
        return False
    return any(v.endswith(p) or p in v for p in BENIGN_PATHS)


def is_static_resource(value: str) -> bool:
    v = (value or "").lower().split("?")[0]
    ext = v.rsplit(".", 1)[-1] if "." in v else ""
    return ext in STATIC_EXTENSIONS


def is_suspicious_domain(host: str) -> bool:
    h = (host or "").lower()
    if not h:
        return False
    return any(k in h for k in SUSPICIOUS_DOMAIN_KEYWORDS)


def assess_finding(attack_type: str, target: str, rec: dict) -> tuple:
    path = _extract_path(target)
    benign = is_benign_path(path) or is_static_resource(path)
    ioc_info = normalize_input(target or "") if target else {"type": "unknown", "value": ""}
    if ioc_info.get("type") == "file_path":
        return "low", "low", "File path resource", "failed"
    if benign:
        return "low", "low", "Benign static resource", "failed"

    if attack_type in ("command_injection", "rfi"):
        return "critical", "high", "RCE pattern detected", "passed"

    if attack_type == "beaconing":
        host = ""
        try:
            host = urlparse(target).hostname or ""
        except Exception:
            host = ""
        if is_suspicious_domain(host):
            return "critical", "high", "Beaconing to suspicious domain", "passed"
        return "low", "low", "Likely benign beaconing", "failed"

    if attack_type in ("sqli", "xss", "lfi"):
        return "high", "medium", "Injection pattern detected", "passed"

    if attack_type in ("brute_force", "port_scan", "high_request_rate"):
        return "medium", "medium", "Abnormal traffic pattern", "passed"

    if attack_type in ("sensitive_endpoint", "blocked_traffic", "suspicious_ua"):
        return "low", "low", "Potentially benign or blocked activity", "failed"

    return "low", "low", "Low confidence finding", "failed"


def _finding(attack_type, src_ip, dst_ip, target, rec, detail):
    src_val = src_ip or "unknown"
    dst_val = dst_ip or "unknown"
    ioc_value = target or src_val or dst_val
    ioc_info = normalize_input(ioc_value) if ioc_value else {"type": "unknown", "value": ""}
    severity, confidence, reason, fp_check = assess_finding(attack_type, target, rec)
    return {
        "attack_type": attack_type,
        "src_ip": src_val,
        "dst_ip": dst_val,
        "src": src_val,
        "dst": dst_val,
        "ioc": ioc_info.get("value") or ioc_value,
        "type": ioc_info.get("type", "unknown"),
        "confidence": confidence,
        "reason": reason,
        "false_positive_check": fp_check,
        "description": detail,
        "target": target,
        "severity": severity,
        "detail": detail,
        "timestamp": normalize_timestamp(rec.get("timestamp", "")),
        "method": rec.get("method", ""),
        "status_code": rec.get("status_code", ""),
        "user_agent": rec.get("user_agent", "")[:80],
        "action": rec.get("action", ""),
    }


def _parse_ts(ts: str):
    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y/%m/%d %H:%M:%S"]:
        try: return datetime.datetime.strptime(ts[:19], fmt)
        except (ValueError, TypeError): pass
    return None


def normalize_timestamp_with_epoch(value: str) -> tuple:
    # NOTE: renamed from `normalize_timestamp` — a second, incompatible
    # `normalize_timestamp(value) -> str` was later defined at module level
    # (see below), which silently shadowed this one and broke every caller
    # that unpacked a (ts_str, epoch) tuple from it. Kept as a distinct name
    # so both the tuple and string variants can coexist safely.
    # Legacy 2-tuple contract (pinned by the test-suite): unavailable/invalid -> ("", 0).
    # New code should call classify_timestamp() so that 0 is not mistaken for 1970.
    ts = classify_timestamp(value)
    if ts["status"] != TS_VALID:
        return "", 0
    return ts["text"], ts["epoch"]


def _severity_rank(sev: str) -> int:
    s = (sev or "").lower()
    if s in ("critical", "high"):
        return 3
    if s == "medium":
        return 2
    if s == "low":
        return 1
    return 0


class _SqlCounter:
    """Exact, memory-bounded replacement for ``collections.Counter`` on
    high-cardinality keys (URLs, IPs). Increments are buffered per chunk and
    upserted into SQLite, so RAM is O(chunk) instead of O(unique keys).
    ``most_common`` orders ties by first appearance, exactly like
    ``Counter.most_common`` (stable sort over insertion order)."""

    def __init__(self, conn, table: str):
        self._conn = conn
        self._t = table
        self._chunk = Counter()
        self._seq = 0
        conn.execute(f"CREATE TABLE IF NOT EXISTS {table} (k TEXT PRIMARY KEY, n INTEGER NOT NULL, seq INTEGER NOT NULL)")

    def add(self, key: str):
        self._chunk[key] += 1

    def flush(self):
        if not self._chunk:
            return
        base = self._seq
        rows = [(k, n, base + i) for i, (k, n) in enumerate(self._chunk.items())]
        self._seq += len(rows)
        self._conn.executemany(
            f"INSERT INTO {self._t} (k, n, seq) VALUES (?,?,?) "
            f"ON CONFLICT(k) DO UPDATE SET n = n + excluded.n", rows)
        self._chunk.clear()

    def most_common(self, limit: int) -> list:
        self.flush()
        return list(self._conn.execute(
            f"SELECT k, n FROM {self._t} ORDER BY n DESC, seq ASC LIMIT ?", (int(limit),)))

    def unique(self) -> int:
        self.flush()
        return self._conn.execute(f"SELECT COUNT(*) FROM {self._t}").fetchone()[0]


def create_forensics_store() -> str:
    fd, path = tempfile.mkstemp(prefix="soc_forensics_", suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS logs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "epoch INTEGER, time TEXT, src_ip TEXT, dst_ip TEXT, method TEXT, url TEXT,"
        "status_code TEXT, action TEXT, protocol TEXT, src_port TEXT, dst_port TEXT,"
        "domain TEXT, user_agent TEXT, raw_json TEXT"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS timeline_events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "epoch INTEGER, time TEXT, src TEXT, event TEXT, severity TEXT, sev_rank INTEGER,"
        "description TEXT, dst TEXT, ioc TEXT"
        ")"
    )
    conn.execute("CREATE TABLE IF NOT EXISTS src_ips (src TEXT PRIMARY KEY)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_epoch ON logs(epoch)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_src ON logs(src_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_epoch ON timeline_events(epoch)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_src ON timeline_events(src)")
    conn.commit(); conn.close()
    return path


def _detect_beaconing(recs):
    ts_list = sorted([t for t in [_parse_ts(r.get("timestamp", "")) for r in recs] if t])
    if len(ts_list) < 5: return None
    intervals = [(ts_list[i+1] - ts_list[i]).total_seconds() for i in range(len(ts_list)-1) if (ts_list[i+1]-ts_list[i]).total_seconds() > 0]
    if len(intervals) < 4: return None
    mean = sum(intervals) / len(intervals)
    if mean < 1: return None
    std = math.sqrt(sum((x - mean)**2 for x in intervals) / len(intervals))
    return {"interval_seconds": round(mean, 1)} if mean > 0 and std / mean <= 0.15 else None


def detect_attacks(records: list) -> list:
    """Run all 11 detection rules."""
    findings = []
    by_ip = defaultdict(list)
    for rec in records:
        if rec.get("src_ip"): by_ip[rec["src_ip"]].append(rec)

    for rec in records:
        src = rec.get("src_ip") or "unknown"
        dst = rec.get("dst_ip") or "unknown"
        url = rec.get("url", "")
        ua  = rec.get("user_agent", "")
        act = rec.get("action", "").lower()

        if RE_SQLI.search(url):   findings.append(_finding("sqli",             src, dst, url, rec, "SQL Injection in URL"))
        if RE_XSS.search(url):    findings.append(_finding("xss",              src, dst, url, rec, "XSS payload detected"))
        if RE_LFI.search(url):    findings.append(_finding("rfi" if url.startswith("http") else "lfi", src, dst, url, rec, "LFI/RFI attempt"))
        if RE_CMDI.search(url):   findings.append(_finding("command_injection", src, dst, url, rec, "Command injection in request"))
        if RE_UA_BAD.search(ua):  findings.append(_finding("suspicious_ua",    src, dst, url, rec, f"Suspicious UA: {ua[:60]}"))
        if RE_SENS.search(url):   findings.append(_finding("sensitive_endpoint",src, dst, url, rec, f"Access to sensitive endpoint: {url[:60]}"))
        if act in ("deny", "drop", "block", "blocked", "reject"):
            findings.append(_finding("blocked_traffic", src, dst, url, rec, f"Traffic blocked: {act.upper()}"))

    for ip, recs in by_ip.items():
        login_posts = [r for r in recs if r.get("method","").upper()=="POST" and RE_SENS.search(r.get("url",""))]
        if len(login_posts) >= 5:
            first = login_posts[0]
            findings.append(_finding("brute_force", ip, first.get("dst_ip", "unknown"), first.get("url",""), first,
                                     f"Brute force: {len(login_posts)} POST attempts to login"))
        ports = {r.get("port","") for r in recs if r.get("port","")}
        if len(ports) >= 10:
            first = recs[0]
            findings.append(_finding("port_scan", ip, first.get("dst_ip", "unknown"), "multiple", first,
                                     f"Port scan: {len(ports)} unique ports"))
        if len(recs) >= 100:
            first = recs[0]
            findings.append(_finding("high_request_rate", ip, first.get("dst_ip", "unknown"), "multiple", first,
                                     f"High rate: {len(recs)} requests from this IP"))
        b = _detect_beaconing(recs)
        if b:
            first = recs[0]
            findings.append(_finding("beaconing", ip, first.get("dst_ip", "unknown"), first.get("url",""), first,
                                     f"Beaconing ~{b['interval_seconds']}s intervals"))
    return findings


def extract_ioc_from_records(records: list) -> dict:
    text = "\n".join(
        " ".join(str(rec.get(f, "")) for f in ("src_ip", "dst_ip", "url", "user_agent"))
        for rec in records
    )
    iocs   = extract_iocs(text)
    all_ip = list(set(iocs["ips"] + [r.get("src_ip","") for r in records if r.get("src_ip")] +
                                     [r.get("dst_ip","") for r in records if r.get("dst_ip")]))
    total = len(all_ip) + len(iocs["domains"]) + len(iocs["urls"]) + len(iocs["hashes"]) + len(iocs["files"])
    if total == 0:
        LOGGER.debug("No IOC found in parsed records.")
    return {
        "ips": all_ip,
        "domains": iocs["domains"],
        "urls": iocs["urls"],
        "hashes": iocs["hashes"],
        "files": iocs["files"],
        "total": total,
    }


def _is_unusual_endpoint(url: str) -> bool:
    path = _extract_path(url)
    if not path:
        return False
    if len(path) >= 80:
        return True
    if ".." in path or "%2e" in path.lower():
        return True
    if path.count("?") >= 1 and path.count("&") >= 4:
        return True
    if re.search(r"[A-Fa-f0-9]{32,}", path):
        return True
    if any(ch in path for ch in ("{", "}", "|", "\\", "`", "<", ">")):
        return True
    return False


def build_traffic_summary(records: list) -> dict:
    total = len(records)
    src_ips = [r.get("src_ip") for r in records if r.get("src_ip") and r.get("src_ip") != "unknown"]
    dst_ips = [r.get("dst_ip") for r in records if r.get("dst_ip") and r.get("dst_ip") != "unknown"]
    urls = [r.get("url") for r in records if r.get("url")]
    methods = [r.get("method") for r in records if r.get("method")]
    status_codes = [str(r.get("status_code")) for r in records if str(r.get("status_code", "")).strip()]

    src_counts = Counter(src_ips)
    dst_counts = Counter(dst_ips)
    url_counts = Counter(urls)
    method_counts = Counter([m.upper() for m in methods])
    status_counts = Counter(status_codes)
    status_class_counts = Counter()
    for code in status_codes:
        if code and code[0].isdigit():
            status_class_counts[f"{code[0]}xx"] += 1

    burst_counts = defaultdict(Counter)
    for rec in records:
        ts = _parse_ts(rec.get("timestamp", ""))
        if not ts:
            continue
        src = rec.get("src_ip")
        if not src or src == "unknown":
            continue
        bucket = ts.replace(second=0, microsecond=0)
        burst_counts[src][bucket] += 1

    burst_candidates = []
    for src, buckets in burst_counts.items():
        if not buckets:
            continue
        peak = max(buckets.values())
        if peak >= 60:
            severity = "medium" if peak >= 120 else "low"
            burst_candidates.append({
                "src": src,
                "count": peak,
                "window": "1m",
                "severity": severity,
            })

    unusual_endpoints = []
    for url, count in url_counts.most_common(10):
        if _is_unusual_endpoint(url):
            unusual_endpoints.append({"value": url, "count": count})

    return {
        "total_records": total,
        "unique_src_ips": len(set(src_ips)),
        "unique_dst_ips": len(set(dst_ips)),
        "top_src_ips": [{"value": k, "count": v} for k, v in src_counts.most_common(5)],
        "top_dst_ips": [{"value": k, "count": v} for k, v in dst_counts.most_common(5)],
        "top_urls": [{"value": k, "count": v} for k, v in url_counts.most_common(5)],
        "top_methods": [{"value": k, "count": v} for k, v in method_counts.most_common(5)],
        "status_distribution": dict(status_counts),
        "status_class_distribution": dict(status_class_counts),
        "request_per_ip": [{"value": k, "count": v} for k, v in src_counts.most_common(10)],
        "burst_candidates": burst_candidates,
        "unusual_endpoints": unusual_endpoints,
    }


def detect_anomalies(summary: dict) -> list:
    anomalies = []
    total = summary.get("total_records", 0)
    top_src = summary.get("top_src_ips", [])
    if top_src:
        top = top_src[0]
        threshold = max(200, int(total * 0.3))
        if top.get("count", 0) >= threshold:
            severity = "medium" if top.get("count", 0) >= max(500, int(total * 0.5)) else "low"
            anomalies.append({
                "type": "anomalous_activity",
                "src": top.get("value", "unknown"),
                "severity": severity,
                "description": f"Trafik tinggi dari satu IP ({top.get('count',0)} request)",
            })

    status_dist = summary.get("status_distribution", {})
    error_count = 0
    for code, cnt in status_dist.items():
        if str(code).startswith("4") or str(code).startswith("5"):
            error_count += cnt
    if total >= 50:
        error_rate = error_count / max(1, total)
        if error_rate >= 0.3:
            severity = "medium" if error_rate >= 0.5 else "low"
            anomalies.append({
                "type": "anomalous_activity",
                "src": "multiple",
                "severity": severity,
                "description": f"Lonjakan error rate ({error_rate:.0%})",
            })
        status_class = summary.get("status_class_distribution", {})
        err_5xx = status_class.get("5xx", 0)
        if err_5xx / max(1, total) >= 0.05:
            anomalies.append({
                "type": "status_code_anomaly",
                "src": "multiple",
                "severity": "medium",
                "description": "Lonjakan 5xx (indikasi error aplikasi/server)",
            })

    top_urls = summary.get("top_urls", [])
    if top_urls:
        top_url = top_urls[0]
        if top_url.get("count", 0) >= max(200, int(total * 0.4)):
            anomalies.append({
                "type": "anomalous_activity",
                "src": "multiple",
                "severity": "low",
                "description": f"Akses berulang ke URL yang sama ({top_url.get('value','')})",
            })

    for b in summary.get("burst_candidates", []):
        anomalies.append({
            "type": "burst_traffic",
            "src": b.get("src", "unknown"),
            "severity": b.get("severity", "low"),
            "description": f"Burst traffic {b.get('count',0)} request/{b.get('window','1m')}",
        })

    for u in summary.get("unusual_endpoints", []):
        anomalies.append({
            "type": "unusual_endpoint",
            "src": "multiple",
            "severity": "low",
            "description": f"Endpoint tidak umum: {u.get('value','')}",
        })

    return anomalies


TIMELINE_EVENT_MAP = {
    "high_request_rate": "Scanning Activity",
    "port_scan": "Scanning Activity",
    "brute_force": "Brute Force Attempt",
    "beaconing": "Possible Beaconing",
    "blocked_traffic": "Security Control Triggered",
    "sqli": "Injection Attempt",
    "xss": "Injection Attempt",
    "lfi": "Injection Attempt",
    "rfi": "Injection Attempt",
    "command_injection": "Injection Attempt",
    "suspicious_ua": "Suspicious User Agent",
    "sensitive_endpoint": "Sensitive Endpoint Access",
    "dns_tunneling": "DNS Anomaly",
    "dns_anomaly": "DNS Anomaly",
    "suspicious_port": "Suspicious Port Activity",
}


def _timeline_event_label(attack_type: str) -> str:
    return TIMELINE_EVENT_MAP.get(attack_type, attack_type.replace("_", " ").title())


def build_timeline_from_findings(findings: list, anomalies: list = None, source: str = "log") -> list:
    anomalies = anomalies or []
    events = []
    for f in findings:
        sev = (f.get("severity") or "low").upper()
        ts = f.get("timestamp", "")
        ioc_val = f.get("ioc") or f.get("target") or f.get("url") or f.get("domain") or ""
        events.append({
            "time": ts or "",
            "src": f.get("src") or f.get("src_ip") or "unknown",
            "dst": f.get("dst") or f.get("dst_ip") or "",
            "event": _timeline_event_label(f.get("attack_type", "event")),
            "severity": sev,
            "description": f.get("description") or f.get("detail") or "",
            "ioc": ioc_val,
            "source": source,
        })
    seen_keys = {(e["src"], e["event"], e["severity"], e["description"]) for e in events}
    for a in anomalies:
        akey = (a.get("src", "unknown"), _timeline_event_label(a.get("type", "anomaly")),
                (a.get("severity") or "low").upper(), a.get("description", ""))
        if akey in seen_keys:
            continue                    # same event already present from the finding itself
        events.append({
            "time": a.get("timestamp") or a.get("time") or "",
            "src": a.get("src") or "unknown",
            "dst": a.get("dst") or "",
            "event": _timeline_event_label(a.get("type", "anomaly")),
            "severity": (a.get("severity") or "low").upper(),
            "description": a.get("description", ""),
            "ioc": a.get("ioc") or a.get("target") or "",
            "source": source,
        })

    def _sort_key(e):
        dt = _parse_time_any(e.get("time"))
        return dt or datetime.datetime.max

    events = sorted(events, key=_sort_key)
    if len(events) > MAX_TIMELINE_EVENTS:
        events = events[:MAX_TIMELINE_EVENTS]
    return events


def build_timeline_insight(timeline: list) -> dict:
    if not timeline:
        return {"duration": "0s", "events_per_attacker": [], "escalation": "none"}

    times = [
        _parse_time_any(e.get("time"))
        for e in timeline
        if e.get("time")
    ]
    times = [t for t in times if t]
    if times:
        start = min(times)
        end = max(times)
        duration_seconds = int((end - start).total_seconds())
    else:
        duration_seconds = 0

    def _fmt_duration(seconds: int) -> str:
        if seconds <= 0:
            return "0s"
        minutes, sec = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours}h {minutes}m {sec}s"
        if minutes:
            return f"{minutes}m {sec}s"
        return f"{sec}s"

    counts = Counter([e.get("src", "unknown") for e in timeline])
    events_per_attacker = [{"src": k, "count": v} for k, v in counts.most_common(5)]

    sev_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    escalation = "none"
    by_src = defaultdict(list)
    for e in timeline:
        by_src[e.get("src", "unknown")].append(e)
    for src, items in by_src.items():
        last = 0
        for e in items:
            level = sev_order.get((e.get("severity") or "LOW").upper(), 0)
            if level > last and last != 0:
                escalation = "detected"
                break
            last = max(last, level)
        if escalation == "detected":
            break

    return {
        "duration": _fmt_duration(duration_seconds),
        "events_per_attacker": events_per_attacker,
        "escalation": escalation,
    }


def _detect_beaconing_times(times: list):
    if len(times) < 5:
        return None
    times = sorted([t for t in times if t])
    intervals = [
        (times[i + 1] - times[i]).total_seconds()
        for i in range(len(times) - 1)
        if (times[i + 1] - times[i]).total_seconds() > 0
    ]
    if len(intervals) < 4:
        return None
    mean = sum(intervals) / len(intervals)
    if mean <= 0:
        return None
    std = math.sqrt(sum((x - mean) ** 2 for x in intervals) / len(intervals))
    return {"interval_seconds": round(mean, 1)} if std / mean <= 0.15 else None


def detect_attacks_realtime(records: list, state: dict) -> list:
    findings = []
    for rec in records:
        src = rec.get("src_ip") or "unknown"
        dst = rec.get("dst_ip") or "unknown"
        url = rec.get("url", "")
        ua = rec.get("user_agent", "")
        act = rec.get("action", "").lower()

        if RE_SQLI.search(url):
            findings.append(_finding("sqli", src, dst, url, rec, "SQL Injection in URL"))
        if RE_XSS.search(url):
            findings.append(_finding("xss", src, dst, url, rec, "XSS payload detected"))
        if RE_LFI.search(url):
            findings.append(_finding("rfi" if url.startswith("http") else "lfi", src, dst, url, rec, "LFI/RFI attempt"))
        if RE_CMDI.search(url):
            findings.append(_finding("command_injection", src, dst, url, rec, "Command injection in request"))
        if RE_UA_BAD.search(ua):
            findings.append(_finding("suspicious_ua", src, dst, url, rec, f"Suspicious UA: {ua[:60]}"))
        if RE_SENS.search(url):
            findings.append(_finding("sensitive_endpoint", src, dst, url, rec, f"Access to sensitive endpoint: {url[:60]}"))
        if act in ("deny", "drop", "block", "blocked", "reject"):
            findings.append(_finding("blocked_traffic", src, dst, url, rec, f"Traffic blocked: {act.upper()}"))

        state["req_counts"][src] += 1
        state["last_rec"][src] = rec
        if rec.get("method", "").upper() == "POST" and RE_SENS.search(url):
            state["login_posts"][src] += 1

        port = rec.get("port") or rec.get("dst_port")
        if port:
            state["ports"][src].add(str(port))

        ts = _parse_ts(rec.get("timestamp", ""))
        if ts:
            state["beacon_times"][src].append(ts)

    return findings


def finalize_attack_state(state: dict) -> list:
    findings = []
    for ip, count in state["login_posts"].items():
        if count >= 5:
            rec = state["last_rec"].get(ip, {})
            findings.append(_finding("brute_force", ip, rec.get("dst_ip", "unknown"), rec.get("url", ""), rec,
                                     f"Brute force: {count} POST attempts to login"))
    for ip, ports in state["ports"].items():
        if len(ports) >= 10:
            rec = state["last_rec"].get(ip, {})
            findings.append(_finding("port_scan", ip, rec.get("dst_ip", "unknown"), "multiple", rec,
                                     f"Port scan: {len(ports)} unique ports"))
    for ip, count in state["req_counts"].items():
        if count >= 100:
            rec = state["last_rec"].get(ip, {})
            findings.append(_finding("high_request_rate", ip, rec.get("dst_ip", "unknown"), "multiple", rec,
                                     f"High rate: {count} requests from this IP"))
    for ip, times in state["beacon_times"].items():
        b = _detect_beaconing_times(list(times))
        if b:
            rec = state["last_rec"].get(ip, {})
            findings.append(_finding("beaconing", ip, rec.get("dst_ip", "unknown"), rec.get("url", ""), rec,
                                     f"Beaconing ~{b['interval_seconds']}s intervals"))
    return findings


def update_iocs_from_records(ioc_state: dict, records: list) -> None:
    for rec in records:
        src = rec.get("src_ip")
        dst = rec.get("dst_ip")
        url = rec.get("url") or ""
        if is_valid_ip(src):
            ioc_state["ips"].add(src)
        if is_valid_ip(dst):
            ioc_state["ips"].add(dst)
        if url:
            u_info = normalize_input(url)
            if u_info.get("type") == "url":
                ioc_state["urls"].add(u_info.get("value"))
            try:
                host = urlparse(url).hostname
            except Exception:
                host = ""
            if host and is_valid_domain(host):
                ioc_state["domains"].add(host)


def build_traffic_summary_from_state(state: dict, total_records: int) -> dict:
    src_counts = state["src_counts"]
    dst_counts = state["dst_counts"]
    url_counts = state["url_counts"]
    method_counts = state["method_counts"]
    status_counts = state["status_counts"]
    status_class_counts = state["status_class_counts"]
    burst_state = state["burst_state"]
    unusual_counts = state["unusual_counts"]

    burst_candidates = []
    for src, info in burst_state.items():
        peak = info.get("peak", 0)
        if peak >= 60:
            severity = "medium" if peak >= 120 else "low"
            burst_candidates.append({
                "src": src,
                "count": peak,
                "window": "1m",
                "severity": severity,
            })

    unusual_endpoints = [
        {"value": url, "count": cnt}
        for url, cnt in unusual_counts.most_common(5)
    ]

    return {
        "total_records": total_records,
        "unique_src_ips": len(src_counts),
        "unique_dst_ips": len(dst_counts),
        "top_src_ips": [{"value": k, "count": v} for k, v in src_counts.most_common(5)],
        "top_dst_ips": [{"value": k, "count": v} for k, v in dst_counts.most_common(5)],
        "top_urls": [{"value": k, "count": v} for k, v in url_counts.most_common(5)],
        "top_methods": [{"value": k, "count": v} for k, v in method_counts.most_common(5)],
        "status_distribution": dict(status_counts),
        "status_class_distribution": dict(status_class_counts),
        "request_per_ip": [{"value": k, "count": v} for k, v in src_counts.most_common(10)],
        "burst_candidates": burst_candidates,
        "unusual_endpoints": unusual_endpoints,
    }


def analyze_log_records_stream(records_iter, field_mapping: dict = None,
                               chunk_size: int = STREAM_CHUNK_SIZE) -> dict:
    raw_preview = []
    parsed_preview = []
    findings = []
    raw_count = 0
    parsed_count = 0

    ioc_state = {"ips": set(), "domains": set(), "urls": set(), "hashes": set(), "files": set()}
    traffic_state = {
        "src_counts": Counter(),
        "dst_counts": Counter(),
        "url_counts": Counter(),
        "method_counts": Counter(),
        "status_counts": Counter(),
        "status_class_counts": Counter(),
        "burst_state": defaultdict(lambda: {"minute": None, "count": 0, "peak": 0}),
        "unusual_counts": Counter(),
    }
    attack_state = {
        "req_counts": Counter(),
        "login_posts": Counter(),
        "ports": defaultdict(set),
        "last_rec": {},
        "beacon_times": defaultdict(lambda: deque(maxlen=8)),
    }

    def _process_chunk(chunk):
        nonlocal parsed_count
        if not chunk:
            return
        normalized = normalize_log(chunk, field_mapping)
        parsed_count += len(normalized)
        if len(parsed_preview) < MAX_TABLE_ROWS:
            parsed_preview.extend(normalized[: MAX_TABLE_ROWS - len(parsed_preview)])

        per_findings = detect_attacks_realtime(normalized, attack_state)
        if per_findings:
            remaining = MAX_FINDINGS_STORE - len(findings)
            if remaining > 0:
                findings.extend(per_findings[:remaining])

        update_iocs_from_records(ioc_state, normalized)

        for rec in normalized:
            src = rec.get("src_ip")
            dst = rec.get("dst_ip")
            url = rec.get("url")
            method = rec.get("method")
            status = str(rec.get("status_code", "")).strip()

            if src and src != "unknown":
                traffic_state["src_counts"][src] += 1
            if dst and dst != "unknown":
                traffic_state["dst_counts"][dst] += 1
            if url:
                traffic_state["url_counts"][url] += 1
                if _is_unusual_endpoint(url):
                    traffic_state["unusual_counts"][url] += 1
            if method:
                traffic_state["method_counts"][method.upper()] += 1
            if status:
                traffic_state["status_counts"][status] += 1
                if status[0].isdigit():
                    traffic_state["status_class_counts"][f"{status[0]}xx"] += 1

            ts = _parse_ts(rec.get("timestamp", ""))
            if ts and src and src != "unknown":
                bucket = ts.replace(second=0, microsecond=0)
                bs = traffic_state["burst_state"][src]
                if bs["minute"] == bucket:
                    bs["count"] += 1
                else:
                    bs["minute"] = bucket
                    bs["count"] = 1
                if bs["count"] > bs["peak"]:
                    bs["peak"] = bs["count"]

    chunk = []
    for rec in records_iter:
        raw_count += 1
        if len(raw_preview) < MAX_TABLE_ROWS:
            raw_preview.append(rec)
        chunk.append(rec)
        if len(chunk) >= chunk_size:
            _process_chunk(chunk)
            chunk = []
    if chunk:
        _process_chunk(chunk)

    findings.extend(finalize_attack_state(attack_state))
    if len(findings) > MAX_FINDINGS_STORE:
        findings = findings[:MAX_FINDINGS_STORE]

    traffic_summary = build_traffic_summary_from_state(traffic_state, parsed_count)
    anomalies = detect_anomalies(traffic_summary)

    iocs = {
        "ips": sorted(ioc_state["ips"]),
        "domains": sorted(ioc_state["domains"]),
        "urls": sorted(ioc_state["urls"]),
        "hashes": sorted(ioc_state["hashes"]),
        "files": sorted(ioc_state["files"]),
    }
    iocs["total"] = len(iocs["ips"]) + len(iocs["domains"]) + len(iocs["urls"]) + \
        len(iocs["hashes"]) + len(iocs["files"])

    sev_counts = dict(Counter(f.get("severity", "low") for f in findings))
    atk_counts = dict(Counter(f.get("attack_type", "unknown") for f in findings))
    top_ips = traffic_summary.get("top_src_ips", [])

    timeline = build_timeline_from_findings(findings, anomalies, source="log")
    timeline_insight = build_timeline_insight(timeline)

    return {
        "total_records": parsed_count,
        "total_findings": len(findings),
        "severity_counts": sev_counts,
        "attack_type_counts": atk_counts,
        "findings": findings,
        "iocs": iocs,
        "top_attacker_ips": top_ips,
        "traffic_summary": traffic_summary,
        "anomalies": anomalies,
        "raw_records": raw_preview,
        "parsed_records": parsed_preview,
        "raw_count": raw_count,
        "parsed_count": parsed_count,
        "timeline": timeline,
        "timeline_insight": timeline_insight,
    }


def _classify_log_event(rec: dict) -> tuple:
    url = rec.get("url", "")
    method = rec.get("method", "")
    status = str(rec.get("status_code", ""))
    action = (rec.get("action", "") or "").lower()
    path = _extract_path(url) or url

    if action in ("deny", "drop", "block", "blocked", "reject"):
        return "Security Control Triggered", "high", f"{action.upper()} {method} {path}"
    if RE_SQLI.search(url):
        return "SQL Injection Attempt", "high", f"{method} {path}"
    if RE_XSS.search(url):
        return "XSS Attempt", "high", f"{method} {path}"
    if RE_LFI.search(url):
        return "LFI/RFI Attempt", "high", f"{method} {path}"
    if RE_CMDI.search(url):
        return "Command Injection Attempt", "high", f"{method} {path}"
    if RE_SENS.search(url) and status in ("401", "403"):
        return "Brute Force Attempt", "medium", f"Failed login {path}"
    if RE_SENS.search(url):
        return "Sensitive Endpoint Access", "low", f"{method} {path}"
    if status.startswith("5"):
        return "Server Error", "low", f"{status} {method} {path}"
    return "Request", "low", f"{method} {path} ({status})"


def _classify_pcap_event(rec: dict) -> tuple:
    proto = rec.get("protocol", "")
    src = rec.get("src_ip", "")
    dst = rec.get("dst_ip", "")
    src_port = rec.get("src_port", "")
    dst_port = rec.get("dst_port", "")
    domain = rec.get("domain", "")
    if domain:
        return "DNS Query", "low", f"{src} -> {dst} {domain}"
    return "Network Flow", "low", f"{proto} {src}:{src_port} -> {dst}:{dst_port}"


def _timeline_row(epoch: int, time_str: str, src: str, event: str, severity: str,
                  description: str, dst: str, ioc: str) -> tuple:
    return (epoch, time_str, src, event, severity, _severity_rank(severity), description, dst, ioc)


def analyze_logs_streaming_store(file_path: str, field_mapping: dict = None,
                                 chunk_size: int = STREAM_CHUNK_SIZE,
                                 progress_cb=None, partial_cb=None,
                                 max_records: int = None, cancel_cb=None) -> dict:
    state = {}
    db_path = create_forensics_store()
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    findings = []
    sev_counts = Counter()
    atk_counts = Counter()
    ioc_sets = {"ips": set(), "domains": set(), "urls": set(), "hashes": set(), "files": set()}

    # High-cardinality aggregates live in SQLite (bounded RAM, identical results).
    src_counts = _SqlCounter(conn, "agg_src")
    dst_counts = _SqlCounter(conn, "agg_dst")
    url_counts = _SqlCounter(conn, "agg_url")
    method_counts = Counter()
    status_counts = Counter()
    status_class_counts = Counter()
    conn.execute("CREATE TABLE IF NOT EXISTS agg_burst (src TEXT NOT NULL, minute INTEGER NOT NULL, "
                 "n INTEGER NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY (src, minute))")
    burst_chunk = Counter()          # (src, minute) -> count, per chunk
    burst_seq = [0]
    conn.execute("CREATE TABLE IF NOT EXISTS agg_session (src TEXT PRIMARY KEY, cnt INTEGER NOT NULL, "
                 "min_e INTEGER, max_e INTEGER, min_r INTEGER, max_r INTEGER, seq INTEGER NOT NULL)")
    session_chunk = {}               # src -> [cnt, min_e, max_e, min_r, max_r], per chunk
    session_seq = [0]

    req_counts = Counter()
    login_counts = Counter()
    port_sets = defaultdict(set)
    # Compact beacon state: key is a 64-bit hash of (src,dst,url); a single sighting is
    # stored as a bare epoch, later ones as the last 6 epochs (all the detector reads).
    beacon_map = {}
    triggered = set()

    total_logs = 0
    timeline_total = 0
    timeline_sample = []

    log_rows = []
    timeline_rows = []
    timeline_event_counts = Counter()
    timeline_severity_counts = Counter()

    def _add_timeline_row(epoch, time_str, src, event, severity, description, dst, ioc):
        if ioc in ("unknown", None):        # a placeholder is not an indicator
            ioc = ""
        # add tuple for DB
        timeline_rows.append(_timeline_row(epoch, time_str, src, event, severity, description, dst, ioc))
        # update lightweight counters and samples
        timeline_event_counts[event] += 1
        timeline_severity_counts[(severity or "").upper()] += 1
        if len(timeline_sample) < 50:
            timeline_sample.append({
                "time": time_str,
                "src": src,
                "event": event,
                "severity": severity,
                "description": description,
                "dst": dst,
                "ioc": ioc,
            })

    def _flush():
        if log_rows:
            cur.executemany(
                "INSERT INTO logs (epoch, time, src_ip, dst_ip, method, url, status_code, action, protocol, "
                "src_port, dst_port, domain, user_agent, raw_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                log_rows,
            )
            log_rows.clear()
        if timeline_rows:
            cur.executemany(
                "INSERT INTO timeline_events (epoch, time, src, event, severity, sev_rank, description, dst, ioc) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                timeline_rows,
            )
            timeline_rows.clear()
        for _c in (src_counts, dst_counts, url_counts):
            _c.flush()
        if burst_chunk:
            _b = burst_seq[0]
            conn.executemany(
                "INSERT INTO agg_burst (src, minute, n, seq) VALUES (?,?,?,?) "
                "ON CONFLICT(src, minute) DO UPDATE SET n = n + excluded.n",
                [(sk, mk, n, _b + i) for i, ((sk, mk), n) in enumerate(burst_chunk.items())])
            burst_seq[0] += len(burst_chunk)
            burst_chunk.clear()
        if session_chunk:
            _s = session_seq[0]
            conn.executemany(
                "INSERT INTO agg_session (src, cnt, min_e, max_e, min_r, max_r, seq) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(src) DO UPDATE SET cnt = cnt + excluded.cnt, "
                "min_e = CASE WHEN min_e IS NULL THEN excluded.min_e WHEN excluded.min_e IS NULL THEN min_e "
                "ELSE MIN(min_e, excluded.min_e) END, "
                "max_e = CASE WHEN max_e IS NULL THEN excluded.max_e WHEN excluded.max_e IS NULL THEN max_e "
                "ELSE MAX(max_e, excluded.max_e) END, "
                "min_r = MIN(min_r, excluded.min_r), max_r = MAX(max_r, excluded.max_r)",
                [(sk, v[0], v[1], v[2], v[3], v[4], _s + i) for i, (sk, v) in enumerate(session_chunk.items())])
            session_seq[0] += len(session_chunk)
            session_chunk.clear()
        conn.commit()

    rec_iter = iter_log_records_from_file(file_path, max_records=max_records, progress_cb=progress_cb,
                                          state=state, cancel_cb=cancel_cb)
    for rec in rec_iter:
        total_logs += 1
        norm = normalize_record(rec, field_mapping)

        _ts = classify_timestamp(norm.get("timestamp", ""))
        ts_str, epoch = _ts["text"], _ts["epoch"]          # epoch None => unavailable/invalid
        src = norm.get("src_ip", "")
        dst = norm.get("dst_ip", "")
        url = norm.get("url", "")
        method = norm.get("method", "")
        status = str(norm.get("status_code", ""))

        if src and src != "unknown":
            src_counts.add(src)
            cur.execute("INSERT OR IGNORE INTO src_ips (src) VALUES (?)", (src,))
        if dst and dst != "unknown":
            dst_counts.add(dst)
        if url:
            url_counts.add(url)
        if method:
            method_counts[method.upper()] += 1
        if status:
            status_counts[status] += 1
            if status[0].isdigit():
                status_class_counts[f"{status[0]}xx"] += 1

        if epoch is not None:
            burst_chunk[(src, epoch // 60)] += 1

        ioc_text = f"{src} {dst} {url} {norm.get('user_agent','')}"
        found = extract_iocs(ioc_text)
        ioc_sets["ips"].update(found.get("ips", []))
        ioc_sets["domains"].update(found.get("domains", []))
        ioc_sets["urls"].update(found.get("urls", []))
        ioc_sets["hashes"].update(found.get("hashes", []))
        ioc_sets["files"].update(found.get("files", []))

        rec_findings = []
        if RE_SQLI.search(url):   rec_findings.append(_finding("sqli", src, dst, url, norm, "SQL Injection in URL"))
        if RE_XSS.search(url):    rec_findings.append(_finding("xss", src, dst, url, norm, "XSS payload detected"))
        if RE_LFI.search(url):    rec_findings.append(_finding("rfi" if url.startswith("http") else "lfi", src, dst, url, norm, "LFI/RFI attempt"))
        if RE_CMDI.search(url):   rec_findings.append(_finding("command_injection", src, dst, url, norm, "Command injection in request"))
        if RE_UA_BAD.search(norm.get("user_agent", "")):
            rec_findings.append(_finding("suspicious_ua", src, dst, url, norm, f"Suspicious UA: {norm.get('user_agent','')[:60]}"))
        if RE_SENS.search(url):
            rec_findings.append(_finding("sensitive_endpoint", src, dst, url, norm, f"Access to sensitive endpoint: {url[:60]}"))
        if (norm.get("action", "") or "").lower() in ("deny", "drop", "block", "blocked", "reject"):
            rec_findings.append(_finding("blocked_traffic", src, dst, url, norm, f"Traffic blocked: {(norm.get('action','') or '').upper()}"))

        for f in rec_findings:
            findings.append(f)
            sev_counts[f.get("severity", "low")] += 1
            atk_counts[f.get("attack_type", "unknown")] += 1

        if src:
            req_counts[src] += 1
            if req_counts[src] == 200 and (src, "scan") not in triggered:
                triggered.add((src, "scan"))
                f = _finding("high_request_rate", src, dst, "multiple", norm, f"High rate: {req_counts[src]} requests from this IP")
                findings.append(f)
                sev_counts[f.get("severity", "low")] += 1
                atk_counts[f.get("attack_type", "unknown")] += 1
                _add_timeline_row(epoch, ts_str, src, "Scanning Activity", "medium",
                                   "High request rate detected", dst, src)

        if method.upper() == "POST" and RE_SENS.search(url):
            login_counts[src] += 1
            if login_counts[src] == 5 and (src, "bruteforce") not in triggered:
                triggered.add((src, "bruteforce"))
                f = _finding("brute_force", src, dst, url, norm, f"Brute force: {login_counts[src]} POST attempts to login")
                findings.append(f)
                sev_counts[f.get("severity", "low")] += 1
                atk_counts[f.get("attack_type", "unknown")] += 1
                _add_timeline_row(epoch, ts_str, src, "Brute Force Attempt", "medium",
                                   "Multiple failed login attempts", dst, url)

        port = norm.get("port", "")
        if port:
            port_sets[src].add(str(port))
            if len(port_sets[src]) >= 10 and (src, "portscan") not in triggered:
                triggered.add((src, "portscan"))
                f = _finding("port_scan", src, dst, "multiple", norm, f"Port scan: {len(port_sets[src])} unique ports")
                findings.append(f)
                sev_counts[f.get("severity", "low")] += 1
                atk_counts[f.get("attack_type", "unknown")] += 1
                _add_timeline_row(epoch, ts_str, src, "Scanning Activity", "medium",
                                   "Multiple destination ports detected", dst, src)

        if epoch is not None and url:
            key = hash((src, dst, url))
            _bv = beacon_map.get(key)
            if _bv is None:
                beacon_map[key] = epoch
                _bv = None
            elif isinstance(_bv, int):
                beacon_map[key] = _bv = [_bv, epoch]
            else:
                _bv.append(epoch)
                if len(_bv) > 6:
                    del _bv[0]
            if isinstance(_bv, list) and len(_bv) >= 5 and (key, "beacon") not in triggered:
                times = [datetime.datetime.fromtimestamp(_e) for _e in _bv[-6:]]
                intervals = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)
                             if (times[i + 1] - times[i]).total_seconds() > 0]
                if len(intervals) >= 4:
                    mean = sum(intervals) / len(intervals)
                    std = math.sqrt(sum((x - mean) ** 2 for x in intervals) / len(intervals)) if mean > 0 else 0
                    if mean > 0 and std / mean <= 0.2:
                        triggered.add((key, "beacon"))
                        f = _finding("beaconing", src, dst, url, norm, "Beaconing pattern detected")
                        findings.append(f)
                        sev_counts[f.get("severity", "low")] += 1
                        atk_counts[f.get("attack_type", "unknown")] += 1
                        _add_timeline_row(epoch, ts_str, src, "Possible Beaconing", "medium",
                                           "Repeated connection pattern", dst, url)

        event, sev, desc = _classify_log_event(norm)
        # ensure WAF logs are represented in timeline even if URL missing
        raw_text = json.dumps(rec, default=str)
        if "waf" in raw_text.lower() or "modsecurity" in raw_text.lower() or (norm.get("action", "").lower() in ("deny","block","drop","reject")):
            # prefer URL/domain as IOC
            ioc_val = url or norm.get("domain") or src
            _add_timeline_row(epoch, ts_str, src, "WAF Event" if "waf" in raw_text.lower() else event, sev, desc, dst, ioc_val)
        else:
            _add_timeline_row(epoch, ts_str, src, event, sev, desc, dst, url or src)
        timeline_total += 1

        rank = _severity_rank(sev)
        sess = session_chunk.get(src)
        if sess is None:
            session_chunk[src] = [1, epoch, epoch, rank, rank]
        else:
            sess[0] += 1
            if epoch is not None:
                sess[1] = epoch if sess[1] is None else min(sess[1], epoch)
                sess[2] = epoch if sess[2] is None else max(sess[2], epoch)
            sess[3] = min(sess[3], rank)
            sess[4] = max(sess[4], rank)

        raw_json = json.dumps(rec, default=str)
        log_rows.append((epoch, ts_str, src, dst, method, url, status, norm.get("action", ""),
                         norm.get("protocol", ""), norm.get("src_port", ""), norm.get("dst_port", ""),
                         norm.get("domain", ""), norm.get("user_agent", ""), raw_json))

        if len(log_rows) >= chunk_size:
            _flush()
            if partial_cb:
                partial_cb({"raw_count": total_logs, "parsed_count": total_logs})

    _flush()
    burst_candidates = []
    for src, peak in conn.execute(
            "SELECT src, MAX(n) AS peak FROM agg_burst GROUP BY src "
            "HAVING MAX(n) >= 60 ORDER BY MIN(seq)"):
        severity = "medium" if peak >= 120 else "low"
        burst_candidates.append({"src": src, "count": peak, "window": "1m", "severity": severity})

    unusual_endpoints = []
    for url, count in url_counts.most_common(10):
        if _is_unusual_endpoint(url):
            unusual_endpoints.append({"value": url, "count": count})

    traffic_summary = {
        "total_records": total_logs,
        "unique_src_ips": src_counts.unique(),
        "unique_dst_ips": dst_counts.unique(),
        "top_src_ips": [{"value": k, "count": v} for k, v in src_counts.most_common(5)],
        "top_dst_ips": [{"value": k, "count": v} for k, v in dst_counts.most_common(5)],
        "top_urls": [{"value": k, "count": v} for k, v in url_counts.most_common(5)],
        "top_methods": [{"value": k, "count": v} for k, v in method_counts.most_common(5)],
        "status_distribution": dict(status_counts),
        "status_class_distribution": dict(status_class_counts),
        "request_per_ip": [{"value": k, "count": v} for k, v in src_counts.most_common(10)],
        "burst_candidates": burst_candidates,
        "unusual_endpoints": unusual_endpoints,
    }

    anomalies = detect_anomalies(traffic_summary)

    iocs = {k: sorted(v) for k, v in ioc_sets.items()}
    iocs["total"] = sum(len(v) for v in ioc_sets.values())

    top_attacker_ips = [{"value": k, "count": v} for k, v in src_counts.most_common(10)]

    session_summary = []
    for src, s_cnt, s_min_e, s_max_e, s_min_r, s_max_r in conn.execute(
            "SELECT src, cnt, min_e, max_e, min_r, max_r FROM agg_session "
            "ORDER BY cnt DESC, seq ASC LIMIT 20").fetchall():
        if not src:
            continue
        duration = 0
        if s_min_e is not None and s_max_e is not None:
            duration = max(0, s_max_e - s_min_e)
        escalation = "YES" if (s_max_r or 0) > (s_min_r or 0) else "NO"
        session_summary.append({
            "src": src,
            "events": s_cnt,
            "duration": duration,
            "escalation": escalation,
        })

    conn.close()      # aggregates above were read from this connection

    return {
        "db_path": db_path,
        "total_records": total_logs,
        "total_findings": len(findings),
        "severity_counts": dict(sev_counts),
        "attack_type_counts": dict(atk_counts),
        "event_counts": dict(timeline_event_counts),
        "timeline_severity_counts": dict(timeline_severity_counts),
        "findings": findings,
        "iocs": iocs,
        "top_attacker_ips": top_attacker_ips,
        "traffic_summary": traffic_summary,
        "anomalies": anomalies,
        "raw_count": total_logs,
        "parsed_count": total_logs,
        "timeline_overview": {
            "total_events": timeline_total,
            "top_attackers": top_attacker_ips[:5],
        },
        "timeline_sample": timeline_sample,
        "timeline_sessions": session_summary,
        "timeline": timeline_sample,
        "timeline_insight": build_timeline_insight(timeline_sample),
        "truncated": state.get("truncated", False),
        "cancelled": bool(state.get("cancelled")),
        "invalid_records": state.get("invalid", 0),
        "invalid_samples": state.get("invalid_samples", []),
        "lines_total": total_logs + state.get("invalid", 0),
    }


# "No usable time": NULL epoch (new rows) OR the legacy sentinel (epoch 0 with empty time text).
# A real 1970-01-01 00:00:00 row has time text, so it is NOT matched.
_NO_TIME_SQL = "(epoch IS NULL OR (epoch = 0 AND COALESCE(time, '') = ''))"


def fetch_timeline_page(db_path: str, page: int = 0, page_size: int = TIMELINE_PAGE_SIZE,
                        src_filter: str = None, severity_filter: str = None) -> dict:
    if not db_path or not os.path.exists(db_path):
        return {"rows": [], "total": 0, "page": page, "page_size": page_size}
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    clauses = []
    params = []
    if src_filter:
        clauses.append("src = ?")
        params.append(src_filter)
    if severity_filter and severity_filter.lower() != "all":
        clauses.append("lower(severity) = ?")
        params.append(severity_filter.lower())
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    total = cur.execute(f"SELECT COUNT(*) FROM timeline_events {where}", params).fetchone()[0]
    offset = max(0, page) * page_size
    rows = cur.execute(
        f"SELECT epoch, time, src, event, severity, description, dst, ioc FROM timeline_events {where} "
        f"ORDER BY {_NO_TIME_SQL} ASC, epoch ASC, id ASC LIMIT ? OFFSET ?",
        params + [page_size, offset],
    ).fetchall()
    conn.close()
    return {"rows": [dict(r) for r in rows], "total": total, "page": page, "page_size": page_size}


def fetch_log_page(db_path: str, page: int = 0, page_size: int = MAX_TABLE_ROWS) -> dict:
    if not db_path or not os.path.exists(db_path):
        return {"rows": [], "total": 0, "page": page, "page_size": page_size}
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    offset = max(0, page) * page_size
    rows = cur.execute(
        "SELECT time, src_ip, dst_ip, method, url, status_code, action, protocol, src_port, dst_port, domain, user_agent "
        f"FROM logs ORDER BY {_NO_TIME_SQL} ASC, epoch ASC, id ASC LIMIT ? OFFSET ?",
        (page_size, offset),
    ).fetchall()
    conn.close()
    return {"rows": [dict(r) for r in rows], "total": total, "page": page, "page_size": page_size}


def _to_utc_naive(dt):
    """Timezone-aware datetimes are converted to UTC; naive ones are returned as is."""
    if dt is not None and dt.tzinfo is not None:
        dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt


_UNIX_TS_RE = re.compile(r"^\d{9,10}(\.\d+)?$|^\d{12,13}$")


TS_VALID, TS_INVALID, TS_UNAVAILABLE = "valid", "invalid", "unavailable"


def classify_timestamp(value) -> dict:
    """Tri-state timestamp normalisation.

    ``{"status": "valid"|"invalid"|"unavailable", "text": str, "epoch": int|None}``

    * unavailable — None / empty / whitespace: the source gave no time at all.
    * invalid     — something was given but cannot be parsed (never guessed, never "now").
    * valid       — UTC wall-clock text + epoch. A genuine 1970-01-01T00:00:00Z is *valid*
                    with epoch 0; ``epoch is None`` (not 0) means "no usable time".
    Zone policy (see _parse_time_any): offsets/"Z" are converted to UTC; zone-less text is
    taken as UTC by explicit decision. Independent of the machine's timezone.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return {"status": TS_UNAVAILABLE, "text": "", "epoch": None}
    dt = _parse_time_any(value) or _parse_ts(str(value))
    if not dt:
        return {"status": TS_INVALID, "text": "", "epoch": None}
    return {"status": TS_VALID, "text": dt.strftime("%Y-%m-%d %H:%M:%S"),
            "epoch": calendar.timegm(dt.utctimetuple())}


def _parse_time_any(ts):
    """Parse a timestamp into a *naive datetime expressed in UTC*.

    Normalisation rules (documented, deterministic, independent of the machine's zone):
      * ISO-8601 with "Z" or an offset (+07:00)  -> converted to UTC.
      * Unix time, 9-10 digits (seconds) or 12-13 digits (milliseconds) -> UTC.
      * Text without any zone (e.g. "2026-01-01 00:00:00") -> its wall-clock value is
        kept as-is and treated as UTC for the epoch; no zone is attached to the text.
      * Anything else -> None (unavailable; never replaced by "now" or a guess).
    """
    if isinstance(ts, datetime.datetime):
        return _to_utc_naive(ts)
    if ts is None or ts == "":
        return None
    text = str(ts).strip()
    if not text:
        return None
    if _UNIX_TS_RE.match(text):
        try:
            val = float(text)
            if len(text.split(".")[0]) >= 12:
                val /= 1000.0
            return datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc).replace(tzinfo=None)
        except (ValueError, OverflowError, OSError):
            return None
    try:
        return _to_utc_naive(datetime.datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError:
        return _parse_ts(text)


def normalize_timestamp(value) -> str:
    dt = _parse_time_any(value)
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _to_int(value):
    try:
        return int(str(value))
    except Exception:
        return None


def _get_row_value(row: dict, keys: list) -> str:
    row_lc = {str(k).lower(): v for k, v in row.items()}
    for k in keys:
        if k in row_lc and row_lc[k] not in (None, ""):
            return str(row_lc[k])
    return ""


def _extract_domain_from_info(info: str) -> str:
    if not info:
        return ""
    m = re.search(r"query\s+[A-Z]+\s+([A-Za-z0-9.-]+)", info)
    if m:
        return m.group(1)
    m = re.search(r"Standard query.*? ([A-Za-z0-9.-]+)", info)
    if m:
        return m.group(1)
    return ""


def _extract_ports_from_info(info: str) -> tuple:
    if not info:
        return "", ""
    m = re.search(r"(\d+)\s*(?:→|->)\s*(\d+)", info)
    if m:
        return m.group(1), m.group(2)
    return "", ""


_PCAP_MAGICS = (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d",
                b"\x4d\x3c\xb2\xa1", b"\x0a\x0d\x0d\x0a")


def _validate_pcap_header(file_path: str) -> str:
    """Return "" if the file looks like pcap/pcapng, otherwise a user-facing reason."""
    try:
        size = os.path.getsize(file_path)
        if size == 0:
            return "The capture file is empty (0 bytes)."
        with open(file_path, "rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        return f"Cannot read capture file: {exc}"
    if magic not in _PCAP_MAGICS:
        return "The file is not a valid .pcap/.pcapng capture (unrecognised file header)."
    return ""


def parse_pcap(file_path: str, max_packets: int = MAX_PREVIEW_PACKETS, progress_cb=None,
               cancel_cb=None) -> dict:
    if pyshark is None:
        return {"error": "pyshark not installed", "records": []}
    bad = _validate_pcap_header(file_path)
    if bad:
        log_event(f"parse_pcap: rejected {file_path!r}: {bad}")
        return {"error": bad, "records": []}
    records = []
    count = 0
    unlimited = max_packets in (None, 0)
    warning = ""
    cancelled = False
    # PyShark drives tshark through asyncio. The loop is owned here so it is
    # created, used, and closed in the same thread/function as the capture.
    loop = asyncio.new_event_loop()
    capture = pyshark.FileCapture(file_path, keep_packets=False, eventloop=loop)
    try:
        for packet in capture:
            if cancel_cb is not None and cancel_cb():
                cancelled = True
                break
            src = ""
            dst = ""
            src_port = ""
            dst_port = ""
            protocol = getattr(packet, "highest_layer", "") or ""
            domain = ""
            url = ""
            # sniff_time is a *naive local-time* datetime, so it shifts with the
            # machine's timezone. Build the string from the raw epoch instead and
            # render it explicitly in UTC so results are reproducible everywhere.
            ts_str = ""
            try:
                ts_str = datetime.datetime.fromtimestamp(float(packet.sniff_timestamp),
                                                         tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            except (AttributeError, TypeError, ValueError, OverflowError, OSError):
                ts_str = ""   # unavailable: left empty, never invented

            try:
                if hasattr(packet, "ip"):
                    src = packet.ip.src
                    dst = packet.ip.dst
                elif hasattr(packet, "ipv6"):
                    src = packet.ipv6.src
                    dst = packet.ipv6.dst
            except Exception:
                pass

            try:
                if hasattr(packet, "tcp"):
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                elif hasattr(packet, "udp"):
                    src_port = packet.udp.srcport
                    dst_port = packet.udp.dstport
            except Exception:
                pass

            try:
                if hasattr(packet, "dns") and hasattr(packet.dns, "qry_name"):
                    domain = str(packet.dns.qry_name)
            except Exception:
                pass

            try:
                if hasattr(packet, "http"):
                    if hasattr(packet.http, "host"):
                        domain = domain or str(packet.http.host)
                    if hasattr(packet.http, "request_full_uri"):
                        url = str(packet.http.request_full_uri)
                    elif hasattr(packet.http, "request_uri"):
                        uri = str(packet.http.request_uri)
                        if domain:
                            url = f"http://{domain}{uri}"
                        else:
                            url = uri
            except Exception:
                pass

            # Build IOC according to priority: HTTP > DNS > port
            ioc = ""
            try:
                if hasattr(packet, "http"):
                    host = getattr(packet.http, "host", "")
                    full_uri = getattr(packet.http, "request_full_uri", None)
                    rel_uri = getattr(packet.http, "request_uri", None) or ""
                    if full_uri:
                        ioc = str(full_uri)          # already includes scheme + host
                    elif host:
                        ioc = f"{host}{rel_uri}" if rel_uri else str(host)
                    else:
                        ioc = str(rel_uri)
                elif hasattr(packet, "dns") and getattr(packet.dns, "qry_name", None):
                    ioc = str(packet.dns.qry_name)
                else:
                    # fallback to destination port as IOC
                    ioc = f"port:{dst_port}" if dst_port else ""
            except Exception:
                ioc = ""

            # Debug prints if essential fields missing
            if not ts_str or not src or not ioc:
                log_event(f"[PCAP] incomplete packet #{count + 1}: time={ts_str!r} src={src!r} dst={dst!r} ioc={ioc!r}")

            records.append({
                "src_ip": src,
                "dst_ip": dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "domain": domain,
                "url": url,
                "timestamp": ts_str,
                "ioc": ioc,
            })
            count += 1
            if progress_cb:
                if unlimited:
                    progress_cb(0)
                else:
                    progress_cb(min(100, int((count / max_packets) * 100)))
            if not unlimited and count >= max_packets:
                break
    except Exception as exc:  # tshark crash / unreadable capture mid-stream
        warning = f"{type(exc).__name__}: {exc}"
        log_event(f"parse_pcap: capture error after {count} packets: {warning}")
    finally:
        try:
            capture.close()
        except Exception as exc:
            # tshark exits non-zero on corrupt/truncated captures; keep the message.
            warning = warning or f"{type(exc).__name__}: {exc}"
            log_event(f"parse_pcap: tshark reported an error on close: {exc}")
            # close() aborts before clearing its process set; clear it so that
            # Capture.__del__ does not try to close again on a dead event loop.
            try:
                capture._running_processes.clear()
            except Exception as clr:
                log_event(f"parse_pcap: could not clear process set: {clr}")
        capture = None
        try:
            # Let subprocess transports finish their callbacks, and finalise any
            # unreachable capture/transport objects while the loop is still open;
            # otherwise their __del__ runs later against a closed loop.
            import gc
            gc.collect()
            loop.run_until_complete(asyncio.sleep(0))
            loop.run_until_complete(asyncio.sleep(0))
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception as exc:
            log_event(f"parse_pcap: event loop drain failed: {exc}")
        finally:
            try:
                loop.close()
            except Exception as exc:
                log_event(f"parse_pcap: event loop close failed: {exc}")

    if not records and warning:
        return {"error": f"Could not read capture: {warning.splitlines()[0]}", "records": []}
    if not records and not cancelled:
        return {"error": "The capture file is valid but contains no packets.", "records": []}
    out = {"records": records, "truncated": (not unlimited and count >= max_packets),
           "cancelled": cancelled}
    if warning:
        out["warning"] = ("Capture ended early or is damaged; only the packets read "
                          f"before the error are included. Details: {warning.splitlines()[0]}")
    return out


def parse_wireshark_csv(file_path: str, max_records: int = MAX_PREVIEW_PACKETS, progress_cb=None,
                        cancel_cb=None) -> dict:
    records = []
    unlimited = max_records in (None, 0)
    invalid = 0
    invalid_samples = []
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as bf:
            f = io.TextIOWrapper(bf, encoding="utf-8", errors="replace", newline="")
            header = f.readline().lstrip("\ufeff")
            try:
                fieldnames = next(csv.reader([header], strict=True), None) if header.strip() else None
            except csv.Error:
                fieldnames = None
            if not fieldnames:
                return {"records": []}
            last_pct = -1
            i = -1
            # One physical line per row with strict quoting: a stray quote
            # invalidates only its own line instead of absorbing the following
            # rows (csv.DictReader would treat them as one multi-line field).
            for line in f:
                if not line.strip():
                    continue
                try:
                    vals = next(csv.reader([line], strict=True))
                except (csv.Error, StopIteration):
                    invalid += 1
                    if len(invalid_samples) < 5:
                        invalid_samples.append(line.strip()[:120])
                    continue
                i += 1
                if cancel_cb is not None and i % 1000 == 0 and cancel_cb():
                    return {"records": records, "cancelled": True, "invalid_records": invalid,
                            "invalid_samples": invalid_samples}
                row = dict(zip(fieldnames, vals))
                src = _get_row_value(row, ["source", "src", "src_ip", "ip.src"])
                dst = _get_row_value(row, ["destination", "dst", "dst_ip", "ip.dst"])
                protocol = _get_row_value(row, ["protocol", "protocols", "_ws.col.protocol"])
                ts = _get_row_value(row, ["time", "timestamp", "_ws.col.time"])
                info = _get_row_value(row, ["info", "_ws.col.info"])
                domain = _get_row_value(row, ["dns.qry.name", "dns.qry.name", "http.host", "host"])
                if not domain:
                    domain = _extract_domain_from_info(info)
                url = _get_row_value(row, ["http.request.full_uri", "http.request.uri", "url", "uri"])
                if not url and domain and "http" in (protocol or "").lower():
                    uri = _get_row_value(row, ["http.request.uri", "uri"]) or ""
                    if uri:
                        url = f"http://{domain}{uri}"
                src_port = _get_row_value(row, ["src port", "source port", "tcp.srcport", "udp.srcport"])
                dst_port = _get_row_value(row, ["dst port", "destination port", "tcp.dstport", "udp.dstport"])
                if not src_port and not dst_port:
                    src_port, dst_port = _extract_ports_from_info(info)

                records.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "domain": domain,
                    "url": url,
                    "timestamp": ts,
                    "info": info,
                })
                if progress_cb:
                    if unlimited:
                        pct = min(100, int(bf.tell() * 100 / file_size)) if file_size else 0
                    else:
                        pct = min(100, int((i + 1) / max_records * 100))
                    if pct != last_pct:          # emit on change only, not per record
                        last_pct = pct
                        progress_cb(pct)
                if not unlimited and i + 1 >= max_records:
                    break
    except Exception as e:
        return {"records": [], "error": str(e)}

    out = {"records": records, "truncated": (not unlimited and len(records) >= max_records),
           "invalid_records": invalid, "invalid_samples": invalid_samples}
    if invalid:
        log_event(f"parse_wireshark_csv: {invalid} malformed CSV line(s) skipped in {file_path!r}")
    return out


def parse_wireshark_txt(file_path: str, max_records: int = MAX_PREVIEW_PACKETS, progress_cb=None,
                        cancel_cb=None) -> dict:
    records = []
    unlimited = max_records in (None, 0)
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            last_pct = -1
            chars_read = 0
            fsize = os.path.getsize(file_path) or 1
            for i, line in enumerate(f):
                if cancel_cb is not None and i % 1000 == 0 and cancel_cb():
                    return {"records": records, "cancelled": True}
                chars_read += len(line)
                line = line.strip()
                if not line:
                    continue
                ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)", line)
                src = ips[0] if len(ips) > 0 else ""
                dst = ips[1] if len(ips) > 1 else ""
                protocol = ""
                if "TCP" in line:
                    protocol = "TCP"
                elif "UDP" in line:
                    protocol = "UDP"
                domain = _extract_domain_from_info(line)
                src_port, dst_port = _extract_ports_from_info(line)
                records.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "domain": domain,
                    "url": "",
                    "timestamp": "",
                    "info": line[:200],
                })
                if progress_cb:
                    if unlimited:       # approximate: characters consumed / file size
                        pct = min(99, int(chars_read * 100 / fsize))
                    else:
                        pct = min(100, int((i + 1) / max_records * 100))
                    if pct != last_pct:                  # on change only, not per record
                        last_pct = pct
                        progress_cb(pct)
                if not unlimited and i + 1 >= max_records:
                    break
    except Exception as e:
        return {"records": [], "error": str(e)}

    return {"records": records, "truncated": (not unlimited and len(records) >= max_records)}


def analyze_network_records(records: list) -> dict:
    findings = []
    iocs = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": [],
        "files": [],
        "total": 0,
    }
    src_counts = Counter()
    dst_counts = Counter()
    domain_counts = Counter()
    domain_by_src = defaultdict(set)
    domain_query_counts = Counter()
    protocol_counts = Counter()
    port_map = defaultdict(set)
    port_first = {}            # src -> first packet time (datetime) seen contributing to a port set
    beacon_map = defaultdict(list)
    tunnel_domains = set()
    tunnel_info = {}           # domain -> earliest sighting {"src","dst","ts"} (kept for the timeline)
    connections = set()
    session_map = defaultdict(lambda: {"total": 0, "dst_counts": Counter(), "proto_counts": Counter()})

    for r in records:
        src = r.get("src_ip", "")
        dst = r.get("dst_ip", "")
        domain = (r.get("domain") or "").strip().lower()
        url = (r.get("url") or "").strip()
        proto = (r.get("protocol") or "").upper()
        ts = _parse_time_any(r.get("timestamp"))

        if is_valid_ip(src):
            iocs["ips"].append(src)
            src_counts[src] += 1
            session_map[src]["total"] += 1
        if is_valid_ip(dst):
            iocs["ips"].append(dst)
            dst_counts[dst] += 1
            if src:
                session_map[src]["dst_counts"][dst] += 1
        if domain:
            d_info = normalize_input(domain)
            if d_info.get("type") == "domain":
                iocs["domains"].append(d_info.get("value"))
                domain_counts[d_info.get("value")] += 1
                if src:
                    domain_by_src[src].add(d_info.get("value"))
                    domain_query_counts[src] += 1
                if len(d_info.get("value")) > 50:
                    _tv = d_info.get("value")
                    tunnel_domains.add(_tv)
                    _prev = tunnel_info.get(_tv)
                    if _prev is None or (ts is not None and (_prev["ts"] is None or ts < _prev["ts"])):
                        tunnel_info[_tv] = {"src": src, "dst": dst, "ts": ts}
        if url:
            u_info = normalize_input(url)
            if u_info.get("type") == "url":
                iocs["urls"].append(u_info.get("value"))

        if proto:
            protocol_counts[proto] += 1
            if src:
                session_map[src]["proto_counts"][proto] += 1

        dst_port = _to_int(r.get("dst_port"))
        if src and dst_port:
            port_map[src].add(dst_port)
            if ts:
                port_first[src] = min(port_first.get(src, ts), ts)

        if src and dst:
            connections.add((src, dst, proto, dst_port))

        beacon_key = (src, dst, domain or url)
        if ts:
            beacon_map[beacon_key].append(ts)

    iocs = {k: sorted(set(v)) if isinstance(v, list) else v for k, v in iocs.items()}
    iocs["total"] = len(iocs["ips"]) + len(iocs["domains"]) + len(iocs["urls"]) + len(iocs["hashes"]) + len(iocs["files"])

    for src, ports in port_map.items():
        if len(ports) >= 20:
            findings.append({
                "attack_type": "port_scan",
                "timestamp": port_first[src].strftime("%Y-%m-%d %H:%M:%S") if src in port_first else "",
                "src_ip": src,
                "dst_ip": "multiple",
                "src": src,
                "dst": "multiple",
                "ioc": src,
                "type": "ip",
                "severity": "medium",
                "confidence": "medium",
                "reason": "Multiple destination ports",
                "false_positive_check": "passed",
                "description": f"Port scan suspected: {len(ports)} unique ports",
                "detail": f"Port scan suspected: {len(ports)} unique ports",
                "target": "multiple",
            })

    for (src, dst, target), times in beacon_map.items():
        if len(times) < 5:
            continue
        times = sorted(times)
        intervals = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)
                     if (times[i + 1] - times[i]).total_seconds() > 0]
        if len(intervals) < 4:
            continue
        mean = sum(intervals) / len(intervals)
        std = math.sqrt(sum((x - mean) ** 2 for x in intervals) / len(intervals)) if mean > 0 else 0
        if mean > 0 and std / mean <= 0.2:
            if is_benign_path(target) or is_static_resource(target):
                severity = "low"
                confidence = "low"
                reason = "Benign static resource beaconing"
                fp_check = "failed"
            else:
                host = ""
                try:
                    host = urlparse(target).hostname or ""
                except Exception:
                    host = ""
                if is_suspicious_domain(host):
                    severity = "high"
                    confidence = "high"
                    reason = "Beaconing to suspicious domain"
                    fp_check = "passed"
                else:
                    severity = "low"
                    confidence = "low"
                    reason = "Likely benign beaconing"
                    fp_check = "failed"
            findings.append({
                "attack_type": "beaconing",
                "timestamp": times[0].strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src or "unknown",
                "dst_ip": dst or "unknown",
                "src": src or "unknown",
                "dst": dst or "unknown",
                "ioc": target or dst or src,
                "type": normalize_input(target or "").get("type", "unknown"),
                "severity": severity,
                "confidence": confidence,
                "reason": reason,
                "false_positive_check": fp_check,
                "description": "Repeated connection pattern detected",
                "detail": "Repeated connection pattern detected",
                "target": target or "",
            })

    for domain in sorted(tunnel_domains):
        _ti = tunnel_info.get(domain) or {}
        # Use the real packet data; "unknown" only when the capture truly has no value.
        _t_src = _ti.get("src") or "unknown"
        _t_dst = _ti.get("dst") or "unknown"
        _t_ts = _ti.get("ts")
        findings.append({
            "attack_type": "dns_tunneling",
            "timestamp": _t_ts.strftime("%Y-%m-%d %H:%M:%S") if _t_ts else "",
            "src_ip": _t_src,
            "dst_ip": _t_dst,
            "src": _t_src,
            "dst": _t_dst,
            "ioc": domain,
            "type": "domain",
            "severity": "medium",
            "confidence": "medium",
            "reason": "Abnormally long domain name",
            "false_positive_check": "passed",
            "description": "Possible DNS tunneling",
            "detail": "Possible DNS tunneling",
            "target": domain,
        })

    for src, domains in domain_by_src.items():
        if len(domains) >= 30 and domain_query_counts.get(src, 0) >= 50:
            findings.append({
                "attack_type": "dns_anomaly",
                "src_ip": src,
                "dst_ip": "multiple",
                "src": src,
                "dst": "multiple",
                "ioc": src,
                "type": "ip",
                "severity": "medium",
                "confidence": "medium",
                "reason": "High unique DNS queries",
                "false_positive_check": "passed",
                "description": "High volume of unique DNS queries",
                "detail": "High volume of unique DNS queries",
                "target": "multiple",
            })

    COMMON_PORTS = {53, 80, 443, 22, 25, 110, 143, 3389, 123, 445, 139}
    port_hits = Counter()
    for r in records:
        dst_port = _to_int(r.get("dst_port"))
        if dst_port and dst_port not in COMMON_PORTS:
            port_hits[dst_port] += 1
    for port, count in port_hits.items():
        if count >= 20:
            findings.append({
                "attack_type": "suspicious_port",
                "src_ip": "multiple",
                "dst_ip": f"port:{port}",
                "src": "multiple",
                "dst": f"port:{port}",
                "ioc": str(port),
                "type": "unknown",
                "severity": "medium",
                "confidence": "medium",
                "reason": "Uncommon port traffic volume",
                "false_positive_check": "passed",
                "description": f"High traffic to uncommon port {port}",
                "detail": f"High traffic to uncommon port {port}",
                "target": str(port),
            })

    severity_counts = dict(Counter(f.get("severity", "low") for f in findings))
    attack_type_counts = dict(Counter(f.get("attack_type", "unknown") for f in findings))
    top_talkers = [{"value": k, "count": v} for k, v in src_counts.most_common(10)]
    top_destinations = [{"value": k, "count": v} for k, v in dst_counts.most_common(10)]
    top_domains = [{"value": k, "count": v} for k, v in domain_counts.most_common(10)]
    total_packets = len(records)
    protocol_distribution = []
    for proto, cnt in sorted(protocol_counts.items(), key=lambda x: -x[1]):
        pct = (cnt / total_packets * 100) if total_packets else 0
        protocol_distribution.append({"protocol": proto, "count": cnt, "percent": round(pct, 1)})
    traffic_summary = {
        "total_packets": total_packets,
        "total_connections": len(connections),
        "unique_src_ips": len(src_counts),
        "unique_dst_ips": len(dst_counts),
        "protocol_counts": dict(protocol_counts),
        "tcp_udp_ratio": "{}/{}".format(protocol_counts.get("TCP", 0), protocol_counts.get("UDP", 0)),
        "protocol_distribution": protocol_distribution,
        "top_talkers": {
            "src": top_talkers[:5],
            "dst": top_destinations[:5],
        },
    }

    session_summary = []
    for src, info in sorted(session_map.items(), key=lambda x: -x[1]["total"])[:10]:
        top_dst = info["dst_counts"].most_common(1)
        top_proto = info["proto_counts"].most_common(1)
        dst_map = [f"{d}({c})" for d, c in info["dst_counts"].most_common(3)]
        session_summary.append({
            "src": src,
            "connections": info["total"],
            "top_destination": top_dst[0][0] if top_dst else "",
            "protocol": top_proto[0][0] if top_proto else "",
            "dst_map": dst_map,
        })

    behavior_detection = []
    for f in findings:
        if f.get("attack_type") in ("port_scan", "beaconing", "dns_tunneling", "dns_anomaly", "suspicious_port"):
            behavior_detection.append({
                "type": f.get("attack_type"),
                "severity": f.get("severity", "low"),
                "description": f.get("description", ""),
                "src": f.get("src", ""),
                "dst": f.get("dst", ""),
                "timestamp": f.get("timestamp", ""),
                "ioc": f.get("ioc") or f.get("target") or "",
            })

    timeline = build_timeline_from_findings(findings, behavior_detection, source="pcap")
    timeline_ins = build_timeline_insight(timeline)
    event_counts = Counter([e.get("event") for e in timeline if e.get("event")])
    timeline_sev_counts = Counter([(e.get("severity") or "").upper() for e in timeline if e.get("severity")])

    return {
        "total_records": len(records),
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "attack_type_counts": attack_type_counts,
        "findings": findings,
        "iocs": iocs,
        "top_attacker_ips": top_talkers,
        "top_destination_ips": top_destinations,
        "top_domains": top_domains,
        "traffic_summary": traffic_summary,
        "session_summary": session_summary,
        "network_overview": {
            "total_packets": total_packets,
            "total_connections": len(connections),
        },
        "top_talkers": {"src": top_talkers, "dst": top_destinations},
        "protocol_distribution": protocol_distribution,
        "behavior_detection": behavior_detection,
        "raw_records": records,
        "parsed_records": records,
        "raw_count": len(records),
        "parsed_count": len(records),
        "timeline": timeline,
        "timeline_insight": timeline_ins,
        "event_counts": dict(event_counts),
        "timeline_severity_counts": dict(timeline_sev_counts),
    }



FORENSICS_ERROR_CODES = ("empty_path", "invalid_path", "not_found", "is_directory",
                         "permission_denied", "empty_file", "unsupported_file",
                         "file_too_large", "confirmation_required")


def _forensics_error(code: str, message: str, file_path=None) -> dict:
    """Error contract for the forensics service: NEVER raises for bad input; returns
    a structured result {"error": <user message>, "error_code": <stable code>, ...}
    (same shape the UI already renders). `records/findings/iocs` stay present and empty."""
    log_event(f"analyze_forensics_file: {code}: {file_path!r}")
    return {"error": message, "error_code": code, "records": [], "findings": [], "iocs": {}}


def validate_forensics_input(file_path) -> Optional[dict]:
    """Return None when *file_path* is a readable, non-empty, supported file;
    otherwise the structured error result."""
    if file_path is None or (isinstance(file_path, str) and not file_path.strip()):
        return _forensics_error("empty_path", "Path file kosong. Pilih file log/PCAP terlebih dahulu.", file_path)
    try:
        path = os.fspath(file_path)
    except TypeError:
        return _forensics_error("invalid_path", "Path file tidak valid.", file_path)
    if isinstance(path, bytes) or "\x00" in path:
        return _forensics_error("invalid_path", "Path file tidak valid.", file_path)
    if os.path.isdir(path):
        return _forensics_error("is_directory", f"Path menunjuk ke folder, bukan file: {path}", path)
    if not os.path.exists(path):
        return _forensics_error("not_found", f"File tidak ditemukan: {path}", path)
    if not os.path.isfile(path):
        return _forensics_error("invalid_path", f"Bukan file reguler: {path}", path)
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:          # real open() — os.access() is unreliable on Windows
            head = fh.read(4096)
    except PermissionError:
        return _forensics_error("permission_denied", f"Tidak punya izin membaca file: {path}", path)
    except OSError as exc:
        return _forensics_error("invalid_path", f"File tidak dapat dibuka: {exc}", path)
    if size == 0:
        return _forensics_error("empty_file", f"File kosong (0 byte): {path}", path)
    ext = os.path.splitext(path)[1].lower()
    if ext not in (".pcap", ".pcapng") and b"\x00" in head:
        return _forensics_error("unsupported_file",
                                f"Tipe file tidak didukung (file biner): {os.path.basename(path)}", path)
    return None


def analyze_forensics_file(file_path: str, max_records: int = MAX_PREVIEW_RECORDS, progress_cb=None,
                           cancel_cb=None, confirm_large: bool = False) -> dict:
    """Analyse a log/CSV/PCAP file. Error contract: invalid input never raises —
    a structured ``{"error", "error_code", "records", "findings", "iocs"}`` result is
    returned (see validate_forensics_input / FORENSICS_ERROR_CODES)."""
    _err = validate_forensics_input(file_path)
    if _err is not None:
        return _err
    # In-memory CSV/TXT path: refuse oversized files, require explicit confirmation for large ones.
    _size = check_tabular_size(file_path)
    if _size["level"] == "blocked":
        res = _forensics_error("file_too_large", _size["message"], file_path)
        res.update(size_mb=_size["size_mb"], est_ram_gb=_size["est_ram_gb"])
        return res
    if _size["level"] == "warn" and not confirm_large:
        res = _forensics_error("confirmation_required", _size["message"], file_path)
        res.update(size_mb=_size["size_mb"], est_ram_gb=_size["est_ram_gb"])
        return res
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".pcap", ".pcapng"):
        parsed = parse_pcap(file_path, max_packets=None, progress_cb=progress_cb, cancel_cb=cancel_cb)
        if parsed.get("error"):
            return {"error": parsed.get("error"), "records": [], "findings": [], "iocs": {}}
        result = analyze_network_records(parsed.get("records", []))
        result["truncated"] = parsed.get("truncated", False)
        if parsed.get("warning"):
            result["warning"] = parsed["warning"]
        if parsed.get("cancelled"):
            result["cancelled"] = True
        return result
    if ext == ".csv":
        parsed = parse_wireshark_csv(file_path, max_records=None, progress_cb=progress_cb, cancel_cb=cancel_cb)
        if parsed.get("cancelled"):
            return {"cancelled": True, "records": [], "findings": [], "iocs": {}}
        if parsed.get("records"):
            result = analyze_network_records(parsed.get("records", []))
            result["truncated"] = parsed.get("truncated", False)
            result["invalid_records"] = parsed.get("invalid_records", 0)
            result["invalid_samples"] = parsed.get("invalid_samples", [])
            result["lines_total"] = len(parsed["records"]) + result["invalid_records"]
            if result["invalid_records"]:
                result["warning"] = (f"{result['invalid_records']} malformed CSV line(s) were skipped "
                                     f"and not analysed (e.g. {parsed['invalid_samples'][0]!r}).")
            return result
    if ext == ".txt":
        parsed = parse_wireshark_txt(file_path, max_records=None, progress_cb=progress_cb, cancel_cb=cancel_cb)
        if parsed.get("cancelled"):
            return {"cancelled": True, "records": [], "findings": [], "iocs": {}}
        if parsed.get("records"):
            result = analyze_network_records(parsed.get("records", []))
            result["truncated"] = parsed.get("truncated", False)
            return result

    return analyze_logs_streaming_store(file_path, max_records=None, progress_cb=progress_cb,
                                        cancel_cb=cancel_cb)


def _pasted_log_suffix(raw_content: str) -> str:
    """Pick the temp-file extension that makes the file parser treat pasted text the
    same way it would treat an uploaded file of that format (the parser keys off the
    extension). A pasted JSON array must not be read as a single text line."""
    head = (raw_content or "").lstrip("\ufeff \t\r\n")
    if head[:1] == "[":
        return ".json"
    lines = [ln for ln in head.splitlines()[:2] if ln.strip()]
    if len(lines) == 2 and not lines[0].lstrip().startswith(("{", "<", "#")):
        cols = [c.strip() for c in lines[0].split(",")]
        if len(cols) >= 3 and all(re.fullmatch(r"[A-Za-z_][\w .\-]{0,40}", c) for c in cols) \
                and len(lines[1].split(",")) >= len(cols) - 1:
            return ".csv"
    return ".log"


def analyze_pasted_log_streaming(raw_content: str, progress_cb=None) -> dict:
    fd, tmp_path = tempfile.mkstemp(prefix="soc_paste_", suffix=_pasted_log_suffix(raw_content))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as f:
            f.write(raw_content or "")
        return analyze_forensics_file(tmp_path, max_records=None, progress_cb=progress_cb)
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


def _starts_with_json_array(file_path: str) -> bool:
    try:
        with open(file_path, "rb") as fh:
            head = fh.read(4096).lstrip(b"\xef\xbb\xbf \t\r\n")
        return head[:1] == b"["
    except OSError:
        return False


def _iter_json_array(bf, state: dict):
    """Incrementally yield the elements of a top-level JSON array (any layout:
    single-line, pretty-printed, one-per-line) without loading the whole file.
    Memory is bounded by one chunk plus the largest single element."""
    import codecs
    dec = json.JSONDecoder()
    inc = codecs.getincrementaldecoder("utf-8")(errors="replace")
    buf, pos, started, eof = "", 0, False, False
    while True:
        while pos < len(buf) and buf[pos] in " \t\r\n,\ufeff":
            pos += 1
        if pos < len(buf):
            if not started:
                if buf[pos] != "[":
                    state["parse_error"] = "not a JSON array"
                    return
                started = True
                pos += 1
                continue
            if buf[pos] == "]":
                return
            try:
                obj, end = dec.raw_decode(buf, pos)
            except json.JSONDecodeError as exc:
                if eof:
                    state["parse_error"] = f"{exc.msg} at char {exc.pos}"
                    return
                # element may continue in the next chunk: fall through to refill
            else:
                pos = end
                yield obj
                continue
        elif eof:
            if started:
                state["parse_error"] = "array not terminated (file ends early)"
            return
        chunk = bf.read(1 << 20)
        state["bytes_read"] = bf.tell()
        if not chunk:
            eof = True
            buf = buf[pos:] + inc.decode(b"", final=True)
        else:
            buf = buf[pos:] + inc.decode(chunk)
        pos = 0


def iter_log_records_from_file(file_path: str, max_records: int = MAX_PREVIEW_RECORDS,
                               progress_cb=None, state: dict = None, cancel_cb=None):
    """Stream records from a file using a generator to avoid loading everything into memory."""
    if state is None:
        state = {}
    file_size = os.path.getsize(file_path)
    state["file_size"] = file_size
    state["bytes_read"] = 0
    state["truncated"] = False
    state["invalid"] = 0
    state["invalid_samples"] = []
    last_pct = -1

    def _bad(line_txt):
        state["invalid"] += 1
        if len(state["invalid_samples"]) < 5:
            state["invalid_samples"].append(line_txt[:120])

    def _report(bytes_read):
        nonlocal last_pct
        if not progress_cb or file_size <= 0:
            return
        pct = min(100, int((bytes_read / file_size) * 100))
        if pct != last_pct:
            last_pct = pct
            progress_cb(pct)

    ext = os.path.splitext(file_path)[1].lower()
    count = 0

    if ext == ".csv":
        with open(file_path, "rb") as bf:
            text = io.TextIOWrapper(bf, encoding="utf-8", errors="replace", newline="")
            reader = csv.DictReader(text)
            for row in reader:
                yield dict(row)
                count += 1
                state["bytes_read"] = bf.tell()
                _report(state["bytes_read"])
                if cancel_cb is not None and count % 500 == 0 and cancel_cb():
                    state["cancelled"] = True
                    break
                if max_records and count >= max_records:
                    state["truncated"] = True
                    break
    elif ext == ".json" and _starts_with_json_array(file_path):
        with open(file_path, "rb") as bf:
            for rec in _iter_json_array(bf, state):
                if isinstance(rec, dict):
                    yield rec
                    count += 1
                else:
                    _bad(repr(rec))
                _report(state["bytes_read"])
                if cancel_cb is not None and (count + state["invalid"]) % 500 == 0 and cancel_cb():
                    state["cancelled"] = True
                    break
                if max_records and count >= max_records:
                    state["truncated"] = True
                    break
        if state.get("parse_error"):
            _bad(f"JSON array error: {state['parse_error']}")
    else:
        with open(file_path, "rb") as bf:
            for line in bf:
                state["bytes_read"] += len(line)
                txt = line.decode("utf-8", errors="replace").strip()
                if not txt or txt in ("[", "]"):
                    _report(state["bytes_read"])
                    continue

                if ext == ".json":
                    if txt.endswith(","):
                        txt = txt[:-1]
                    if txt.startswith("{"):
                        try:
                            rec = json.loads(txt)
                            if isinstance(rec, dict):
                                yield rec
                                count += 1
                            else:
                                _bad(txt)
                        except json.JSONDecodeError:
                            _bad(txt)           # reported, never silently dropped
                else:
                    if txt.startswith("{"):
                        try:
                            rec = json.loads(txt)
                        except json.JSONDecodeError:
                            _bad(txt)           # JSON-looking but broken: not a text record
                        else:
                            yield rec if isinstance(rec, dict) else _parse_plain_text_line(txt)
                            count += 1
                    else:
                        yield _parse_plain_text_line(txt)
                        count += 1

                _report(state["bytes_read"])
                if cancel_cb is not None and (count + state["invalid"]) % 500 == 0 and cancel_cb():
                    state["cancelled"] = True
                    break
                if max_records and count >= max_records:
                    state["truncated"] = True
                    break

    _report(file_size)
    state["count"] = count


def analyze_logs_streaming(file_path: str, field_mapping: dict = None,
                           max_records: int = MAX_PREVIEW_RECORDS, progress_cb=None) -> dict:
    """Full forensics pipeline for file input using streaming reads."""
    state = {}
    records = [r for r in iter_log_records_from_file(file_path, max_records=max_records,
                                                     progress_cb=progress_cb, state=state)]
    if not records:
        LOGGER.warning("Parsing error: could not parse log file.")
        return {"error": "Could not parse log", "records": [], "findings": [], "iocs": {}}
    normalized = normalize_log(records, field_mapping)
    findings   = detect_attacks(normalized)
    iocs       = extract_ioc_from_records(normalized)
    sev_counts = dict(Counter(f["severity"]  for f in findings))
    atk_counts = dict(Counter(f["attack_type"] for f in findings))
    traffic_summary = build_traffic_summary(normalized)
    anomalies = detect_anomalies(traffic_summary)
    top_ips = traffic_summary.get("top_src_ips", [])
    if top_ips:
        top_preview = ", ".join([f"{t['value']}({t['count']})" for t in top_ips[:3]])
        log_event(f"Top attacker IPs: {top_preview}")
    timeline = build_timeline_from_findings(findings, anomalies, source="log")
    timeline_insight = build_timeline_insight(timeline)
    return {
        "total_records": len(normalized),
        "total_findings": len(findings),
        "severity_counts": sev_counts,
        "attack_type_counts": atk_counts,
        "findings": findings,
        "iocs": iocs,
        "top_attacker_ips": top_ips,
        "traffic_summary": traffic_summary,
        "anomalies": anomalies,
        "raw_records": records,
        "parsed_records": normalized,
        "raw_count": len(records),
        "parsed_count": len(normalized),
        "truncated": state.get("truncated", False),
    }


def analyze_logs(raw_content: str, field_mapping: dict = None,
                 max_records: int = MAX_PREVIEW_RECORDS) -> dict:
    """Full forensics pipeline: parse → normalize → detect → extract IOCs."""
    records = parse_log(raw_content)
    if not records:
        LOGGER.warning("Parsing error: could not parse log content.")
        return {"error": "Could not parse log", "records": [], "findings": [], "iocs": {}}
    truncated = False
    if len(records) > max_records:
        records = records[:max_records]
        truncated = True
    normalized = normalize_log(records, field_mapping)
    findings   = detect_attacks(normalized)
    iocs       = extract_ioc_from_records(normalized)
    sev_counts = dict(Counter(f["severity"]  for f in findings))
    atk_counts = dict(Counter(f["attack_type"] for f in findings))
    traffic_summary = build_traffic_summary(normalized)
    anomalies = detect_anomalies(traffic_summary)
    top_ips = traffic_summary.get("top_src_ips", [])
    if top_ips:
        top_preview = ", ".join([f"{t['value']}({t['count']})" for t in top_ips[:3]])
        log_event(f"Top attacker IPs: {top_preview}")
    timeline = build_timeline_from_findings(findings, anomalies, source="log")
    timeline_insight = build_timeline_insight(timeline)
    return {
        "total_records": len(normalized),
        "total_findings": len(findings),
        "severity_counts": sev_counts,
        "attack_type_counts": atk_counts,
        "findings": findings,
        "iocs": iocs,
        "top_attacker_ips": top_ips,
        "traffic_summary": traffic_summary,
        "anomalies": anomalies,
        "raw_records": records,
        "parsed_records": normalized,
        "raw_count": len(records),
        "parsed_count": len(normalized),
        "timeline": timeline,
        "timeline_insight": timeline_insight,
        "truncated": truncated,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — AI MODULE
# ══════════════════════════════════════════════════════════════════════════════

def generate_ai_summary(data: dict, mode: str = "cti") -> dict:
    """Generate AI summary with rule-based fallback."""
    return AI.generate_summary(data, mode=mode)


def generate_local_ai_summary(local_result: dict) -> dict:
    """Generate AI summary from local analysis with rule-based fallback."""
    return AI.generate_local_summary(local_result)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — UI PALETTE & STYLESHEET
# ══════════════════════════════════════════════════════════════════════════════

from ui.styles.colors import PALETTE as _PALETTE
from ui.styles.theme import base_font_qss as _base_font_qss
P = dict(_PALETTE)   # single source of truth: ui/styles/colors.py
from ui.styles.typography import FONT_STACK as _FONT_STACK, FONT_MONO_STACK as _FONT_MONO
from ui.styles.components import status_badge_qss as _status_badge_qss
from ui.styles import qss_compat as _qss_compat
_qss_compat.install()   # fixes legacy f"{color}22" tints (Qt reads hex8 as #AARRGGBB)
from ui.widgets import (SidebarButton, SidebarSection, HeaderBar, StatCard, SeverityBadge,
                        StatusBadge, SectionHeader, ModernButton, IconLabel, RiskMeter,
                        LoadingIndicator, AnalysisEmptyState, IOCChip, SourceCard, IconButton,
                        TypingIndicator)
from ui.styles.colors import tint as _tint, severity_color as _severity_color

STYLESHEET = f"""
/* ═══════════════════════════════════════════════════════════
   GUARDIAN AI — Enterprise SOC Platform Stylesheet v3.0
   Design: CrowdStrike Falcon / Microsoft Sentinel inspired
   ═══════════════════════════════════════════════════════════ */

QMainWindow, QWidget {{
    background-color: {P['bg_dark']};
    color: {P['text_main']};
    {_base_font_qss()}
}}
QLabel {{
    color: {P['text_main']};
    background: transparent;
}}

/* ── Inputs ──────────────────────────────────────────────── */
QLineEdit, QTextEdit, QComboBox {{
    background-color: {P['bg_input']};
    border: 1px solid {P['border2']};
    border-radius: 8px;
    color: {P['text_main']};
    padding: 9px 14px;
    font-family: {_FONT_STACK};
    font-size: 13px;
    selection-background-color: {P['accent']}44;
}}
QLineEdit:focus, QTextEdit:focus, QComboBox:focus {{
    border: 1px solid {P['accent']};
    background-color: {P['bg_card2']};
    outline: none;
}}
QLineEdit::placeholder {{
    color: {P['text_dim']};
}}
QComboBox::drop-down {{
    border: none;
    padding-right: 10px;
    width: 20px;
}}
QComboBox QAbstractItemView {{
    background: {P['bg_card']};
    border: 1px solid {P['border2']};
    border-radius: 6px;
    color: {P['text_main']};
    selection-background-color: {P['accent']}33;
    padding: 4px;
}}
QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 5px solid {P['text_dim']};
}}

/* ── Buttons ─────────────────────────────────────────────── */
QPushButton {{
    background-color: {P['bg_card2']};
    border: 1px solid {P['border2']};
    border-radius: 8px;
    color: {P['text_main']};
    padding: 9px 20px;
    font-weight: 600;
    font-size: 13px;
    font-family: {_FONT_STACK};
}}
QPushButton:hover {{
    background-color: {P['accent']}18;
    border: 1px solid {P['accent']}88;
    color: {P['accent']};
}}
QPushButton:pressed {{
    background-color: {P['accent']}30;
    border: 1px solid {P['accent']};
}}
QPushButton:disabled {{
    background-color: {P['bg_card']};
    color: {P['text_dim']};
    border-color: {P['border']};
}}
QPushButton#btn_primary {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {P['accent']}, stop:1 {P['accent2']});
    color: #04121A;
    border: none;
    font-weight: 700;
    font-size: 13px;
    border-radius: 8px;
    padding: 10px 24px;
    letter-spacing: 0.3px;
}}
QPushButton#btn_primary:hover {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #33D6F2, stop:1 #4C8BFF);
    color: #04121A;
}}
QPushButton#btn_primary:pressed {{
    background-color: #0A8FB0;
}}
QPushButton#btn_primary:disabled {{
    background: {P['bg_input']};
    color: {P['text_dim']};
}}
QPushButton#btn_danger {{
    background-color: {P['high_bg']};
    border: 1px solid {P['high_border']};
    color: {P['high_text']};
    border-radius: 8px;
    padding: 9px 20px;
    font-weight: 600;
}}
QPushButton#btn_danger:hover {{
    background-color: {P['critical']}33;
    border-color: {P['critical']};
    color: #fff;
}}

/* ── Sidebar nav buttons ─────────────────────────────────── */
QPushButton#btn_sidebar {{
    background-color: transparent;
    border: none;
    border-radius: 0px;
    border-left: 3px solid transparent;
    color: {P['text_dim']};
    padding: 13px 20px 13px 18px;
    text-align: left;
    font-size: 13px;
    font-weight: 500;
}}
QPushButton#btn_sidebar:hover {{
    background-color: {P['bg_card']}cc;
    color: {P['text_main']};
    border-left: 3px solid {P['border3']};
}}
QPushButton#btn_sidebar_active {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {P['accent']}1e, stop:1 transparent);
    border: none;
    border-radius: 0px;
    border-left: 3px solid {P['accent']};
    color: {P['accent']};
    padding: 13px 20px 13px 18px;
    text-align: left;
    font-size: 13px;
    font-weight: 700;
}}

/* ── Scrollbars ──────────────────────────────────────────── */
QScrollBar:vertical {{
    background: {P['bg_dark']};
    width: 6px;
    border-radius: 3px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {P['border3']};
    border-radius: 3px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {P['accent']}88; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
QScrollBar:horizontal {{
    background: {P['bg_dark']};
    height: 6px;
    border-radius: 3px;
}}
QScrollBar::handle:horizontal {{
    background: {P['border3']};
    border-radius: 3px;
    min-width: 30px;
}}
QScrollBar::handle:horizontal:hover {{ background: {P['accent']}88; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0px; }}

/* ── Tab widget (underline style) ────────────────────────── */
QTabWidget::pane {{
    border: none;
    border-top: 1px solid {P['border']};
    background: transparent;
}}
QTabBar {{ qproperty-drawBase: 0; background: transparent; }}
QTabBar::tab {{
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    color: {P['text_label']};
    padding: 10px 12px;
    margin-right: 0px;
    font-size: 12px;
    font-weight: 600;
    min-width: 40px;
}}
QTabBar::tab:selected {{
    color: {P['accent']};
    border-bottom: 2px solid {P['accent']};
}}
QTabBar::tab:hover:!selected {{
    color: {P['text_main']};
    border-bottom: 2px solid {P['border2']};
}}
QTabBar::scroller {{ width: 26px; }}
QTabBar QToolButton {{ background: {P['bg_card']}; border: 1px solid {P['border']}; border-radius: 6px; }}

/* ── Tables ──────────────────────────────────────────────── */
QTableWidget {{
    background: {P['bg_panel']};
    border: 1px solid {P['border']};
    border-radius: 10px;
    gridline-color: {P['border']};
    color: {P['text_main']};
    selection-background-color: {P['accent']}22;
    alternate-background-color: {P['bg_card']};
    font-size: 13px;
}}
QTableWidget::item {{
    padding: 9px 12px;
    border: none;
    border-bottom: 1px solid {P['border']};
}}
QTableWidget::item:hover {{
    background: {P['accent']}10;
}}
QTableWidget::item:selected {{
    background: {P['accent']}22;
    color: {P['text_bright']};
}}
QHeaderView::section {{
    background-color: {P['bg_card']};
    border: none;
    border-bottom: 2px solid {P['accent']}55;
    border-right: 1px solid {P['border']};
    color: {P['accent']};
    padding: 10px 12px;
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.8px;
    text-transform: uppercase;
}}
QHeaderView::section:first {{
    border-top-left-radius: 10px;
}}
QHeaderView::section:last {{
    border-right: none;
}}

/* ── Progress bars ───────────────────────────────────────── */
QProgressBar {{
    background-color: {P['bg_input']};
    border: none;
    border-radius: 6px;
    height: 10px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {P['accent']}, stop:1 #0099bb);
    border-radius: 6px;
}}

/* ── Menu bar (View ▸ Reset Layout) ─────────────────────────── */
QMenuBar {{
    background: {P['sidebar_bg']};
    color: {P['text_label']};
    border-bottom: 1px solid {P['border']};
    padding: 2px 4px;
    font-family: 'Segoe UI','Inter',Arial,sans-serif;
    font-size: 12px;
}}
QMenuBar::item {{
    background: transparent;
    padding: 4px 10px;
    border-radius: 4px;
}}
QMenuBar::item:selected {{
    background: {P['bg_card2']};
    color: {P['accent']};
}}
QMenu {{
    background: {P['bg_card']};
    color: {P['text_main']};
    border: 1px solid {P['border']};
    padding: 4px;
}}
QMenu::item {{
    padding: 6px 20px;
    border-radius: 4px;
}}
QMenu::item:selected {{
    background: {P['bg_card2']};
    color: {P['accent']};
}}

/* ── Splitter ────────────────────────────────────────────── */
/* SmoothSplitterHandle paints itself (slim line + hover/drag glow), so the
   stylesheet only needs to stay out of the way — no fixed width/height here,
   which would otherwise fight QSplitter.setHandleWidth()'s wider hitbox. */
QSplitter::handle {{
    background: transparent;
}}

/* ── Message boxes ───────────────────────────────────────── */
QMessageBox {{
    background: {P['bg_card']};
    color: {P['text_main']};
}}
QMessageBox QPushButton {{
    min-width: 90px;
}}

/* ── Tooltips ────────────────────────────────────────────── */
QToolTip {{
    background: {P['bg_card2']};
    color: {P['text_main']};
    border: 1px solid {P['accent']}66;
    border-radius: 8px;
    padding: 7px 12px;
    font-size: 12px;
}}

/* ── QTextBrowser ────────────────────────────────────────── */
QTextBrowser {{
    background: {P['bg_panel']};
    color: {P['text_main']};
    border: 1px solid {P['border']};
    border-radius: 8px;
    padding: 10px;
    font-size: 13px;
    selection-background-color: {P['accent']}33;
}}

/* ── QCheckBox ───────────────────────────────────────────── */
QCheckBox {{
    color: {P['text_main']};
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {P['border2']};
    border-radius: 4px;
    background: {P['bg_input']};
}}
QCheckBox::indicator:checked {{
    background: {P['accent']};
    border-color: {P['accent']};
}}

/* ── QListWidget ─────────────────────────────────────────── */
QListWidget {{
    background: {P['bg_panel']};
    color: {P['text_main']};
    border: 1px solid {P['border']};
    border-radius: 8px;
    outline: none;
    font-size: 12px;
}}
QListWidget::item {{
    padding: 8px 12px;
    border-bottom: 1px solid {P['border']};
}}
QListWidget::item:hover {{
    background: {P['bg_card2']};
}}
QListWidget::item:selected {{
    background: {P['accent']}22;
    color: {P['accent']};
}}
"""




# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — REUSABLE UI HELPERS
# ══════════════════════════════════════════════════════════════════════════════

_LBL_SIZE_MAP = {9: 11, 10: 11, 11: 12, 12: 13}   # legacy sizes → readable design-system sizes


def lbl(text, color=None, bold=False, size=13):
    w = QLabel(text)
    size = _LBL_SIZE_MAP.get(size, size)
    parts = [
        f"font-family:{_FONT_STACK};",
        f"font-size:{size}px;",
        "background:transparent;",
    ]
    if color: parts.append(f"color:{color};")
    if bold:  parts.append("font-weight:600;")
    w.setStyleSheet("".join(parts))
    return w


def sep():
    f = QFrame()
    f.setFrameShape(QFrame.HLine)
    f.setFixedHeight(1)
    f.setStyleSheet(f"background:{P['border']};")
    return f


def vsep():
    f = QFrame()
    f.setFrameShape(QFrame.VLine)
    f.setFixedWidth(1)
    f.setStyleSheet(f"background:{P['border']};")
    return f


def card(title="", color=None):
    """Returns (widget, inner_layout). Design-system card with accented title."""
    accent = color or P["accent"]
    w = QFrame()
    w.setObjectName("dscard")
    w.setStyleSheet(
        f"QFrame#dscard{{background:{P['bg_card']};border:1px solid {P['border']};"
        f"border-radius:12px;}}"
        f"QFrame#dscard:hover{{border:1px solid {_tint(accent, 110)};}}"
    )
    cl = QVBoxLayout(w)
    cl.setContentsMargins(16, 14, 16, 14)
    cl.setSpacing(10)
    if title:
        hrow = QHBoxLayout()
        bar = QFrame()
        bar.setFixedSize(3, 14)
        bar.setStyleSheet(f"background:{accent};border-radius:2px;border:none;")
        hrow.addWidget(bar)
        hrow.addSpacing(8)
        t = QLabel(title.upper())
        t.setStyleSheet(
            f"color:{accent};font-weight:600;font-size:12px;"
            f"background:transparent;border:none;font-family:{_FONT_STACK};"
        )
        hrow.addWidget(t)
        hrow.addStretch()
        cl.addLayout(hrow)
        div = QFrame()
        div.setFrameShape(QFrame.HLine)
        div.setFixedHeight(1)
        div.setStyleSheet(f"background:{P['border']};border:none;")
        cl.addWidget(div)
    return w, cl



def badge(sev: str) -> QLabel:
    """Severity badge — the single shared SeverityBadge style."""
    return SeverityBadge(str(sev or "unknown"), min_width=64)


def score_bar(value: int) -> QProgressBar:
    """Gradient risk score progress bar."""
    bar = QProgressBar()
    bar.setMaximum(100)
    bar.setValue(value)
    bar.setFixedHeight(8)
    bar.setTextVisible(False)
    if value >= 80:   color = P["critical"]; color2 = "#C23030"
    elif value >= 60: color = P["high"];     color2 = "#B8303C"
    elif value >= 40: color = P["medium"];   color2 = "#B97A07"
    elif value >= 20: color = P["low"];      color2 = "#169A4A"
    else:             color = P["info"];     color2 = "#1B8FB3"
    bar.setStyleSheet(
        f"QProgressBar{{background:{P['bg_input']};border:none;border-radius:4px;}}"
        f"QProgressBar::chunk{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,"
        f"stop:0 {color},stop:1 {color2});border-radius:4px;}}"
    )
    return bar


def ai_browser():
    """Styled text browser for AI summary output."""
    w = QTextBrowser()
    w.setStyleSheet(
        f"QTextBrowser{{background:{P['bg_panel']};color:{P['text_main']};"
        f"font-size:14px;padding:16px 18px;"
        f"border:1px solid {P['border']};"
        f"border-radius:10px;"
        f"font-family:{_FONT_STACK};}}"
    )
    w.setOpenExternalLinks(True)
    return w


def scroll_page():
    """Returns (QScrollArea, inner QWidget, inner QVBoxLayout)."""
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setFrameShape(QFrame.NoFrame)
    iw = QWidget()
    iw.setStyleSheet(f"background:{P['bg_panel']};")
    il = QVBoxLayout(iw)
    il.setContentsMargins(14, 14, 14, 14)
    il.setSpacing(10)
    sa.setWidget(iw)
    return sa, iw, il



def clear_layout(layout):
    while layout.count():
        item = layout.takeAt(0)
        if item.widget():
            item.widget().hide()             # vanish immediately; deleteLater frees it next loop turn
            item.widget().deleteLater()
        elif item.layout():
            clear_layout(item.layout())      # nested rows: delete their widgets too


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — WORKER THREAD
# ══════════════════════════════════════════════════════════════════════════════

class Worker(QThread):
    done  = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn; self.args = args; self.kwargs = kwargs

    def run(self):
        try:
            r = self.fn(*self.args, **self.kwargs)
            self.done.emit(r if isinstance(r, dict) else {"data": r})
        except Exception as e:
            self.error.emit(str(e))


def stop_thread(th, timeout_ms: int = 5000) -> bool:
    """Ask a QThread to finish cooperatively and wait for it. Never terminate().
    Returns True when the thread is not running afterwards."""
    try:
        if th is None or _sip.isdeleted(th) or not th.isRunning():
            return True
        th.requestInterruption()
        th.quit()
        if th.wait(timeout_ms):
            return True
        log_event(f"stop_thread: {type(th).__name__} still running after {timeout_ms} ms")
        return False
    except Exception as exc:
        log_event(f"stop_thread error: {type(exc).__name__}: {exc}")
        return False


def stop_all_threads(*owners, timeout_ms: int = 5000) -> list:
    """Stop every running QThread held as an attribute of the given objects.
    Returns the class names of threads that did not stop in time."""
    stuck = []
    for owner in owners:
        for name, val in list(vars(owner).items()):
            items = val if isinstance(val, list) else [val]
            for th in list(items):
                if isinstance(th, QThread) and not stop_thread(th, timeout_ms):
                    stuck.append(f"{type(owner).__name__}.{name}")
    for th in list(_RUNNING_AI_WORKERS):       # superseded / orphaned AI-summary workers
        if not stop_thread(th, timeout_ms):
            stuck.append("AI summary worker")
    return stuck


def reflow_buttons(grid, buttons: list, avail_width: int, spacing: int = 6):
    """Lay buttons out in as many columns as fit in avail_width (at least one),
    so labels are never squeezed below their text width on a narrow panel."""
    for b in buttons:
        grid.removeWidget(b)
    if not buttons:
        return
    need = max(b.sizeHint().width() for b in buttons) + spacing
    cols = max(1, min(len(buttons), (max(avail_width, 1) + spacing) // need))
    for i, b in enumerate(buttons):
        grid.addWidget(b, i // cols, i % cols)
    for c in range(len(buttons)):
        grid.setColumnStretch(c, 1 if c < cols else 0)


def is_busy(worker) -> bool:
    """True while a QThread worker is still running (request guard)."""
    try:
        return worker is not None and not _sip.isdeleted(worker) and worker.isRunning()
    except Exception:
        return False


# Every AI-summary worker is kept alive here until its thread has REALLY finished, independent of
# the page that started it: if the page is destroyed/closed while the worker runs, the QThread must
# not be garbage-collected mid-run ("QThread: Destroyed while thread is still running" aborts the app).
_RUNNING_AI_WORKERS = set()


def _make_retired_dropper(lst: list, th):
    def _drop():                       # plain closure (no default-arg slot)
        if th in lst:
            lst.remove(th)
    return _drop


def _qt_deleted(obj) -> bool:
    """True only for a Qt wrapper whose C++ object is gone; plain Python objects are never 'deleted'."""
    try:
        return bool(_sip.isdeleted(obj))
    except TypeError:
        return False


def _owner_alive(owner) -> bool:
    try:
        return not _qt_deleted(owner) and not _qt_deleted(owner.ai)
    except AttributeError:
        return False


def run_ai_summary(owner, fn, module_label: str, target: dict = None):
    """Start the AI-summary worker for a page without ever dropping the last
    reference to a running QThread, and without letting a stale summary
    overwrite a newer one (or touch a page that no longer exists)."""
    old = getattr(owner, "_ai_w", None)
    if old is not None:
        for sig in (old.done, old.error):
            try:
                sig.disconnect()
            except TypeError:
                pass                      # nothing connected
        if is_busy(old):
            # keep the superseded, still-running worker referenced on the page too (and in
            # _RUNNING_AI_WORKERS) until it has really finished
            retired = owner.__dict__.setdefault("_ai_retired", [])
            retired.append(old)
            old.finished.connect(_make_retired_dropper(retired, old))
    owner.ai.setPlainText("⏳ Generating AI summary...")
    w = Worker(fn)
    _RUNNING_AI_WORKERS.add(w)

    def _on_summary(res):
        if not _owner_alive(owner):
            log_event(f"AI summary ({module_label}) finished after its page was closed; discarded")
            return
        text = res.get("summary", "No summary")
        owner.ai.setMarkdown(text)
        # Keep the summary WITH the result it describes (the exact object passed in), so the PDF
        # export / history reload show what the user saw, and a late answer for an old result
        # can never attach itself to a newer one.
        if isinstance(target, dict) and res.get("summary"):
            target["ai_summary"] = text
            target["ai_summary_source"] = res.get("source", "")

    def _on_error(e):
        log_event(f"AI summary error ({module_label}): {e}")
        if _owner_alive(owner):
            owner.ai.setMarkdown(f"⚠ AI summary unavailable.\n\n**Reason:** {e[:200]}\n\nFindings above are still valid.")

    def _release():
        w.wait(2000)                      # QThread.finished fires slightly before the OS thread is gone
        _RUNNING_AI_WORKERS.discard(w)

    w.done.connect(_on_summary)
    w.error.connect(_on_error)
    w.finished.connect(_release)
    w.start()
    owner._ai_w = w


class LogParseWorker(QThread):
    done     = pyqtSignal(dict)
    error    = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, file_path: str, max_records: int = MAX_PREVIEW_RECORDS, confirm_large: bool = False):
        super().__init__()
        self.file_path = file_path
        self.max_records = max_records
        self.confirm_large = confirm_large

    def run(self):
        # The asyncio loop PyShark needs is created and closed inside parse_pcap(),
        # in this same thread, so it cannot outlive the capture that uses it.
        try:
            def _cb(pct):
                self.progress.emit(pct)
            r = analyze_forensics_file(self.file_path, max_records=self.max_records,
                                       progress_cb=_cb, cancel_cb=self.isInterruptionRequested,
                                       confirm_large=self.confirm_large)
            self.done.emit(r if isinstance(r, dict) else {"data": r})
        except Exception as e:
            log_event(f"LogParseWorker failed: {type(e).__name__}: {e}")
            self.error.emit(str(e))


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9b — SQLITE DATABASE MANAGER
# ══════════════════════════════════════════════════════════════════════════════

DB_PATH = os.path.join(app_base_dir(), "soc_history.db")

def init_db():
    """Initialize the SQLite database and create tables if needed."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                module TEXT,
                severity TEXT,
                ioc TEXT,
                summary TEXT,
                raw_json TEXT
            )
        """)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        log_event(f"DB init error: {e}")
        return False


def _fit_json(obj, limit: int = 50000) -> str:
    """Serialise obj to *valid* JSON of at most `limit` chars. Oversized data is
    progressively shrunk (not cut mid-string) and flagged with _truncated."""
    raw = json.dumps(obj, default=str)
    if len(raw) <= limit:
        return raw
    def shrink(o, depth, n_list, n_str):
        if depth > 6:
            return "…"
        if isinstance(o, dict):
            return {str(k): shrink(v, depth + 1, n_list, n_str) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [shrink(v, depth + 1, n_list, n_str) for v in list(o)[:n_list]]
        if isinstance(o, str):
            return o[:n_str]
        return o
    for n_list, n_str in ((500, 2000), (100, 500), (30, 200), (10, 100), (3, 60)):
        red = shrink(obj, 0, n_list, n_str)
        if isinstance(red, dict):
            red["_truncated"] = True
        out = json.dumps(red, default=str)
        if len(out) <= limit:
            return out
    return json.dumps({"_truncated": True, "note": "result too large to store"})


def save_to_db(module: str, severity: str, ioc: str, summary: str, raw_data: dict):
    """Save analysis result to SQLite. Non-blocking via thread."""
    def _save():
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            raw_json = _fit_json(raw_data)
            c.execute(
                "INSERT INTO analysis_history (timestamp, module, severity, ioc, summary, raw_json) VALUES (?,?,?,?,?,?)",
                (ts, module, severity, ioc or "", summary or "", raw_json)
            )
            conn.commit()
            conn.close()
            log_event(f"DB saved: module={module} severity={severity} ioc={ioc}")
        except Exception as e:
            log_event(f"DB save error: {e}")
    t = threading.Thread(target=_save, daemon=True)
    t.start()


def query_db_stats() -> dict:
    """Query dashboard statistics from SQLite."""
    try:
        # ONE read transaction: every number below comes from the same snapshot, and the change
        # signature is taken from that snapshot too. (Previously the signature was read first and
        # the statistics later; a row committed in between made the next poll look "changed" and
        # repeat all queries.)
        conn = sqlite3.connect(DB_PATH, timeout=5, isolation_level=None)
        c = conn.cursor()
        c.execute("BEGIN")
        c.execute("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM analysis_history")
        snapshot_sig = tuple(c.fetchone())

        # Module counts
        c.execute("SELECT module, COUNT(*) FROM analysis_history GROUP BY module")
        module_counts = dict(c.fetchall())

        # Severity breakdown
        c.execute("SELECT severity, COUNT(*) FROM analysis_history GROUP BY severity")
        sev_counts = dict(c.fetchall())

        # Total findings today
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        c.execute("SELECT COUNT(*) FROM analysis_history WHERE timestamp LIKE ?", (f"{today}%",))
        today_count = c.fetchone()[0]

        # Total all
        c.execute("SELECT COUNT(*) FROM analysis_history")
        total = c.fetchone()[0]

        # Unique IOCs (distinct, independent of the top-5 list below)
        c.execute("SELECT COUNT(DISTINCT ioc) FROM analysis_history WHERE ioc != ''")
        unique_iocs = c.fetchone()[0]

        # Top IOCs
        c.execute("""
            SELECT ioc, COUNT(*) as cnt, severity
            FROM analysis_history
            WHERE ioc != ''
            GROUP BY ioc
            ORDER BY cnt DESC
            LIMIT 5
        """)
        top_iocs = [{"ioc": row[0], "count": row[1], "severity": row[2]} for row in c.fetchall()]

        # Recent activity (last 10)
        c.execute("""
            SELECT timestamp, module, severity, summary
            FROM analysis_history
            ORDER BY id DESC
            LIMIT 10
        """)
        recent = [{"ts": r[0], "module": r[1], "severity": r[2], "summary": r[3]} for r in c.fetchall()]

        # Trend per day (last 7 days)
        c.execute("""
            SELECT substr(timestamp,1,10) as day, COUNT(*)
            FROM analysis_history
            GROUP BY day
            ORDER BY day DESC
            LIMIT 7
        """)
        trend = [{"day": r[0], "count": r[1]} for r in c.fetchall()]

        conn.close()
        return {
            "module_counts": module_counts,
            "sev_counts": sev_counts,
            "today_count": today_count,
            "total": total,
            "top_iocs": top_iocs,
            "unique_iocs": unique_iocs,
            "recent": recent,
            "trend": trend,
            "db_ok": True,
            "sig": snapshot_sig,
        }
    except Exception as e:
        log_event(f"DB query error: {e}")
        return {"db_ok": False, "error": str(e)}


def db_signature():
    """Cheap change detector for the dashboard: (row count, newest id).
    Returns None if the database cannot be read."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=2)
        try:
            return tuple(conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(id), 0) FROM analysis_history").fetchone())
        finally:
            conn.close()
    except Exception as e:
        log_event(f"DB signature error: {e}")
        return None


# Initialize DB on startup
init_db()


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9c — PDF EXPORT ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _sev_color_rgb(sev: str):
    """Return (R, G, B) float tuple for severity."""
    s = (sev or "").lower()
    if s in ("critical", "high"):
        return colors.HexColor("#E53935")
    if s == "medium":
        return colors.HexColor("#FB8C00")
    if s == "low":
        return colors.HexColor("#43A047")
    return colors.HexColor("#1565C0")


def _pdf_clean(v):
    """Recursively drop None dict values and None list items so that
    ``dict.get(key, default)`` falls back to the default (``dict.get`` only uses
    the default for MISSING keys, not explicit None)."""
    if isinstance(v, dict):
        return {k: _pdf_clean(x) for k, x in v.items() if x is not None}
    if isinstance(v, (list, tuple)):
        return [_pdf_clean(x) for x in v if x is not None]
    return v


def _pdf_drop_none(data) -> dict:
    return _pdf_clean(data) if isinstance(data, dict) else {}


def _pdf_esc(value, default: str = "N/A") -> str:
    """Escape a value for ReportLab Paragraph mini-markup (&, <, >)."""
    if value is None or value == "":
        return default
    from xml.sax.saxutils import escape
    return escape(str(value))


class PDFExportError(Exception):
    """User-presentable PDF export failure (message is safe to show)."""


def export_pdf_report_ex(module: str, data, file_path: str) -> tuple:
    """Generate the PDF report. Returns ``(True, "")`` or ``(False, user_message)``.
    The failure reason is always populated, logged with traceback, and safe to show."""
    import traceback
    if not REPORTLAB_OK:
        return False, "ReportLab tidak terinstall. Install dengan: pip install reportlab"
    if isinstance(data, (str, bytes)):
        try:
            data = json.loads(data)
        except (ValueError, TypeError) as ex:
            log_event(f"PDF export: malformed report JSON: {ex}")
            return False, f"Data laporan rusak (JSON tidak valid): {ex}"
    if not isinstance(data, dict) or not data:
        return False, "Tidak ada data analisis yang valid untuk di-export."
    if not file_path or not str(file_path).strip():
        return False, "Lokasi output PDF kosong."
    out_dir = os.path.dirname(os.path.abspath(file_path))
    if not os.path.isdir(out_dir):
        return False, f"Folder output tidak ditemukan: {out_dir}"
    if os.path.isdir(file_path):
        return False, "Lokasi output adalah folder, bukan file PDF."
    try:
        _export_pdf_report_impl(module, data, file_path)
    except PermissionError as ex:
        log_event(f"PDF export permission error: {ex}\n{traceback.format_exc()}")
        return False, f"Tidak punya izin menulis file: {file_path}"
    except Exception as ex:
        log_event(f"PDF export error: {ex}\n{traceback.format_exc()}")
        return False, f"Gagal membuat PDF: {type(ex).__name__}: {str(ex)[:200]}"
    if not os.path.isfile(file_path) or os.path.getsize(file_path) == 0:
        return False, "PDF tidak terbentuk (file kosong)."
    return True, ""


def export_pdf_report(module: str, data: dict, file_path: str) -> bool:
    """Backward-compatible bool API. Prefer export_pdf_report_ex() for the reason."""
    ok, _msg = export_pdf_report_ex(module, data, file_path)
    return ok


def _export_pdf_report_impl(module: str, data: dict, file_path: str) -> None:
    """Build the PDF. Raises on failure (callers use export_pdf_report_ex)."""
    data = _pdf_drop_none(data)
    module = str(module or "unknown")
    if True:
        doc = SimpleDocTemplate(
            file_path,
            pagesize=A4,
            rightMargin=20*mm, leftMargin=20*mm,
            topMargin=24*mm, bottomMargin=24*mm,
        )
        W, H = A4
        story = []
        styles = getSampleStyleSheet()

        # ── Custom styles ────────────────────────────────────────────────
        header_style = ParagraphStyle(
            "GuardianHeader",
            parent=styles["Normal"],
            fontSize=22, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0D47A1"),
            spaceAfter=2*mm,
        )
        subtitle_style = ParagraphStyle(
            "GuardianSubtitle",
            parent=styles["Normal"],
            fontSize=10, fontName="Helvetica",
            textColor=colors.HexColor("#546E7A"),
            spaceAfter=1*mm,
        )
        section_style = ParagraphStyle(
            "GuardianSection",
            parent=styles["Normal"],
            fontSize=12, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#0D47A1"),
            spaceBefore=6*mm, spaceAfter=2*mm,
            borderPad=2,
        )
        body_style = ParagraphStyle(
            "GuardianBody",
            parent=styles["Normal"],
            fontSize=9, fontName="Helvetica",
            textColor=colors.HexColor("#212121"),
            spaceAfter=1*mm, leading=14,
        )
        mono_style = ParagraphStyle(
            "GuardianMono",
            parent=styles["Normal"],
            fontSize=8, fontName="Courier",
            textColor=colors.HexColor("#263238"),
            spaceAfter=1*mm,
        )
        footer_style = ParagraphStyle(
            "GuardianFooter",
            parent=styles["Normal"],
            fontSize=8, fontName="Helvetica",
            textColor=colors.HexColor("#90A4AE"),
            alignment=TA_CENTER,
        )

        now = datetime.datetime.now()
        ts_str = now.strftime("%Y-%m-%d %H:%M:%S")
        module_upper = module.upper()

        # ── HEADER BLOCK ─────────────────────────────────────────────────
        header_data = [
            [
                Paragraph("⚡ guardian_ai", header_style),
                Paragraph(
                    f"<b>INCIDENT ANALYSIS REPORT</b><br/>"
                    f"Module: {_pdf_esc(module_upper)}<br/>"
                    f"Generated: {ts_str}",
                    subtitle_style,
                ),
            ]
        ]
        header_table = Table(header_data, colWidths=[80*mm, None])
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#E3F2FD")),
            ("BOX", (0, 0), (-1, -1), 1.5, colors.HexColor("#1565C0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 6*mm))

        # Severity badge in header
        sev = str(data.get("severity") or data.get("risk_level") or "unknown").lower()
        _rs = data.get("risk_score") if data.get("risk_score") is not None else data.get("threat_score")
        risk_score = _pdf_esc(_rs, "N/A")   # never invent 0 for a missing score
        sev_color = _sev_color_rgb(sev)
        sev_data = [[
            Paragraph(f"Severity:", subtitle_style),
            Paragraph(f"<b>{_pdf_esc(sev.upper())}</b>", ParagraphStyle(
                "sev_badge", parent=styles["Normal"],
                fontSize=11, fontName="Helvetica-Bold",
                textColor=sev_color,
            )),
            Paragraph(f"Risk Score: <b>{risk_score}{'/100' if _rs is not None else ''}</b>", subtitle_style),
            Paragraph(f"Confidence: <b>{_pdf_esc(data.get('confidence'))}</b>", subtitle_style),
        ]]
        sev_table = Table(sev_data, colWidths=[30*mm, 35*mm, 55*mm, 50*mm])
        sev_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FAFAFA")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#B0BEC5")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 5*mm))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1565C0")))
        story.append(Spacer(1, 3*mm))

        # ── EXECUTIVE SUMMARY ────────────────────────────────────────────
        story.append(Paragraph("Executive Summary", section_style))

        # Build summary text from data
        summ_text = ""
        E = _pdf_esc
        if module == "cti":
            sm = data.get("summary") if isinstance(data.get("summary"), dict) else {}
            summ_text = (
                f"IOC: <b>{E(data.get('ioc'))}</b> [{E(str(data.get('type','')).upper(), 'UNKNOWN')}]<br/>"
                f"Verdict: <b>{E(sm.get('verdict'), 'Unknown')}</b> — "
                f"Country: {E(sm.get('country'))}, ISP: {E(sm.get('isp'))}<br/>"
                f"VirusTotal malicious detections: {E(sm.get('vt_malicious'), 'N/A')} engine(s). "
                f"AbuseIPDB score: {E(sm.get('abuse_score'), 'N/A')}/100. "
                f"TOR exit node: {E(sm.get('is_tor'))}.<br/>"
                f"Open ports: {E(sm.get('open_ports'))}. "
                f"Known vulnerabilities: {E(sm.get('vulns'))}."
            )
        elif module == "malware":
            rep = data.get("report") if isinstance(data.get("report"), dict) else {}
            summ_text = (
                f"Sample: <b>{E(rep.get('submit_name') or data.get('input'))}</b><br/>"
                f"Verdict: <b>{E(str(data.get('verdict') or 'unknown').upper())}</b> — "
                f"Threat Score: {E(data.get('threat_score'), 'N/A')}/100<br/>"
                f"Classification: {E(rep.get('classification'))}<br/>"
                f"Analysis Summary: {E(str(rep.get('analysis_summary') or '')[:300], 'N/A')}"
            )
        elif module == "forensics":
            io_ = data.get("iocs") if isinstance(data.get("iocs"), dict) else {}
            sc_ = data.get("severity_counts") if isinstance(data.get("severity_counts"), dict) else {}
            summ_text = (
                f"Log Analysis completed. "
                f"Total records analysed: <b>{E(data.get('total_records'), 'N/A')}</b><br/>"
                f"Total findings: <b>{E(data.get('total_findings'), 'N/A')}</b> — "
                f"Total IOCs extracted: <b>{E(io_.get('total'), 'N/A')}</b><br/>"
                f"Severity distribution: "
                + (", ".join(f"{E(str(k).upper())}: {E(v)}" for k, v in sc_.items()) or "Not available")
            )
        else:
            summ_text = "Analysis data not available for this module."

        story.append(Paragraph(summ_text, body_style))
        story.append(Spacer(1, 4*mm))

        # ── AI SUMMARY ───────────────────────────────────────────────────
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CFD8DC")))
        story.append(Paragraph("AI Summary &amp; Risk Assessment", section_style))
        ai_text = data.get("ai_summary") or data.get("summary_text") or ""
        if not isinstance(ai_text, str):
            ai_text = str(ai_text)
        if not ai_text:
            ai_text = "AI summary not available. Run analysis with AI Summary enabled."
        # Truncate the RAW text, escape it, and only then convert markdown -> tags
        # (truncating after tag conversion could cut a tag in half and crash ReportLab).
        ai_clean = _pdf_esc(ai_text[:2000])
        ai_clean = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", ai_clean)
        ai_clean = re.sub(r"\*(.*?)\*", r"<i>\1</i>", ai_clean)
        ai_clean = ai_clean.replace("\n", "<br/>")
        story.append(Paragraph(ai_clean, body_style))
        story.append(Spacer(1, 4*mm))

        # ── IOC TABLE ────────────────────────────────────────────────────
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CFD8DC")))
        story.append(Paragraph("Indicators of Compromise (IOC)", section_style))

        ioc_rows = [["IOC Value", "Type", "Source"]]
        if module == "cti":
            ioc_val = str(data.get("ioc") or "")
            ioc_type = str(data.get("type") or "")
            if ioc_val:
                ioc_rows.append([ioc_val[:60], ioc_type.upper(), "CTI Analysis"])
        elif module == "forensics":
            iocs = data.get("iocs") if isinstance(data.get("iocs"), dict) else {}
            for cat, items in iocs.items():
                if cat == "total" or not items or not isinstance(items, (list, tuple, set)):
                    continue
                for item in list(items)[:20]:
                    ioc_rows.append([str(item)[:60], cat.upper(), "Forensics"])
        elif module == "malware":
            rep = data.get("report") if isinstance(data.get("report"), dict) else {}
            net = rep.get("network_connections") if isinstance(rep.get("network_connections"), dict) else {}
            for cat, items in net.items():
                if not isinstance(items, (list, tuple, set)):
                    continue
                for item in list(items)[:10]:
                    ioc_rows.append([str(item)[:60], str(cat).upper(), "Malware"])
            yara = data.get("yara") if isinstance(data.get("yara"), dict) else {}
            for m in (yara.get("matches") or [])[:5]:
                if isinstance(m, dict):
                    ioc_rows.append([str(m.get("rule") or "")[:60], "YARA Rule", "YARA"])

        if len(ioc_rows) == 1:
            ioc_rows.append(["No IOC data available", "", ""])

        ioc_table = Table(ioc_rows, colWidths=[90*mm, 40*mm, 40*mm])
        ioc_ts = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1565C0")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F5F5F5"), colors.white]),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("FONTNAME", (0, 1), (-1, -1), "Courier"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#90A4AE")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
        ioc_table.setStyle(ioc_ts)
        story.append(ioc_table)
        story.append(Spacer(1, 4*mm))

        # ── FINDINGS TABLE ───────────────────────────────────────────────
        findings = []
        if module == "forensics":
            findings = (data.get("findings") or [])[:30]
        elif module == "malware":
            _rp = data.get("report") if isinstance(data.get("report"), dict) else {}
            findings = (_rp.get("findings") or [])[:30]
        findings = [f for f in findings if isinstance(f, dict)]

        if not findings and module in ("forensics", "malware"):
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CFD8DC")))
            story.append(Paragraph("Findings", section_style))
            story.append(Paragraph("No findings were recorded for this analysis.", body_style))
            story.append(Spacer(1, 4*mm))
        if findings:
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CFD8DC")))
            story.append(Paragraph("Findings", section_style))
            f_rows = [["Severity", "Type / Technique", "Source → Dest", "Description"]]
            for f in findings:
                sev_f = str(f.get("severity") or "unknown").upper()
                tech  = str(f.get("technique") or f.get("attack_type") or "")[:40]
                src   = f.get("src_ip") or f.get("src") or ""
                dst   = f.get("dst_ip") or f.get("dst") or ""
                srcdst = f"{src} → {dst}" if (src or dst) else "N/A"
                desc  = str(f.get("description") or f.get("evidence") or "")[:100]
                f_rows.append([sev_f, tech, srcdst[:40], desc])
            f_table = Table(f_rows, colWidths=[22*mm, 45*mm, 50*mm, 55*mm])
            f_ts = TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474F")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FAFAFA"), colors.white]),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#90A4AE")),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
            f_table.setStyle(f_ts)
            story.append(f_table)
            story.append(Spacer(1, 4*mm))

        # ── TIMELINE ─────────────────────────────────────────────────────
        timeline = [e for e in (data.get("timeline") or []) if isinstance(e, dict)][:20]
        if not timeline and module == "forensics":
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CFD8DC")))
            story.append(Paragraph("Attack Timeline", section_style))
            story.append(Paragraph("No timeline events available for this analysis.", body_style))
            story.append(Spacer(1, 4*mm))
        if timeline:
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CFD8DC")))
            story.append(Paragraph("Attack Timeline", section_style))
            tl_rows = [["Timestamp", "Source IP", "Event", "Severity"]]
            for ev in timeline:
                tl_rows.append([
                    str(ev.get("time") or ev.get("timestamp") or "Not available")[:20],
                    str(ev.get("src") or ev.get("src_ip") or "N/A")[:20],
                    str(ev.get("event") or ev.get("technique") or "")[:60],
                    str(ev.get("severity") or "unknown").upper(),
                ])
            tl_table = Table(tl_rows, colWidths=[38*mm, 38*mm, 72*mm, 22*mm])
            tl_ts = TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4527A0")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#EDE7F6"), colors.white]),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("FONTNAME", (0, 1), (0, -1), "Courier"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#90A4AE")),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ])
            tl_table.setStyle(tl_ts)
            story.append(tl_table)
            story.append(Spacer(1, 4*mm))

        # ── RECOMMENDATIONS ──────────────────────────────────────────────
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CFD8DC")))
        story.append(Paragraph("Recommendations", section_style))

        recs = data.get("recommendations") or []
        if not recs:
            # Generate generic recommendations based on severity
            s_low = (sev or "").lower()
            if s_low in ("high", "critical"):
                recs = [
                    "Immediately isolate the affected host(s) from the network.",
                    "Block identified malicious IPs and domains at the perimeter firewall/WAF.",
                    "Escalate to Tier-2 SOC analyst and initiate incident response procedure.",
                    "Preserve forensic artifacts: memory dump, disk image, event logs.",
                    "Notify relevant stakeholders and document the incident timeline.",
                ]
            elif s_low == "medium":
                recs = [
                    "Apply IOC-based blocking rules on NGFW/EDR.",
                    "Monitor affected systems for lateral movement indicators.",
                    "Review access logs for related suspicious activity.",
                    "Update threat intelligence feeds with detected IOCs.",
                ]
            else:
                recs = [
                    "Continue monitoring for changes in baseline behaviour.",
                    "Enrich identified IOCs via external threat intelligence.",
                    "Review findings during next scheduled security review.",
                ]

        for i, rec in enumerate(recs[:10], 1):
            story.append(Paragraph(f"{i}. {_pdf_esc(rec)}", body_style))

        # ── FOOTER ───────────────────────────────────────────────────────
        story.append(Spacer(1, 8*mm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1565C0")))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(
            f"Generated by guardian_ai SOC Platform &nbsp;|&nbsp; {ts_str} &nbsp;|&nbsp; CONFIDENTIAL",
            footer_style,
        ))

        doc.build(story)


# ── PDF Export Worker Thread ────────────────────────────────────────────────
class PDFExportWorker(QThread):
    done  = pyqtSignal(bool, str)   # (success, file_path)

    def __init__(self, module: str, data: dict, file_path: str):
        super().__init__()
        self._module = module
        self._data   = data
        self._path   = file_path
        self.error_message = ""

    def run(self):
        ok, msg = export_pdf_report_ex(self._module, self._data, self._path)
        self.error_message = msg
        self.done.emit(ok, self._path)


def _trigger_pdf_export(parent_widget, module: str, data: dict):
    """Show save dialog and kick off PDF export. Returns worker or None."""
    if not REPORTLAB_OK:
        QMessageBox.critical(parent_widget, "Missing Dependency",
                             "ReportLab tidak terinstall.\n"
                             "Install dengan: pip install reportlab")
        return None
    if not data:
        QMessageBox.warning(parent_widget, "No Data",
                            "Belum ada hasil analisis untuk di-export.")
        return None

    default_name = datetime.datetime.now().strftime("guardian_ai_report_%Y%m%d_%H%M%S.pdf")
    path, _ = QFileDialog.getSaveFileName(
        parent_widget, "Export PDF Report", default_name,
        "PDF Files (*.pdf)"
    )
    if not path:
        return None

    worker = PDFExportWorker(module, data, path)

    def _on_done(ok, fpath):
        if ok:
            QMessageBox.information(parent_widget, "Export Berhasil",
                                    f"Report berhasil disimpan:\n{fpath}")
        else:
            QMessageBox.critical(parent_widget, "Export Gagal",
                                 "Tidak dapat membuat PDF report.\n\n"
                                 f"{worker.error_message or 'Penyebab tidak diketahui.'}\n\n"
                                 "Detail teknis ada di debug.log.")

    worker.done.connect(_on_done)
    worker.start()
    return worker


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9d — ANALYSIS HISTORY PANEL
# ══════════════════════════════════════════════════════════════════════════════

def query_history(module_filter: str = "all", search_text: str = "",
                  limit: int = 200) -> list:
    """Query analysis_history table with optional filters."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        params = []
        where = []
        if module_filter and module_filter != "all":
            where.append("module = ?")
            params.append(module_filter)
        if search_text:
            where.append("(ioc LIKE ? OR summary LIKE ?)")
            params += [f"%{search_text}%", f"%{search_text}%"]
        sql = "SELECT id, timestamp, module, severity, ioc, summary, raw_json FROM analysis_history"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        c.execute(sql, params)
        rows = c.fetchall()
        conn.close()
        return [
            {
                "id": r[0], "timestamp": r[1], "module": r[2],
                "severity": r[3], "ioc": r[4], "summary": r[5],
                "raw_json": r[6],
            }
            for r in rows
        ]
    except Exception as e:
        log_event(f"query_history error: {e}")
        return []


def query_history_by_ioc(ioc: str, limit: int = 50) -> list:
    """Exact-match history lookup for a single IOC, oldest first — used to
    build the CTI 'IOC Activity Timeline' from real analysis history rows
    (never fabricated)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "SELECT id, timestamp, module, severity, ioc, summary, raw_json "
            "FROM analysis_history WHERE ioc = ? ORDER BY id ASC LIMIT ?",
            (ioc, limit),
        )
        rows = c.fetchall()
        conn.close()
        return [
            {"id": r[0], "timestamp": r[1], "module": r[2],
             "severity": r[3], "ioc": r[4], "summary": r[5], "raw_json": r[6]}
            for r in rows
        ]
    except Exception as e:
        log_event(f"query_history_by_ioc error: {e}")
        return []


class IOCTimelineWorker(QThread):
    """Runs the exact-IOC history query off the UI thread so opening the
    Timeline dialog never freezes the app."""
    done = pyqtSignal(list)

    def __init__(self, ioc: str):
        super().__init__()
        self._ioc = ioc

    def run(self):
        try:
            rows = query_history_by_ioc(self._ioc)
        except Exception as e:
            log_event(f"IOCTimelineWorker error: {e}")
            rows = []
        self.done.emit(rows)


def delete_history_entry(entry_id: int):
    """Delete a single history entry by id."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM analysis_history WHERE id = ?", (entry_id,))
        conn.commit(); conn.close()
    except Exception as e:
        log_event(f"delete_history error: {e}")


class HistoryLoadWorker(QThread):
    done = pyqtSignal(list)
    # (generation, rows) — lets the receiver discard results of superseded requests.
    done_gen = pyqtSignal(int, list)
    def __init__(self, module_filter, search_text, generation=0):
        super().__init__()
        self._mod = module_filter
        self._srch = search_text
        self._gen = generation
    def run(self):
        rows = query_history(self._mod, self._srch)
        self.done.emit(rows)
        self.done_gen.emit(self._gen, rows)


class AnalysisHistoryPanel(QWidget):
    """
    SOC Investigation Log Panel — card-based history with structured preview.
    Emits load_requested(module, data_dict) when user clicks a card to re-display.
    Emits investigate_requested(module, entry_dict) when Investigate is clicked —
    MainWindow re-opens the entry in its owning module (CTI/Malware/Forensics).
    Emits explain_requested(module, context_dict) when Explain is clicked —
    MainWindow forwards the context to the AI SOC Analyst panel.
    Timeline is handled locally (no other panel needs to react to it).
    """
    load_requested        = pyqtSignal(str, dict)
    investigate_requested = pyqtSignal(str, object)
    explain_requested     = pyqtSignal(str, object)

    _MOD_COLORS = {
        "cti":       (P["accent"], P["info_bg"]),
        "malware":   ("#8B5CF6", "#1D1236"),
        "forensics": (P["medium"], "#33240A"),
    }
    _SEV_COLORS = {
        "critical": P["critical"], "high": P["high"],
        "medium":   P["medium"],   "low":  P["low"],
        "info":     P["info"],     "clean": P["low"],
    }
    _MOD_ICONS = {"cti": "cti", "malware": "malware", "forensics": "forensics"}

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_entries   = []
        self._pdf_worker        = None
        self._load_worker       = None
        self._timeline_worker   = None
        self._selected_entry    = None
        self._active_mod_filter = "all"
        self._card_widgets      = []

        self.setMinimumWidth(280)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ───────────────────────────────────────────────────────
        hdr = QFrame(); hdr.setObjectName("histhdr")
        hdr.setStyleSheet(
            f"QFrame#histhdr{{background:{P['bg_panel']};border-bottom:1px solid {P['border']};}}")
        hdrl = QHBoxLayout(hdr)
        hdrl.setContentsMargins(14, 12, 12, 10)
        hdrl.setSpacing(10)
        hdrl.addWidget(IconLabel("history", P["accent"], 18), 0, Qt.AlignTop)
        title_col = QVBoxLayout(); title_col.setSpacing(1)
        t1 = QLabel("ANALYSIS HISTORY")
        t1.setStyleSheet(
            f"color:{P['text_main']};font-size:13px;font-weight:700;background:transparent;border:none;")
        t2 = QLabel("Investigation log")
        t2.setStyleSheet(
            f"color:{P['text_label']};font-size:11px;background:transparent;border:none;")
        self._live_badge = QLabel("● LIVE")
        self._live_badge.setStyleSheet(
            f"color:{P['low']};font-size:11px;font-weight:700;background:transparent;border:none;")
        sub_row = QHBoxLayout(); sub_row.setSpacing(8); sub_row.setContentsMargins(0, 0, 0, 0)
        sub_row.addWidget(t2); sub_row.addWidget(self._live_badge); sub_row.addStretch()
        title_col.addWidget(t1); title_col.addLayout(sub_row)
        hdrl.addLayout(title_col, 1)

        self._count_badge = QLabel("  0  ")
        self._count_badge.setToolTip("Entries matching the current filter")
        self._count_badge.setStyleSheet(
            f"color:{P['text_main']};background:{P['bg_input']};"
            f"border:1px solid {P['border2']};border-radius:9px;font-size:11px;font-weight:600;padding:1px 6px;")
        hdrl.addWidget(self._count_badge, 0, Qt.AlignTop)
        root.addWidget(hdr)

        # ── Search + filters ─────────────────────────────────────────────
        search_w = QWidget(); search_w.setObjectName("histsearch")
        search_w.setStyleSheet(f"QWidget#histsearch{{background:{P['bg_panel']};}}")
        search_l = QVBoxLayout(search_w)
        search_l.setContentsMargins(12, 10, 12, 8)
        search_l.setSpacing(8)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search IOC, IP, domain, hash, finding…")
        self._search.setClearButtonEnabled(True)
        self._search.setMinimumHeight(36)
        self._search.textChanged.connect(self._on_filter_changed)
        search_l.addWidget(self._search)

        filter_row = QGridLayout(); filter_row.setSpacing(6)
        self._filter_grid = filter_row
        self._filter_btns: dict = {}
        self._filter_btn_styles: dict = {}
        self._filtering_guard = False
        self._mod_combo = QComboBox()  # kept for _load() compatibility
        self._mod_combo.addItems(["all", "cti", "malware", "forensics"])
        self._mod_combo.hide()

        # Exclusive QButtonGroup: Qt guarantees one checked button, so no manual
        # setChecked() juggling (that used to cause a RecursionError).
        self._filter_group = QButtonGroup(self)
        self._filter_group.setExclusive(True)

        for mk, ml in [("all", "ALL"), ("cti", "CTI"), ("malware", "MALWARE"), ("forensics", "FORENSICS")]:
            mc2, _ = self._MOD_COLORS.get(mk, (P["accent"], P["bg_input"]))
            b = QPushButton(ml)
            b.setCheckable(True)
            b.setMinimumHeight(28)
            b.setCursor(Qt.PointingHandCursor)
            b.setToolTip(f"Show {ml.title() if mk != 'all' else 'all'} entries")
            _act = (
                f"QPushButton{{background:{_tint(mc2, 36)};color:{mc2};"
                f"border:1px solid {_tint(mc2, 140)};border-radius:8px;"
                f"font-size:11px;font-weight:700;padding:0 10px;}}"
                f"QPushButton:hover{{background:{_tint(mc2, 56)};}}"
            )
            _ina = (
                f"QPushButton{{background:{P['bg_input']};color:{P['text_label']};"
                f"border:1px solid {P['border']};border-radius:8px;"
                f"font-size:11px;font-weight:600;padding:0 10px;}}"
                f"QPushButton:hover{{background:{P['bg_card2']};color:{P['text_main']};}}"
            )
            self._filter_btn_styles[mk] = (_act, _ina)
            b.setChecked(mk == "all")
            b.setStyleSheet(_act if mk == "all" else _ina)
            self._filter_group.addButton(b)
            b.clicked.connect(lambda checked=False, key=mk: self._set_module_filter(key))
            self._filter_btns[mk] = b
        reflow_buttons(filter_row, list(self._filter_btns.values()), 260, spacing=6)
        search_l.addLayout(filter_row)
        root.addWidget(search_w)

        # ── Toolbar ───────────────────────────────────────────────────────
        toolbar = QWidget(); toolbar.setObjectName("histtb")
        toolbar.setStyleSheet(
            f"QWidget#histtb{{background:{P['bg_panel']};border-bottom:1px solid {P['border']};}}")
        tbl = QHBoxLayout(toolbar)
        tbl.setContentsMargins(12, 0, 12, 8)
        tbl.setSpacing(8)
        self._btn_refresh = ModernButton("Refresh", "ghost", icon="refresh", tooltip="Reload history")
        self._btn_delete  = ModernButton("Delete", "danger", icon="trash", tooltip="Delete the selected entry")
        self._btn_refresh.clicked.connect(self._load)
        self._btn_delete.clicked.connect(self._delete_selected)
        tbl.addWidget(self._btn_refresh)
        tbl.addWidget(self._btn_delete)
        tbl.addStretch()
        root.addWidget(toolbar)

        # ── Card list + preview in a vertical splitter (drag to resize) ──
        self._hist_split = QSplitter(Qt.Vertical)
        self._hist_split.setChildrenCollapsible(False)
        self._hist_split.setHandleWidth(7)
        self._hist_split.setStyleSheet(
            f"QSplitter::handle{{background:{P['border']};margin:2px 40px;border-radius:2px;}}"
            f"QSplitter::handle:hover{{background:{P['accent']};}}")

        self._card_sa = QScrollArea()
        self._card_sa.setWidgetResizable(True)
        self._card_sa.setFrameShape(QFrame.NoFrame)
        self._card_sa.setMinimumHeight(120)
        self._card_sa.setStyleSheet(
            f"QScrollArea{{background:{P['bg_dark']};border:none;}}"
            f"QScrollBar:vertical{{background:{P['bg_dark']};width:8px;}}"
            f"QScrollBar::handle:vertical{{background:{P['border2']};border-radius:4px;min-height:24px;}}"
            f"QScrollBar::handle:vertical:hover{{background:{P['accent']};}}"
            f"QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;background:none;}}"
        )
        self._card_inner = QWidget()
        self._card_inner.setStyleSheet(f"background:{P['bg_dark']};")
        self._card_layout = QVBoxLayout(self._card_inner)
        self._card_layout.setContentsMargins(10, 10, 10, 6)
        self._card_layout.setSpacing(8)
        self._card_layout.addStretch()
        self._card_sa.setWidget(self._card_inner)
        self._hist_split.addWidget(self._card_sa)

        # ── Detail preview ───────────────────────────────────────────────
        self._preview_panel = QFrame(); self._preview_panel.setObjectName("histpreview")
        self._preview_panel.setMinimumHeight(190)
        self._preview_panel.setStyleSheet(
            f"QFrame#histpreview{{background:{P['bg_panel']};border-top:1px solid {P['border']};}}")
        pvl = QVBoxLayout(self._preview_panel)
        pvl.setContentsMargins(12, 10, 12, 10)
        pvl.setSpacing(8)

        ph = QHBoxLayout()
        ph_ttl = QLabel("ANALYSIS PREVIEW")
        ph_ttl.setStyleSheet(
            f"color:{P['text_label']};font-size:11px;font-weight:700;letter-spacing:0.8px;"
            f"background:transparent;border:none;")
        self._prev_copy_btn = ModernButton("Copy", "ghost", icon="copy", tooltip="Copy the preview as text")
        self._prev_copy_btn.setMinimumHeight(26)
        self._prev_copy_btn.clicked.connect(self._copy_preview)
        ph.addWidget(ph_ttl); ph.addStretch(); ph.addWidget(self._prev_copy_btn)
        pvl.addLayout(ph)

        self._prev_kv_sa = QScrollArea()
        self._prev_kv_sa.setWidgetResizable(True)
        self._prev_kv_sa.setFrameShape(QFrame.NoFrame)
        self._prev_kv_sa.setStyleSheet("QScrollArea{background:transparent;border:none;}")
        self._prev_kv_sa.setMinimumHeight(70)
        self._prev_kv_sa.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Ignored)
        self._prev_kv_w = QWidget()
        self._prev_kv_w.setStyleSheet("background:transparent;")
        self._prev_kv_l = QVBoxLayout(self._prev_kv_w)
        self._prev_kv_l.setContentsMargins(0, 2, 0, 0)
        self._prev_kv_l.setSpacing(6)
        self._prev_kv_l.addWidget(self._placeholder_label())
        self._prev_kv_sa.setWidget(self._prev_kv_w)
        pvl.addWidget(self._prev_kv_sa, 1)

        # Investigation workflow actions — disabled until an entry is selected.
        qa = QGridLayout(); qa.setSpacing(6)
        self._qa_grid = qa
        self._quick_action_btns: dict = {}
        _quick_actions = [
            ("investigate", "Investigate", "search",   "Open this item in the corresponding analysis module", self._investigate_selected),
            ("explain",     "Explain",     "ai",       "Ask AI SOC Analyst to explain this result",            self._explain_selected),
            ("timeline",    "Timeline",    "history",  "View historical and correlated activity",              self._show_selected_timeline),
        ]
        for key, text_, icon_, tip_txt, cb in _quick_actions:
            qb = ModernButton(text_, "secondary", icon=icon_, tooltip=tip_txt)
            qb.setMinimumHeight(34)
            qb.setEnabled(False)
            qb.clicked.connect(cb)
            self._quick_action_btns[key] = qb
        self._btn_export_pdf = ModernButton("Export PDF", "secondary", icon="pdf",
                                            tooltip="Export the selected entry as a PDF report")
        self._btn_export_pdf.setMinimumHeight(34)
        self._btn_export_pdf.setEnabled(False)
        self._btn_export_pdf.clicked.connect(self._export_selected_pdf)
        reflow_buttons(qa, list(self._quick_action_btns.values()) + [self._btn_export_pdf], 230, spacing=6)
        pvl.addLayout(qa)
        self._hist_split.addWidget(self._preview_panel)
        self._hist_split.setStretchFactor(0, 6)
        self._hist_split.setStretchFactor(1, 4)
        root.addWidget(self._hist_split, 1)

        self._load()

    _split_initialised = False

    def showEvent(self, event):
        super().showEvent(event)
        if not self._split_initialised:
            self._split_initialised = True
            safe_single_shot(self, 0, lambda: self._hist_split.setSizes(
                [int(self._hist_split.height() * 0.58), int(self._hist_split.height() * 0.42)]))

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if getattr(self, "_quick_action_btns", None):
            reflow_buttons(self._qa_grid, list(self._quick_action_btns.values()) + [self._btn_export_pdf],
                           self.width() - 44, spacing=6)
        if getattr(self, "_filter_btns", None):
            reflow_buttons(self._filter_grid, list(self._filter_btns.values()), self.width() - 28, spacing=6)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _placeholder_label(self):
        ph = QLabel("Select an entry to preview details.")
        ph.setWordWrap(True)
        ph.setStyleSheet(f"color:{P['text_dim']};font-size:12px;background:transparent;border:none;")
        return ph

    def _add_kv_row(self, label_txt: str, val_txt: str, val_color: str, widget=None):
        rw = QWidget(); rw.setStyleSheet("background:transparent;")
        rl = QHBoxLayout(rw); rl.setContentsMargins(0, 0, 0, 0); rl.setSpacing(10)
        la = QLabel(label_txt); la.setFixedWidth(104)
        la.setStyleSheet(f"color:{P['text_dim']};font-size:12px;background:transparent;border:none;")
        rl.addWidget(la, 0, Qt.AlignTop)
        if widget is not None:
            if isinstance(widget, SeverityBadge):
                rl.addWidget(widget, 0, Qt.AlignLeft | Qt.AlignTop); rl.addStretch(1)
            else:
                rl.addWidget(widget, 1)
        else:
            full = str(val_txt)
            va = QLabel(full if len(full) <= 140 else full[:139] + "…")
            va.setWordWrap(True)
            va.setToolTip(full)
            va.setTextInteractionFlags(Qt.TextSelectableByMouse)
            va.setStyleSheet(
                f"color:{val_color};font-size:12px;font-weight:600;background:transparent;border:none;")
            rl.addWidget(va, 1)
        self._prev_kv_l.addWidget(rw)

    def _clear_kv(self):
        while self._prev_kv_l.count():
            item = self._prev_kv_l.takeAt(0)
            if item.widget():
                item.widget().hide()
                item.widget().deleteLater()

    def _copy_preview(self):
        if not self._selected_entry:
            return
        lines = [
            "GUARDIAN AI — Analysis Preview",
            f"Module:    {(self._selected_entry.get('module') or '').upper()}",
            f"Severity:  {(self._selected_entry.get('severity') or '').upper()}",
            f"IOC:       {self._selected_entry.get('ioc', '')}",
            f"Timestamp: {self._selected_entry.get('timestamp', '')}",
            f"Summary:   {(self._selected_entry.get('summary') or '')[:300]}",
        ]
        QApplication.clipboard().setText("\n".join(lines))

    # ── Internal ──────────────────────────────────────────────────────────────

    def _on_filter_changed(self):
        self._load()

    def _set_module_filter(self, key: str):
        """Single centralized handler for the ALL/CTI/MALWARE/FORENSICS
        module filter buttons. Because the buttons live in an exclusive
        QButtonGroup, Qt already guarantees only one is checked — this
        method never needs to call setChecked() on another button, which
        removes the recursive setChecked()<->toggled() feedback loop that
        used to crash the app with a RecursionError."""
        if self._filtering_guard:
            return
        # Keep the checked state in sync even for programmatic calls. The handler
        # is wired to `clicked`, which setChecked() does not emit -> no recursion.
        btn = self._filter_btns.get(key)
        if btn is not None and not btn.isChecked():
            btn.setChecked(True)
        if self._active_mod_filter == key:
            return
        self._filtering_guard = True
        try:
            self._active_mod_filter = key
            self._mod_combo.setCurrentText(key)
            for ok, ob in self._filter_btns.items():
                act_ss, ina_ss = self._filter_btn_styles[ok]
                ob.setStyleSheet(act_ss if ok == key else ina_ss)
            self._on_filter_changed()
        finally:
            self._filtering_guard = False

    _reload_pending = False   # kept for backward compatibility; no longer used
    _load_gen = 0             # latest-request-wins generation counter

    def _load(self):
        """Start a history query for the *current* filter/search immediately.
        Every call bumps a generation counter; only the result of the newest
        generation is ever rendered, so a slow older query can never overwrite a
        newer one. Superseded workers are kept referenced until they finish
        (never dropped/overwritten while running)."""
        self._load_gen += 1
        gen = self._load_gen
        mod  = self._mod_combo.currentText()
        srch = self._search.text().strip()
        worker = HistoryLoadWorker(mod, srch, gen)
        worker.done_gen.connect(self._on_rows_loaded)
        worker.finished.connect(lambda w=worker: self._on_load_worker_finished(w))
        if not hasattr(self, "_live_workers"):
            self._live_workers = set()
        self._live_workers.add(worker)
        self._load_worker = worker
        worker.start()

    def _on_rows_loaded(self, gen: int, rows: list):
        if gen != self._load_gen:
            log_event(f"History: discarded stale result (gen {gen}, latest {self._load_gen})")
            return
        self._populate(rows)

    def _on_load_worker_finished(self, worker=None):
        """QThread.finished — release the finished worker."""
        if worker is not None:
            self._live_workers.discard(worker)
            worker.deleteLater()
            if self._load_worker is worker:
                self._load_worker = None

    def shutdown_workers(self, timeout_ms: int = 3000):
        """Wait for in-flight history queries (call from closeEvent)."""
        for w in list(getattr(self, "_live_workers", ())):
            w.wait(timeout_ms)

    def _card_qss(self, sc: str, selected: bool) -> str:
        border = P["accent"] if selected else P["border"]
        bg = P["bg_card2"] if selected else P["bg_card"]
        return (
            f"QFrame#hcard{{background:{bg};border:1px solid {border};"
            f"border-left:3px solid {sc};border-radius:10px;}}"
            f"QFrame#hcard:hover{{background:{P['bg_card2']};border-color:{sc};}}"
        )

    def _make_history_card(self, entry: dict, idx: int) -> QFrame:
        mod  = (entry.get("module") or "").lower()
        sev  = (entry.get("severity") or "info").lower()
        ioc_full = entry.get("ioc") or "—"
        ts   = (entry.get("timestamp") or "")
        sc   = self._SEV_COLORS.get(sev, P["info"])
        mc, _mbg = self._MOD_COLORS.get(mod, (P["accent"], P["bg_card"]))

        card = QFrame(); card.setObjectName("hcard")
        card._entry = entry; card._sev_color = sc
        card.setStyleSheet(self._card_qss(sc, False))
        card.setCursor(Qt.PointingHandCursor)
        card.setToolTip(f"{mod.upper()} · {sev.upper()}\n{ioc_full}")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(6)

        r1 = QHBoxLayout(); r1.setSpacing(6)
        r1.addWidget(StatusBadge(mod.upper() or "—", mc))
        r1.addWidget(SeverityBadge(sev, min_width=56))
        r1.addStretch()
        ts_w = QLabel(ts[:16] if ts else "—")
        ts_w.setStyleSheet(f"color:{P['text_dim']};font-size:11px;background:transparent;border:none;")
        r1.addWidget(ts_w)
        cl.addLayout(r1)

        ioc_w = QLabel(ioc_full if len(ioc_full) <= 60 else ioc_full[:59] + "…")
        ioc_w.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        ioc_w.setStyleSheet(
            f"color:{P['text_main']};font-size:12px;font-weight:600;font-family:{_FONT_MONO};"
            f"background:transparent;border:none;")
        cl.addWidget(ioc_w)

        summ = (entry.get("summary") or "").replace("\n", " ")
        if summ:
            sn_w = QLabel(summ[:110] + ("…" if len(summ) > 110 else ""))
            sn_w.setWordWrap(True)
            sn_w.setStyleSheet(f"color:{P['text_label']};font-size:12px;background:transparent;border:none;")
            cl.addWidget(sn_w)

        card.mousePressEvent = lambda e, en=entry: self._on_card_click(en)
        # Double-click == Investigate, without disturbing the single-click preview.
        card.mouseDoubleClickEvent = lambda e, en=entry: self._on_card_double_click(en)
        return card

    def _mark_selected_card(self, entry: dict):
        eid = (entry or {}).get("id")
        for cw in self._card_widgets:
            en = getattr(cw, "_entry", None)
            if en is not None:
                cw.setStyleSheet(self._card_qss(cw._sev_color, en.get("id") == eid))

    def _populate(self, rows: list):
        self._current_entries = rows

        # Clear old cards
        self._card_widgets.clear()
        while self._card_layout.count() > 1:
            item = self._card_layout.takeAt(0)
            if item.widget():
                item.widget().hide()
                item.widget().deleteLater()

        self._count_badge.setText(f"  {len(rows)}  ")

        if not rows:
            ef = AnalysisEmptyState("history", "No Analysis History",
                                    "Run CTI, Malware, or Forensics analysis to populate history.")
            self._card_layout.insertWidget(0, ef)
            self._card_widgets.append(ef)
            return

        for i, entry in enumerate(rows):
            cw = self._make_history_card(entry, i)
            self._card_layout.insertWidget(i, cw)
            self._card_widgets.append(cw)

    def _on_card_click(self, entry: dict):
        self._selected_entry = entry
        self._mark_selected_card(entry)
        mod = (entry.get("module") or "").lower()
        sev = (entry.get("severity") or "info").lower()
        ioc = entry.get("ioc") or "—"
        ts  = (entry.get("timestamp") or "—")[:16]

        mc, _ = self._MOD_COLORS.get(mod, (P["accent"], P["bg_card"]))
        sc    = self._SEV_COLORS.get(sev, P["info"])

        self._clear_kv()

        raw_data: dict = {}
        try:
            raw_data = json.loads(entry.get("raw_json") or "{}")
        except Exception:
            pass

        self._add_kv_row("Module", mod.upper(), mc)
        self._add_kv_row("Timestamp", ts, P["text_main"])
        self._add_kv_row("Severity", sev.upper(), sc, widget=SeverityBadge(sev, min_width=64))
        self._add_kv_row("IOC", ioc, P["accent"], widget=IOCChip(str(ioc), "IOC"))

        kv_rows = []
        # Module-specific enrichment. Field lookups follow the shape each module actually
        # stores (the old code read a non-existent "summary" dict for malware/forensics → "—").
        if mod == "cti":
            sources = raw_data.get("sources", {}) or {}
            ab = sources.get("abuseipdb", {}) or {}
            vt = sources.get("virustotal", {}) or {}
            ab_score = ab.get("score", "—")
            kv_rows += [
                ("Abuse score",  f"{ab_score}%" if ab_score != "—" else "—",
                 P["medium"] if isinstance(ab_score, int) and ab_score > 50 else P["low"]),
                ("Country",      ab.get("country_code") or vt.get("country") or "—", P["text_main"]),
                ("ISP",          (ab.get("isp") or "—")[:40], P["text_main"]),
                ("VT verdict",   vt.get("verdict", "—"),
                 P["critical"] if vt.get("verdict") == "malicious" else P["low"]),
            ]
        elif mod == "malware":
            rep_ = raw_data.get("report", {}) or {}
            legacy = raw_data.get("summary", {}) or {}
            sha = rep_.get("sha256") or raw_data.get("hash") or legacy.get("sha256") or "—"
            verdict = str(raw_data.get("verdict") or legacy.get("verdict") or "—")
            score = raw_data.get("threat_score", legacy.get("threat_score", "—"))
            kv_rows += [
                ("SHA256",       sha[:18] + "…" if len(sha) > 18 else sha, P["text_main"]),
                ("Threat score", str(score), P["critical"] if isinstance(score, (int, float)) and score >= 60 else P["text_main"]),
                ("Verdict",      verdict,
                 P["critical"] if "malicious" in verdict.lower()
                 else P["medium"] if "test_signature" in verdict.lower() else P["low"]),
            ]
        elif mod == "forensics":
            legacy = raw_data.get("summary", {}) or {}
            ov = raw_data.get("timeline_overview", {}) or {}
            findings_n = raw_data.get("total_findings", legacy.get("total_findings"))
            if findings_n is None and isinstance(raw_data.get("findings"), list):
                findings_n = len(raw_data["findings"])
            events_n = ov.get("total_events", raw_data.get("total_records", legacy.get("total_events", "—")))
            tl = raw_data.get("timeline") or []
            rng = legacy.get("time_range") or (
                f"{tl[0].get('time', '')} → {tl[-1].get('time', '')}" if tl and isinstance(tl[0], dict) else "—")
            kv_rows += [
                ("Findings",   str(findings_n if findings_n is not None else "—"), P["medium"]),
                ("Events",     str(events_n), P["text_main"]),
                ("Time range", str(rng), P["text_label"]),
            ]
        for ltxt, vtxt, vc in kv_rows:
            self._add_kv_row(ltxt, vtxt, vc)
        if entry.get("summary"):
            self._add_kv_row("Summary", entry.get("summary"), P["text_label"])
        self._prev_kv_l.addStretch()

        # Emit signal to re-display full analysis
        try:
            data = json.loads(entry.get("raw_json") or "{}")
            self.load_requested.emit(entry["module"], data)
        except Exception as ex:
            log_event(f"History load_requested error: {ex}")

        # A valid selection unlocks the Investigation Workflow buttons.
        # Timeline is always allowed to try — it has its own empty-state
        # message rather than being disabled outright.
        for btn in self._quick_action_btns.values():
            btn.setEnabled(True)
        self._btn_export_pdf.setEnabled(True)

    # kept for QListWidget backward compat (no longer used internally)
    def _on_item_clicked(self, item):
        entry_id = item.data(Qt.UserRole)
        entry = next((e for e in self._current_entries if e["id"] == entry_id), None)
        if entry:
            self._on_card_click(entry)

    def _on_card_double_click(self, entry: dict):
        self._on_card_click(entry)
        self._investigate_selected()

    def _disable_quick_actions(self):
        for btn in self._quick_action_btns.values():
            btn.setEnabled(False)
        self._btn_export_pdf.setEnabled(False)

    def _delete_selected(self):
        if not self._selected_entry:
            QMessageBox.information(self, "History", "Pilih entry yang ingin dihapus.")
            return
        eid = self._selected_entry["id"]
        reply = QMessageBox.question(
            self, "Hapus Entry", f"Hapus entry ID {eid}?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            delete_history_entry(eid)
            self._selected_entry = None
            self._clear_kv()
            self._prev_kv_l.addWidget(self._placeholder_label())
            self._mark_selected_card({})
            self._disable_quick_actions()
            self._load()

    def _export_selected_pdf(self):
        if not self._selected_entry:
            QMessageBox.information(self, "Export", "Pilih entry yang ingin di-export.")
            return
        try:
            data = json.loads(self._selected_entry.get("raw_json") or "{}")
        except Exception:
            data = {}
        self._pdf_worker = _trigger_pdf_export(self, self._selected_entry["module"], data)

    # ── Investigation Workflow: Investigate / Explain / Timeline ───────────────
    #
    # These three make Investigation Log a real re-investigation entry point.
    # HistoryPanel never runs its own CTI/malware/forensics logic — it only
    # gathers the selected record and hands it to the owning module (via
    # signals to MainWindow) or, for Timeline, renders what is already
    # stored. Actions never refresh the history list or touch the current
    # selection, so there is no risk of re-triggering the old selection ↔
    # refresh recursion.

    def _investigate_selected(self):
        if not self._selected_entry:
            return
        entry = self._selected_entry
        try:
            log_event(
                f"History action clicked: action=investigate analysis_id={entry.get('id')}"
            )
            self.investigate_requested.emit((entry.get("module") or "").lower(), entry)
        except Exception as ex:
            log_event(f"History investigate error: {ex}")
            QMessageBox.warning(
                self, "Investigate",
                "Tidak dapat membuka analisis ini.\nDetail teknis telah disimpan di log."
            )

    def _build_explain_context(self, entry: dict) -> dict:
        """Repackage the already-selected history record into the context
        shape the AI SOC Analyst expects. This is just data assembly from
        what _on_card_click already loaded — no new analysis logic."""
        try:
            raw = json.loads(entry.get("raw_json") or "{}")
        except Exception:
            raw = {}
        def _shrink(o, depth=0):
            # Keep the AI prompt small so the useful fields survive the
            # chat panel's size cap (raw results can be 50 KB).
            if depth > 4:
                return "…"
            if isinstance(o, dict):
                return {str(k): _shrink(v, depth + 1) for k, v in list(o.items())[:30]}
            if isinstance(o, (list, tuple)):
                return [_shrink(v, depth + 1) for v in o[:8]]
            if isinstance(o, str):
                return o[:200]
            return o
        return {
            "source": "analysis_history",
            "analysis_id": entry.get("id"),
            "module": (entry.get("module") or "").lower(),
            "timestamp": entry.get("timestamp"),
            "severity": entry.get("severity"),
            "ioc": entry.get("ioc"),
            "summary": entry.get("summary"),
            "details": _shrink(raw),
        }

    def _explain_selected(self):
        if not self._selected_entry:
            return
        entry = self._selected_entry
        try:
            log_event(
                f"History action clicked: action=explain analysis_id={entry.get('id')}"
            )
            context = self._build_explain_context(entry)
            self.explain_requested.emit(context["module"], context)
        except Exception as ex:
            log_event(f"History explain error: {ex}")
            QMessageBox.warning(
                self, "Explain",
                "AI SOC Analyst sedang tidak tersedia.\nHistorical analysis tetap dapat dilihat."
            )

    # ── Timeline (self-contained: no other panel needs to react) ───────────────

    def _forensics_timeline_events(self, raw: dict) -> list:
        events = []
        for e in (raw.get("timeline") or [])[:50]:
            if not isinstance(e, dict):
                continue
            src = e.get("src_ip", ""); dst = e.get("dst_ip", "")
            desc = f"{src} → {dst}" if (src or dst) else (e.get("description") or "")
            events.append({
                "time": e.get("timestamp", ""), "tag": "FORENSICS",
                "label": e.get("technique") or "Event", "desc": desc,
            })
        return events

    def _malware_timeline_events(self, entry: dict, raw: dict) -> list:
        """Only includes stages that are actually present in the stored
        result — no fabricated timestamps or steps that weren't recorded."""
        events = []
        events.append({
            "time": "", "tag": "MALWARE", "label": "Sample Submitted",
            "desc": raw.get("input") or entry.get("ioc") or "—",
        })
        rep = raw.get("report") or {}
        sha = rep.get("sha256")
        if sha:
            events.append({"time": "", "tag": "MALWARE", "label": "Hash Calculated", "desc": sha})
        if rep.get("local_analysis"):
            events.append({
                "time": "", "tag": "MALWARE", "label": "Local Analysis",
                "desc": rep.get("analysis_summary") or "—",
            })
        elif rep.get("found"):
            events.append({
                "time": "", "tag": "MALWARE", "label": "Hybrid Analysis Lookup",
                "desc": rep.get("analysis_summary") or "—",
            })
        net = rep.get("network_connections") or {}
        n_ioc = len(net.get("urls") or []) + len(net.get("ips") or [])
        if n_ioc:
            events.append({
                "time": "", "tag": "MALWARE", "label": "Network IOC Extracted",
                "desc": f"{n_ioc} indicator(s) found",
            })
        events.append({
            "time": entry.get("timestamp", ""), "tag": "MALWARE", "label": "Final Verdict",
            "desc": str(raw.get("verdict") or "—"),
        })
        return events

    def _load_cti_ioc_timeline(self, entry: dict):
        ioc = (entry.get("ioc") or "").strip()
        if not ioc:
            self._open_timeline_dialog("IOC Activity Timeline", "—", [])
            return
        self._timeline_worker = IOCTimelineWorker(ioc)
        self._timeline_worker.done.connect(
            lambda rows, e=entry: self._on_cti_timeline_loaded(e, rows)
        )
        self._timeline_worker.start()

    def _on_cti_timeline_loaded(self, entry: dict, rows: list):
        try:
            events = []
            for r in rows:
                sev = (r.get("severity") or "").upper()
                events.append({
                    "time": r.get("timestamp", ""), "tag": "CTI",
                    "label": "Analysis History Event",
                    "desc": f"Severity {sev} — {(r.get('summary') or '')[:70]}",
                })
                # External Threat Intelligence Events, kept visually distinct
                # from Analysis History Events (spec requirement) — only
                # added when AbuseIPDB actually returned report dates.
                try:
                    raw = json.loads(r.get("raw_json") or "{}")
                    ab = (raw.get("sources") or {}).get("abuseipdb", {})
                    for rpt in (ab.get("reports") or [])[:5]:
                        rdate = rpt.get("reportedAt")
                        if rdate:
                            events.append({
                                "time": rdate, "tag": "THREAT INTEL",
                                "label": "AbuseIPDB report",
                                "desc": (rpt.get("comment") or "")[:70],
                            })
                except Exception:
                    pass
            events.sort(key=lambda e: e.get("time") or "")
            self._open_timeline_dialog("IOC Activity Timeline", entry.get("ioc") or "—", events)
        except Exception as ex:
            log_event(f"History CTI timeline build error: {ex}")
            QMessageBox.warning(self, "Timeline", "Timeline tidak tersedia untuk analysis ini.")

    def _show_selected_timeline(self):
        if not self._selected_entry:
            return
        entry = self._selected_entry
        module = (entry.get("module") or "").lower()
        log_event(f"History action clicked: action=timeline analysis_id={entry.get('id')}")
        try:
            raw = json.loads(entry.get("raw_json") or "{}")
        except Exception as ex:
            log_event(f"History timeline raw_json parse error: {ex}")
            raw = {}
        try:
            if module == "forensics":
                events = self._forensics_timeline_events(raw)
                self._open_timeline_dialog("Attack Timeline", entry.get("ioc") or "—", events)
            elif module == "malware":
                events = self._malware_timeline_events(entry, raw)
                self._open_timeline_dialog("Malware Analysis Timeline", entry.get("ioc") or "—", events)
            elif module == "cti":
                self._load_cti_ioc_timeline(entry)  # async — opens dialog on completion
            else:
                self._open_timeline_dialog("Timeline", entry.get("ioc") or "—", [])
        except Exception as ex:
            log_event(f"History timeline error: {ex}")
            QMessageBox.warning(self, "Timeline", "Timeline tidak tersedia untuk analysis ini.")

    def _open_timeline_dialog(self, title: str, subject: str, events: list):
        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.setMinimumSize(420, 480)
        dlg.setStyleSheet(f"QDialog{{background:{P['bg_dark']};}}")
        root = QVBoxLayout(dlg); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)

        hdr = QFrame()
        hdr.setStyleSheet(f"QFrame{{background:{P['bg_card']};border-bottom:2px solid {P['accent']}33;}}")
        hl = QVBoxLayout(hdr); hl.setContentsMargins(14, 10, 14, 10); hl.setSpacing(2)
        t1 = QLabel(title.upper())
        t1.setStyleSheet(
            f"color:{P['accent']};font-size:11px;font-weight:700;letter-spacing:1px;"
            f"background:transparent;font-family:'Segoe UI','Inter',Arial,sans-serif;"
        )
        t2 = QLabel(subject)
        t2.setStyleSheet(
            f"color:{P['text_dim']};font-size:10px;background:transparent;"
            f"font-family:'Courier New',monospace;"
        )
        hl.addWidget(t1); hl.addWidget(t2)
        root.addWidget(hdr)

        sa = QScrollArea(); sa.setWidgetResizable(True); sa.setFrameShape(QFrame.NoFrame)
        sa.setStyleSheet(f"QScrollArea{{background:{P['bg_dark']};border:none;}}")
        inner = QWidget(); inner.setStyleSheet(f"background:{P['bg_dark']};")
        il = QVBoxLayout(inner); il.setContentsMargins(12, 10, 12, 10); il.setSpacing(6)

        if not events:
            empty = QLabel(
                "No timeline data available for this analysis.\n\n"
                "Timeline requires historical or correlated events."
            )
            empty.setAlignment(Qt.AlignCenter)
            empty.setWordWrap(True)
            empty.setStyleSheet(
                f"color:{P['text_dim']};font-size:11px;background:transparent;"
                f"font-family:'Segoe UI','Inter',Arial,sans-serif;padding:24px;"
            )
            il.addWidget(empty)
        else:
            _tag_colors = {
                "FORENSICS": "#f59e0b", "CTI": "#00d4ff",
                "MALWARE": "#7c3aed", "THREAT INTEL": "#22c55e",
            }
            for ev in events:
                tc = _tag_colors.get(ev.get("tag", ""), P["accent"])
                row = QFrame()
                row.setStyleSheet(
                    f"QFrame{{background:{P['bg_card']};border:1px solid {P['border']};"
                    f"border-left:3px solid {tc};border-radius:6px;}}"
                )
                rl = QVBoxLayout(row); rl.setContentsMargins(10, 6, 10, 6); rl.setSpacing(2)
                top = QHBoxLayout(); top.setSpacing(6)
                time_txt = (ev.get("time") or "—")
                tw = QLabel(time_txt[:16])
                tw.setStyleSheet(
                    f"color:{P['text_dim']};font-size:9px;background:transparent;"
                    f"font-family:'Courier New',monospace;"
                )
                tag_w = QLabel(f"  {ev.get('tag','')}  ")
                tag_w.setStyleSheet(
                    f"color:{tc};background:{tc}18;border:1px solid {tc}55;"
                    f"border-radius:4px;font-size:8px;font-weight:700;padding:1px 2px;"
                    f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
                )
                top.addWidget(tw); top.addWidget(tag_w); top.addStretch()
                rl.addLayout(top)
                label_w = QLabel(ev.get("label", ""))
                label_w.setStyleSheet(
                    f"color:{P['text_main']};font-size:10px;font-weight:600;background:transparent;"
                    f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
                )
                rl.addWidget(label_w)
                if ev.get("desc"):
                    desc_w = QLabel(ev["desc"]); desc_w.setWordWrap(True)
                    desc_w.setStyleSheet(
                        f"color:{P['text_dim']};font-size:9px;background:transparent;"
                        f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
                    )
                    rl.addWidget(desc_w)
                il.addWidget(row)
        il.addStretch()
        sa.setWidget(inner)
        root.addWidget(sa, 1)
        dlg.exec_()

    def refresh(self):
        """Public API: call after new analysis to update list."""
        self._load()




# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — DASHBOARD PAGE (LIVE THREAT COUNTER)
# ══════════════════════════════════════════════════════════════════════════════

class DBQueryWorker(QThread):
    """Background thread to query SQLite without freezing UI."""
    result_ready = pyqtSignal(dict)

    def __init__(self, last_sig=None):
        super().__init__()
        self._last_sig = last_sig

    def run(self):
        # An exception escaping QThread.run() makes PyQt abort the whole process, so any
        # unexpected failure is logged and reported to the UI as "DB ERROR" instead.
        try:
            sig = db_signature()
            if sig is not None and sig == self._last_sig:
                # Nothing was committed since the last successful render: skip the
                # six aggregate queries and only report that the DB is still healthy.
                self.result_ready.emit({"db_ok": True, "unchanged": True, "sig": sig})
                return
            data = query_db_stats()
            if data.get("db_ok"):
                data["sig"] = data.get("sig") or sig      # prefer the signature of the data actually read
            else:
                data["sig"] = None
            self.result_ready.emit(data)
        except Exception as exc:
            import traceback
            log_event(f"DBQueryWorker failed: {exc}\n{traceback.format_exc()}")
            self.result_ready.emit({"db_ok": False, "error": str(exc)})


# ── Dashboard-local palette (scoped to Dashboard UI only) ───────────────────
DASH = {
    "bg_main":     P["bg_dark"],
    "bg_panel":    P["bg_card"],       # cards
    "bg_panel2":   P["bg_input"],      # wells / bar tracks
    "border":      P["border"],
    "text_main":   P["text_main"],
    "text_dim":    P["text_label"],
    "accent":      P["accent"],
    "critical":    P["critical"],
    "high":        P["high"],
    "medium":      P["medium"],
    "low":         P["low"],
    "info":        P["info"],
}

_DASH_FONT = _FONT_STACK


def _dash_sev_color(sev_key: str) -> str:
    key = (sev_key or "info").lower()
    if key == "critical":
        return DASH["critical"]
    if key == "high":
        return DASH["high"]
    if key == "medium":
        return DASH["medium"]
    if key == "low":
        return DASH["low"]
    return DASH["info"]


class ClickableFrame(QFrame):
    """A QFrame that emits `clicked` on left mouse press — used for
    interactive rows (Top IOC list, activity rows) without disturbing
    hover styling handled purely via QSS."""
    clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setCursor(QCursor(Qt.PointingHandCursor))

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class ThreatAlertBanner(QFrame):
    """Security status at a glance: green when stable, red when HIGH/CRITICAL
    findings exist. One row — never takes over the dashboard."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("alertbanner")
        self.setMinimumHeight(60)
        la = QHBoxLayout(self)
        la.setContentsMargins(18, 10, 18, 10)
        la.setSpacing(14)

        self._icon = IconLabel("shield_ok", DASH["low"], 28)
        la.addWidget(self._icon)

        txt_col = QVBoxLayout()
        txt_col.setSpacing(1)
        self._title = QLabel("No high-severity threats detected")
        txt_col.addWidget(self._title)
        self._subtitle = QLabel("Environment appears stable")
        self._subtitle.setStyleSheet(
            f"color:{DASH['text_dim']};font-size:12px;background:transparent;border:none;"
        )
        for _l in (self._title, self._subtitle):
            _l.setWordWrap(True)                      # shrink instead of widening the page
            _l.setMinimumWidth(0)
            _l.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        txt_col.addWidget(self._subtitle)
        la.addLayout(txt_col, 1)

        self._badge = StatusBadge("SECURE", DASH["low"])
        la.addWidget(self._badge, 0, Qt.AlignVCenter)
        self._set_style(ok=True)

    def _set_style(self, ok: bool):
        color = DASH["low"] if ok else DASH["critical"]
        self.setStyleSheet(
            f"QFrame#alertbanner{{background:{color}14;border:1px solid {color}55;border-radius:12px;}}"
        )
        self._title.setStyleSheet(
            f"color:{color};font-size:15px;font-weight:600;background:transparent;border:none;"
        )
        self._icon.set_icon("shield_ok" if ok else "shield_alert", color)
        self._badge.set_status("SECURE" if ok else "ACTION REQUIRED", color)

    def set_state(self, high_count: int, critical_count: int):
        total = (high_count or 0) + (critical_count or 0)
        if total > 0:
            label = "CRITICAL" if critical_count > 0 else "HIGH SEVERITY"
            self._title.setText(f"{total} {label} THREAT{'S' if total != 1 else ''} DETECTED")
            self._subtitle.setText("Immediate investigation recommended")
            self._set_style(ok=False)
        else:
            self._title.setText("No high-severity threats detected")
            self._subtitle.setText("Environment appears stable")
            self._set_style(ok=True)


class SeverityOverview(QWidget):
    """Thin horizontal severity distribution bars — no donut chart."""
    def __init__(self, parent=None):
        super().__init__(parent)
        la = QVBoxLayout(self)
        la.setContentsMargins(0, 0, 0, 0)
        la.setSpacing(8)
        self._bars = {}
        for key, label in [("high", "HIGH"), ("medium", "MEDIUM"), ("low", "LOW"), ("info", "INFO")]:
            row = QHBoxLayout()
            row.setSpacing(8)
            color = _dash_sev_color(key)

            lbl = QLabel(label)
            lbl.setMinimumWidth(64)
            lbl.setStyleSheet(
                f"color:{color};font-size:12px;font-weight:bold;background:transparent;border:none;"
                f"font-family:{_DASH_FONT};"
            )
            row.addWidget(lbl)

            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(0)
            bar.setFixedHeight(8)
            bar.setTextVisible(False)
            bar.setStyleSheet(
                f"QProgressBar{{background:{DASH['bg_panel2']};border:none;border-radius:4px;}}"
                f"QProgressBar::chunk{{background:{color};border-radius:4px;}}"
            )
            row.addWidget(bar, 1)

            cnt = QLabel("0")
            cnt.setFixedWidth(28)
            cnt.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            cnt.setStyleSheet(
                f"color:{color};font-size:13px;font-weight:bold;background:transparent;border:none;"
                f"font-family:{_DASH_FONT};"
            )
            row.addWidget(cnt)

            la.addLayout(row)
            self._bars[key] = (bar, cnt)

    def set_values(self, high: int, medium: int, low: int, info: int):
        vals = {"high": high, "medium": medium, "low": low, "info": info}
        max_v = max(vals.values(), default=1) or 1
        for key, (bar, cnt) in self._bars.items():
            v = vals[key]
            bar.setValue(int((v / max_v) * 100) if max_v else 0)
            cnt.setText(str(v))


class TopIOCList(QWidget):
    """Compact clickable Top-IOC list. Clicking a row opens a CTI lookup."""
    ioc_clicked = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(4)
        self._placeholder = QLabel("No IOC data yet")
        self._placeholder.setStyleSheet(
            f"color:{DASH['text_dim']};font-size:12px;background:transparent;border:none;"
            f"font-family:{_DASH_FONT};"
        )
        self._layout.addWidget(self._placeholder)

    def set_data(self, top_iocs: list):
        while self._layout.count():
            item = self._layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not top_iocs:
            pl = QLabel("No IOC data yet")
            pl.setStyleSheet(
                f"color:{DASH['text_dim']};font-size:12px;background:transparent;border:none;"
                f"font-family:{_DASH_FONT};"
            )
            self._layout.addWidget(pl)
            return

        for i, entry in enumerate(top_iocs[:5], start=1):
            ioc_val = (entry.get("ioc", "") or "")[:36]
            cnt = entry.get("count", 0)
            color = _dash_sev_color(entry.get("severity"))

            row = ClickableFrame()
            row.setStyleSheet(
                f"QFrame{{background:transparent;border-radius:5px;}}"
                f"QFrame:hover{{background:{P['bg_card2']};}}"
            )
            rl = QHBoxLayout(row)
            rl.setContentsMargins(6, 5, 6, 5)
            rl.setSpacing(6)

            idx_lbl = QLabel(f"{i}.")
            idx_lbl.setFixedWidth(16)
            idx_lbl.setStyleSheet(
                f"color:{DASH['text_dim']};font-size:12px;background:transparent;border:none;"
                f"font-family:{_DASH_FONT};"
            )
            rl.addWidget(idx_lbl)

            ioc_lbl = QLabel(ioc_val)
            ioc_lbl.setStyleSheet(
                f"color:{DASH['text_main']};font-size:13px;background:transparent;border:none;"
                f"font-family:{_FONT_MONO};"
            )
            ioc_lbl.setToolTip(entry.get("ioc", "") or "")
            ioc_lbl.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)   # long hashes clip, never widen the page
            rl.addWidget(ioc_lbl, 1)

            cnt_lbl = QLabel(f"×{cnt}")
            cnt_lbl.setAlignment(Qt.AlignRight)
            cnt_lbl.setStyleSheet(
                f"color:{color};font-size:12px;font-weight:bold;background:transparent;border:none;"
                f"font-family:{_DASH_FONT};"
            )
            rl.addWidget(cnt_lbl)

            row.clicked.connect(lambda checked=False, v=entry.get("ioc", ""): self.ioc_clicked.emit(v))
            self._layout.addWidget(row)


class ThreatActivityTable(QWidget):
    """Clean recent-activity list: small severity badge, subtle left
    border, hover highlight. No full-row background fill."""
    view_all = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(8)

        self._rows_layout = QVBoxLayout()
        self._rows_layout.setSpacing(2)
        self._placeholder = QLabel("No analysis history available")
        self._placeholder.setStyleSheet(
            f"color:{DASH['text_dim']};font-size:12px;background:transparent;border:none;"
            f"font-family:{_DASH_FONT};"
        )
        self._rows_layout.addWidget(self._placeholder)
        outer.addLayout(self._rows_layout)

        link_row = QHBoxLayout()
        link_row.addStretch()
        self._view_all_btn = QPushButton("View all activity →")
        self._view_all_btn.setCursor(QCursor(Qt.PointingHandCursor))
        self._view_all_btn.setFlat(True)
        self._view_all_btn.setStyleSheet(
            f"QPushButton{{color:{DASH['accent']};background:transparent;border:none;"
            f"font-size:12px;font-weight:600;font-family:{_DASH_FONT};}}"
            f"QPushButton:hover{{color:{DASH['text_main']};}}"
        )
        self._view_all_btn.clicked.connect(self.view_all.emit)
        link_row.addWidget(self._view_all_btn)
        outer.addLayout(link_row)

    def set_data(self, recent: list):
        while self._rows_layout.count():
            item = self._rows_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not recent:
            pl = QLabel("No analysis history available")
            pl.setStyleSheet(
                f"color:{DASH['text_dim']};font-size:12px;background:transparent;border:none;"
                f"font-family:{_DASH_FONT};"
            )
            self._rows_layout.addWidget(pl)
            return

        for entry in recent[:9]:
            ts = (entry.get("ts", "") or "")[-8:] or "—"
            mod = (entry.get("module", "") or "").upper()
            sev_key = (entry.get("severity") or "info").lower()
            color = _dash_sev_color(sev_key)
            summ = (entry.get("summary") or "")[:60]

            row = QFrame()
            row.setStyleSheet(
                f"QFrame{{background:transparent;border-left:3px solid {color}88;border-radius:3px;}}"
                f"QFrame:hover{{background:{P['bg_card2']};}}"
            )
            rl = QHBoxLayout(row)
            rl.setContentsMargins(10, 6, 10, 6)
            rl.setSpacing(10)

            ts_lbl = QLabel(f"[{ts}]")
            ts_lbl.setFixedWidth(76)
            ts_lbl.setStyleSheet(
                f"color:{DASH['text_dim']};font-size:12px;"
                f"background:transparent;border:none;"
            )
            rl.addWidget(ts_lbl)

            mod_lbl = QLabel(mod)
            mod_lbl.setFixedWidth(84)
            mod_lbl.setStyleSheet(
                f"color:{DASH['accent']};font-size:12px;font-weight:bold;background:transparent;border:none;"
                f"font-family:{_DASH_FONT};"
            )
            rl.addWidget(mod_lbl)

            sev_badge = SeverityBadge(sev_key, min_width=78)
            rl.addWidget(sev_badge)

            summ_lbl = QLabel(summ)
            summ_lbl.setToolTip(entry.get("summary") or "")
            summ_lbl.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
            summ_lbl.setStyleSheet(
                f"color:{DASH['text_main']};font-size:12px;background:transparent;border:none;"
                f"font-family:{_DASH_FONT};"
            )
            rl.addWidget(summ_lbl, 1)

            self._rows_layout.addWidget(row)


class AISecuritySummary(QFrame):
    """Short, readable AI-generated summary with a call-to-action into
    the full AI SOC Analyst panel."""
    ask_ai = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            f"QFrame{{background:{DASH['bg_panel']};border:1px solid {DASH['border']};border-radius:12px;}}"
        )
        la = QVBoxLayout(self)
        la.setContentsMargins(18, 14, 18, 14)
        la.setSpacing(8)

        hdr = QHBoxLayout()
        hdr.addWidget(IconLabel("ai", DASH["accent"], 18))
        title = QLabel("AI SECURITY SUMMARY")
        title.setStyleSheet(
            f"color:{DASH['accent']};font-size:14px;font-weight:bold;background:transparent;border:none;"
            f"font-family:{_DASH_FONT};"
        )
        hdr.addWidget(title)
        hdr.addStretch()

        self._ask_btn = ModernButton("Ask AI Analyst", "ghost", icon="ai", tooltip="Open the AI SOC Analyst panel")
        self._ask_btn.clicked.connect(self.ask_ai.emit)
        hdr.addWidget(self._ask_btn)
        la.addLayout(hdr)

        self._summary_lbl = QLabel("Belum ada data analisis.")
        self._summary_lbl.setWordWrap(True)
        self._summary_lbl.setStyleSheet(
            f"color:{DASH['text_main']};font-size:13px;background:transparent;border:none;"
            f"font-family:{_DASH_FONT};"
        )
        la.addWidget(self._summary_lbl)

    def set_summary(self, text: str):
        self._summary_lbl.setText(text)


class DashboardPage(QWidget):
    """Enterprise SOC overview dashboard. Pure UI/UX layer — data source
    (SQLite via query_db_stats / DBQueryWorker), polling cadence (5s
    QTimer), and all other modules are unchanged."""

    goto_history = pyqtSignal()
    goto_cti = pyqtSignal(str)
    goto_chat = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._worker = None
        self._last_sig = None
        self._setup_ui()
        self._setup_timers()

    # ── UI Build ──────────────────────────────────────────────────────────
    def _setup_ui(self):
        self.setStyleSheet(f"background:{DASH['bg_main']};")
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Live-data strip (page title/breadcrumb now lives in the global HeaderBar) ──
        strip = QWidget()
        strip.setFixedHeight(40)
        strip.setStyleSheet(f"background:{DASH['bg_main']};")
        strip_l = QHBoxLayout(strip)
        strip_l.setContentsMargins(24, 8, 24, 0)
        strip_l.setSpacing(10)
        feed_lbl = QLabel("Live data feed")
        feed_lbl.setStyleSheet(
            f"color:{DASH['text_dim']};font-size:12px;background:transparent;border:none;"
        )
        strip_l.addWidget(feed_lbl)
        self._status_dot = QLabel("● SYSTEM LIVE")
        self._status_dot.setStyleSheet(_status_badge_qss(DASH["low"]))
        strip_l.addWidget(self._status_dot)
        strip_l.addStretch()
        self._last_update_lbl = QLabel("Last updated: —")
        self._last_update_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._last_update_lbl.setStyleSheet(
            f"color:{DASH['text_dim']};font-size:12px;background:transparent;border:none;"
        )
        strip_l.addWidget(self._last_update_lbl)
        root.addWidget(strip)

        # ── Scrollable body (keeps everything readable on small windows) ──
        body_scroll = QScrollArea()
        body_scroll.setWidgetResizable(True)
        body_scroll.setStyleSheet(
            f"QScrollArea{{background:{DASH['bg_main']};border:none;}}"
            f"QScrollBar:vertical{{background:{DASH['bg_main']};width:6px;}}"
            f"QScrollBar::handle:vertical{{background:{DASH['border']};border-radius:3px;}}"
        )
        body_w = QWidget()
        body_w.setStyleSheet(f"background:{DASH['bg_main']};")
        body = QVBoxLayout(body_w)
        body.setContentsMargins(24, 12, 24, 24)
        body.setSpacing(16)

        # ── Alert banner ────────────────────────────────────────────────
        self._alert_banner = ThreatAlertBanner()
        body.addWidget(self._alert_banner)

        # ── Stat cards (4 only) ────────────────────────────────────────
        self._cards_grid = QGridLayout()
        self._cards_grid.setSpacing(16)
        self._card_total = StatCard("TOTAL RUNS", "All analyses", DASH["accent"])
        self._card_today = StatCard("TODAY", "Analysis runs", DASH["info"])
        self._card_high = StatCard("HIGH RISK", "Requires action", DASH["high"], emphasis=True)
        self._card_iocs = StatCard("ACTIVE IOCs", "Unique", DASH["medium"])
        self._stat_cards = [self._card_total, self._card_today, self._card_high, self._card_iocs]
        body.addLayout(self._cards_grid)
        self._cards_cols = 0
        self._reflow_cards(1000)

        # ── Main content: LEFT 65% (activity) / RIGHT 35% (overview) ──────
        main_row = QBoxLayout(QBoxLayout.LeftToRight)
        self._main_row = main_row           # stacks vertically on narrow pages
        main_row.setSpacing(16)

        # LEFT — Threat Activity
        left_frame = QFrame()
        left_frame.setStyleSheet(
            f"QFrame{{background:{DASH['bg_panel']};border:1px solid {DASH['border']};border-radius:12px;}}"
        )
        left_l = QVBoxLayout(left_frame)
        left_l.setContentsMargins(18, 14, 18, 14)
        left_l.setSpacing(10)
        left_title = QLabel("Threat Activity")
        left_title.setStyleSheet(
            f"color:{DASH['text_main']};font-size:15px;font-weight:600;background:transparent;border:none;"
            f"font-family:{_DASH_FONT};"
        )
        left_l.addWidget(left_title)
        self._activity_table = ThreatActivityTable()
        self._activity_table.view_all.connect(self.goto_history.emit)
        left_l.addWidget(self._activity_table)
        left_l.addStretch()
        main_row.addWidget(left_frame, 65)

        # RIGHT — Threat Overview (severity bars + top IOCs)
        right_col = QVBoxLayout()
        right_col.setSpacing(16)

        overview_frame = QFrame()
        overview_frame.setStyleSheet(
            f"QFrame{{background:{DASH['bg_panel']};border:1px solid {DASH['border']};border-radius:12px;}}"
        )
        ov_l = QVBoxLayout(overview_frame)
        ov_l.setContentsMargins(16, 14, 16, 14)
        ov_l.setSpacing(10)
        ov_title = QLabel("Threat Overview")
        ov_title.setStyleSheet(
            f"color:{DASH['text_main']};font-size:15px;font-weight:600;background:transparent;border:none;"
            f"font-family:{_DASH_FONT};"
        )
        ov_l.addWidget(ov_title)
        self._severity_overview = SeverityOverview()
        ov_l.addWidget(self._severity_overview)

        ov_l.addSpacing(4)
        ioc_title = QLabel("TOP IOC")
        ioc_title.setStyleSheet(
            f"color:{DASH['text_dim']};font-size:12px;font-weight:700;letter-spacing:0.6px;"
            f"background:transparent;border:none;font-family:{_DASH_FONT};"
        )
        ov_l.addWidget(ioc_title)
        self._top_iocs = TopIOCList()
        self._top_iocs.ioc_clicked.connect(self.goto_cti.emit)
        ov_l.addWidget(self._top_iocs)
        right_col.addWidget(overview_frame)
        right_col.addStretch()

        right_wrap = QWidget()
        right_wrap.setLayout(right_col)
        main_row.addWidget(right_wrap, 35)

        body.addLayout(main_row)

        # ── Bottom: AI Security Summary ────────────────────────────────
        self._ai_summary = AISecuritySummary()
        self._ai_summary.ask_ai.connect(self.goto_chat.emit)
        body.addWidget(self._ai_summary)

        # ── Quick start (only shown when there is no data at all) ─────
        self._quickstart_frame = QFrame()
        self._quickstart_frame.setStyleSheet(
            f"QFrame{{background:{DASH['bg_panel']};border:1px solid {DASH['border']};border-radius:12px;}}"
        )
        qs_l = QVBoxLayout(self._quickstart_frame)
        qs_l.setContentsMargins(18, 14, 18, 14)
        qs_l.setSpacing(8)
        qs_title = QLabel("QUICK START — Run an analysis to populate this dashboard")
        qs_title.setStyleSheet(
            f"color:{DASH['low']};font-size:13px;font-weight:bold;background:transparent;border:none;"
            f"font-family:{_DASH_FONT};"
        )
        qs_title.setWordWrap(True)        # a long single-line label made the whole page 838 px wide on Windows
        qs_l.addWidget(qs_title)
        for num, mod, desc in [
            ("1", "CTI", "Sidebar → CTI → masukkan IP/domain/hash → ANALYZE"),
            ("2", "Malware", "Sidebar → Malware → masukkan hash atau upload file → ANALYZE"),
            ("3", "Forensics", "Sidebar → Forensics → upload/paste log → ANALYZE LOG"),
        ]:
            rw = QHBoxLayout()
            n = QLabel(f" {num} ")
            n.setStyleSheet(
                f"background:{DASH['accent']};color:#04121A;border-radius:9px;padding:2px 6px;"
                f"font-weight:bold;font-size:12px;font-family:{_DASH_FONT};"
            )
            rw.addWidget(n)
            mod_l = QLabel(mod)
            mod_l.setMinimumWidth(90)         # was setFixedWidth(90): clips with wider fonts
            mod_l.setStyleSheet(
                f"color:{DASH['accent']};font-weight:bold;font-size:12px;background:transparent;border:none;"
                f"font-family:{_DASH_FONT};"
            )
            rw.addWidget(mod_l)
            desc_l = QLabel(desc)
            desc_l.setWordWrap(True)
            desc_l.setStyleSheet(
                f"color:{DASH['text_dim']};font-size:12px;background:transparent;border:none;"
                f"font-family:{_DASH_FONT};"
            )
            rw.addWidget(desc_l)
            rw.addStretch()
            qs_l.addLayout(rw)
        body.addWidget(self._quickstart_frame)

        body.addStretch()
        body_scroll.setWidget(body_w)
        root.addWidget(body_scroll)

    def _reflow_cards(self, avail_width: int):
        """4 cards in one row when there is room, otherwise 2x2 — never squeezed."""
        cols = 4 if avail_width >= 720 else 2
        if hasattr(self, "_main_row"):
            want = QBoxLayout.LeftToRight if avail_width >= 760 else QBoxLayout.TopToBottom
            if self._main_row.direction() != want:
                self._main_row.setDirection(want)
        if cols == self._cards_cols:
            return
        self._cards_cols = cols
        for c in self._stat_cards:
            self._cards_grid.removeWidget(c)
        for i, c in enumerate(self._stat_cards):
            self._cards_grid.addWidget(c, i // cols, i % cols)
        for col in range(4):
            self._cards_grid.setColumnStretch(col, 1 if col < cols else 0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._reflow_cards(self.width())

    # ── Timers ────────────────────────────────────────────────────────────
    def _setup_timers(self):
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._start_refresh)
        self._refresh_timer.start(DASHBOARD_POLL_MS)
        self._start_refresh()

    _refresh_pending = False      # True from worker start until its result has been applied

    def _start_refresh(self):
        # A finished worker's result is still queued for the GUI thread. Starting the next poll
        # before _on_data() ran would use the OLD signature and repeat the heavy queries
        # (a race that shows up on Windows, where thread/timer scheduling is slower).
        if self._refresh_pending or (self._worker and self._worker.isRunning()):
            return
        self._refresh_pending = True
        self._worker = DBQueryWorker(self._last_sig)
        self._worker.result_ready.connect(self._on_data)
        # `finished` is emitted after result_ready from the same thread, so it is delivered after
        # _on_data() — and it also fires if run() raised, so the flag can never get stuck.
        self._worker.finished.connect(self._on_refresh_finished)
        self._worker.start()

    def _on_refresh_finished(self):
        self._refresh_pending = False

    # ── Data rendering (updates existing widgets, never rebuilds UI) ──────
    def _on_data(self, data: dict):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self._last_update_lbl.setText(f"Last updated: {now}")

        if not data.get("db_ok"):
            self._last_sig = None            # force a full redraw once the DB recovers
            self._status_dot.setText("● DB ERROR")
            self._status_dot.setStyleSheet(_status_badge_qss(DASH["critical"]))
            return

        self._status_dot.setText("● SYSTEM LIVE")
        self._status_dot.setStyleSheet(_status_badge_qss(DASH["low"]))
        if data.get("unchanged"):
            return                           # same data already on screen
        self._last_sig = data.get("sig")

        mc = data.get("module_counts", {})
        sev = data.get("sev_counts", {})
        total = data.get("total", 0)
        top_iocs = data.get("top_iocs", [])

        high_n = sev.get("high", 0)
        crit_n = sev.get("critical", 0)
        med_n = sev.get("medium", 0)
        low_n = sev.get("low", 0)
        info_n = sev.get("info", 0) + sev.get("unknown", 0)

        # Stat cards
        self._card_total.set_value(total)
        self._card_today.set_value(data.get("today_count", 0))
        self._card_high.set_value(high_n + crit_n)
        self._card_iocs.set_value(data.get("unique_iocs", len(top_iocs)))

        # Alert banner
        self._alert_banner.set_state(high_n, crit_n)

        # Severity overview
        self._severity_overview.set_values(high_n + crit_n, med_n, low_n, info_n)

        # Top IOCs
        self._top_iocs.set_data(top_iocs)

        # Recent activity
        self._activity_table.set_data(data.get("recent", []))

        # AI summary
        self._ai_summary.set_summary(self._build_summary(total, high_n + crit_n, med_n, low_n, mc, data.get("recent", [])))

        # Quick start only when there's genuinely no data yet
        self._quickstart_frame.setVisible(total == 0)

    def _build_summary(self, total, high_n, med_n, low_n, mc, recent) -> str:
        if total == 0:
            return "Belum ada data analisis. Jalankan analisis CTI, Malware, atau Forensics untuk melihat ringkasan keamanan."

        modules_hit = sorted({(e.get("module") or "").capitalize() for e in recent if e.get("module")})
        modules_txt = " dan ".join(modules_hit[:2]) if modules_hit else "berbagai modul"

        if high_n > 0:
            lines = [f"Monitoring hari ini menunjukkan {high_n} aktivitas HIGH severity yang memerlukan investigasi."]
            lines.append(f"Aktivitas utama berasal dari modul {modules_txt}.")
            prios = []
            for e in recent:
                if (e.get("severity") or "").lower() in ("high", "critical"):
                    ioc = e.get("summary") or e.get("module", "")
                    prios.append(f"• Investigate {ioc}")
                if len(prios) >= 2:
                    break
            if prios:
                lines.append("Prioritas:\n" + "\n".join(prios))
            return "\n\n".join(lines)
        elif med_n > 0:
            return (
                f"Sebagian besar aktivitas berada pada severity MEDIUM ({med_n} temuan). "
                "Monitor traffic dan lakukan investigasi lanjutan pada IOC yang terdeteksi."
            )
        else:
            return (
                f"Tidak ditemukan ancaman signifikan saat ini ({total} analisis dijalankan). "
                "Environment terlihat stabil — tetap monitor secara berkala."
            )

    def refresh_now(self):
        """Public method: call this after a new analysis to force immediate dashboard refresh."""
        self._start_refresh()


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 11 — CTI PAGE
# ══════════════════════════════════════════════════════════════════════════════

_IOC_TYPE_LABEL = {"ip": "IP ADDRESS", "domain": "DOMAIN", "url": "URL", "hash_md5": "MD5",
                   "hash_sha1": "SHA1", "hash_sha256": "SHA256"}


def cti_source_view(name: str, data: dict):
    """Map a raw CTI source dict to (state, headline, detail, severity) for a SourceCard.
    Real errors stay visible (auth, rate limit, network…) instead of being flattened."""
    data = data or {}
    if "error" in data:
        err = str(data.get("error") or "")
        el = err.lower()
        if el == "api key not configured":
            return ("off", "API key not configured", "This integration is disabled until a key is set in .env.", None)
        if "invalid" in el or "http 400" in el or el.startswith("skipped"):
            return ("warn", "Skipped", "Not a valid IOC for this source.", None)
        if el in ("no intelligence found", "unsupported ioc type") or "not found" in el or "no data" in el:
            return ("warn", "No intelligence found", err if el != "no intelligence found" else "", None)
        return ("error", "Lookup failed", err or "Unknown error", None)
    score = data.get("score", 0) or 0
    sev = score_to_severity(score) if score else "low"
    nm = name.lower()
    if nm == "virustotal":
        mal = data.get("malicious_count", 0)
        head = f"{mal} malicious engine(s)  ·  detection ratio {score}%"
        return ("ok", head, "", sev)
    if nm == "abuseipdb":
        head = f"Abuse confidence {score}/100  ·  {data.get('total_reports', 0)} report(s)"
        return ("ok", head, "", sev)
    if nm == "shodan":
        ports = data.get("open_ports", []) or []
        return ("ok", f"{len(ports)} open port(s)" + (f"  ·  {len(data.get('vulns', []) or [])} CVE(s)" if data.get("vulns") else ""), "", None)
    return ("ok", "Result available", "", None)


class CTIPage(QWidget):
    context_ready = pyqtSignal(str, object)   # (module_name, context_dict)

    def __init__(self):
        super().__init__()
        self.worker = None
        root = QHBoxLayout(self); root.setContentsMargins(0, 0, 0, 0)
        sp = QSplitter(Qt.Horizontal); sp.setChildrenCollapsible(False); root.addWidget(sp)

        # ── LEFT — IOC input ───────────────────────────────────────────────
        lsa = QScrollArea(); lsa.setWidgetResizable(True); lsa.setFrameShape(QFrame.NoFrame)
        lsa.setMinimumWidth(300); lsa.setMaximumWidth(420)
        lsa.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)   # input panel must fit, never side-scroll
        lw = QWidget(); lw.setStyleSheet("background:transparent;"); lsa.setWidget(lw)
        ll = QVBoxLayout(lw); ll.setContentsMargins(24, 24, 16, 24); ll.setSpacing(16)
        ttl = QLabel("THREAT INTELLIGENCE")
        ttl.setWordWrap(True)
        ttl.setStyleSheet(f"color:{P['text_main']};font-size:22px;font-weight:700;background:transparent;")
        stl = QLabel("Cyber Threat Intelligence lookup")
        stl.setStyleSheet(f"color:{P['text_label']};font-size:13px;background:transparent;")
        ll.addWidget(ttl); ll.addWidget(stl)

        ic, icl = card("TARGET IOC", color=P["accent"])
        _hint = lbl("IP / Domain / URL / Hash (MD5, SHA1, SHA256)", color=P["text_label"], size=12)
        _hint.setWordWrap(True); icl.addWidget(_hint)
        self.inp = QLineEdit(); self.inp.setPlaceholderText("Enter IOC")
        self.inp.returnPressed.connect(self._run)
        self.inp.textChanged.connect(self._on_ioc_changed)
        icl.addWidget(self.inp)
        trow = QHBoxLayout(); trow.setSpacing(8)
        trow.addWidget(lbl("Detected type", color=P["text_dim"], size=12))
        self._type_badge = StatusBadge("—", P["text_dim"])
        trow.addWidget(self._type_badge); trow.addStretch()
        icl.addLayout(trow)
        ll.addWidget(ic)

        self.btn_go = ModernButton("ANALYZE", "primary", icon="send", tooltip="Query all intelligence sources (Enter)")
        self.btn_go.setMinimumHeight(40)
        self.btn_go.clicked.connect(self._run)
        ll.addWidget(self.btn_go)
        self.prog = QProgressBar(); self.prog.setRange(0, 0); self.prog.setVisible(False)
        self.prog.setFixedHeight(4); self.prog.setTextVisible(False)
        ll.addWidget(self.prog)
        self._loading = LoadingIndicator("Querying sources…")
        ll.addWidget(self._loading)

        sc_, scl_ = card("LOOKUP STATUS", color=P["accent2"])
        self._status_lay = QVBoxLayout(); self._status_lay.setSpacing(8)
        scl_.addLayout(self._status_lay)
        ll.addWidget(sc_)
        self._set_status_rows(None)

        self._btn_export = ModernButton("Export Report (PDF)", "secondary", icon="pdf",
                                        tooltip="Export the analysis as a PDF Incident Report")
        self._btn_export.setEnabled(False)
        self._btn_export.clicked.connect(self._export_pdf)
        ll.addWidget(self._btn_export)
        self._last_result = None
        self._pdf_worker = None
        ll.addStretch(); sp.addWidget(lsa)

        # ── RIGHT — workspace tabs ─────────────────────────────────────────
        rw = QWidget(); rl = QVBoxLayout(rw); rl.setContentsMargins(8, 24, 24, 16)
        self.tabs = tabs = QTabWidget(); rl.addWidget(tabs)
        self.sa, _, self.ol = scroll_page(); tabs.addTab(self.sa, "OVERVIEW")
        self.sa_s, _, self.sl = scroll_page(); tabs.addTab(self.sa_s, "SOURCES")
        self.sa_w, _, self.wl = scroll_page(); tabs.addTab(self.sa_w, "WHOIS")
        self.sa_a, _, self.al = scroll_page(); tabs.addTab(self.sa_a, "ABUSEIPDB")
        self.raw = QTextEdit(); self.raw.setReadOnly(True)
        self.raw.setPlaceholderText("Raw JSON appears here after a lookup.")
        self.raw.setStyleSheet(f"background:{P['bg_dark']};font-size:12px;font-family:{_FONT_MONO};")
        tabs.addTab(self.raw, "RAW JSON")
        self.ai = ai_browser(); tabs.addTab(self.ai, "AI SUMMARY")
        self.ai.setPlaceholderText("The AI summary is generated after a lookup completes.")
        tabs.setTabToolTip(1, "Intelligence sources")
        tabs.setTabToolTip(3, "AbuseIPDB reports")
        sp.addWidget(rw)
        sp.setStretchFactor(0, 3); sp.setStretchFactor(1, 7); sp.setSizes([320, 800])
        self._show_empty_states()

    # ── states ─────────────────────────────────────────────────────────────
    def _show_empty_states(self):
        for layout in (self.ol, self.sl, self.wl, self.al):
            clear_layout(layout)
        self.ol.addWidget(AnalysisEmptyState(
            "cti", "Ready for Threat Intelligence",
            "Enter an IP address, domain, URL or file hash to query VirusTotal, AbuseIPDB, Shodan and WHOIS."))
        self.ol.addStretch()
        for layout, title, body in (
                (self.sl, "No intelligence sources queried yet", "Run a lookup to see each source's status and findings."),
                (self.wl, "No WHOIS data", "WHOIS enrichment is available for domain lookups."),
                (self.al, "No AbuseIPDB data", "AbuseIPDB reports are available for IP address lookups.")):
            layout.addWidget(AnalysisEmptyState("search", title, body)); layout.addStretch()

    def _placeholder(self, layout, text):
        clear_layout(layout)
        layout.addWidget(AnalysisEmptyState("cti", text))
        layout.addStretch()

    def _set_busy(self, busy: bool):
        self.btn_go.set_loading(busy, "Analyzing…")
        self.prog.setVisible(busy)
        if busy:
            self._loading.start("Querying VirusTotal, AbuseIPDB, Shodan, WHOIS…")
        else:
            self._loading.stop()

    def _set_status_rows(self, sources):
        clear_layout(self._status_lay)
        if not sources:
            self._status_lay.addWidget(lbl("No lookup yet", color=P["text_dim"], size=12))
            return
        for name, data in sources:
            state, head, _d, _sev = cti_source_view(name, data)
            row = QHBoxLayout(); row.setSpacing(8)
            row.addWidget(lbl(name, size=13), 1)
            col = {"ok": P["low"], "warn": P["medium"], "error": P["critical"], "off": P["text_dim"]}.get(state, P["info"])
            row.addWidget(StatusBadge({"ok": "OK", "warn": "NO DATA", "error": "ERROR", "off": "OFF"}.get(state, "…"), col))
            self._status_lay.addLayout(row)

    def _on_ioc_changed(self, text: str):
        t = (text or "").strip()
        if not t:
            self._type_badge.set_status("—", P["text_dim"]); return
        try:
            kind = normalize_input(t)["type"]
        except Exception:
            kind = "unknown"
        label = _IOC_TYPE_LABEL.get(kind)
        if label:
            self._type_badge.set_status(label, P["accent"])
        else:
            self._type_badge.set_status("NOT A VALID IOC", P["medium"])

    def _show_error(self, msg: str):
        clear_layout(self.ol)
        self.ol.addWidget(AnalysisEmptyState("shield_alert", "Lookup failed", str(msg), kind="error"))
        self.ol.addStretch()
        self.tabs.setCurrentIndex(0)

    def _run(self):
        ioc = self.inp.text().strip()
        if not ioc:
            return QMessageBox.warning(self, "Input", "Please enter an IOC.")
        info = normalize_input(ioc)
        if info["type"] in ("file_path", "unknown"):
            log_event(f"Invalid IOC for CTI lookup: {ioc}")
            return QMessageBox.warning(self, "IOC", "Skipped (not valid IOC)")
        self.inp.setText(info["value"])
        self._start(lambda: aggregate_cti_result(info["value"]))

    def _start(self, fn):
        if is_busy(getattr(self, "worker", None)):
            log_event("CTIPage._start ignored: analysis already running")
            return
        self._set_busy(True)
        self.worker = Worker(fn)
        self.worker.done.connect(self._on_done)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _on_error(self, e):
        self._set_busy(False)
        self._show_error(e)
        QMessageBox.critical(self, "Error", e)

    def _on_done(self, r):
        self._set_busy(False)
        self._last_result = r
        self._display(r); self._ai_summary(r)
        # Save to SQLite
        try:
            ioc_val  = r.get("ioc", "")
            sev_val  = r.get("severity", "info")
            summ_val = f"CTI: {ioc_val} — verdict={r.get('summary',{}).get('verdict','unknown')} score={r.get('risk_score',0)}"
            save_to_db("cti", sev_val, ioc_val, summ_val, r)
        except Exception as e:
            log_event(f"CTI save_to_db error: {e}")
        # Emit context for chatbot
        try:
            ioc = r.get("ioc", "N/A")
            summ = r.get("summary", {})
            ctx = {
                "module": "cti",
                "ioc": ioc,
                "type": r.get("type", "unknown"),
                "risk_score": r.get("risk_score", 0),
                "severity": r.get("severity", "unknown"),
                "findings": [
                    f"VirusTotal malicious engines: {summ.get('vt_malicious', 0)}",
                    f"AbuseIPDB score: {summ.get('abuse_score', 0)}",
                    f"Country: {summ.get('country', 'N/A')}",
                    f"ISP: {summ.get('isp', 'N/A')}",
                    f"Verdict: {summ.get('verdict', 'N/A')}",
                    f"Is TOR exit node: {summ.get('is_tor', False)}",
                    f"Open ports: {summ.get('open_ports', [])}",
                    f"Vulnerabilities: {summ.get('vulns', [])}",
                ],
                "iocs": [ioc],
                "statistics": {"risk_score": r.get("risk_score", 0)},
                "analysis_result": summ,
                "sources": r.get("sources", {}),
                "whois": r.get("whois", {}),
            }
            self.context_ready.emit("cti", ctx)
        except Exception as e:
            log_event(f"Chatbot CTI context injection error: {e}")
            import traceback; log_event(traceback.format_exc())

    def _kv_grid(self, layout, pairs, cols=2):
        g = QGridLayout(); g.setHorizontalSpacing(24); g.setVerticalSpacing(10)
        for i, (k, v, col) in enumerate(pairs):
            cell = QVBoxLayout(); cell.setSpacing(2)
            kl = lbl(k, color=P["text_dim"], size=12)
            vl_ = lbl(str(v), color=col or P["text_main"], size=13)
            vl_.setWordWrap(True); vl_.setTextInteractionFlags(Qt.TextSelectableByMouse)
            cell.addWidget(kl); cell.addWidget(vl_)
            holder = QWidget(); holder.setLayout(cell); holder.setStyleSheet("background:transparent;")
            g.addWidget(holder, i // cols, i % cols)
        for c in range(cols):
            g.setColumnStretch(c, 1)
        layout.addLayout(g)

    def _display(self, r):
        for layout in (self.ol, self.sl, self.wl, self.al):
            clear_layout(layout)
        self._btn_export.setEnabled(bool(r))
        summ = r.get("summary", {}) or {}; score = r.get("risk_score", 0)
        sev = r.get("severity", "unknown"); ioc = r.get("ioc", ""); itype = r.get("type", "")
        note = summ.get("note")
        sources = r.get("sources", {}) or {}
        self._set_status_rows(list(sources.items()) + ([("WHOIS", {"error": r["whois"]["error"]} if r.get("whois", {}).get("error") else {})] if r.get("whois") else []))

        # ── OVERVIEW ───────────────────────────────────────────────────────
        hc, hcl = card("INDICATOR", color=P["accent"])
        top = QHBoxLayout(); top.setSpacing(10)
        top.addWidget(IOCChip(ioc, itype), 1)
        top.addWidget(StatusBadge(_IOC_TYPE_LABEL.get(itype, str(itype).upper() or "IOC"), P["accent"]))
        top.addWidget(badge(sev))
        hcl.addLayout(top)
        hcl.addWidget(RiskMeter(score, f"Risk score · {str(sev).upper()}"))
        self.ol.addWidget(hc)

        if note:
            nc, ncl = card("NOTE", color=P["medium"])
            nl_ = lbl(note, color=P["medium"], size=13); nl_.setWordWrap(True)
            ncl.addWidget(nl_); self.ol.addWidget(nc)

        smc, smcl = card("SUMMARY", color=P["accent"])
        hostnames = ", ".join(summ.get("hostnames", []) or []) or "N/A"
        v = summ.get("verdict", "N/A")
        self._kv_grid(smcl, [
            ("Verdict", v, P["critical"] if v == "malicious" else None),
            ("Country", summ.get("country", "N/A"), None),
            ("ISP", summ.get("isp", "N/A"), None),
            ("Organization", summ.get("org", "N/A"), None),
            ("Resolved domain", summ.get("resolved_domain") or "N/A", None),
            ("Hostnames", hostnames, None),
            ("Tor exit node", "Yes" if summ.get("is_tor") else "No", P["critical"] if summ.get("is_tor") else None),
            ("Abuse score", f"{summ.get('abuse_score', 0)}/100", None),
            ("VirusTotal malicious", f"{summ.get('vt_malicious', 0)} engine(s)", None),
            ("Open ports", ", ".join(str(x) for x in summ.get("open_ports", []) or []) or "None", None),
        ])
        self.ol.addWidget(smc)

        if sources:
            self.ol.addWidget(SectionHeader("Intelligence sources", "Status per source — details in the SOURCES tab"))
            grid = QGridLayout(); grid.setSpacing(16)
            for i, (name, data) in enumerate(sources.items()):
                st, hd, dt, sv = cti_source_view(name, data)
                grid.addWidget(SourceCard(data.get("source", name) if isinstance(data, dict) else name, st, hd, dt, sv),
                               i // 2, i % 2)
            grid.setColumnStretch(0, 1); grid.setColumnStretch(1, 1)
            wrap = QWidget(); wrap.setLayout(grid); wrap.setStyleSheet("background:transparent;")
            self.ol.addWidget(wrap)
        self.ol.addStretch()

        # ── SOURCES ────────────────────────────────────────────────────────
        for name, data in sources.items():
            if name == "abuseipdb":
                title = "AbuseIPDB"
            else:
                title = (data or {}).get("source", name) if isinstance(data, dict) else name
            st, hd, dt, sv = cti_source_view(name, data)
            if st == "ok":
                lines = []
                for k, val in (data or {}).items():
                    if k in ("source", "score", "reports", "services"):
                        continue
                    if isinstance(val, (list, dict)):
                        val = json.dumps(val)
                    lines.append(f"{k}: {str(val)[:120]}")
                dt = "\n".join(lines)
            self.sl.addWidget(SourceCard(title, st, hd, dt, sv))
        svcs = sources.get("shodan", {}).get("services", []) if isinstance(sources.get("shodan"), dict) else []
        if svcs:
            tc, tcl = card("OPEN SERVICES (Shodan)", color=P["accent3"])
            tbl = QTableWidget(len(svcs), 4)
            tbl.setHorizontalHeaderLabels(["Port", "Protocol", "Product", "Banner"])
            tbl.horizontalHeader().setStretchLastSection(True)
            tbl.verticalHeader().setVisible(False); tbl.setMaximumHeight(220)
            tbl.setEditTriggers(QTableWidget.NoEditTriggers)
            for i, s_ in enumerate(svcs):
                tbl.setItem(i, 0, QTableWidgetItem(str(s_.get("port", ""))))
                tbl.setItem(i, 1, QTableWidgetItem(s_.get("transport", "")))
                tbl.setItem(i, 2, QTableWidgetItem(s_.get("product", "")))
                tbl.setItem(i, 3, QTableWidgetItem(s_.get("banner_snippet", "")[:60]))
            tcl.addWidget(tbl); self.sl.addWidget(tc)
        if not sources:
            self.sl.addWidget(AnalysisEmptyState("shield_alert", "No sources returned data",
                              note or "The lookup did not return any intelligence.", kind="error"))
        self.sl.addStretch()

        # ── WHOIS ──────────────────────────────────────────────────────────
        self._out = self.wl
        whois_data = r.get("whois")
        if whois_data:
            self._render_whois_card(whois_data)
        else:
            self.wl.addWidget(AnalysisEmptyState("search", "No WHOIS data",
                              "WHOIS enrichment is only performed for domain lookups."))
        self.wl.addStretch()

        # ── ABUSEIPDB ──────────────────────────────────────────────────────
        self._out = self.al
        if "abuseipdb" in sources:
            self._render_abuseipdb_card(sources["abuseipdb"])
        else:
            self.al.addWidget(AnalysisEmptyState("search", "No AbuseIPDB data",
                              "AbuseIPDB reports are only available for IP address lookups."))
        self.al.addStretch()
        self._out = self.ol

        self.raw.setPlainText(json.dumps(r, indent=2, default=str))

    def _render_whois_card(self, w: dict):
        """Render a styled WHOIS enrichment card into self.ol."""
        if not w:
            return

        err = w.get("error")
        if err:
            ec, ecl = card("WHOIS", color=P["text_dim"])
            ecl.addWidget(lbl(f"⚠ {err}", color=P["text_dim"], size=11))
            self._out.addWidget(ec)
            return

        whois_risk = w.get("whois_risk", "LOW")
        risk_color = {
            "HIGH":   P["critical"],
            "MEDIUM": P["medium"],
            "LOW":    P["low"],
        }.get(whois_risk, P["low"])

        border_color = risk_color
        card_widget = QFrame()
        card_widget.setObjectName("whoiscard")
        card_widget.setStyleSheet(
            f"QFrame#whoiscard{{background:{P['bg_card']};border:1px solid {border_color};"
            f"border-radius:12px;}}"
        )
        cl = QVBoxLayout(card_widget)
        cl.setContentsMargins(14, 12, 14, 12)
        cl.setSpacing(8)

        # ── Header row ────────────────────────────────────────────────────
        hdr_row = QHBoxLayout()
        title_lbl = lbl("WHOIS ENRICHMENT", color=P["accent"], bold=True, size=11)
        hdr_row.addWidget(title_lbl)
        hdr_row.addStretch()
        risk_badge = lbl(f" {whois_risk} RISK ", color=risk_color, bold=True, size=10)
        risk_badge.setStyleSheet(
            f"color:{risk_color};background:{risk_color}22;border:1px solid {risk_color};"
            f"border-radius:4px;padding:2px 8px;font-weight:bold;font-size:10px;"
        )
        hdr_row.addWidget(risk_badge)
        if w.get("cached"):
            cache_lbl = lbl(" CACHED ", color=P["text_dim"], size=9)
            cache_lbl.setStyleSheet(
                f"color:{P['text_dim']};border:1px solid {P['border']};"
                f"border-radius:3px;padding:1px 4px;font-size:9px;"
            )
            hdr_row.addWidget(cache_lbl)
        cl.addLayout(hdr_row)
        cl.addWidget(sep())

        # ── Risk flags (HIGH RISK banner) ─────────────────────────────────
        risk_flags = w.get("risk_flags", [])
        if risk_flags:
            flags_frame = QFrame()
            flags_frame.setStyleSheet(
                f"QFrame{{background:{risk_color}15;border:1px solid {risk_color}44;"
                f"border-radius:4px;padding:4px;}}"
            )
            fl = QVBoxLayout(flags_frame)
            fl.setContentsMargins(8, 6, 8, 6); fl.setSpacing(4)
            for flag in risk_flags:
                fl.addWidget(lbl(flag, color=risk_color, bold=True, size=10))
            cl.addWidget(flags_frame)

        # ── Domain age bar ────────────────────────────────────────────────
        age_days  = w.get("domain_age_days")
        age_label = w.get("domain_age_label", "Unknown")
        if age_days is not None or age_label != "Unknown":
            age_row = QHBoxLayout()
            age_row.addWidget(lbl("Domain Age:", color=P["text_label"], size=11))
            if age_days is not None and age_days < 30:
                display = f"{age_label}  ⚠️ BARU"
                age_col = P["critical"]
            elif age_days is not None and age_days < 365:
                display = age_label
                age_col = P["medium"]
            elif age_days is not None:
                display = age_label
                age_col = P["low"]
            else:
                display = age_label
                age_col = P["text_dim"]
            age_row.addWidget(lbl(display, color=age_col, bold=True, size=11))
            age_row.addStretch()
            cl.addLayout(age_row)

        # ── Data fields ───────────────────────────────────────────────────
        fields = [
            ("Registrar",        w.get("registrar", "N/A")),
            ("Creation Date",    w.get("creation_date", "N/A")),
            ("Expiration Date",  w.get("expiration_date", "N/A")),
            ("Updated Date",     w.get("updated_date", "N/A")),
            ("Country",          w.get("country", "N/A")),
            ("Contact Email",    ", ".join(w.get("emails", [])) or "N/A"),
            ("Name Servers",     "\n".join(w.get("name_servers", [])) or "N/A"),
        ]
        for k, v in fields:
            row = QHBoxLayout()
            row.addWidget(lbl(f"{k}:", color=P["text_label"], size=10))
            val_lbl = lbl(str(v)[:120], color=P["text_main"], size=10)
            val_lbl.setWordWrap(True)
            row.addWidget(val_lbl); row.addStretch()
            cl.addLayout(row)

        # ── Heuristic flags ───────────────────────────────────────────────
        hints = []
        if w.get("suspicious_tld"):
            hints.append(("Suspicious TLD", "⚠️ Ya", P["medium"]))
        if w.get("registrar_low_rep"):
            hints.append(("Low-Rep Registrar", "⚠️ Ya", P["medium"]))
        if w.get("uses_free_hosting"):
            hints.append(("Free Hosting DNS", "⚠️ Ya", P["medium"]))
        if hints:
            cl.addWidget(sep())
            for k, v, c in hints:
                row2 = QHBoxLayout()
                row2.addWidget(lbl(f"{k}:", color=P["text_label"], size=10))
                row2.addWidget(lbl(v, color=c, size=10))
                row2.addStretch(); cl.addLayout(row2)

        self._out.addWidget(card_widget)

    # ─────────────────────────────────────────────────────────────────────────
    #  AbuseIPDB Enterprise Intelligence Card
    # ─────────────────────────────────────────────────────────────────────────
    def _render_abuseipdb_card(self, ab: dict):
        """Render enterprise-grade AbuseIPDB Intelligence card (VirusTotal-style)."""
        if not ab:
            return

        # ── Error state ───────────────────────────────────────────────────
        if "error" in ab:
            ec, ecl = card("ABUSEIPDB", color=P["text_dim"])
            ecl.addWidget(lbl(f"⚠ {ab['error']}", color=P["text_dim"], size=11))
            self._out.addWidget(ec)
            return

        # ── Data extraction ───────────────────────────────────────────────
        score           = ab.get("score", 0)
        total_reports   = ab.get("total_reports", 0)
        distinct_users  = ab.get("num_distinct_users", 0)
        last_reported   = (ab.get("last_reported_at") or "N/A")
        country_code    = ab.get("country_code", "N/A")
        country_name    = ab.get("country_name", "") or ""
        isp             = ab.get("isp", "N/A")
        domain          = ab.get("domain", "N/A")
        usage_type      = ab.get("usage_type", "N/A")
        is_tor          = ab.get("is_tor", False)
        reports         = ab.get("reports", []) or []

        # ── Risk classification ───────────────────────────────────────────
        if score >= 81:
            risk_level, risk_color, risk_bg = "HIGH",   P["critical"],  P["high_bg"]
        elif score >= 51:
            risk_level, risk_color, risk_bg = "MEDIUM", P["medium"],    P["med_bg"]
        elif score >= 21:
            risk_level, risk_color, risk_bg = "LOW",    P["low"],       P["low_bg"]
        else:
            risk_level, risk_color, risk_bg = "INFO",   P["info"],      P["info_bg"]

        # ── Category map ──────────────────────────────────────────────────
        CATEGORY_MAP = {
            1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
            4: "DDoS Attack",    5: "FTP Brute-Force", 6: "Ping of Death",
            7: "Phishing",       8: "Fraud VoIP",    9: "Open Proxy",
            10: "Web Spam",      11: "Email Spam",   12: "Blog Spam",
            13: "VPN IP",        14: "Port Scan",    15: "Hacking",
            16: "SQL Injection", 17: "Spoofing",     18: "Brute-Force",
            19: "Bad Web Bot",   20: "Exploited Host", 21: "Web App Attack",
            22: "SSH",           23: "IoT Targeted",
        }

        # ── Outer card frame ──────────────────────────────────────────────
        outer = QFrame()
        outer.setObjectName("abusecard")
        outer.setStyleSheet(
            f"QFrame#abusecard{{background:{P['bg_card']};border:1px solid {risk_color}66;"
            f"border-radius:12px;}}"
            f"QFrame#abusecard:hover{{border:1px solid {risk_color};}}"
        )
        ol = QVBoxLayout(outer)
        ol.setContentsMargins(18, 14, 18, 16)
        ol.setSpacing(10)

        # ── Header row ────────────────────────────────────────────────────
        hrow = QHBoxLayout()
        accent_bar = QFrame()
        accent_bar.setFixedSize(4, 18)
        accent_bar.setStyleSheet(
            f"background:{risk_color};border-radius:2px;border:none;"
        )
        hrow.addWidget(accent_bar)
        hrow.addSpacing(8)
        title_w = QLabel("ABUSEIPDB INTELLIGENCE")
        title_w.setStyleSheet(
            f"color:{risk_color};font-weight:700;font-size:11px;letter-spacing:1.4px;"
            f"background:transparent;border:none;"
            f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
        )
        hrow.addWidget(title_w)
        hrow.addStretch()
        risk_badge_w = QLabel(f"  ● {risk_level}  ")
        risk_badge_w.setStyleSheet(
            f"color:{risk_color};background:{risk_bg};border:1px solid {risk_color}99;"
            f"border-radius:5px;font-size:10px;font-weight:700;padding:2px 6px;"
            f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
        )
        hrow.addWidget(risk_badge_w)
        ol.addLayout(hrow)

        hdiv = QFrame(); hdiv.setFrameShape(QFrame.HLine)
        hdiv.setFixedHeight(1)
        hdiv.setStyleSheet(f"background:{risk_color}44;border:none;")
        ol.addWidget(hdiv)

        # ── Stats band (Score | Reports | Reporters | Last Seen) ──────────
        stats_frame = QFrame()
        stats_frame.setStyleSheet(
            f"QFrame{{background:{risk_bg};border:1px solid {risk_color}33;"
            f"border-radius:8px;}}"
        )
        sfl = QHBoxLayout(stats_frame)
        sfl.setContentsMargins(12, 12, 12, 12)
        sfl.setSpacing(0)

        def _stat_block(icon_txt, val_txt, sub_txt, val_color):
            w = QWidget(); w.setStyleSheet("background:transparent;")
            bl = QVBoxLayout(w)
            bl.setContentsMargins(0, 0, 0, 0); bl.setSpacing(2)
            bl.setAlignment(Qt.AlignCenter)
            ico = QLabel(icon_txt)
            ico.setAlignment(Qt.AlignCenter)
            ico.setStyleSheet(
                f"font-size:15px;background:transparent;color:{val_color};"
            )
            val = QLabel(str(val_txt))
            val.setAlignment(Qt.AlignCenter)
            val.setStyleSheet(
                f"color:{val_color};font-size:20px;font-weight:700;"
                f"background:transparent;"
                f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
            )
            sub = QLabel(sub_txt)
            sub.setAlignment(Qt.AlignCenter)
            sub.setStyleSheet(
                f"color:{P['text_dim']};font-size:8px;letter-spacing:0.8px;"
                f"background:transparent;"
                f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
            )
            bl.addWidget(ico); bl.addWidget(val); bl.addWidget(sub)
            return w

        def _vdivider():
            d = QFrame(); d.setFrameShape(QFrame.VLine)
            d.setStyleSheet(f"color:{risk_color}33;background:{risk_color}33;")
            d.setFixedWidth(1)
            return d

        last_disp = (last_reported[:10] if last_reported and last_reported != "N/A" else "N/A")
        sfl.addWidget(_stat_block("🔥", f"{score}%",       "ABUSE SCORE",       risk_color))
        sfl.addWidget(_vdivider())
        sfl.addWidget(_stat_block("📢", str(total_reports), "REPORTS",           P["text_bright"]))
        sfl.addWidget(_vdivider())
        sfl.addWidget(_stat_block("👥", str(distinct_users),"DISTINCT REPORTERS",P["text_bright"]))
        sfl.addWidget(_vdivider())
        sfl.addWidget(_stat_block("🕒", last_disp,          "LAST REPORT",       P["accent"]))
        ol.addWidget(stats_frame)

        # Abuse score progress bar
        ol.addWidget(score_bar(score))

        # ── IP Intelligence grid ──────────────────────────────────────────
        def _info_tile(label_txt, val_txt, val_color=None):
            w = QFrame()
            w.setStyleSheet(
                f"QFrame{{background:{P['bg_card2']};border:1px solid {P['border']};"
                f"border-radius:6px;}}"
            )
            il = QVBoxLayout(w)
            il.setContentsMargins(10, 7, 10, 7); il.setSpacing(2)
            lbl_q = QLabel(label_txt)
            lbl_q.setStyleSheet(
                f"color:{P['text_dim']};font-size:8px;letter-spacing:0.8px;"
                f"background:transparent;"
                f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
            )
            val_q = QLabel(str(val_txt)[:36])
            val_q.setStyleSheet(
                f"color:{val_color or P['text_main']};font-size:11px;font-weight:600;"
                f"background:transparent;"
                f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
            )
            il.addWidget(lbl_q); il.addWidget(val_q)
            return w

        country_disp = f"{country_code} — {country_name}" if country_name else country_code
        grid_row1 = QHBoxLayout(); grid_row1.setSpacing(8)
        grid_row1.addWidget(_info_tile("🌍  COUNTRY",    country_disp[:36]))
        grid_row1.addWidget(_info_tile("🏢  ISP",         isp[:36]))
        grid_row2 = QHBoxLayout(); grid_row2.setSpacing(8)
        grid_row2.addWidget(_info_tile("🌐  DOMAIN",      domain[:36]))
        grid_row2.addWidget(_info_tile("⚙  USAGE TYPE",  usage_type[:36]))
        ol.addLayout(grid_row1)
        ol.addLayout(grid_row2)

        # ── TOR warning ───────────────────────────────────────────────────
        if is_tor:
            tor_row = QHBoxLayout()
            tor_badge = QLabel("  🧅  TOR EXIT NODE DETECTED — HIGH ANONYMITY RISK  ")
            tor_badge.setStyleSheet(
                f"color:#ff4d4f;background:#3b0d11;border:1px solid #ff4d4f;"
                f"border-radius:5px;font-size:10px;font-weight:700;padding:3px 10px;"
                f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
            )
            tor_row.addWidget(tor_badge); tor_row.addStretch()
            ol.addLayout(tor_row)

        # ── Attack category tags ──────────────────────────────────────────
        all_cats: dict = {}
        for rpt in reports:
            for cat_id in (rpt.get("categories") or []):
                all_cats[cat_id] = all_cats.get(cat_id, 0) + 1
        if all_cats:
            cat_div = QFrame(); cat_div.setFrameShape(QFrame.HLine)
            cat_div.setFixedHeight(1)
            cat_div.setStyleSheet(f"background:{P['border']};border:none;")
            ol.addWidget(cat_div)

            cat_hdr = QHBoxLayout()
            cat_hdr.addWidget(
                lbl("⚔  OBSERVED ATTACK CATEGORIES", color=P["text_label"], bold=True, size=10)
            )
            cat_hdr.addStretch()
            ol.addLayout(cat_hdr)

            TAG_COLORS = [
                "#00d4ff", "#7c3aed", "#f59e0b", "#ff4d4f", "#10b981",
                "#f97316", "#38bdf8", "#a78bfa", "#34d399", "#fb923c",
            ]
            tags_row = QHBoxLayout()
            tags_row.setSpacing(6)
            tags_row.setContentsMargins(0, 0, 0, 0)
            sorted_cats = sorted(all_cats.items(), key=lambda x: -x[1])
            for i, (cat_id, _count) in enumerate(sorted_cats[:10]):
                cat_name = CATEGORY_MAP.get(cat_id, f"Cat-{cat_id}")
                tc = TAG_COLORS[i % len(TAG_COLORS)]
                tag = QLabel(f"  {cat_name}  ")
                tag.setStyleSheet(
                    f"color:{tc};background:{tc}1A;border:1px solid {tc}66;"
                    f"border-radius:4px;font-size:9px;font-weight:600;padding:2px 4px;"
                    f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
                )
                tags_row.addWidget(tag)
            tags_row.addStretch()
            ol.addLayout(tags_row)

        # ── Last Reports — card-scroll mode ──────────────────────────────────
        rep_div = QFrame(); rep_div.setFrameShape(QFrame.HLine)
        rep_div.setFixedHeight(1)
        rep_div.setStyleSheet(f"background:{P['border']};border:none;")
        ol.addWidget(rep_div)

        rep_hdr_row = QHBoxLayout()
        rep_hdr_row.addWidget(
            lbl("🚨  LAST REPORTS", color=P["medium"], bold=True, size=10)
        )
        loaded_badge = QLabel(
            f"  {min(len(reports), 10)} / {total_reports}  " if reports else "  0  "
        )
        loaded_badge.setStyleSheet(
            f"color:{P['text_dim']};background:{P['bg_input']};"
            f"border:1px solid {P['border']};border-radius:3px;"
            f"font-size:9px;padding:1px 5px;"
            f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
        )
        rep_hdr_row.addWidget(loaded_badge)
        rep_hdr_row.addStretch()
        ol.addLayout(rep_hdr_row)

        # Per-category severity colour map (for badge & left-border tinting)
        _CAT_COLORS = {
            4:  P["critical"],  # DDoS Attack
            15: P["critical"],  # Hacking
            16: P["critical"],  # SQL Injection
            20: P["critical"],  # Exploited Host
            21: P["critical"],  # Web App Attack
            5:  P["medium"],    # FTP Brute-Force
            18: P["medium"],    # Brute-Force
            22: P["medium"],    # SSH
            14: P["accent4"],   # Port Scan
            6:  P["accent4"],   # Ping of Death
            23: P["accent4"],   # IoT Targeted
            7:  P["accent2"],   # Phishing
            9:  P["accent2"],   # Open Proxy
            11: P["accent2"],   # Email Spam
            10: P["accent2"],   # Web Spam
            19: P["accent2"],   # Bad Web Bot
            3:  P["accent3"],   # Fraud Orders
            8:  P["accent3"],   # Fraud VoIP
        }

        # ── Empty state ───────────────────────────────────────────────────
        if not reports:
            empty_f = QFrame()
            empty_f.setStyleSheet(
                f"QFrame{{background:{P['bg_card2']};border:1px dashed {P['border2']};"
                f"border-radius:8px;}}"
            )
            empty_l = QVBoxLayout(empty_f)
            empty_l.setContentsMargins(16, 22, 16, 22)
            no_rpt = QLabel("No recent abuse reports found in the last 90 days.")
            no_rpt.setAlignment(Qt.AlignCenter)
            no_rpt.setStyleSheet(
                f"color:{P['text_dim']};font-size:12px;background:transparent;"
                f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
            )
            empty_l.addWidget(no_rpt)
            ol.addWidget(empty_f)
        else:
            # ── Scroll area ───────────────────────────────────────────────
            rep_sa = QScrollArea()
            rep_sa.setWidgetResizable(True)
            rep_sa.setFrameShape(QFrame.NoFrame)
            rep_sa.setMinimumHeight(320)
            rep_sa.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            rep_sa.setStyleSheet(
                f"QScrollArea{{background:{P['bg_card2']};"
                f"border:1px solid {P['border']};border-radius:8px;}}"
                # slim neon scrollbar
                f"QScrollBar:vertical{{background:{P['bg_panel']};width:6px;"
                f"border-radius:3px;margin:2px 0 2px 0;}}"
                f"QScrollBar::handle:vertical{{background:{risk_color}66;"
                f"border-radius:3px;min-height:24px;}}"
                f"QScrollBar::handle:vertical:hover{{background:{risk_color}CC;}}"
                f"QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical"
                f"{{height:0px;background:none;}}"
                f"QScrollBar::add-page:vertical,QScrollBar::sub-page:vertical"
                f"{{background:none;}}"
                f"QScrollBar:horizontal{{background:{P['bg_panel']};height:6px;"
                f"border-radius:3px;margin:0 2px 0 2px;}}"
                f"QScrollBar::handle:horizontal{{background:{risk_color}66;"
                f"border-radius:3px;min-width:24px;}}"
                f"QScrollBar::handle:horizontal:hover{{background:{risk_color}CC;}}"
                f"QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal"
                f"{{width:0px;background:none;}}"
            )

            rep_inner = QWidget()
            rep_inner.setStyleSheet(f"background:{P['bg_card2']};")
            rep_lay = QVBoxLayout(rep_inner)
            rep_lay.setContentsMargins(8, 8, 8, 8)
            rep_lay.setSpacing(6)

            def _make_report_card(rpt, idx):
                """Build a single styled report card — full word-wrap, selectable."""
                ts_raw  = (rpt.get("reportedAt") or "")
                ts_disp = ts_raw[:16].replace("T", " ") + " UTC" if ts_raw else "—"
                cats    = rpt.get("categories") or []
                comment = (rpt.get("comment") or "").strip() or "No comment provided."
                rep_cc  = rpt.get("reporterCountryCode", "")

                # Derive left-border accent from highest-severity category
                sev_color = P["border2"]
                for _cid in cats:
                    _c = _CAT_COLORS.get(_cid)
                    if _c == P["critical"]:
                        sev_color = P["critical"]; break
                    if _c == P["medium"] and sev_color not in (P["critical"],):
                        sev_color = P["medium"]
                    elif _c and sev_color == P["border2"]:
                        sev_color = _c

                bg_c = P["bg_card"] if idx % 2 == 0 else P["bg_card2"]
                rc = QFrame()
                rc.setStyleSheet(
                    f"QFrame{{background:{bg_c};"
                    f"border:1px solid {sev_color}2E;"
                    f"border-left:3px solid {sev_color};"
                    f"border-radius:6px;}}"
                    f"QFrame:hover{{background:{sev_color}0D;"
                    f"border:1px solid {sev_color}66;"
                    f"border-left:3px solid {sev_color};}}"
                )
                rl = QVBoxLayout(rc)
                rl.setContentsMargins(12, 9, 12, 9)
                rl.setSpacing(5)

                # ── Row 1: index · timestamp · reporter CC ────────────────
                top = QHBoxLayout()
                num = QLabel(f"#{idx+1:02d}")
                num.setFixedWidth(30)
                num.setStyleSheet(
                    f"color:{P['text_dim']};background:{P['bg_input']};"
                    f"border:1px solid {P['border']};border-radius:3px;"
                    f"font-size:9px;font-weight:600;padding:1px 4px;"
                    f"font-family:'Courier New',monospace;"
                )
                ts_w = QLabel(ts_disp)
                ts_w.setStyleSheet(
                    f"color:{P['text_dim']};font-size:10px;background:transparent;"
                    f"font-family:'Courier New','Consolas','JetBrains Mono',monospace;"
                )
                top.addWidget(num); top.addSpacing(6); top.addWidget(ts_w)
                top.addStretch()
                if rep_cc:
                    cc_w = QLabel(f"🌐 {rep_cc}")
                    cc_w.setStyleSheet(
                        f"color:{P['text_dim']};font-size:9px;background:transparent;"
                        f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
                    )
                    top.addWidget(cc_w)
                rl.addLayout(top)

                # ── Row 2: category badges ────────────────────────────────
                if cats:
                    badges = QHBoxLayout()
                    badges.setSpacing(5)
                    badges.setContentsMargins(0, 0, 0, 0)
                    for cid in cats:
                        cname = CATEGORY_MAP.get(cid, f"Cat-{cid}")
                        tc    = _CAT_COLORS.get(cid, P["accent"])
                        b     = QLabel(f"  {cname}  ")
                        b.setStyleSheet(
                            f"color:{tc};background:{tc}1E;"
                            f"border:1px solid {tc}66;border-radius:4px;"
                            f"font-size:9px;font-weight:700;padding:1px 3px;"
                            f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
                        )
                        badges.addWidget(b)
                    badges.addStretch()
                    rl.addLayout(badges)

                # ── Row 3: full comment, word-wrap, text-selectable ───────
                cmt = QLabel(comment)
                cmt.setWordWrap(True)
                cmt.setTextInteractionFlags(Qt.TextSelectableByMouse)
                cmt.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
                cmt.setStyleSheet(
                    f"color:{P['text_main']};font-size:12px;background:transparent;"
                    f"padding-top:2px;"
                    f"font-family:'Segoe UI','Inter',Arial,sans-serif;"
                )
                rl.addWidget(cmt)
                return rc

            # Initial batch
            BATCH = 10
            for _i in range(min(BATCH, len(reports))):
                rep_lay.addWidget(_make_report_card(reports[_i], _i))

            # Load More
            if len(reports) > BATCH:
                _lm_state = {"offset": BATCH}

                load_btn = QPushButton(
                    f"↓  Load More  ({len(reports) - BATCH} remaining)"
                )
                load_btn.setStyleSheet(
                    f"QPushButton{{background:transparent;color:{risk_color};"
                    f"border:1px solid {risk_color}55;border-radius:6px;"
                    f"font-size:10px;font-weight:600;padding:7px 14px;margin-top:4px;"
                    f"font-family:'Segoe UI','Inter',Arial,sans-serif;}}"
                    f"QPushButton:hover{{background:{risk_color}15;"
                    f"border:1px solid {risk_color};}}"
                    f"QPushButton:pressed{{background:{risk_color}30;}}"
                )

                def _on_load_more():
                    off = _lm_state["offset"]
                    nxt = min(off + BATCH, len(reports))
                    btn_pos = rep_lay.indexOf(load_btn)
                    for j in range(off, nxt):
                        rep_lay.insertWidget(btn_pos + (j - off),
                                             _make_report_card(reports[j], j))
                    _lm_state["offset"] = nxt
                    remaining = len(reports) - nxt
                    if remaining <= 0:
                        load_btn.setVisible(False)
                    else:
                        load_btn.setText(f"↓  Load More  ({remaining} remaining)")
                    loaded_badge.setText(f"  {nxt} / {total_reports}  ")

                load_btn.clicked.connect(_on_load_more)
                rep_lay.addWidget(load_btn)

            rep_sa.setWidget(rep_inner)
            ol.addWidget(rep_sa)

        self._out.addWidget(outer)

    def _ai_summary(self, r):
        run_ai_summary(self, lambda: generate_ai_summary(r, mode="cti"), "CTI", target=r)

    def _export_pdf(self):
        self._pdf_worker = _trigger_pdf_export(self, "cti", self._last_result)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 12 — MALWARE ANALYSIS PAGE
# ══════════════════════════════════════════════════════════════════════════════

def _fmt_size(n: int) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


def _hash_kind(h: str) -> str:
    h = (h or "").strip()
    return {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(h), "HASH") if re.fullmatch(r"[0-9a-fA-F]+", h or "") else "HASH"


class FileHashWorker(QThread):
    """SHA256 of the selected sample, off the UI thread (read-only, chunked)."""
    done = pyqtSignal(str, str)          # (path, sha256 or "")

    def __init__(self, path: str):
        super().__init__()
        self._path = path

    def run(self):
        try:
            import hashlib
            h = hashlib.sha256()
            with open(self._path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    if self.isInterruptionRequested():
                        return
                    h.update(chunk)
            self.done.emit(self._path, h.hexdigest())
        except Exception:
            self.done.emit(self._path, "")


def malware_sources(r: dict) -> dict:
    """Describe — truthfully — where each part of a malware result came from.
    Never reports a sandbox/Hybrid success that did not happen."""
    r = r or {}
    rep = r.get("report") or {}
    enr = r.get("enrichment") or {}
    local = bool(rep.get("local_analysis") or r.get("local_analysis"))
    if enr:
        st = enr.get("status")
        if st == "found":
            hyb = ("ok", "Report found", "Verdict and score come from the existing Hybrid Analysis report.")
        elif st == "no_api_key":
            hyb = ("off", "Not configured",
                   "No Hybrid Analysis API key is set, so no request was sent. Local static analysis was used.")
        elif st == "not_found":
            hyb = ("warn", "No existing report",
                   "Hybrid Analysis has no report for this hash. A local fallback was used instead; "
                   "no sandbox detonation took place.")
        else:
            hyb = ("error", f"Unavailable ({st or 'error'})",
                   str(enr.get("error") or "Hybrid Analysis could not be reached. Local fallback was used."))
    elif rep.get("submitted"):
        hyb = ("ok", "URL submitted", "Submission accepted by Hybrid Analysis; results may take time.")
    elif rep.get("error_code") == "no_api_key":
        hyb = ("off", "Not configured", "No Hybrid Analysis API key is set, so no request was sent.")
    elif rep.get("error"):
        hyb = ("error", "Lookup failed", str(rep.get("error")))
    elif rep.get("found"):
        hyb = ("ok", "Report found", "Verdict and score come from Hybrid Analysis.")
    elif rep.get("message"):
        hyb = ("warn", "No result", str(rep.get("message")))
    else:
        hyb = ("pending", "Not queried", "")
    if local:
        loc = ("ok", "Completed",
               f"{rep.get('analysis_source') or 'Local Static Heuristics'} — static analysis only, "
               "no sandbox execution.")
    elif r.get("strings") or r.get("yara"):
        loc = ("off", "Static extraction only",
               "Strings/YARA extracted locally. Behavioral analysis was not needed because a "
               "Hybrid Analysis report was available.")
    else:
        loc = ("off", "Not applicable", "Local analysis runs for uploaded files only.")
    hyb_ok = hyb[0] == "ok"
    if local and hyb_ok:
        badge_txt = "CORRELATED ANALYSIS"
    elif local:
        badge_txt = "LOCAL ANALYSIS"
    elif hyb_ok:
        badge_txt = "HYBRID ANALYSIS ENRICHMENT"
    else:
        badge_txt = ""
    return {"local": loc, "hybrid": hyb, "badge": badge_txt}


class MalwarePage(QWidget):
    context_ready = pyqtSignal(str, object)   # (module_name, context_dict)

    def __init__(self):
        super().__init__()
        self._file = None
        self._file_sha = ""
        self._hash_worker = None
        root = QHBoxLayout(self); root.setContentsMargins(0, 0, 0, 0)
        sp = QSplitter(Qt.Horizontal); sp.setChildrenCollapsible(False); root.addWidget(sp)

        # ── LEFT — analysis input (≈30%) ───────────────────────────────────
        lsa = QScrollArea(); lsa.setWidgetResizable(True); lsa.setFrameShape(QFrame.NoFrame)
        lsa.setMinimumWidth(300); lsa.setMaximumWidth(420)
        lsa.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)   # input panel must fit, never side-scroll
        lw = QWidget(); lw.setStyleSheet("background:transparent;")
        lsa.setWidget(lw)
        ll = QVBoxLayout(lw); ll.setContentsMargins(24, 24, 16, 24); ll.setSpacing(16)
        ttl = QLabel("MALWARE ANALYSIS")
        ttl.setWordWrap(True)
        ttl.setStyleSheet(f"color:{P['text_main']};font-size:22px;font-weight:700;background:transparent;")
        stl = QLabel("Static Analysis & Threat Intelligence")
        stl.setStyleSheet(f"color:{P['text_label']};font-size:13px;background:transparent;")
        ll.addWidget(ttl); ll.addWidget(stl)

        fc, fcl = card("FILE ANALYSIS", color=P["accent"])
        self.btn_file = ModernButton("Upload Sample", "secondary", icon="upload",
                                     tooltip="Choose a file to analyze (static analysis)")
        self.btn_file.clicked.connect(self._pick)
        fcl.addWidget(self.btn_file)
        self.lbl_file = lbl("No file selected", color=P["text_dim"], size=12)
        self.lbl_file.setWordWrap(True); fcl.addWidget(self.lbl_file)
        self._file_info = {}
        info_w = QWidget(); info_l = QGridLayout(info_w)
        info_l.setContentsMargins(0, 0, 0, 0); info_l.setHorizontalSpacing(12); info_l.setVerticalSpacing(6)
        for i, key in enumerate(("File name", "Size", "Extension", "SHA256")):
            k = lbl(key, color=P["text_dim"], size=11)
            v = QLabel("—"); v.setWordWrap(False)
            v.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
            mono = key == "SHA256"
            v.setStyleSheet(f"color:{P['text_main']};font-size:12px;background:transparent;"
                            + (f"font-family:{_FONT_MONO};" if mono else ""))
            info_l.addWidget(k, i, 0); info_l.addWidget(v, i, 1)
            self._file_info[key] = v
        info_l.setColumnStretch(1, 1)
        fcl.addWidget(info_w)
        fmts = " ".join(sorted(ALLOWED_MALWARE_EXTENSIONS))
        self._fmt_lbl = lbl(f"Supported: {fmts}", color=P["text_dim"], size=11)
        self._fmt_lbl.setWordWrap(True); fcl.addWidget(self._fmt_lbl)
        ll.addWidget(fc)

        ic, icl = card("HASH / URL LOOKUP", color=P["accent2"])
        icl.addWidget(lbl("SHA256 / MD5 / SHA1 / URL", color=P["text_label"], size=12))
        self.inp = QLineEdit(); self.inp.setPlaceholderText("Enter IOC or URL")
        self.inp.returnPressed.connect(self._run)
        icl.addWidget(self.inp)
        ll.addWidget(ic)

        self.btn_go = ModernButton("ANALYZE", "primary", icon="send", tooltip="Run analysis (Enter)")
        self.btn_go.setMinimumHeight(40)
        self.btn_go.clicked.connect(self._run)
        ll.addWidget(self.btn_go)
        self.prog = QProgressBar(); self.prog.setRange(0, 0); self.prog.setVisible(False)
        self.prog.setFixedHeight(4); self.prog.setTextVisible(False)
        ll.addWidget(self.prog)
        self._loading = LoadingIndicator("Analyzing…")
        ll.addWidget(self._loading)
        self._btn_export_m = ModernButton("Export Report (PDF)", "secondary", icon="pdf",
                                          tooltip="Export the current analysis as a PDF report")
        self._btn_export_m.setEnabled(False)
        self._btn_export_m.clicked.connect(self._export_pdf)
        ll.addWidget(self._btn_export_m)
        self._last_result = None
        self._pdf_worker = None
        ll.addStretch()
        sp.addWidget(lsa)

        # ── RIGHT — analysis workspace (≈70%) ──────────────────────────────
        rw = QWidget(); rl = QVBoxLayout(rw); rl.setContentsMargins(8, 24, 24, 16)
        self.tabs = tabs = QTabWidget(); rl.addWidget(tabs)
        self.sa_v, _, self.vl = scroll_page(); tabs.addTab(self.sa_v, "OVERVIEW")
        self.str_view = QTextEdit(); self.str_view.setReadOnly(True)
        self.str_view.setPlaceholderText("Extracted strings appear here after analyzing an uploaded file.")
        self.str_view.setStyleSheet(
            f"background:{P['bg_dark']};font-size:12px;font-family:{_FONT_MONO};")
        tabs.addTab(self.str_view, "STRINGS")
        self.sa_y, _, self.yl = scroll_page(); tabs.addTab(self.sa_y, "YARA")
        self.sa_n, _, self.nl = scroll_page(); tabs.addTab(self.sa_n, "NETWORK")
        self.sa_b, _, self.bl = scroll_page(); tabs.addTab(self.sa_b, "BEHAVIOR")
        self.ai = ai_browser(); tabs.addTab(self.ai, "AI SUMMARY")
        self.ai.setPlaceholderText("The AI summary is generated after an analysis completes.")
        sp.addWidget(rw)
        sp.setStretchFactor(0, 3); sp.setStretchFactor(1, 7); sp.setSizes([320, 800])
        self._show_empty_states()

    # ── states ─────────────────────────────────────────────────────────────
    def _reflow_sources(self):
        row = getattr(self, "_src_row", None)
        if row is None:
            return
        want = QBoxLayout.LeftToRight if self.sa_v.viewport().width() >= 620 else QBoxLayout.TopToBottom
        try:
            if row.direction() != want:
                row.setDirection(want)
        except RuntimeError:
            self._src_row = None

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._reflow_sources()

    def _show_empty_states(self):
        self._src_row = None
        for layout in (self.vl, self.yl, self.nl, self.bl):
            clear_layout(layout)
        self.vl.addWidget(AnalysisEmptyState(
            "malware", "Ready for Malware Investigation",
            "Upload a sample or enter a file hash to begin analysis.\n\n"
            "Local behavioral analysis and available threat intelligence will be used "
            "to enrich the investigation."))
        self.vl.addStretch()
        for layout, title in ((self.yl, "No YARA results yet"), (self.nl, "No network indicators yet"),
                               (self.bl, "No behavioral findings yet")):
            layout.addWidget(AnalysisEmptyState("search", title, "Run an analysis to populate this tab."))
            layout.addStretch()

    def _set_busy(self, busy: bool):
        self.btn_go.set_loading(busy, "Analyzing…")
        self.btn_file.setEnabled(not busy)
        self.prog.setVisible(busy)
        if busy:
            self._loading.start("Analyzing sample — this can take a moment…")
        else:
            self._loading.stop()

    def _show_error(self, msg: str):
        clear_layout(self.vl)
        self.vl.addWidget(AnalysisEmptyState("shield_alert", "Analysis failed", str(msg), kind="error"))
        self.vl.addStretch()
        self.tabs.setCurrentIndex(0)

    # ── input ──────────────────────────────────────────────────────────────
    def _pick(self):
        filt = "Malware Files (*.exe *.dll *.pdf *.doc *.ps1 *.cmd *.txt *.com *.bat);;All Files (*)"
        path, _ = QFileDialog.getOpenFileName(self, "Select File", "", filt)
        if path:
            ext = os.path.splitext(path)[1].lower()
            if ext not in ALLOWED_MALWARE_EXTENSIONS:
                QMessageBox.warning(self, "Unsupported", f"Unsupported file type: {ext}")
                self._file = None
                self.lbl_file.setText("No file selected")
                self._reset_file_info()
                return
            self._file = path
            self.lbl_file.setText(f"Selected: {os.path.basename(path)}")
            self._update_file_info(path)

    def _reset_file_info(self):
        for v in self._file_info.values():
            v.setText("—"); v.setToolTip("")

    def _update_file_info(self, path: str):
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        vals = {"File name": os.path.basename(path), "Size": _fmt_size(size),
                "Extension": os.path.splitext(path)[1].lower() or "—", "SHA256": "calculating…"}
        for k, v in vals.items():
            self._file_info[k].setText(v); self._file_info[k].setToolTip(v)
        if is_busy(self._hash_worker):
            self._hash_worker.requestInterruption()
        self._hash_worker = FileHashWorker(path)
        self._hash_worker.done.connect(self._on_hash_done)
        self._hash_worker.start()

    def _on_hash_done(self, path: str, sha: str):
        if path != self._file:
            return                                   # stale result from a previous selection
        self._file_sha = sha
        v = self._file_info["SHA256"]
        v.setText(sha or "unavailable"); v.setToolTip(sha)

    def _run(self):
        h = self.inp.text().strip()
        if not h and not self._file:
            return QMessageBox.warning(self, "Input", "Enter a hash/URL or upload a file.")
        if self._file:
            ext = os.path.splitext(self._file)[1].lower()
            if ext not in ALLOWED_MALWARE_EXTENSIONS:
                return QMessageBox.warning(self, "Unsupported", f"Unsupported file type: {ext}")
        if is_busy(getattr(self, "worker", None)):
            log_event("MalwarePage._run ignored: analysis already running")
            return
        self._set_busy(True)
        self.worker = Worker(analyze_malware, h, self._file)
        self.worker.done.connect(self._on_done)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _on_error(self, e):
        self._set_busy(False)
        self._show_error(e)
        QMessageBox.critical(self, "Error", e)

    def _on_done(self, r):
        self._set_busy(False)
        self._last_result = r
        self._display(r); self._ai_summary(r)
        # Save to SQLite
        try:
            sev_val  = r.get("severity", "info")
            _rep = r.get("report", {}) or {}
            ioc_val  = _rep.get("submit_name", "") or r.get("hash", "") or _rep.get("sha256", "") or r.get("input", "")
            summ_val = f"Malware: verdict={r.get('verdict','unknown')} score={r.get('threat_score',0)}"
            save_to_db("malware", sev_val, ioc_val, summ_val, r)
        except Exception as e:
            log_event(f"Malware save_to_db error: {e}")
        # Emit context for chatbot
        try:
            rep = r.get("report", {})
            ctx = {
                "module": "malware",
                "verdict": r.get("verdict", "unknown"),
                "threat_score": r.get("threat_score", 0),
                "severity": r.get("severity", "unknown"),
                "findings": [
                    f"{f.get('technique','')} [{f.get('severity','')}]: {f.get('evidence','')[:80]}"
                    for f in rep.get("findings", [])[:10]
                ],
                "signatures": [s.get("name","") for s in rep.get("signatures", [])[:10]],
                "mitre_attcks": rep.get("mitre_attcks", []),
                "classification": rep.get("classification", ""),
                "classification_tags": rep.get("classification_tags", [])[:10],
                "iocs": list(r.get("strings", {}).get("suspicious", {}).get("urls", []))[:10],
                "network_connections": rep.get("network_connections", {}),
                "yara_matches": [m.get("rule","") for m in r.get("yara", {}).get("matches", [])],
                "statistics": {"threat_score": r.get("threat_score", 0)},
                "analysis_result": {
                    "verdict": r.get("verdict"),
                    "submit_name": rep.get("submit_name", "N/A"),
                    "analysis_summary": rep.get("analysis_summary", ""),
                },
            }
            self.context_ready.emit("malware", ctx)
        except Exception as e:
            log_event(f"Chatbot Malware context injection error: {e}")
            import traceback; log_event(traceback.format_exc())

    def _kv(self, layout, key, value, mono=False):
        rw_ = QHBoxLayout(); rw_.setSpacing(12)
        k = lbl(f"{key}", color=P["text_dim"], size=12); k.setFixedWidth(120)
        rw_.addWidget(k, 0, Qt.AlignTop)
        if mono and value not in ("", "N/A", None):
            rw_.addWidget(IOCChip(str(value), key), 1)
        else:
            v = lbl(str(value if value not in ("", None) else "N/A"), size=13)
            v.setWordWrap(True); v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            rw_.addWidget(v, 1)
        layout.addLayout(rw_)

    def _display(self, r):
        self._src_row = None
        for layout in (self.vl, self.yl, self.nl, self.bl):
            clear_layout(layout)
        self._btn_export_m.setEnabled(bool(r))

        rep = r.get("report", {}) or {}
        score = _safe_score(r.get("threat_score"))
        sev = r.get("severity", "unknown")
        verdict = r.get("verdict") or "unknown"
        src = malware_sources(r)

        # ── OVERVIEW ───────────────────────────────────────────────────────
        hc, hcl = card("VERDICT", color=P["accent"])
        col = (P["critical"] if verdict == "malicious"
               else P["medium"] if verdict in ("test_signature", "suspicious") else P["low"])
        _vtxt = "EICAR TEST SIGNATURE (not real malware)" if verdict == "test_signature" else verdict.upper()
        top = QHBoxLayout(); top.setSpacing(12)
        vl_ = QLabel(_vtxt); vl_.setWordWrap(True)
        vl_.setStyleSheet(f"color:{col};font-size:22px;font-weight:700;background:transparent;border:none;")
        top.addWidget(vl_, 1)
        top.addWidget(badge(sev), 0, Qt.AlignVCenter)
        hcl.addLayout(top)
        if src["badge"]:
            chips = QHBoxLayout(); chips.setSpacing(8)
            chips.addWidget(StatusBadge(src["badge"], P["accent"]))
            chips.addStretch(); hcl.addLayout(chips)
        hcl.addWidget(RiskMeter(score, f"Threat score · {str(sev).upper()}"))
        self.vl.addWidget(hc)

        if rep.get("error"):
            self.vl.addWidget(AnalysisEmptyState("shield_alert", "Report error", str(rep.get("error")), kind="error"))
        if rep.get("message") and not rep.get("found"):
            mc, mcl = card("REPORT STATUS", color=P["info"])
            mcl.addWidget(lbl(str(rep.get("message")), color=P["text_label"], size=13)); self.vl.addWidget(mc)

        sc_, scl_ = card("SAMPLE", color=P["accent"])
        h_val = rep.get("sha256") or r.get("hash") or ""
        self._kv(scl_, _hash_kind(h_val), h_val, mono=True)
        self._kv(scl_, "Sample", rep.get("submit_name") or r.get("input") or "N/A")
        self._kv(scl_, "Analysis source", rep.get("analysis_source") or src["badge"].title() or "N/A")
        if rep.get("found") or rep.get("submitted"):
            self._kv(scl_, "Environment", rep.get("environment", "N/A"))
            self._kv(scl_, "Analysis time", rep.get("analysis_start_time", "N/A"))
        self.vl.addWidget(sc_)

        srow = QBoxLayout(QBoxLayout.LeftToRight); srow.setSpacing(16)
        self._src_row = srow
        lc = SourceCard("Local Analysis", src["local"][0], src["local"][1], src["local"][2])
        hcard = SourceCard("Hybrid Analysis", src["hybrid"][0], src["hybrid"][1], src["hybrid"][2])
        srow.addWidget(lc, 1); srow.addWidget(hcard, 1)
        self.vl.addLayout(srow)
        self._reflow_sources()

        if rep.get("is_test_artifact"):
            tc, tcl = card("TEST ARTIFACT", color=P["medium"])
            tcl.addWidget(lbl(f"{rep.get('detection_name','Test signature')} — {rep.get('evidence','')}",
                              color=P["text_main"], size=13))
            self.vl.addWidget(tc)
        if rep.get("analysis_summary") or rep.get("classification") or rep.get("detected") is not None:
            ac, acl = card("ANALYSIS SUMMARY", color=P["accent3"])
            if rep.get("analysis_summary"):
                t = lbl(str(rep.get("analysis_summary")), color=P["text_main"], size=13); t.setWordWrap(True); acl.addWidget(t)
            if rep.get("classification"):
                self._kv(acl, "Classification", rep.get("classification"))
            if rep.get("detected") is not None:
                self._kv(acl, "Detected", rep.get("detected"))
            self.vl.addWidget(ac)
        if rep.get("note"):
            nc, ncl = card("NOTE", color=P["info"])
            n_ = lbl(str(rep.get("note")), color=P["text_label"], size=13); n_.setWordWrap(True)
            ncl.addWidget(n_); self.vl.addWidget(nc)
        self.vl.addStretch()

        # ── STRINGS ────────────────────────────────────────────────────────
        sd = r.get("strings", {}) or {}; susp = sd.get("suspicious", {}) or {}
        txt = ""
        if sd:
            txt = f"=== SUSPICIOUS ({len(susp)} categories) ===\n\n"
            for cat, matches in susp.items():
                txt += f"[{cat.upper()}]\n" + "\n".join(f"  {m}" for m in matches[:10]) + "\n\n"
            txt += f"\n=== ALL STRINGS ({sd.get('total_strings',0)} total) ===\n\n"
            txt += "\n".join(sd.get("strings", [])[:200])
        self.str_view.setPlainText(txt or "No string data — upload a file for extraction.")

        # ── YARA ───────────────────────────────────────────────────────────
        yd = r.get("yara", {}) or {}; matches = yd.get("matches", []); risk = yd.get("risk", "clean")
        yh = QHBoxLayout()
        yt = QLabel(f"{len(matches)} rule(s) matched")
        yt.setStyleSheet(f"color:{P['text_main']};font-size:16px;font-weight:600;background:transparent;")
        yh.addWidget(yt); yh.addStretch(); yh.addWidget(badge(risk)); self.yl.addLayout(yh)
        for m in matches:
            yc, ycl = card()
            rwy = QHBoxLayout()
            rn = QLabel(m.get("rule", ""))
            rn.setStyleSheet(f"color:{P['accent']};font-size:13px;font-weight:600;font-family:{_FONT_MONO};background:transparent;border:none;")
            rwy.addWidget(rn); rwy.addStretch(); rwy.addWidget(badge(m.get("severity", "info"))); ycl.addLayout(rwy)
            d_ = lbl(m.get("description", ""), color=P["text_label"], size=13); d_.setWordWrap(True); ycl.addWidget(d_)
            self.yl.addWidget(yc)
        if not matches:
            self.yl.addWidget(AnalysisEmptyState("search", "No YARA matches",
                              "Upload a file to scan." if not sd else "No rule matched this sample."))
        if yd.get("note"):
            n_ = lbl(yd.get("note", ""), color=P["text_dim"], size=12); n_.setWordWrap(True); self.yl.addWidget(n_)
        self.yl.addStretch()

        # ── NETWORK ────────────────────────────────────────────────────────
        net = rep.get("network_connections", {}) or {}
        any_net = False
        for section, items in net.items():
            nc, ncl = card(section.replace("_", " ").upper(), color=P["accent"])
            for item in (items or []):
                ncl.addWidget(IOCChip(str(item), section)); any_net = True
            if not items:
                ncl.addWidget(lbl("None", color=P["text_dim"], size=13))
            self.nl.addWidget(nc)
        if not net:
            self.nl.addWidget(AnalysisEmptyState("cti", "No network indicators",
                              "No URLs, IPs or domains were extracted for this sample."))
        self.nl.addStretch()

        # ── BEHAVIOR ───────────────────────────────────────────────────────
        any_b = False
        findings = rep.get("findings", []) or []
        if findings:
            any_b = True
            fc, fcl = card(f"LOCAL FINDINGS ({len(findings)})", color=P["accent2"])
            for f in findings[:20]:
                row = QHBoxLayout(); row.setSpacing(10)
                row.addWidget(badge(f.get("severity", "LOW")), 0, Qt.AlignTop)
                col_ = QVBoxLayout(); col_.setSpacing(2)
                tl = lbl(f.get("technique", ""), size=13, bold=True); tl.setWordWrap(True); col_.addWidget(tl)
                ev = QLabel(str(f.get("evidence", ""))); ev.setWordWrap(True)
                ev.setTextInteractionFlags(Qt.TextSelectableByMouse)
                ev.setStyleSheet(f"color:{P['text_label']};font-size:12px;font-family:{_FONT_MONO};background:transparent;")
                col_.addWidget(ev); row.addLayout(col_, 1); fcl.addLayout(row)
            self.bl.addWidget(fc)
        decoded = rep.get("decoded_payload", []) or []
        if decoded:
            any_b = True
            dc2, dcl2 = card("DECODED PAYLOAD", color=P["accent3"])
            for d in decoded[:5]:
                q = QLabel(str(d)[:160]); q.setWordWrap(True)
                q.setStyleSheet(f"color:{P['text_label']};font-size:12px;font-family:{_FONT_MONO};background:transparent;")
                dcl2.addWidget(q)
            self.bl.addWidget(dc2)
        sigs = rep.get("signatures", []) or []
        if sigs:
            any_b = True
            sc2, scl2 = card(f"BEHAVIORAL SIGNATURES ({len(sigs)})", color=P["accent2"])
            for sig in sigs:
                rw3 = QHBoxLayout()
                rw3.addWidget(badge(sig.get("severity", "medium")))
                nm = lbl(sig.get("name", ""), size=13); nm.setWordWrap(True)
                rw3.addWidget(nm, 1); scl2.addLayout(rw3)
            self.bl.addWidget(sc2)
        mitre = rep.get("mitre_attcks", []) or []
        if mitre:
            any_b = True
            mc, mcl = card("MITRE ATT&CK", color=P["accent3"])
            for m in mitre:
                rw4 = QHBoxLayout(); rw4.setSpacing(10)
                rw4.addWidget(StatusBadge(str(m.get("attck_id", "")), P["accent"]))
                rw4.addWidget(lbl(m.get("technique", ""), size=13), 1); mcl.addLayout(rw4)
            self.bl.addWidget(mc)
        tags = rep.get("classification_tags") or []
        if tags:
            any_b = True
            tc, tcl = card("CLASSIFICATION TAGS", color=P["accent2"])
            tl_ = QHBoxLayout(); tl_.setSpacing(6)
            for t in tags[:8]:
                tl_.addWidget(StatusBadge(str(t), P["accent2"]))
            tl_.addStretch(); tcl.addLayout(tl_)
            if len(tags) > 8:
                tcl.addWidget(lbl(" · ".join(str(t) for t in tags[8:20]), color=P["text_label"], size=12))
            self.bl.addWidget(tc)
        if not any_b:
            self.bl.addWidget(AnalysisEmptyState("search", "No behavioral findings",
                              "No behavioral indicators were reported for this sample."))
        self.bl.addStretch()

    def _ai_summary(self, r):
        if r.get("local_analysis"):
            fn = lambda: generate_local_ai_summary(r.get("local_analysis", {}))
        else:
            fn = lambda: generate_ai_summary(r, mode="malware")
        run_ai_summary(self, fn, "Malware", target=r)

    def _export_pdf(self):
        self._pdf_worker = _trigger_pdf_export(self, "malware", self._last_result)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 12b — ATTACK GRAPH COMPONENTS  (Enterprise Edition)
# ══════════════════════════════════════════════════════════════════════════════

# ── Node palette: richer glow colors ─────────────────────────────────────────
GRAPH_NODE_COLORS = {
    "ip":      "#FF4D4D",
    "domain":  "#FFD633",
    "hash":    "#00D4FF",
    "url":     "#44FF88",
    "file":    "#CC99FF",
    "unknown": "#6B7FA8",
}

# Glow color per type (RGBA tint for radial gradient outer ring)
GRAPH_GLOW_COLORS = {
    "ip":      (255, 60,  60,  120),
    "domain":  (255, 210, 50,  100),
    "hash":    (0,   210, 255, 110),
    "url":     (50,  255, 130, 90),
    "file":    (180, 120, 255, 90),
    "unknown": (100, 120, 170, 60),
}

# Node radii by type (enterprise: IPs biggest, hashes smallest)
GRAPH_NODE_RADIUS = {
    "ip":      28,
    "domain":  22,
    "url":     18,
    "file":    16,
    "hash":    14,
    "unknown": 14,
}


# ─── Background grid scene ────────────────────────────────────────────────────
class CyberGridScene(QGraphicsScene):
    """QGraphicsScene with a custom cyber-grid background."""

    def drawBackground(self, painter: QPainter, rect):
        # Dark base fill
        painter.fillRect(rect, QColor("#080E1F"))

        # Major grid lines
        grid_step = 60
        pen_major = QPen(QColor(0, 180, 255, 12), 1, Qt.SolidLine)
        painter.setPen(pen_major)
        left  = int(rect.left())  - (int(rect.left())  % grid_step)
        top   = int(rect.top())   - (int(rect.top())   % grid_step)
        x = left
        while x < rect.right():
            painter.drawLine(int(x), int(rect.top()), int(x), int(rect.bottom()))
            x += grid_step
        y = top
        while y < rect.bottom():
            painter.drawLine(int(rect.left()), int(y), int(rect.right()), int(y))
            y += grid_step

        # Minor grid lines (faint)
        pen_minor = QPen(QColor(0, 150, 255, 5), 1, Qt.SolidLine)
        painter.setPen(pen_minor)
        minor_step = 20
        lx = int(rect.left()) - (int(rect.left()) % minor_step)
        x2 = lx
        while x2 < rect.right():
            painter.drawLine(int(x2), int(rect.top()), int(x2), int(rect.bottom()))
            x2 += minor_step
        ty = int(rect.top()) - (int(rect.top()) % minor_step)
        y2 = ty
        while y2 < rect.bottom():
            painter.drawLine(int(rect.left()), int(y2), int(rect.right()), int(y2))
            y2 += minor_step


# ─── Worker ───────────────────────────────────────────────────────────────────
GRAPH_MAX_NODES = 2000          # hard ceiling; anything beyond is *reported*, never silently dropped
GRAPH_ANIMATE_MAX_NODES = 150   # live force/pulse animation only for small graphs
_GRAPH_SEV_RANK = {"": 0, "info": 0, "low": 0, "medium": 1, "high": 2, "critical": 3}


def _force_layout_np(ids: list, edges: list, seed: int = 7):
    """Fruchterman-Reingold layout, vectorised with numpy, meant to run in a
    worker thread. Returns {id: (x, y)} or None if numpy is unavailable."""
    try:
        import numpy as np
    except ImportError:
        return None
    n = len(ids)
    if n == 0:
        return {}
    idx = {nid: i for i, nid in enumerate(ids)}
    rng = np.random.default_rng(seed)
    ang = 2 * np.pi * np.arange(n) / n
    r = max(180.0, n * 6.0)
    pos = (np.stack([r * np.cos(ang), r * np.sin(ang)], 1) + rng.normal(0, 5, (n, 2))).astype(np.float32)
    e = np.array([(idx[a], idx[b]) for a, b, *_ in edges if a in idx and b in idx], dtype=np.int64).reshape(-1, 2)
    k = np.float32(90.0)
    iters = 100 if n <= 500 else 70
    for t in range(iters):
        temp = np.float32(max(4.0, 35.0 * (1 - t / iters)))
        d = pos[:, None, :] - pos[None, :, :]
        dist = np.maximum(np.float32(1.0), np.hypot(d[..., 0], d[..., 1]))
        rep = (k * k) / (dist * dist)
        np.fill_diagonal(rep, 0)
        disp = (d * rep[..., None]).sum(1)
        disp -= pos * np.float32(0.5)       # gravity: without it unconnected nodes are repelled ~2000px away
        if len(e):
            dd = pos[e[:, 1]] - pos[e[:, 0]]
            dl = np.maximum(np.float32(1.0), np.hypot(dd[:, 0], dd[:, 1]))
            att = (dl / k)[:, None] * dd / dl[:, None]
            np.add.at(disp, e[:, 0], att)
            np.add.at(disp, e[:, 1], -att)
        mag = np.maximum(np.float32(1.0), np.hypot(disp[:, 0], disp[:, 1]))
        pos += disp / mag[:, None] * np.minimum(mag, temp)[:, None]
    return {nid: (float(pos[i, 0]), float(pos[i, 1])) for nid, i in idx.items()}


def _graph_norm_severity(severity) -> str:
    """Canonical lower-case severity; unknown/empty -> 'low' (rank 0)."""
    sev = str(severity or "").strip().lower()
    if sev in ("info", "informational", "information"):
        return "low"                      # UI knows only low/medium/high/critical
    return sev if sev in ("medium", "high", "critical") else "low"


def _graph_normalize_ioc(value, ntype: str) -> str:
    """Canonical form so the same IOC written differently becomes ONE node:
    IPs via ipaddress, domains lower-case without trailing dot, hashes lower-case,
    URLs with lower-case scheme/host. Paths/queries keep their case."""
    if value is None:
        return ""
    v = str(value).strip()
    if not v:
        return ""
    if ntype == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return v.lower()
    if ntype == "domain":
        return v.lower().rstrip(".")
    if ntype == "hash":
        return v.lower()
    if ntype == "url":
        try:
            parts = urlsplit(v)
            if parts.scheme and parts.netloc:
                return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path,
                                   parts.query, parts.fragment))
        except ValueError:
            pass
        return v
    return v


class GraphBuildWorker(QThread):
    """Builds graph data in background thread to avoid freezing UI."""
    done  = pyqtSignal(object)  # emits (nodes_dict, edges_list)
    error = pyqtSignal(str)

    def __init__(self, forensics_result: dict):
        super().__init__()
        self._r = forensics_result or {}

    def run(self):
        try:
            nodes = {}   # id -> {type, label, severity, color}
            edges = []   # (src_id, dst_id, label)

            dropped = set()

            def _add_node(raw_id, ntype, severity="low"):
                """Normalise the IOC, add/merge the node and return its canonical id
                (also when the node had to be dropped, so edges can be accounted for)."""
                nid = _graph_normalize_ioc(raw_id, ntype)
                if not nid:
                    return ""
                severity = _graph_norm_severity(severity)
                cur = nodes.get(nid)
                if cur is not None:
                    # same IOC seen again: keep the highest severity seen
                    if _GRAPH_SEV_RANK[severity] > _GRAPH_SEV_RANK[cur["severity"]]:
                        cur["severity"] = severity
                    return nid
                if len(nodes) >= GRAPH_MAX_NODES:
                    dropped.add(nid)
                    return nid
                nodes[nid] = {
                    "type":     ntype,
                    "label":    nid[:40],
                    "severity": severity,
                    "color":    GRAPH_NODE_COLORS.get(ntype, GRAPH_NODE_COLORS["unknown"]),
                }
                return nid

            def _add_edge(src, dst, label="→"):
                if src and dst and src != dst:
                    edges.append((src, dst, label))

            iocs     = self._r.get("iocs", {}) or {}
            findings = self._r.get("findings", []) or []
            traffic  = self._r.get("traffic_summary", {}) or {}

            # Evidence first: if the node limit is hit, it is the bare IOC-list entries
            # (no relationship, no severity) that are dropped, never finding-derived nodes.
            for finding in findings:
                sev    = finding.get("severity") or "low"
                src    = finding.get("src_ip") or finding.get("src") or ""
                dst    = finding.get("dst_ip") or finding.get("dst") or ""
                domain = finding.get("domain") or finding.get("host") or ""
                url    = finding.get("url") or finding.get("ioc") or ""
                url    = url if isinstance(url, str) and url.lower().startswith("http") else ""

                s_id = _add_node(src,    "ip",     sev) if src else ""
                d_id = _add_node(dst,    "ip",     sev) if dst else ""
                dm_id = _add_node(domain, "domain", sev) if domain else ""
                u_id = _add_node(url,    "url",    sev) if url else ""

                _add_edge(s_id, d_id, "→")
                _add_edge(s_id, dm_id, "resolves")
                _add_edge(dm_id, u_id, "serves")

            for ip in (iocs.get("ips") or []):
                _add_node(ip, "ip")
            for domain in (iocs.get("domains") or []):
                _add_node(domain, "domain")
            for url in (iocs.get("urls") or []):
                u_id = _add_node(url, "url")
                try:
                    host = urlparse(str(url)).hostname or ""
                except ValueError as ex:             # malformed URL (e.g. bad IPv6 bracket)
                    log_event(f"GraphBuildWorker: skipped URL host parse for {str(url)[:80]!r}: {ex}")
                    host = ""
                if host:
                    h_id = _graph_normalize_ioc(host, "domain")
                    if h_id in nodes:
                        _add_edge(h_id, u_id, "serves")
            for h in (iocs.get("hashes") or []):
                _add_node(h, "hash")
            for f in (iocs.get("files") or []):
                _add_node(f, "file")

            top_srcs = traffic.get("top_src_ips") or []
            top_dsts = traffic.get("top_dst_ips") or []
            for src_item in top_srcs[:8]:
                src_ip = src_item.get("value", "")
                if src_ip:
                    s_id = _add_node(src_ip, "ip")
                    for dst_item in top_dsts[:4]:
                        dst_ip = dst_item.get("value", "")
                        if dst_ip:
                            d_id = _add_node(dst_ip, "ip")
                            _add_edge(s_id, d_id, "→")

            seen, unique_edges = set(), []
            for e in edges:
                key = (e[0], e[1])
                if key not in seen:
                    seen.add(key)
                    unique_edges.append(e)

            kept_edges = [e for e in unique_edges if e[0] in nodes and e[1] in nodes]
            dropped_edges = len(unique_edges) - len(kept_edges)
            positions = None
            if len(nodes) > GRAPH_ANIMATE_MAX_NODES:
                positions = _force_layout_np(list(nodes.keys()), kept_edges)
            meta = {
                "dropped": len(dropped),                 # nodes not shown
                "dropped_edges": dropped_edges,          # edges that lost an endpoint
                "total_nodes": len(nodes) + len(dropped),
                "shown_nodes": len(nodes),
                "limit": GRAPH_MAX_NODES,
                "reason": (f"node limit {GRAPH_MAX_NODES} reached" if dropped else ""),
                "positions": positions,
            }
            self.done.emit((nodes, kept_edges, meta))
        except Exception as ex:
            import traceback
            self.error.emit(f"Graph build error: {ex}\n{traceback.format_exc()}")


# ─── Node item ────────────────────────────────────────────────────────────────
class AttackGraphNode(QGraphicsObject):
    """Enterprise-grade interactive draggable node."""
    clicked    = pyqtSignal(str, str)   # (ioc_type, ioc_value)
    hovered_on = pyqtSignal(str, str)   # (ioc_type, ioc_value)

    def __init__(self, node_id: str, node_data: dict, x=0.0, y=0.0):
        super().__init__()
        self.node_id   = node_id
        self.node_data = node_data
        self._hover      = False
        self._highlight  = False
        self._pulse      = 0.0          # 0..1 animation value
        self._connected_ids: list = []  # filled by AttackGraphView for click-highlight
        self.vx = self.vy = 0.0

        self.setPos(x, y)
        self.setFlags(
            QGraphicsItem.ItemIsMovable |
            QGraphicsItem.ItemSendsGeometryChanges |
            QGraphicsItem.ItemIsSelectable
        )
        self.setAcceptHoverEvents(True)
        self.setZValue(1)

    @property
    def _radius(self) -> int:
        return GRAPH_NODE_RADIUS.get(self.node_data.get("type", "unknown"), 16)

    def boundingRect(self):
        r = self._radius + 14   # leave room for glow rings
        return QRectF(-r, -r, r * 2, r * 2)

    def paint(self, painter: QPainter, option, widget=None):
        painter.setRenderHint(QPainter.Antialiasing)
        r        = self._radius
        ntype    = self.node_data.get("type", "unknown")
        color_str= self.node_data.get("color", "#6B7FA8")
        sev      = (self.node_data.get("severity") or "low").lower()
        base_col = QColor(color_str)
        gc       = GRAPH_GLOW_COLORS.get(ntype, (100, 120, 170, 60))

        is_threat = sev in ("critical", "high")

        # ── Outer glow ring ──────────────────────────────────────────────
        glow_r = r + (10 if self._hover else 6)
        if is_threat:
            glow_r = r + 14
        glow = QRadialGradient(0, 0, glow_r)
        alpha_scale = 1.3 if self._hover else (1.0 + self._pulse * 0.4)
        glow.setColorAt(0,   QColor(gc[0], gc[1], gc[2], min(255, int(gc[3] * alpha_scale))))
        glow.setColorAt(0.5, QColor(gc[0], gc[1], gc[2], int(gc[3] * 0.3)))
        glow.setColorAt(1,   QColor(gc[0], gc[1], gc[2], 0))
        painter.setBrush(QBrush(glow))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(-glow_r, -glow_r, glow_r * 2, glow_r * 2)

        # ── Highlight ring (selected neighbors) ──────────────────────────
        if self._highlight:
            hl_pen = QPen(QColor(255, 255, 255, 200), 2, Qt.DotLine)
            painter.setPen(hl_pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawEllipse(-r - 5, -r - 5, (r + 5) * 2, (r + 5) * 2)

        # ── Node body gradient ───────────────────────────────────────────
        grad = QRadialGradient(-r * 0.25, -r * 0.25, r * 1.4)
        grad.setColorAt(0, base_col.lighter(170))
        grad.setColorAt(0.6, base_col)
        grad.setColorAt(1, base_col.darker(140))
        painter.setBrush(QBrush(grad))

        # Border
        if self._hover or self.isSelected():
            pen = QPen(QColor("#FFFFFF"), 2.5)
        elif is_threat:
            pen = QPen(QColor("#FF2222"), 2.0)
        else:
            pen = QPen(base_col.darker(180), 1.5)
        painter.setPen(pen)
        painter.drawEllipse(-r, -r, r * 2, r * 2)

        # ── Label ────────────────────────────────────────────────────────
        label = self.node_data.get("label", "")
        max_chars = max(6, r // 5)
        label = label[:max_chars] if len(label) > max_chars else label

        f = QFont("Consolas", max(6, r // 5))
        f.setBold(True)
        painter.setFont(f)
        # Shadow
        painter.setPen(QPen(QColor(0, 0, 0, 160)))
        painter.drawText(QRectF(-r + 1, -r + 1, r * 2, r * 2), Qt.AlignCenter, label)
        # Text
        painter.setPen(QPen(QColor("#FFFFFF")))
        painter.drawText(QRectF(-r, -r, r * 2, r * 2), Qt.AlignCenter, label)

        # ── Type badge (tiny) ────────────────────────────────────────────
        badge_map = {"ip": "IP", "domain": "DOM", "hash": "HASH",
                     "url": "URL", "file": "FILE"}
        badge_txt = badge_map.get(ntype, "")
        if badge_txt:
            bf = QFont("Consolas", 5)
            painter.setFont(bf)
            badge_col = base_col.lighter(120)
            badge_col.setAlpha(200)
            painter.setPen(QPen(badge_col))
            painter.drawText(QRectF(-r, r - 10, r * 2, 10), Qt.AlignCenter, badge_txt)

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            if self.scene():
                self.scene().update()
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event):
        self._hover = True
        self.update()
        self.hovered_on.emit(self.node_data.get("type", "unknown"), self.node_id)
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self._hover = False
        self.update()
        super().hoverLeaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.node_data.get("type", "unknown"), self.node_id)
        super().mousePressEvent(event)


# ─── Edge item ────────────────────────────────────────────────────────────────
class AttackGraphEdge(QGraphicsLineItem):
    """Styled directional edge with arrowhead."""

    def __init__(self, src_node: AttackGraphNode, dst_node: AttackGraphNode, label: str = ""):
        super().__init__()
        self.src_node   = src_node
        self.dst_node   = dst_node
        self.edge_label = label
        self._highlighted = False

        sev = (src_node.node_data.get("severity") or "low").lower()
        if sev in ("critical", "high"):
            self._color = QColor("#FF5555")
            self._width = 2.0
        elif sev == "medium":
            self._color = QColor("#FFB830")
            self._width = 1.5
        else:
            self._color = QColor("#1E4080")
            self._width = 1.2

        self.setZValue(0)
        self.update_position()

    def set_highlighted(self, on: bool):
        self._highlighted = on
        self.update()

    def update_position(self):
        sp = self.src_node.pos()
        dp = self.dst_node.pos()
        self.setLine(sp.x(), sp.y(), dp.x(), dp.y())

    def paint(self, painter: QPainter, option, widget=None):
        painter.setRenderHint(QPainter.Antialiasing)
        sp = self.src_node.pos()
        dp = self.dst_node.pos()
        dx, dy = dp.x() - sp.x(), dp.y() - sp.y()
        length = math.hypot(dx, dy)
        if length < 1:
            return

        col = QColor("#00D4FF") if self._highlighted else self._color
        w   = (self._width + 1.0) if self._highlighted else self._width

        # Shorten line so it doesn't overlap node circles
        r_src = self.src_node._radius
        r_dst = self.dst_node._radius
        ux, uy = dx / length, dy / length
        x1 = sp.x() + ux * r_src
        y1 = sp.y() + uy * r_src
        x2 = dp.x() - ux * (r_dst + 4)
        y2 = dp.y() - uy * (r_dst + 4)

        pen = QPen(col, w, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen)
        painter.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        # Arrowhead
        arrow_len, arrow_half = 10, 4
        angle = math.atan2(dy, dx)
        ax1 = x2 - arrow_len * math.cos(angle - 0.4)
        ay1 = y2 - arrow_len * math.sin(angle - 0.4)
        ax2 = x2 - arrow_len * math.cos(angle + 0.4)
        ay2 = y2 - arrow_len * math.sin(angle + 0.4)
        painter.setBrush(QBrush(col))
        painter.setPen(Qt.NoPen)
        painter.drawPolygon(QPolygonF([QPointF(x2, y2), QPointF(ax1, ay1), QPointF(ax2, ay2)]))

    def boundingRect(self):
        sp = self.src_node.pos()
        dp = self.dst_node.pos()
        return QRectF(sp, dp).normalized().adjusted(-15, -15, 15, 15)

    def shape(self):
        path = QPainterPath()
        sp = self.src_node.pos()
        dp = self.dst_node.pos()
        path.moveTo(sp)
        path.lineTo(dp)
        stroker = QPainterPathStroker()
        stroker.setWidth(10)
        return stroker.createStroke(path)


# ─── Floating Legend overlay ──────────────────────────────────────────────────
class GraphLegendOverlay(QWidget):
    """Semi-transparent floating legend card rendered inside the graph view."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_NoSystemBackground)
        self.setFixedWidth(130)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Card background
        bg = QColor(8, 14, 31, 210)
        painter.setBrush(QBrush(bg))
        painter.setPen(QPen(QColor(0, 212, 255, 80), 1))
        painter.drawRoundedRect(self.rect().adjusted(1, 1, -1, -1), 8, 8)

        # Title
        tf = QFont("Segoe UI", 8, QFont.Bold)
        painter.setFont(tf)
        painter.setPen(QColor("#00D4FF"))
        painter.drawText(QRect(0, 8, self.width(), 18), Qt.AlignCenter, "LEGEND")

        # Separator
        painter.setPen(QPen(QColor(0, 212, 255, 60), 1))
        painter.drawLine(10, 28, self.width() - 10, 28)

        items = [
            ("ip",     "⬤", "IP Address"),
            ("domain", "⬤", "Domain"),
            ("hash",   "⬤", "Hash / File"),
            ("url",    "⬤", "URL"),
            ("file",   "⬤", "File Path"),
        ]
        y = 36
        ef = QFont("Segoe UI", 8)
        for itype, dot, label in items:
            col = QColor(GRAPH_NODE_COLORS.get(itype, "#888"))
            # Dot
            painter.setFont(QFont("Segoe UI", 10))
            painter.setPen(col)
            painter.drawText(QRect(10, y - 2, 16, 16), Qt.AlignCenter, dot)
            # Label
            painter.setFont(ef)
            painter.setPen(QColor("#C8D8FF"))
            painter.drawText(QRect(28, y, self.width() - 30, 16), Qt.AlignLeft | Qt.AlignVCenter, label)
            y += 20

        painter.end()

    def sizeHint(self):
        return QSize(130, 38 + len(GRAPH_NODE_COLORS) * 20)


# ─── Main Attack Graph Widget ─────────────────────────────────────────────────
class AttackGraphView(QWidget):
    """Enterprise-grade Attack Graph tab — centerpiece of Forensics module."""
    cti_lookup_requested = pyqtSignal(str)

    _FILTER_BTNS = [
        ("all",       "⬡ ALL"),
        ("ip",        "⬤ IPs"),
        ("domain",    "◈ Domains"),
        ("hash",      "◇ Hashes"),
        ("url",       "⬡ URLs"),
        ("malicious", "☠ Malicious"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._nodes: dict      = {}
        self._edges: list      = []
        self._raw_nodes: dict  = {}
        self._raw_edges: list  = []
        self._filter_type      = "all"
        self._active_filter_btn = None

        # Force-directed layout timer
        self._layout_timer = QTimer(self)
        self._layout_timer.setInterval(25)
        self._layout_timer.timeout.connect(self._tick_layout)
        self._tick_count = 0

        # Pulse animation timer (for new nodes)
        self._pulse_timer = QTimer(self)
        self._pulse_timer.setInterval(50)
        self._pulse_timer.timeout.connect(self._tick_pulse)
        self._pulse_phase = 0.0

        self._build_ui()

    # ── UI construction ───────────────────────────────────────────────────────
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header bar ───────────────────────────────────────────────────
        header = QFrame()
        header.setMinimumHeight(72)
        header.setMaximumHeight(80)
        header.setStyleSheet(
            "QFrame {"
            "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "    stop:0 #0A1225, stop:0.5 #0D1830, stop:1 #0A1225);"
            "  border-bottom: 2px solid #00D4FF33;"
            "}"
        )
        hl = QHBoxLayout(header)
        hl.setContentsMargins(16, 8, 16, 8)
        hl.setSpacing(12)

        # Title group
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_lbl = QLabel("⚡  ATTACK GRAPH")
        title_lbl.setStyleSheet(
            "color: #00D4FF;"
            "font-size: 20px;"
            "font-weight: bold;"
            "font-family: 'Segoe UI', 'Arial';"
            "letter-spacing: 2px;"
        )
        sub_lbl = QLabel("IOC Relationship Visualization  ·  Threat Intelligence Graph")
        sub_lbl.setStyleSheet(
            "color: #3A6090;"
            "font-size: 10px;"
            "font-family: 'Segoe UI';"
            "letter-spacing: 0.5px;"
        )
        title_col.addWidget(title_lbl)
        title_col.addWidget(sub_lbl)
        hl.addLayout(title_col)

        # Vertical separator
        sep_line = QFrame()
        sep_line.setFrameShape(QFrame.VLine)
        sep_line.setStyleSheet("color: #1A3060; background: #1A3060;")
        sep_line.setFixedWidth(2)
        hl.addWidget(sep_line)

        # Stats badges
        self._badge_nodes = self._make_badge("NODES", "0", "#00D4FF")
        self._badge_edges = self._make_badge("EDGES", "0", "#44FF88")
        self._badge_threat= self._make_badge("THREATS", "0", "#FF4D4D")
        hl.addWidget(self._badge_nodes)
        hl.addWidget(self._badge_edges)
        hl.addWidget(self._badge_threat)

        hl.addStretch()

        # Filter buttons
        filter_label = QLabel("FILTER:")
        filter_label.setStyleSheet(
            "color: #3A6090; font-size: 9px; font-weight: bold; letter-spacing: 1px;"
        )
        hl.addWidget(filter_label)
        self._filter_btn_map = {}
        for ftype, label_text in self._FILTER_BTNS:
            btn = QPushButton(label_text)
            btn.setFixedHeight(34)
            btn.setMinimumWidth(72)
            btn.setCursor(Qt.PointingHandCursor)
            self._style_filter_btn(btn, active=(ftype == "all"))
            btn.clicked.connect(lambda _, f=ftype, b=btn: self._apply_filter(f, b))
            self._filter_btn_map[ftype] = btn
            hl.addWidget(btn)
            if ftype == "all":
                self._active_filter_btn = btn

        hl.addSpacing(8)

        # Reset + Fit buttons
        btn_fit = QPushButton("⊞ Fit")
        btn_fit.setFixedHeight(34)
        btn_fit.setMinimumWidth(60)
        btn_fit.setCursor(Qt.PointingHandCursor)
        btn_fit.setStyleSheet(self._ctrl_btn_style())
        btn_fit.clicked.connect(self._fit_view)
        hl.addWidget(btn_fit)

        btn_reset = QPushButton("↺ Reset")
        btn_reset.setFixedHeight(34)
        btn_reset.setMinimumWidth(64)
        btn_reset.setCursor(Qt.PointingHandCursor)
        btn_reset.setStyleSheet(self._ctrl_btn_style())
        btn_reset.clicked.connect(self._reset_layout)
        hl.addWidget(btn_reset)

        root.addWidget(header)

        # ── Search bar ───────────────────────────────────────────────────
        search_bar = QFrame()
        search_bar.setFixedHeight(36)
        search_bar.setStyleSheet(
            "QFrame { background: #090D1E; border-bottom: 1px solid #0F1E40; }"
        )
        sl = QHBoxLayout(search_bar)
        sl.setContentsMargins(14, 4, 14, 4)
        sl.setSpacing(8)
        search_icon = QLabel("🔍")
        search_icon.setStyleSheet("font-size: 12px;")
        sl.addWidget(search_icon)
        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText("Search node / IOC…  (highlight matching)")
        self._search_box.setStyleSheet(
            "QLineEdit {"
            "  background: transparent; border: none;"
            "  color: #C8D8FF; font-size: 11px; font-family: Consolas;"
            "}"
        )
        self._search_box.textChanged.connect(self._on_search)
        sl.addWidget(self._search_box)

        self._lbl_status = QLabel("Run Forensics analysis to generate graph.")
        self._lbl_status.setStyleSheet(
            "color: #3A5080; font-size: 10px; font-family: 'Segoe UI';"
        )
        sl.addWidget(self._lbl_status)
        root.addWidget(search_bar)

        # ── Graph scene + view ───────────────────────────────────────────
        self._scene = CyberGridScene()
        self._view  = QGraphicsView(self._scene)
        self._view.setRenderHint(QPainter.Antialiasing)
        self._view.setRenderHint(QPainter.SmoothPixmapTransform)
        self._view.setDragMode(QGraphicsView.ScrollHandDrag)
        self._view.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self._view.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        self._view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._view.setStyleSheet(
            "QGraphicsView { background: transparent; border: none; }"
        )
        self._view.wheelEvent = self._wheel_zoom
        root.addWidget(self._view, 1)   # stretch factor = 1 → takes all remaining space

        # Floating legend overlaid on graph view
        self._legend = GraphLegendOverlay(self._view)
        self._legend.setFixedHeight(38 + 5 * 20)   # title+sep+5 items
        self._legend.move(12, 12)
        self._legend.show()

        # ── Node detail panel ────────────────────────────────────────────
        detail = QFrame()
        detail.setFixedHeight(54)
        detail.setStyleSheet(
            "QFrame {"
            "  background: #090D1E;"
            "  border-top: 1px solid #0F1E40;"
            "}"
        )
        dl = QHBoxLayout(detail)
        dl.setContentsMargins(14, 6, 14, 6)
        dl.setSpacing(10)

        self._detail_icon  = QLabel("◎")
        self._detail_icon.setStyleSheet("font-size: 20px; color: #3A6090;")
        dl.addWidget(self._detail_icon)

        detail_text_col = QVBoxLayout()
        detail_text_col.setSpacing(1)
        self._detail_ioc = QLabel("Click or hover a node for details")
        self._detail_ioc.setStyleSheet(
            "color: #C8D8FF; font-size: 12px; font-weight: bold; font-family: Consolas;"
        )
        self._detail_meta = QLabel("Scroll to zoom  ·  Drag to pan  ·  Click node → CTI lookup")
        self._detail_meta.setStyleSheet("color: #3A5080; font-size: 10px;")
        detail_text_col.addWidget(self._detail_ioc)
        detail_text_col.addWidget(self._detail_meta)
        dl.addLayout(detail_text_col)
        dl.addStretch()

        self._btn_cti = QPushButton("🔍  CTI Lookup")
        self._btn_cti.setFixedHeight(30)
        self._btn_cti.setMinimumWidth(110)
        self._btn_cti.setStyleSheet(
            "QPushButton {"
            "  background: #0A2040; color: #00D4FF;"
            "  border: 1px solid #00D4FF55; border-radius: 5px;"
            "  font-size: 10px; padding: 0 10px;"
            "}"
            "QPushButton:hover { background: #0F3060; border-color: #00D4FF; }"
            "QPushButton:disabled { color: #3A5080; border-color: #1A3060; }"
        )
        self._btn_cti.setEnabled(False)
        self._btn_cti.clicked.connect(self._cti_from_detail)
        self._selected_ioc = ""
        dl.addWidget(self._btn_cti)
        root.addWidget(detail)

    # ── Style helpers ─────────────────────────────────────────────────────────
    def _make_badge(self, label: str, value: str, color: str) -> QFrame:
        frame = QFrame()
        frame.setFixedSize(74, 48)
        frame.setStyleSheet(
            f"QFrame {{"
            f"  background: {color}0F;"
            f"  border: 1px solid {color}40;"
            f"  border-radius: 6px;"
            f"}}"
        )
        bl = QVBoxLayout(frame)
        bl.setContentsMargins(4, 4, 4, 4)
        bl.setSpacing(0)
        val_lbl = QLabel(value)
        val_lbl.setAlignment(Qt.AlignCenter)
        val_lbl.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold; border: none; background: transparent;")
        key_lbl = QLabel(label)
        key_lbl.setAlignment(Qt.AlignCenter)
        key_lbl.setStyleSheet("color: #3A5080; font-size: 8px; letter-spacing: 1px; border: none; background: transparent;")
        bl.addWidget(val_lbl)
        bl.addWidget(key_lbl)
        frame._val_lbl = val_lbl
        return frame

    def _update_badge(self, badge: QFrame, value: str):
        badge._val_lbl.setText(value)

    def _style_filter_btn(self, btn: QPushButton, active: bool):
        if active:
            btn.setStyleSheet(
                "QPushButton {"
                "  background: #00D4FF22; color: #00D4FF;"
                "  border: 1px solid #00D4FF88; border-radius: 6px;"
                "  font-size: 10px; font-weight: bold; padding: 0 8px;"
                "}"
                "QPushButton:hover { background: #00D4FF33; }"
            )
        else:
            btn.setStyleSheet(
                "QPushButton {"
                "  background: #0A1225; color: #5A7AAA;"
                "  border: 1px solid #1A3060; border-radius: 6px;"
                "  font-size: 10px; padding: 0 8px;"
                "}"
                "QPushButton:hover { background: #0F1E40; color: #8AACCC; border-color: #2A4080; }"
            )

    def _ctrl_btn_style(self):
        return (
            "QPushButton {"
            "  background: #0D1830; color: #8AACCC;"
            "  border: 1px solid #1A3060; border-radius: 6px;"
            "  font-size: 10px; padding: 0 8px;"
            "}"
            "QPushButton:hover { background: #142040; color: #C8D8FF; border-color: #2A5090; }"
        )

    # ── Zoom / Pan ────────────────────────────────────────────────────────────
    def _wheel_zoom(self, event):
        factor = 1.18 if event.angleDelta().y() > 0 else 1 / 1.18
        self._view.scale(factor, factor)

    def _fit_view(self):
        if self._scene.items():
            self._view.fitInView(self._scene.itemsBoundingRect().adjusted(-40, -40, 40, 40),
                                 Qt.KeepAspectRatio)

    # ── Graph build ───────────────────────────────────────────────────────────
    def build_graph(self, forensics_result: dict):
        self._lbl_status.setText("⏳  Building graph…")
        self._layout_timer.stop()
        self._pulse_timer.stop()
        old = getattr(self, "_worker", None)
        if old is not None:                       # never drop a running QThread / stale result
            for sig in (old.done, old.error):
                try:
                    sig.disconnect()
                except TypeError:
                    pass
            if is_busy(old):
                retired = self.__dict__.setdefault("_graph_retired", [])
                retired.append(old)
                old.finished.connect(lambda o=old, lst=retired: lst.remove(o) if o in lst else None)
        self._worker = GraphBuildWorker(forensics_result)
        self._worker.done.connect(self._on_graph_built)
        self._worker.error.connect(lambda e: self._lbl_status.setText(f"⚠  {e[:100]}"))
        self._worker.start()

    def _on_graph_built(self, result):
        nodes_dict, edges_list = result[0], result[1]
        meta = result[2] if len(result) > 2 else {}
        self._raw_nodes = nodes_dict
        self._raw_edges = edges_list
        self._positions = meta.get("positions") or {}
        self._dropped = int(meta.get("dropped") or 0)
        self._dropped_edges = int(meta.get("dropped_edges") or 0)
        self._graph_total_nodes = int(meta.get("total_nodes") or len(nodes_dict))
        self._graph_limit_reason = meta.get("reason") or ""
        self._render_graph(nodes_dict, edges_list)

    def _render_graph(self, nodes_dict: dict, edges_list: list):
        self._layout_timer.stop()
        self._pulse_timer.stop()
        self._scene.clear()
        self._nodes.clear()
        self._edges.clear()

        if not nodes_dict:
            txt = self._scene.addText(
                "No IOC relationships found.\n\nRun Forensics analysis to generate the attack graph.",
                QFont("Segoe UI", 13)
            )
            txt.setDefaultTextColor(QColor("#2A4060"))
            self._lbl_status.setText("No IOC data.")
            self._update_badge(self._badge_nodes, "0")
            self._update_badge(self._badge_edges, "0")
            self._update_badge(self._badge_threat, "0")
            return

        n = len(nodes_dict)
        threat_count = sum(1 for nd in nodes_dict.values()
                           if nd.get("severity") in ("critical", "high"))
        self._update_badge(self._badge_nodes, str(n))
        self._update_badge(self._badge_edges, str(len(edges_list)))
        self._update_badge(self._badge_threat, str(threat_count))
        extra = ""
        if getattr(self, "_dropped", 0):
            extra = (f"    |    ⚠ showing {n} of {getattr(self, '_graph_total_nodes', n + self._dropped)} nodes "
                     f"({self._dropped} not shown — {getattr(self, '_graph_limit_reason', '') or 'limit reached'}"
                     f"; {getattr(self, '_dropped_edges', 0)} edges omitted)")
        self._lbl_status.setText(
            f"✔  {n} nodes · {len(edges_list)} edges · {threat_count} threats"
            "    |    Scroll to zoom · Drag to pan · Click node → CTI" + extra
        )

        # Circular initial placement (spring-like initial positions)
        radius = max(180.0, n * 22.0)
        precomputed = getattr(self, "_positions", None) or {}
        for i, (nid, ndata) in enumerate(nodes_dict.items()):
            angle = 2 * math.pi * i / max(n, 1)
            x = radius * math.cos(angle)
            y = radius * math.sin(angle)
            if nid in precomputed:            # layout already computed off the GUI thread
                x, y = precomputed[nid]
            node_item = AttackGraphNode(nid, ndata, x, y)
            node_item.clicked.connect(self._on_node_clicked)
            node_item.hovered_on.connect(self._on_node_hovered)
            self._scene.addItem(node_item)
            self._nodes[nid] = node_item

        # Build adjacency for click-highlight
        adjacency: dict = {nid: set() for nid in nodes_dict}      # sets: repeated edges count once
        for (src_id, dst_id, lbl) in edges_list:
            if src_id in adjacency:
                adjacency[src_id].add(dst_id)
            if dst_id in adjacency:
                adjacency[dst_id].add(src_id)
        for nid, node_item in self._nodes.items():
            node_item._connected_ids = list(adjacency.get(nid, ()))

        # Draw edges
        for (src_id, dst_id, label) in edges_list:
            if src_id in self._nodes and dst_id in self._nodes:
                edge = AttackGraphEdge(self._nodes[src_id], self._nodes[dst_id], label)
                self._scene.addItem(edge)
                self._edges.append(edge)

        self._fit_view()

        # Live animation only for small graphs: the O(n^2) per-tick simulation and
        # per-node pulse repaint freeze the GUI thread on large ones.
        self._tick_count = 0
        self._pulse_phase = 0.0
        if n <= GRAPH_ANIMATE_MAX_NODES:
            self._layout_timer.start()
            self._pulse_timer.start()

    # ── Layout tick ───────────────────────────────────────────────────────────
    def _tick_layout(self):
        MAX_TICKS = 150
        self._tick_count += 1
        if self._tick_count > MAX_TICKS:
            self._layout_timer.stop()
            return

        nodes = list(self._nodes.values())
        k    = 90.0
        temp = max(4.0, 35.0 * (1 - self._tick_count / MAX_TICKS))

        for i, u in enumerate(nodes):
            fx = fy = 0.0
            ux, uy = u.pos().x(), u.pos().y()
            for j, v in enumerate(nodes):
                if i == j:
                    continue
                vx, vy = v.pos().x(), v.pos().y()
                dx, dy = ux - vx, uy - vy
                dist = max(1.0, math.hypot(dx, dy))
                rep = k * k / dist
                fx += (dx / dist) * rep
                fy += (dy / dist) * rep
            u.vx = (getattr(u, 'vx', 0) + fx) * 0.5
            u.vy = (getattr(u, 'vy', 0) + fy) * 0.5

        for edge in self._edges:
            sn, dn = edge.src_node, edge.dst_node
            dx2 = dn.pos().x() - sn.pos().x()
            dy2 = dn.pos().y() - sn.pos().y()
            dist2 = max(1.0, math.hypot(dx2, dy2))
            att = dist2 / k
            ax, ay = (dx2 / dist2) * att, (dy2 / dist2) * att
            sn.vx = getattr(sn, 'vx', 0) + ax
            sn.vy = getattr(sn, 'vy', 0) + ay
            dn.vx = getattr(dn, 'vx', 0) - ax
            dn.vy = getattr(dn, 'vy', 0) - ay

        for u in nodes:
            vx, vy = getattr(u, 'vx', 0), getattr(u, 'vy', 0)
            speed  = max(1.0, math.hypot(vx, vy))
            move   = min(speed, temp)
            u.setPos(u.pos().x() + (vx / speed) * move,
                     u.pos().y() + (vy / speed) * move)

        for edge in self._edges:
            edge.update_position()

        self._scene.update()

    # ── Pulse animation ───────────────────────────────────────────────────────
    def _tick_pulse(self):
        self._pulse_phase = (self._pulse_phase + 0.08) % (2 * math.pi)
        pulse = (math.sin(self._pulse_phase) + 1) / 2   # 0..1
        for node in self._nodes.values():
            node._pulse = pulse
            node.update()

    # ── Interactions ──────────────────────────────────────────────────────────
    def _on_node_hovered(self, ioc_type: str, ioc_value: str):
        color = GRAPH_NODE_COLORS.get(ioc_type, "#888")
        conn  = self._nodes[ioc_value]._connected_ids if ioc_value in self._nodes else []
        sev   = self._nodes[ioc_value].node_data.get("severity", "low") if ioc_value in self._nodes else "low"
        self._detail_ioc.setText(
            f"<span style='color:{color}'>[{ioc_type.upper()}]</span>"
            f"  <span style='color:#E8EEFF'>{ioc_value[:80]}</span>"
        )
        self._detail_meta.setText(
            f"Severity: {sev.upper()}  ·  Connections: {len(conn)}  ·  Click → CTI Lookup"
        )

    def _on_node_clicked(self, ioc_type: str, ioc_value: str):
        # Highlight connected nodes + edges
        for nid, node in self._nodes.items():
            node._highlight = (nid in self._nodes[ioc_value]._connected_ids) if ioc_value in self._nodes else False
            node.update()
        for edge in self._edges:
            connected = (
                edge.src_node.node_id == ioc_value or
                edge.dst_node.node_id == ioc_value
            )
            edge.set_highlighted(connected)

        color = GRAPH_NODE_COLORS.get(ioc_type, "#888")
        conn  = self._nodes[ioc_value]._connected_ids if ioc_value in self._nodes else []
        sev   = self._nodes[ioc_value].node_data.get("severity", "low") if ioc_value in self._nodes else "low"
        self._detail_ioc.setText(
            f"<span style='color:{color}'>[{ioc_type.upper()}]</span>"
            f"  <span style='color:#E8EEFF'>{ioc_value[:80]}</span>"
        )
        self._detail_meta.setText(
            f"Severity: {sev.upper()}  ·  Connections: {len(conn)}  ·  Running CTI lookup…"
        )
        self._selected_ioc = ioc_value
        self._btn_cti.setEnabled(True)
        self.cti_lookup_requested.emit(ioc_value)

    def _cti_from_detail(self):
        if self._selected_ioc:
            self.cti_lookup_requested.emit(self._selected_ioc)

    def _on_search(self, text: str):
        text = text.strip().lower()
        for nid, node in self._nodes.items():
            match = text and text in nid.lower()
            node._highlight = match
            node.update()

    def _apply_filter(self, ftype: str, btn: QPushButton = None):
        self._filter_type = ftype
        # Restyle buttons
        if self._active_filter_btn:
            self._style_filter_btn(self._active_filter_btn, active=False)
        if btn:
            self._style_filter_btn(btn, active=True)
            self._active_filter_btn = btn

        if ftype == "all":
            fn, fe = self._raw_nodes, self._raw_edges
        elif ftype == "malicious":
            fn = {nid: nd for nid, nd in self._raw_nodes.items()
                  if nd.get("severity") in ("critical", "high", "medium")}
            fe = [e for e in self._raw_edges if e[0] in fn or e[1] in fn]
        else:
            fn = {nid: nd for nid, nd in self._raw_nodes.items() if nd.get("type") == ftype}
            fe = [e for e in self._raw_edges if e[0] in fn and e[1] in fn]

        self._render_graph(fn, fe)

    def _reset_layout(self):
        if self._raw_nodes:
            self._search_box.clear()
            self._render_graph(self._raw_nodes, self._raw_edges)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 13 — FORENSICS PAGE
# ══════════════════════════════════════════════════════════════════════════════

def detect_log_format(path: str = "", text: str = "") -> str:
    """Cheap, read-only format hint for the UI (the parser still auto-detects)."""
    ext = os.path.splitext(path or "")[1].lower()
    if ext in (".pcap", ".pcapng"):
        return "PCAP"
    t = (text or "").lstrip()[:2000]
    if ext == ".json" or t.startswith(("{", "[")):
        return "JSON"
    if ext == ".csv" or (t.count(",") >= 2 and "\n" in t and not t.startswith(("<", "#"))):
        return "CSV"
    if ext in (".log", ".txt") or t:
        return "TEXT / SYSLOG"
    return "—"


class ForensicsPage(QWidget):
    cti_lookup_requested = pyqtSignal(str)  # emits IOC value to trigger CTI lookup
    context_ready        = pyqtSignal(str, object)  # (module_name, context_dict)

    def __init__(self):
        super().__init__()
        self._file_path = None
        self._use_file = False
        self._setting_preview = False
        self._analysis_db_path = None
        self._last_forensics_result = {}
        self._log_page = 0
        self._timeline_page = 0
        self._timeline_src_filter = ""
        self._timeline_severity_filter = "all"
        root = QHBoxLayout(self); root.setContentsMargins(0, 0, 0, 0)
        sp = QSplitter(Qt.Horizontal); sp.setChildrenCollapsible(False); root.addWidget(sp)
        self._split = sp

        # ── LEFT — log source ──────────────────────────────────────────────
        lsa = QScrollArea(); lsa.setWidgetResizable(True); lsa.setFrameShape(QFrame.NoFrame)
        lsa.setMinimumWidth(300); lsa.setMaximumWidth(420)
        lsa.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._left = lsa
        lw = QWidget(); lw.setStyleSheet("background:transparent;"); lsa.setWidget(lw)
        ll = QVBoxLayout(lw); ll.setContentsMargins(24, 24, 16, 24); ll.setSpacing(16)
        ttl = QLabel("FORENSICS")
        ttl.setWordWrap(True)
        ttl.setStyleSheet(f"color:{P['text_main']};font-size:22px;font-weight:700;background:transparent;")
        stl = QLabel("WAF / NGFW / PCAP log investigation")
        stl.setStyleSheet(f"color:{P['text_label']};font-size:13px;background:transparent;")
        ll.addWidget(ttl); ll.addWidget(stl)

        sc_, scl_ = card("LOG SOURCE", color=P["accent"])
        self.btn_upload = ModernButton("Upload Log / PCAP", "secondary", icon="upload",
                                       tooltip="Upload a WAF/NGFW log (JSON, CSV, text) or a PCAP file")
        self.btn_upload.clicked.connect(self._pick)
        scl_.addWidget(self.btn_upload)
        self.lbl_file = lbl("Or paste log content below", color=P["text_dim"], size=12)
        self.lbl_file.setWordWrap(True); scl_.addWidget(self.lbl_file)
        frow = QHBoxLayout(); frow.setSpacing(8)
        frow.addWidget(lbl("Detected format", color=P["text_dim"], size=12))
        self._fmt_badge = StatusBadge("—", P["text_dim"]); frow.addWidget(self._fmt_badge); frow.addStretch()
        scl_.addLayout(frow)
        ll.addWidget(sc_)

        pc_, pcl_ = card("LOG CONTENT", color=P["accent2"])
        self.log_in = QTextEdit(); self.log_in.setPlaceholderText("Paste JSON / CSV / plain text log…")
        self.log_in.setMinimumHeight(150)
        self.log_in.setStyleSheet(f"font-family:{_FONT_MONO};font-size:12px;")
        pcl_.addWidget(self.log_in)
        self.log_in.textChanged.connect(self._on_log_changed)
        ll.addWidget(pc_)

        self.btn_go = ModernButton("ANALYZE LOG", "primary", icon="send", tooltip="Parse and analyze the log")
        self.btn_go.setMinimumHeight(40)
        self.btn_go.clicked.connect(self._run)
        ll.addWidget(self.btn_go)
        self.prog = QProgressBar(); self.prog.setRange(0, 0); self.prog.setVisible(False)
        self.prog.setFixedHeight(6); self.prog.setTextVisible(False)
        ll.addWidget(self.prog)
        self._loading = LoadingIndicator("Parsing…")
        ll.addWidget(self._loading)
        self._btn_export_f = ModernButton("Export Report (PDF)", "secondary", icon="pdf",
                                          tooltip="Export the analysis as a PDF report")
        self._btn_export_f.setEnabled(False)
        self._btn_export_f.clicked.connect(self._export_pdf)
        ll.addWidget(self._btn_export_f)
        self.worker = None
        self._pdf_worker = None
        ll.addStretch(); sp.addWidget(lsa)

        # ── RIGHT — investigation workspace ────────────────────────────────
        rw = QWidget(); rl = QVBoxLayout(rw); rl.setContentsMargins(8, 24, 24, 16)
        self.tabs = tabs = QTabWidget(); rl.addWidget(tabs)
        self.sa_f, _, self.fl = scroll_page(); tabs.addTab(self.sa_f, "FINDINGS")
        self.sa_i, _, self.il = scroll_page(); tabs.addTab(self.sa_i, "IOCs")
        self.sa_s, _, self.sl = scroll_page(); tabs.addTab(self.sa_s, "STATISTICS")
        self.sa_t, _, self.tl = scroll_page(); tabs.addTab(self.sa_t, "ATTACK TIMELINE")
        self.attack_graph_tab = AttackGraphView()
        self.attack_graph_tab.cti_lookup_requested.connect(self.cti_lookup_requested)
        tabs.addTab(self.attack_graph_tab, "ATTACK GRAPH")
        self.ai = ai_browser(); tabs.addTab(self.ai, "AI SUMMARY")
        self.ai.setPlaceholderText("The AI summary is generated after an analysis completes.")
        self.sa_r, _, self.rawl = scroll_page(); tabs.addTab(self.sa_r, "RAW LOGS")
        self._graph_idx = tabs.indexOf(self.attack_graph_tab)

        # corner button: show/hide the input panel to give the graph/timeline the full width
        self._btn_panel = ModernButton("Input panel", "ghost", icon="menu",
                                       tooltip="Show / hide the input panel")
        self._btn_panel.setMinimumHeight(28)
        self._btn_panel.clicked.connect(lambda: self._set_left_visible(not self._left.isVisible()))
        tabs.setCornerWidget(self._btn_panel, Qt.TopRightCorner)
        tabs.currentChanged.connect(self._on_tab_changed)

        sp.addWidget(rw)
        sp.setStretchFactor(0, 3); sp.setStretchFactor(1, 7); sp.setSizes([340, 800])
        self._fstat_cards = []
        self._fstat_grid = None
        self._show_empty_states()

    def _show_empty_states(self):
        for layout in (self.fl, self.il, self.sl, self.tl, self.rawl):
            clear_layout(layout)
        self.fl.addWidget(AnalysisEmptyState(
            "forensics", "Ready for Log Investigation",
            "Upload a WAF / NGFW log or a PCAP, or paste log content, then click ANALYZE LOG.\n\n"
            "Findings, IOCs, statistics, an attack timeline and an attack graph are built from the parsed records."))
        self.fl.addStretch()
        for layout, title in ((self.il, "No IOCs yet"), (self.sl, "No statistics yet"),
                              (self.tl, "No attack timeline yet"), (self.rawl, "No log records yet")):
            layout.addWidget(AnalysisEmptyState("search", title, "Run an analysis to populate this tab."))
            layout.addStretch()

    def _show_error(self, msg: str):
        for layout in (self.fl, self.il, self.sl, self.tl, self.rawl):
            clear_layout(layout)
        self.fl.addWidget(AnalysisEmptyState("shield_alert", "Analysis failed", str(msg), kind="error"))
        self.fl.addStretch()
        self.tabs.setCurrentIndex(0)

    def _set_busy(self, busy: bool, determinate: bool = False):
        self.btn_go.set_loading(busy, "Analyzing…")
        self.btn_upload.setEnabled(not busy)
        if busy:
            if determinate:
                self.prog.setRange(0, 100); self.prog.setValue(0)
            else:
                self.prog.setRange(0, 0)
            self.prog.setVisible(True)
            self._loading.start("Parsing and analyzing log…")
        else:
            self.prog.setVisible(False); self.prog.setValue(0)
            self._loading.stop()

    def _on_run_error(self, e):
        self._set_busy(False)
        self._show_error(e)
        QMessageBox.critical(self, "Error", e)

    def _set_left_visible(self, vis: bool):
        self._left.setVisible(vis)
        if vis:
            self._split.setSizes([340, max(400, self.width() - 340)])

    def _on_tab_changed(self, idx: int):
        # the attack graph needs width: tuck the input panel away (one click to bring it back)
        if idx == self._graph_idx and self._left.isVisible() and self.width() < 1500:
            self._set_left_visible(False)
        elif idx != self._graph_idx and not self._left.isVisible():
            self._set_left_visible(True)

    def _reflow_stats(self):
        g = self._fstat_grid
        if g is None or not self._fstat_cards:
            return
        cols = 4 if self.sa_f.viewport().width() >= 720 else 2
        try:
            for c in self._fstat_cards:
                g.removeWidget(c)
            for i, c in enumerate(self._fstat_cards):
                g.addWidget(c, i // cols, i % cols)
            for col in range(4):
                g.setColumnStretch(col, 1 if col < cols else 0)
        except RuntimeError:
            self._fstat_grid = None

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._reflow_stats()

    def _pick(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Log or PCAP",
            "",
            "PCAP Files (*.pcap *.pcapng);;Log Files (*.json *.csv *.log *.txt);;All Files (*)",
        )
        if path:
            try:
                self._file_path = path
                self._use_file = True
                size = os.path.getsize(path)
                self.lbl_file.setText(f"{os.path.basename(path)}  ·  {size/1024/1024:.2f} MB")
                self._fmt_badge.set_status(detect_log_format(path), P["accent"])
                ext = os.path.splitext(path)[1].lower()
                preview = "Preview disabled for large or binary file. Click ANALYZE LOG to process."
                if size <= 1024 * 1024 and ext not in (".pcap", ".pcapng"):
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        preview = f.read(200 * 1024)
                self._setting_preview = True
                self.log_in.setPlainText(preview)
                self._setting_preview = False
            except Exception as e:
                QMessageBox.critical(self,"Error",str(e))

    def _confirm_large_file(self, path: str):
        """Returns False (small file, go ahead), True (large file, user confirmed) or None (stop)."""
        chk = check_tabular_size(path)
        if chk["level"] == "blocked":
            QMessageBox.critical(self, "File terlalu besar", chk["message"])
            return None
        if chk["level"] == "warn":
            ans = QMessageBox.question(self, "File besar", chk["message"],
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            return True if ans == QMessageBox.Yes else None
        return False

    def _on_log_changed(self):
        if self._setting_preview:
            return
        if self._use_file:
            self._use_file = False
            self._file_path = None
            self.lbl_file.setText("Using pasted log content")
        self._fmt_badge.set_status(detect_log_format("", self.log_in.toPlainText()) if self.log_in.toPlainText().strip() else "—",
                                   P["accent"] if self.log_in.toPlainText().strip() else P["text_dim"])

    def _run(self):
        if is_busy(self.worker):
            log_event("ForensicsPage._run ignored: analysis already running")
            return
        content = self.log_in.toPlainText().strip()
        if self._use_file and self._file_path:
            confirmed = self._confirm_large_file(self._file_path)
            if confirmed is None:                 # refused or declined: nothing started, UI stays usable
                return
            self._set_busy(True, determinate=True)
            self.worker = LogParseWorker(self._file_path, max_records=MAX_PREVIEW_RECORDS,
                                         confirm_large=confirmed)
            self.worker.progress.connect(lambda v: self.prog.setValue(v))
            self.worker.done.connect(self._on_done)
            self.worker.error.connect(self._on_run_error)
            self.worker.start()
            return

        if not content:
            return QMessageBox.warning(self,"Input","Please upload or paste a log.")
        self._set_busy(True)
        self.worker = Worker(analyze_pasted_log_streaming, content, None)
        self.worker.done.connect(self._on_done)
        self.worker.error.connect(self._on_run_error)
        self.worker.start()

    def _on_done(self, r):
        self._set_busy(False)
        if isinstance(r, dict) and r.get("error"):
            # A failed analysis is reported, never stored as a successful run.
            log_event(f"Forensics analysis failed: {r['error']}")
            self._show_error(r["error"])
            QMessageBox.critical(self, "Analysis failed", str(r["error"]))
            return
        if isinstance(r, dict) and r.get("cancelled"):
            log_event("Forensics analysis cancelled; result not stored")
            return
        if isinstance(r, dict) and r.get("warning"):
            QMessageBox.warning(self, "Analysis incomplete", str(r["warning"]))
        self._last_forensics_result = r or {}

        # Save to SQLite
        try:
            findings_list = r.get("findings", []) or []
            sev_counts    = r.get("severity_counts", {})
            sev_val = "high" if sev_counts.get("high",0)+sev_counts.get("critical",0) > 0 \
                      else "medium" if sev_counts.get("medium",0) > 0 else "low"
            top_ioc = ""
            iocs_obj = r.get("iocs", {})
            if isinstance(iocs_obj, dict):
                for ioc_group in ["ips", "domains", "urls"]:
                    items = iocs_obj.get(ioc_group, [])
                    if items:
                        top_ioc = items[0]; break
            summ_val = f"Forensics: {len(findings_list)} findings, {r.get('total_records',0)} records"
            save_to_db("forensics", sev_val, top_ioc, summ_val, r)
        except Exception as e:
            log_event(f"Forensics save_to_db error: {e}")

        # ── Emit chatbot context FIRST (before any display that might crash) ──
        self._emit_chatbot_context(r)

        self._display(r); self._ai_summary(r)
        self._analysis_db_path = r.get("db_path")
        self._log_page = 0
        self._timeline_page = 0
        self._timeline_src_filter = ""
        self._timeline_severity_filter = "all"
        self._display_timeline(r)

        # ── Auto-generate Attack Graph ────────────────────────────────────────
        try:
            self.attack_graph_tab.build_graph(r)
        except Exception as ex:
            log_event(f"Attack Graph build error: {ex}")

    def _emit_chatbot_context(self, r):
        """Build and emit chatbot context — called immediately after analysis."""
        try:
            findings_list = r.get("findings", [])
            if not isinstance(findings_list, list):
                findings_list = []
            iocs_obj = r.get("iocs", {})
            if not isinstance(iocs_obj, dict):
                iocs_obj = {}
            all_iocs = (
                list(iocs_obj.get("ips", []))[:5] +
                list(iocs_obj.get("urls", []))[:3] +
                list(iocs_obj.get("domains", []))[:3]
            )
            ctx = {
                "module": "forensics",
                "findings": [
                    f"{f.get('attack_type') or f.get('technique','')}: "
                    f"{f.get('src_ip') or f.get('src','')}->{f.get('dst_ip') or f.get('dst','')} [{f.get('severity','')}]"
                    for f in findings_list[:15]
                ],
                "iocs": all_iocs,
                "timeline": [
                    f"{e.get('timestamp') or e.get('time','')} | {e.get('technique') or e.get('event','')} | "
                    f"src:{e.get('src_ip') or e.get('src','')}"
                    for e in (r.get("timeline", []) or [])[:10]
                ],
                "statistics": r.get("statistics", {}) or {},
                "top_attacker_ips": [x.get("value","") for x in (r.get("top_attacker_ips", []) or [])[:5]],
                "anomalies": [a.get("description","") for a in (r.get("anomalies", []) or [])[:5]],
                "behavior_detection": (r.get("behavior_detection", []) or [])[:5],
                "analysis_result": {
                    "total_findings": len(findings_list),
                    # iocs also carries an int "total": count only the collections
                    "total_iocs": sum(len(v) for v in iocs_obj.values()
                                      if isinstance(v, (list, tuple, set, dict))),
                },
            }
            LOGGER.debug(f"[CHATBOT] Emitting forensics context: {len(findings_list)} findings, {len(all_iocs)} iocs")
            log_event(f"[CHATBOT] Emitting forensics context: {len(findings_list)} findings")
            self.context_ready.emit("forensics", ctx)
        except Exception as e:
            import traceback
            print(f"[CHATBOT ERROR] {e}\n{traceback.format_exc()}")
            log_event(f"Chatbot Forensics context error: {e}\n{traceback.format_exc()}")

    def _export_pdf(self):
        self._pdf_worker = _trigger_pdf_export(self, "forensics", self._last_forensics_result)

    def _select_columns(self, records, candidates):
        cols = []
        for c in candidates:
            if any(c in r and str(r.get(c, "")) not in ("", "None") for r in records):
                cols.append(c)
        return cols

    def _build_table(self, headers, rows, max_rows=MAX_TABLE_ROWS, mono=False, max_h=240):
        tbl = QTableWidget(min(len(rows), max_rows), len(headers))
        tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        tbl.setAlternatingRowColors(True)
        tbl.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        if mono:
            tbl.setStyleSheet(f"font-family:{_FONT_MONO};font-size:12px;")
        tbl.setHorizontalHeaderLabels(headers)
        tbl.horizontalHeader().setStretchLastSection(True)
        tbl.verticalHeader().setVisible(False)
        for r_i, row in enumerate(rows[:max_rows]):
            for c_i, key in enumerate(headers):
                val = row.get(key, "")
                if isinstance(val, (dict, list)):
                    val = json.dumps(val)[:200]
                item = QTableWidgetItem(str(val)[:200])
                tbl.setItem(r_i, c_i, item)
        tbl.setMaximumHeight(max_h)
        return tbl

    def _log_prev_page(self):
        if self._log_page > 0:
            self._log_page -= 1
            self._display(self._last_forensics_result)

    def _log_next_page(self):
        self._log_page += 1
        self._display(self._last_forensics_result)

    def _timeline_table(self, rows):
        headers = ["time", "src", "event", "severity", "description", "dst", "ioc"]
        table = QTableWidget(len(rows), len(headers))
        table.setHorizontalHeaderLabels([h.upper() for h in headers])
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setSortingEnabled(False)
        for row_index, row in enumerate(rows):
            for col_index, key in enumerate(headers):
                value = row.get(key, "")
                item = QTableWidgetItem(str(value)[:220])
                sev = str(row.get("severity", "low")).lower()
                soft = SEVERITY_SOFT_STYLE.get(sev)
                if soft:
                    item.setBackground(QColor(soft["bg"]))
                    item.setForeground(QColor(soft["text"]))
                table.setItem(row_index, col_index, item)
        table.setMaximumHeight(320)
        return table

    def _display_timeline(self, r):
        clear_layout(self.tl)
        base = self._last_forensics_result or {}

        timeline = base.get("timeline", [])
        db_path = self._analysis_db_path if self._analysis_db_path and os.path.exists(self._analysis_db_path) else None

        controls = QHBoxLayout()
        self.timeline_src = QLineEdit()
        self.timeline_src.setPlaceholderText("Filter by source IP")
        self.timeline_src.setText(self._timeline_src_filter)
        self.timeline_sev = QComboBox()
        self.timeline_sev.addItems(["all", "critical", "high", "medium", "low"])
        self.timeline_sev.setCurrentText(self._timeline_severity_filter)
        apply_btn = QPushButton("Apply")
        prev_btn = QPushButton("Prev")
        next_btn = QPushButton("Next")
        self.timeline_info = lbl("", color=P["text_dim"], size=10)

        apply_btn.clicked.connect(self._apply_timeline_filters)
        prev_btn.clicked.connect(self._timeline_prev_page)
        next_btn.clicked.connect(self._timeline_next_page)

        controls.addWidget(self.timeline_src)
        controls.addWidget(self.timeline_sev)
        controls.addWidget(apply_btn)
        controls.addWidget(prev_btn)
        controls.addWidget(next_btn)
        controls.addStretch()
        self.tl.addLayout(controls)
        self.tl.addWidget(self.timeline_info)

        insight = base.get("timeline_insight", {})
        if insight:
            card_widget, card_layout = card("ATTACK TIMELINE INSIGHT", color=P["accent3"])
            card_layout.addWidget(lbl(f"Duration: {insight.get('duration', '0s')}", size=11))
            top_attackers = insight.get("events_per_attacker", [])[:3]
            if top_attackers:
                card_layout.addWidget(lbl(f"Top attackers: {top_attackers}", size=11))
            card_layout.addWidget(lbl(f"Escalation pattern: {insight.get('escalation', 'none')}", size=11))
            self.tl.addWidget(card_widget)

        if db_path:
            page_data = fetch_timeline_page(
                db_path,
                page=self._timeline_page,
                page_size=TIMELINE_PAGE_SIZE,
                src_filter=(self._timeline_src_filter or None),
                severity_filter=self._timeline_severity_filter,
            )
            rows = page_data.get("rows", [])
            total = page_data.get("total", 0)
            start = self._timeline_page * TIMELINE_PAGE_SIZE + 1 if total else 0
            end = start + len(rows) - 1 if rows else 0
            self.timeline_info.setText(f"Showing {start}-{end} of {total} events")
        else:
            rows = timeline[self._timeline_page * TIMELINE_PAGE_SIZE:(self._timeline_page + 1) * TIMELINE_PAGE_SIZE]
            total = len(timeline)
            start = self._timeline_page * TIMELINE_PAGE_SIZE + 1 if total else 0
            end = start + len(rows) - 1 if rows else 0
            self.timeline_info.setText(f"Showing {start}-{end} of {total} events")

        if not rows:
            self.tl.addWidget(lbl("No timeline events available.", color=P["text_dim"], size=11))
            self.tl.addStretch()
            return

        self.tl.addWidget(self._timeline_table(rows))
        self.tl.addStretch()

    def _apply_timeline_filters(self):
        self._timeline_page = 0
        self._timeline_src_filter = self.timeline_src.text().strip()
        self._timeline_severity_filter = self.timeline_sev.currentText().strip().lower()
        self._display_timeline({"timeline": []})

    def _timeline_prev_page(self):
        if self._timeline_page > 0:
            self._timeline_page -= 1
            self._display_timeline({"timeline": []})

    def _timeline_next_page(self):
        self._timeline_page += 1
        self._display_timeline({"timeline": []})

    def _display(self, r):
        for layout in [self.fl, self.il, self.sl, self.rawl]: clear_layout(layout)
        self._fstat_cards, self._fstat_grid = [], None
        self._btn_export_f.setEnabled(bool(r))

        if r.get("error"):
            self._show_error(r.get("error"))
            return
        findings = r.get("findings", [])
        iocs = r.get("iocs", {})
        db_path = r.get("db_path") or self._analysis_db_path
        raw_records = r.get("raw_records", []) or r.get("records", [])
        parsed_records = r.get("parsed_records", []) or raw_records
        raw_count = r.get("raw_count", len(raw_records))
        parsed_count = r.get("parsed_count", len(parsed_records))
        ts = r.get("traffic_summary", {})
        unique_src = ts.get("unique_src_ips", 0)

        sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        sorted_f  = sorted(findings, key=lambda f: sev_order.get(f.get("severity","info"),5))
        threat_findings = [f for f in sorted_f if f.get("severity") in ("critical", "high", "medium")]

        # ── Findings tab: overview stat cards ─────────────────────────────
        if r.get("truncated"):
            tw = lbl(f"Preview limited to {MAX_PREVIEW_RECORDS} records for performance.",
                     color=P["medium"], size=12)
            tw.setWordWrap(True); self.fl.addWidget(tw)
        hi = sum(1 for f in threat_findings if f.get("severity") in ("critical", "high"))
        cards_ = [StatCard("TOTAL LOGS", "Records received", P["accent"]),
                  StatCard("PARSED LOGS", "Records parsed", P["info"]),
                  StatCard("UNIQUE SOURCE IPs", "Distinct sources", P["medium"]),
                  StatCard("THREATS", f"{hi} high / critical", P["high"], emphasis=bool(hi))]
        for c_, v_ in zip(cards_, (raw_count, parsed_count, unique_src, len(threat_findings))):
            c_.set_value(v_)
        self._fstat_cards = cards_
        gwrap = QWidget(); gwrap.setStyleSheet("background:transparent;")
        self._fstat_grid = QGridLayout(gwrap); self._fstat_grid.setContentsMargins(0, 0, 0, 0)
        self._fstat_grid.setSpacing(16)
        self.fl.addWidget(gwrap)
        self._reflow_stats()

        # ── RAW LOGS tab (paginated from SQLite when available) ───────────
        if db_path and os.path.exists(db_path):
            page = fetch_log_page(db_path, page=self._log_page, page_size=MAX_TABLE_ROWS)
            page_rows = page.get("rows", [])
            total_logs = page.get("total", 0)
            start = self._log_page * MAX_TABLE_ROWS + 1 if total_logs else 0
            end = start + len(page_rows) - 1 if page_rows else 0
            pager = QHBoxLayout(); pager.setSpacing(8)
            prev_btn = ModernButton("Prev", "secondary", tooltip="Previous page")
            next_btn = ModernButton("Next", "secondary", tooltip="Next page")
            prev_btn.setEnabled(self._log_page > 0)
            next_btn.setEnabled(end < total_logs)
            prev_btn.clicked.connect(self._log_prev_page)
            next_btn.clicked.connect(self._log_next_page)
            pager.addWidget(prev_btn); pager.addWidget(next_btn); pager.addStretch()
            pager.addWidget(lbl(f"Showing {start}-{end} of {total_logs} logs", color=P["text_label"], size=12))
            self.rawl.addLayout(pager)

            raw_cols = ["time", "src_ip", "dst_ip", "method", "url", "status_code", "action", "protocol", "domain", "user_agent"]
            raw_rows = [{c: rec.get(c, "") for c in raw_cols} for rec in page_rows]
            rc, rcl = card("RAW LOG TABLE", color=P["accent"])
            rcl.addWidget(self._build_table(raw_cols, raw_rows, mono=True, max_h=420))
            self.rawl.addWidget(rc)

            parsed_cols = ["src_ip", "dst_ip", "url", "status_code", "method"]
            parsed_rows = [{c: rec.get(c, "") for c in parsed_cols} for rec in page_rows]
            pc, pcl = card("PARSED LOG TABLE", color=P["accent2"])
            pcl.addWidget(self._build_table(parsed_cols, parsed_rows, mono=True, max_h=320))
            self.rawl.addWidget(pc)
        else:
            raw_cols = self._select_columns(raw_records, [
                "timestamp", "src_ip", "dst_ip", "method", "url", "status_code",
                "action", "protocol", "src_port", "dst_port", "domain", "user_agent",
            ])
            raw_rows = []
            if raw_cols:
                for rec in raw_records:
                    row = {c: rec.get(c, "") for c in raw_cols}
                    raw_rows.append(row)
            else:
                raw_cols = ["raw"]
                for rec in raw_records:
                    raw_rows.append({"raw": json.dumps(rec)[:200]})
            rc, rcl = card("RAW LOG PREVIEW", color=P["accent"])
            if raw_records:
                rcl.addWidget(self._build_table(raw_cols, raw_rows, mono=True, max_h=420))
            else:
                rcl.addWidget(lbl("No log records available.", color=P["text_dim"], size=13))
            self.rawl.addWidget(rc)

            parsed_cols = ["src_ip", "dst_ip", "url", "status_code", "method"]
            parsed_rows = [{c: rec.get(c, "") for c in parsed_cols} for rec in parsed_records]
            pc, pcl = card("PARSED LOG PREVIEW", color=P["accent2"])
            if parsed_records:
                pcl.addWidget(self._build_table(parsed_cols, parsed_rows, mono=True, max_h=320))
            else:
                pcl.addWidget(lbl("No parsed records available.", color=P["text_dim"], size=13))
            self.rawl.addWidget(pc)
        self.rawl.addStretch()

        if threat_findings:
            self.fl.addWidget(SectionHeader(f"{len(threat_findings)} finding(s) require attention",
                                            "Sorted by severity"))
            for f in threat_findings:
                sev = f.get("severity", "info")
                col = _severity_color(sev)
                fc = QFrame(); fc.setObjectName("fcard")
                fc.setStyleSheet(
                    f"QFrame#fcard{{background:{_tint(col, 22)};border:1px solid {_tint(col, 90)};"
                    f"border-left:3px solid {col};border-radius:10px;}}")
                fcl = QVBoxLayout(fc); fcl.setContentsMargins(16, 14, 16, 14); fcl.setSpacing(8)
                rw1 = QHBoxLayout(); rw1.setSpacing(10)
                tl_ = lbl(f.get("attack_type", "").replace("_", " ").upper(), color=col, bold=True, size=14)
                tl_.setWordWrap(True)
                rw1.addWidget(tl_, 1); rw1.addWidget(badge(sev), 0, Qt.AlignTop); fcl.addLayout(rw1)
                src_val = f.get("src_ip") or f.get("src") or "unknown"
                dst_val = f.get("dst_ip") or f.get("dst") or "unknown"
                ioc_type = (f.get("type") or "unknown").upper()
                ioc_val = f.get("ioc") or f.get("target") or src_val
                g = QGridLayout(); g.setHorizontalSpacing(10); g.setVerticalSpacing(6)
                g.addWidget(lbl("SOURCE", color=P["text_dim"], size=11), 0, 0)
                g.addWidget(IOCChip(str(src_val), "source"), 0, 1)
                g.addWidget(lbl("DEST", color=P["text_dim"], size=11), 0, 2)
                g.addWidget(IOCChip(str(dst_val), "destination"), 0, 3)
                g.addWidget(lbl(f"IOC · {ioc_type}", color=P["text_dim"], size=11), 1, 0)
                g.addWidget(IOCChip(str(ioc_val), ioc_type.lower()), 1, 1, 1, 3)
                g.setColumnStretch(1, 1); g.setColumnStretch(3, 1)
                fcl.addLayout(g)
                if f.get("timestamp"):
                    fcl.addWidget(lbl(f.get("timestamp", ""), color=P["text_label"], size=12))
                desc = lbl(f.get("description") or f.get("detail", ""), size=13); desc.setWordWrap(True)
                fcl.addWidget(desc)
                reason = f.get("reason", "")
                confidence = f.get("confidence", "low")
                fp_check = f.get("false_positive_check", "unknown")
                meta = lbl(f"Confidence: {confidence}  ·  False-positive check: {fp_check}"
                           + (f"  ·  {reason}" if reason else ""), color=P["text_label"], size=12)
                meta.setWordWrap(True); fcl.addWidget(meta)
                btn_cti = ModernButton("CTI Lookup", "secondary", icon="cti", tooltip=f"Look up {ioc_val} in CTI")
                btn_cti.clicked.connect(lambda _, v=ioc_val: self.cti_lookup_requested.emit(v))
                fcl.addWidget(btn_cti, alignment=Qt.AlignRight)
                self.fl.addWidget(fc)
        low_findings = [f for f in sorted_f if f not in threat_findings]
        if low_findings:
            lc_, lcl_ = card(f"LOWER-SEVERITY FINDINGS ({len(low_findings)})", color=P["accent2"])
            for f in low_findings[:30]:
                row = QHBoxLayout(); row.setSpacing(10)
                row.addWidget(badge(f.get("severity", "low")), 0, Qt.AlignTop)
                col_ = QVBoxLayout(); col_.setSpacing(3)
                t_ = lbl(str(f.get("attack_type", "")).replace("_", " ").upper(), size=13, bold=True)
                col_.addWidget(t_)
                src_ = f.get("src_ip") or f.get("src")
                if src_:
                    col_.addWidget(IOCChip(str(src_), "source"))
                d_ = f.get("description") or f.get("detail", "")
                if d_:
                    dl_ = lbl(str(d_), color=P["text_label"], size=12); dl_.setWordWrap(True); col_.addWidget(dl_)
                row.addLayout(col_, 1); lcl_.addLayout(row)
            self.fl.addWidget(lc_)
        if not threat_findings:
            anomalies = r.get("anomalies", [])
            sc, scl = card("STATUS", color=P["low"])
            scl.addWidget(lbl("No Critical Threat Detected", color=P["low"], bold=True, size=12))
            self.fl.addWidget(sc)

            ic, icl = card("INSIGHT", color=P["accent"])
            icl.addWidget(lbl("Traffic terlihat normal.", size=11))
            icl.addWidget(lbl("Tidak ada indikasi serangan signifikan.", size=11))
            icl.addWidget(lbl("Data dapat digunakan sebagai baseline monitoring.", size=11))
            self.fl.addWidget(ic)

            if anomalies:
                ac, acl = card("ANOMALY DETECTION", color=P["medium"])
                for a in anomalies:
                    row = QHBoxLayout()
                    row.addWidget(badge(a.get("severity", "low")))
                    row.addWidget(lbl(a.get("description", ""), size=10))
                    row.addStretch(); acl.addLayout(row)
                self.fl.addWidget(ac)
        self.fl.addStretch()

        # ── IOCs tab ────────────────────────────────────────────────────
        label_map = {
            "ips": "IP",
            "domains": "DOMAIN",
            "urls": "URL",
            "files": "FILE",
            "hashes": "HASH",
        }
        color_map = {
            "ips": P["high"],
            "domains": "#4FC3F7",
            "urls": "#00C896",
            "files": P["text_dim"],
            "hashes": P["accent"],
        }
        ioc_added = False
        for cat, items in iocs.items():
            if cat == "total" or not items: continue
            ic, icl = card(cat.upper(), color=P["accent"])
            for item in items[:50]:
                rw_i = QHBoxLayout()
                tag = label_map.get(cat, "IOC")
                tag_color = color_map.get(cat, P["text_dim"])
                rw_i.addWidget(lbl(f"[{tag}]", color=tag_color, bold=True, size=10))
                rw_i.addWidget(lbl(f"  {item}", size=11))
                rw_i.addStretch()
                if cat != "files":
                    btn_c = QPushButton("CTI ▸"); btn_c.setMinimumWidth(60); btn_c.setFixedHeight(20)
                    btn_c.clicked.connect(lambda _, v=item: self.cti_lookup_requested.emit(v))
                    rw_i.addWidget(btn_c)
                icl.addLayout(rw_i)
            self.il.addWidget(ic)
            ioc_added = True
        if not ioc_added:
            self.il.addWidget(lbl("No IOC found in this log.", color=P["text_dim"], size=11))
        self.il.addStretch()

        # ── Statistics tab ───────────────────────────────────────────────
        sh, scl = card("ANALYSIS STATISTICS", color=P["accent3"])
        for k, v in [("Total Records", r.get("total_records",0)),
                     ("Total Findings", r.get("total_findings",0)),
                     ("Total IOCs", iocs.get("total",0))]:
            rws = QHBoxLayout()
            rws.addWidget(lbl(f"{k}:", color=P["text_label"], size=11))
            rws.addWidget(lbl(str(v), color=P["accent"], bold=True, size=13))
            rws.addStretch(); scl.addLayout(rws)
        self.sl.addWidget(sh)

        svc, svcl = card("SEVERITY BREAKDOWN", color=P["accent2"])
        for sv, cnt in r.get("severity_counts",{}).items():
            rws2 = QHBoxLayout()
            rws2.addWidget(badge(sv))
            rws2.addWidget(lbl(str(cnt), bold=True, size=12))
            rws2.addStretch(); svcl.addLayout(rws2)
        self.sl.addWidget(svc)

        atc, atcl = card("ATTACK TYPES", color=P["medium"])
        for atk, cnt in sorted(r.get("attack_type_counts",{}).items(), key=lambda x: -x[1]):
            rwa = QHBoxLayout()
            rwa.addWidget(lbl(atk.replace("_"," "), size=11))
            rwa.addStretch(); rwa.addWidget(lbl(str(cnt), color=P["accent"], bold=True, size=11))
            atcl.addLayout(rwa)
        self.sl.addWidget(atc)

        traffic = r.get("traffic_summary", {})
        anomalies = r.get("anomalies", [])
        if traffic:
            ta, tal = card("TOP ANALYSIS", color=P["accent3"])
            top_src = traffic.get("top_src_ips", [])
            top_dst = traffic.get("top_dst_ips", [])
            top_url = traffic.get("top_urls", [])
            top_method = traffic.get("top_methods", [])
            added = False
            if top_src:
                tal.addWidget(lbl(f"Top Source IP: {top_src[0]['value']} ({top_src[0]['count']})", size=11))
                added = True
            if top_dst:
                tal.addWidget(lbl(f"Top Destination IP: {top_dst[0]['value']} ({top_dst[0]['count']})", size=11))
                added = True
            if top_url:
                tal.addWidget(lbl(f"Top URL: {top_url[0]['value']}", size=11))
                added = True
            if top_method:
                tal.addWidget(lbl(f"Top Method: {top_method[0]['value']}", size=11))
                added = True
            if added:
                self.sl.addWidget(ta)

            req_ip = traffic.get("request_per_ip", [])
            if req_ip:
                rp, rpl = card("REQUESTS PER IP", color=P["accent"])
                for item in req_ip[:10]:
                    rpl.addWidget(lbl(f"{item['value']}: {item['count']}", size=10))
                self.sl.addWidget(rp)

            tp, tpl = card("TRAFFIC PATTERN", color=P["accent2"])
            burst = traffic.get("burst_candidates", [])
            unusual = traffic.get("unusual_endpoints", [])
            status_class = traffic.get("status_class_distribution", {})
            if burst:
                for b in burst[:5]:
                    tpl.addWidget(lbl(f"Burst {b.get('src','unknown')}: {b.get('count',0)}/{b.get('window','1m')}", size=10))
            if unusual:
                for u in unusual[:5]:
                    tpl.addWidget(lbl(f"Unusual endpoint: {u.get('value','')}", size=10))
            if status_class:
                dist_txt = ", ".join([f"{k}:{v}" for k, v in sorted(status_class.items())])
                tpl.addWidget(lbl(f"Status class: {dist_txt}", size=10))
            if not burst and not unusual and not status_class:
                tpl.addWidget(lbl("No notable traffic pattern detected.", size=10))
            self.sl.addWidget(tp)

            if anomalies:
                ac, acl = card("ANOMALY DETECTION", color=P["medium"])
                for a in anomalies[:10]:
                    row = QHBoxLayout()
                    row.addWidget(badge(a.get("severity", "low")))
                    row.addWidget(lbl(a.get("description", ""), size=10))
                    row.addStretch(); acl.addLayout(row)
                self.sl.addWidget(ac)

        tpc, tpcl = card("TOP ATTACKER IPs", color=P["critical"])
        for ip_d in r.get("top_attacker_ips",[])[:8]:
            rwt = QHBoxLayout()
            rwt.addWidget(lbl(ip_d["value"], color=P["critical"], size=11))
            rwt.addStretch()
            rwt.addWidget(lbl(f"{ip_d['count']} findings", color=P["text_dim"], size=10))
            btn_c2 = QPushButton("CTI ▸"); btn_c2.setMinimumWidth(60); btn_c2.setFixedHeight(20)
            btn_c2.clicked.connect(lambda _, v=ip_d["value"]: self.cti_lookup_requested.emit(v))
            rwt.addWidget(btn_c2); tpcl.addLayout(rwt)
        self.sl.addWidget(tpc)

        top_domains = r.get("top_domains", [])
        if top_domains:
            tdc, tdcl = card("TOP DOMAINS", color=P["accent3"])
            for d in top_domains[:8]:
                rwd = QHBoxLayout()
                rwd.addWidget(lbl(d.get("value", ""), color=P["accent3"], size=11))
                rwd.addStretch()
                rwd.addWidget(lbl(str(d.get("count", 0)), color=P["text_dim"], size=10))
                tdcl.addLayout(rwd)
            self.sl.addWidget(tdc)

        network_overview = r.get("network_overview", {})
        top_talkers = r.get("top_talkers", {})
        protocol_dist = r.get("protocol_distribution", [])
        behavior = r.get("behavior_detection", [])
        if network_overview:
            nw, nwl = card("NETWORK OVERVIEW", color=P["medium"])
            nwl.addWidget(lbl(f"Total packets: {network_overview.get('total_packets',0)}", size=10))
            nwl.addWidget(lbl(f"Total connections: {network_overview.get('total_connections',0)}", size=10))
            self.sl.addWidget(nw)

        if top_talkers:
            tt, ttl = card("TOP TALKERS", color=P["accent3"])
            for item in top_talkers.get("src", [])[:5]:
                ttl.addWidget(lbl(f"Most Active SRC: {item.get('value','')} ({item.get('count',0)})", size=10))
            for item in top_talkers.get("dst", [])[:5]:
                ttl.addWidget(lbl(f"Most Active DST: {item.get('value','')} ({item.get('count',0)})", size=10))
            self.sl.addWidget(tt)

        if protocol_dist:
            pd, pdl = card("PROTOCOL DISTRIBUTION", color=P["accent2"])
            for p in protocol_dist:
                pdl.addWidget(lbl(f"{p.get('protocol','')}: {p.get('count',0)} ({p.get('percent',0)}%)", size=10))
            self.sl.addWidget(pd)

        if behavior:
            bd, bdl = card("BEHAVIOR DETECTION", color=P["medium"])
            for b in behavior[:10]:
                row = QHBoxLayout()
                row.addWidget(badge(b.get("severity", "low")))
                row.addWidget(lbl(b.get("description", ""), size=10))
                row.addStretch(); bdl.addLayout(row)
            self.sl.addWidget(bd)

        session_summary = r.get("session_summary", [])
        if session_summary:
            sc2, scl2 = card("SESSION SUMMARY", color=P["accent2"])
            for s in session_summary[:8]:
                rws3 = QHBoxLayout()
                rws3.addWidget(lbl(f"SRC: {s.get('src','')}", size=10))
                rws3.addStretch()
                rws3.addWidget(lbl(f"{s.get('connections',0)} connections", color=P["text_dim"], size=10))
                scl2.addLayout(rws3)
                dst_map = ", ".join(s.get("dst_map", []))
                scl2.addWidget(lbl(f"Top dst: {s.get('top_destination','')} | Protocol: {s.get('protocol','')}",
                                   color=P["text_dim"], size=10))
                if dst_map:
                    scl2.addWidget(lbl(f"SRC -> DST map: {dst_map}", color=P["text_dim"], size=10))
            self.sl.addWidget(sc2)
        self.sl.addStretch()

    def _ai_summary(self, r):
        run_ai_summary(self, lambda: generate_ai_summary(r, mode="forensics"), "Forensics", target=r)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 13b — AI SOC ANALYST CHATBOT
# ══════════════════════════════════════════════════════════════════════════════

class ChatWorker(QThread):
    """Background thread to call Groq API for chatbot."""
    reply_ready  = pyqtSignal(str)
    error        = pyqtSignal(str)

    def __init__(self, messages: list):
        super().__init__()
        self.messages = messages

    def run(self):
        api_key = GROQ_API_KEY
        if not api_key:
            self.error.emit("GROQ_API_KEY tidak dikonfigurasi.")
            return
        try:
            resp = requests.post(
                GROQ_API_URL,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": GROQ_MODEL,
                    "messages": self.messages,
                    "max_tokens": 2500,   # headroom: gpt-oss spends tokens on reasoning
                    "reasoning_effort": "low",
                    "temperature": 0.3,
                },
                timeout=60,
            )
            if resp.status_code == 200:
                text = resp.json()["choices"][0]["message"]["content"]
                self.reply_ready.emit(text)
            else:
                info = classify_api_failure("Groq", resp.status_code, resp.text, resp.headers)
                self.error.emit(f"Groq: {info['error']}")
        except Exception as e:      # any failure must reach the UI, or the panel stays in "loading"
            self.error.emit(f"Groq: {classify_api_failure('Groq', exc=e)['error']}")


_CHAT_HEADINGS = ("Analisis", "Risiko", "Alasan", "Rekomendasi", "Technical Evidence", "Evidence", "Kesimpulan")


def prettify_chat_markdown(text: str) -> str:
    """Turn the analyst's mandated '**Analisis:**' style lines into real headings so
    sections are scannable (heading → short paragraph → bullets). Content is untouched."""
    out = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*\*\*\s*([^*]+?)\s*:?\s*\*\*\s*:?\s*(.*)$", line)
        if m and any(m.group(1).strip().lower().startswith(h.lower()) for h in _CHAT_HEADINGS):
            out.append(f"### {m.group(1).strip().rstrip(':')}")
            rest = m.group(2).strip()
            if rest:
                out.append(rest)
        else:
            out.append(line)
    return "\n".join(out)


def _colorize_risk_level(doc):
    """Color the LOW/MEDIUM/HIGH/CRITICAL word that follows the 'Risiko' heading."""
    from PyQt5.QtGui import QTextCursor, QTextCharFormat
    blk = doc.begin()
    while blk.isValid():
        if blk.text().strip().lower().startswith("risiko"):
            nxt = blk.next()
            word = nxt.text().strip().upper().rstrip(".")
            if nxt.isValid() and word in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"):
                cur = QTextCursor(nxt)
                cur.select(QTextCursor.BlockUnderCursor)
                cur.setPosition(nxt.position())
                cur.setPosition(nxt.position() + nxt.length() - 1, QTextCursor.KeepAnchor)
                fmt = QTextCharFormat()
                fmt.setForeground(QColor(_severity_color(word)))
                fmt.setFontWeight(75)
                cur.mergeCharFormat(fmt)
            break
        blk = blk.next()


_CHAT_MODULE_COLORS = {"cti": P["accent"], "malware": "#8B5CF6", "forensics": P["medium"]}


def chat_context_target(module: str, data: dict) -> str:
    """Short, human label for what the chat is currently about."""
    data = data or {}
    try:
        if module == "cti":
            return str(data.get("ioc") or "IOC")
        if module == "malware":
            nm = (data.get("analysis_result") or {}).get("submit_name")
            return str(nm) if nm and nm != "N/A" else str(data.get("verdict") or "sample")
        if module == "forensics":
            n = (data.get("analysis_result") or {}).get("total_findings", 0)
            return f"{n} finding(s)"
    except Exception:
        pass
    return "analysis"


class SOCChatPanel(QWidget):
    """
    AI SOC Analyst Chatbot panel — can be embedded in any page.
    Call set_context(module, data_dict) after each analysis to inject context.
    """
    QUICK_ACTIONS = [
        ("Explain Threat",     "Jelaskan secara detail ancaman yang ditemukan dalam analisis ini."),
        ("Recommended Action", "Apa tindakan yang harus segera dilakukan berdasarkan temuan ini?"),
        ("Is This Malicious?", "Apakah temuan ini benar-benar berbahaya atau bisa merupakan false positive? Jelaskan alasannya."),
        ("Executive Summary",  "Buat ringkasan eksekutif singkat dari hasil analisis ini untuk dilaporkan ke manajemen."),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._context   = {}
        self._module    = "unknown"
        self._history   = []
        self._worker    = None
        self._retired   = []
        self._ctx_gen   = 0            # bumped on every context change (stale delayed-callback guard)
        self._shut_down = False
        self._build_ui()
        # Panel-owned, coalescing scroll timer: stops with the panel (no dangling callbacks).
        self._scroll_timer = QTimer(self)
        self._scroll_timer.setSingleShot(True)
        self._scroll_timer.setInterval(50)
        self._scroll_timer.timeout.connect(self._scroll_to_bottom)

    # ── Context injection ──────────────────────────────────────────────────
    def resizeEvent(self, event):
        super().resizeEvent(event)
        if getattr(self, "_qa_btns", None):
            reflow_buttons(self._qa_grid, self._qa_btns, self.width() - 16)

    def _retire_worker(self):
        """Detach an in-flight ChatWorker so its reply (generated under the old
        context) can never land in the new context; keep it referenced until it
        finishes so the QThread is never destroyed while running."""
        w = self._worker
        self._worker = None
        if w is None:
            return
        for sig in (w.reply_ready, w.error):
            try:
                sig.disconnect()
            except TypeError:
                pass
        if is_busy(w):
            self._retired.append(w)
            w.finished.connect(lambda o=w: self._retired.remove(o) if o in self._retired else None)
        self._loading.setVisible(False)
        self._btn_send.setEnabled(True)
        self._inp.setEnabled(True)

    def set_context(self, module: str, data: dict):
        self._ctx_gen += 1
        self._retire_worker()
        self._module  = module
        self._context = data
        self._history = []

        mc = _CHAT_MODULE_COLORS.get(module, P["accent"])
        target = chat_context_target(module, data)
        shown = target if len(target) <= 26 else target[:25] + "…"
        self._lbl_ctx.setText("Active Context")
        self._lbl_ctx.setStyleSheet(
            f"color:{P['text_label']};font-size:11px;font-weight:600;background:transparent;border:none;")
        self._mod_badge.setText(f"{module.upper()} • {shown}")
        self._mod_badge.setToolTip(f"{module.upper()} • {target}")
        self._mod_badge.setStyleSheet(
            f"color:{mc};background:{_tint(mc, 30)};border:1px solid {_tint(mc, 110)};"
            f"border-radius:10px;font-size:11px;font-weight:700;padding:2px 10px;")
        self._mod_badge.setVisible(True)
        self._set_dot(P["low"])

        msg = f"[OK] Konteks analisis [{module.upper()}] berhasil dimuat. Silakan tanyakan apa saja."
        log_event(f"[CHATBOT] set_context called: module={module}")
        safe_single_shot(self, 0, lambda m=msg, gen=self._ctx_gen: (
            self._append_system_note(m) if gen == self._ctx_gen and not self._shut_down else None))

    def explain_context(self, module: str, context: dict):
        """Entry point for the Analysis History 'Explain' button: injects
        the selected history record as context, then automatically asks
        the AI to explain it — no user typing required. Uses the same
        QThread-backed _send() as every other message, so the UI never
        freezes while waiting on the API."""
        self.set_context(module, context)
        prompt = (
            "Jelaskan hasil analisis ini.\n\n"
            "Mengapa IOC/temuan ini mendapatkan severity tersebut?\n\n"
            "Jelaskan: evidence, reputation, risk, potential impact, dan recommended action.\n\n"
            "Bedakan confirmed fact dengan suspicion. Jangan mengarang malware family, "
            "campaign, CVE, atau attacker identity jika tidak ada di data yang diberikan."
        )
        # Only send if the context is still the one that was explained.
        safe_single_shot(self, 150, lambda gen=self._ctx_gen: (
            self._send(prompt) if gen == self._ctx_gen and not self._shut_down else None))

    # ── Clear chat ─────────────────────────────────────────────────────────
    def _clear_chat(self):
        """Remove all chat bubbles, keep only the trailing stretch."""
        while self._chat_layout.count() > 1:
            item = self._chat_layout.takeAt(0)
            if item.widget():
                item.widget().hide()
                item.widget().deleteLater()
        self._history = []
        self._lbl_ctx.setText("Waiting for analysis context…")
        self._lbl_ctx.setStyleSheet(
            f"color:{P['text_dim']};font-size:11px;background:transparent;border:none;")
        self._mod_badge.setVisible(False)
        self._set_dot(P["text_dim"])
        self._chat_stack.setCurrentIndex(0)

    def _set_dot(self, color: str):
        self._status_dot.setStyleSheet(f"color:{color};font-size:12px;background:transparent;border:none;")

    # ── UI ─────────────────────────────────────────────────────────────────
    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Header ───────────────────────────────────────────────────────
        hdr = QFrame(); hdr.setObjectName("chathdr")
        hdr.setStyleSheet(
            f"QFrame#chathdr{{background:{P['bg_panel']};border-bottom:1px solid {P['border']};}}")
        hdr_l = QVBoxLayout(hdr)
        hdr_l.setContentsMargins(14, 12, 12, 10)
        hdr_l.setSpacing(8)

        top_row = QHBoxLayout(); top_row.setSpacing(8)
        top_row.addWidget(IconLabel("ai", P["accent"], 18))
        title_lbl = QLabel("AI SOC ANALYST")
        title_lbl.setStyleSheet(
            f"color:{P['text_main']};font-size:13px;font-weight:700;background:transparent;border:none;")
        top_row.addWidget(title_lbl)
        top_row.addStretch()
        btn_clear = ModernButton("Clear", "ghost", icon="trash", tooltip="Clear the conversation")
        btn_clear.setMinimumHeight(28)
        btn_clear.clicked.connect(self._clear_chat)
        self._btn_clear = btn_clear
        top_row.addWidget(btn_clear)
        hdr_l.addLayout(top_row)

        ctx_row = QHBoxLayout(); ctx_row.setSpacing(8)
        self._status_dot = QLabel("●")
        self._set_dot(P["text_dim"])
        ctx_row.addWidget(self._status_dot)
        self._lbl_ctx = QLabel("Waiting for analysis context…")
        self._lbl_ctx.setStyleSheet(
            f"color:{P['text_dim']};font-size:11px;background:transparent;border:none;")
        ctx_row.addWidget(self._lbl_ctx)
        ctx_row.addStretch()
        self._mod_badge = QLabel("")
        self._mod_badge.setVisible(False)
        ctx_row.addWidget(self._mod_badge)
        hdr_l.addLayout(ctx_row)
        layout.addWidget(hdr)

        # ── Chat history (or empty state before the first message) ───────
        self._chat_area = QScrollArea()
        self._chat_area.setWidgetResizable(True)
        self._chat_area.setFrameShape(QFrame.NoFrame)
        self._chat_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._chat_area.setStyleSheet(
            f"QScrollArea{{background:{P['bg_dark']};border:none;}}"
            f"QScrollBar:vertical{{background:{P['bg_dark']};width:8px;}}"
            f"QScrollBar::handle:vertical{{background:{P['border2']};border-radius:4px;min-height:24px;}}"
            f"QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}")
        self._chat_inner = QWidget()
        self._chat_inner.setStyleSheet(f"background:{P['bg_dark']};")
        self._chat_layout = QVBoxLayout(self._chat_inner)
        self._chat_layout.setContentsMargins(12, 12, 12, 12)
        self._chat_layout.setSpacing(12)
        self._chat_layout.addStretch()
        self._chat_area.setWidget(self._chat_inner)

        empty_page = QWidget(); empty_page.setStyleSheet(f"background:{P['bg_dark']};")
        epl = QVBoxLayout(empty_page); epl.setContentsMargins(14, 14, 14, 14)
        self._chat_empty = AnalysisEmptyState(
            "ai", "No active context",
            "Run a CTI, Malware or Forensics analysis, then ask the AI SOC Analyst about the findings.")
        epl.addWidget(self._chat_empty); epl.addStretch()
        self._chat_stack = QStackedWidget()
        self._chat_stack.addWidget(empty_page)       # 0
        self._chat_stack.addWidget(self._chat_area)  # 1
        layout.addWidget(self._chat_stack, 1)

        # ── Typing / loading indicator ───────────────────────────────────
        self._loading = TypingIndicator("AI Analyst is analyzing…")
        layout.addWidget(self._loading)

        # ── Quick actions ────────────────────────────────────────────────
        qa_row = QWidget(); qa_row.setObjectName("qarow")
        qa_row.setStyleSheet(f"QWidget#qarow{{background:{P['bg_panel']};border-top:1px solid {P['border']};}}")
        qa_l = QGridLayout(qa_row); qa_l.setContentsMargins(10, 8, 10, 8); qa_l.setSpacing(6)
        self._qa_grid, self._qa_btns = qa_l, []
        for label, prompt in self.QUICK_ACTIONS:
            btn = ModernButton(label, "secondary", tooltip=prompt)
            btn.setMinimumHeight(30)
            btn.clicked.connect(lambda _, p=prompt: self._send(p))
            self._qa_btns.append(btn)
        reflow_buttons(qa_l, self._qa_btns, 264)
        layout.addWidget(qa_row)

        # ── Input row ────────────────────────────────────────────────────
        inp_row = QWidget(); inp_row.setObjectName("inprow")
        inp_row.setStyleSheet(f"QWidget#inprow{{background:{P['bg_panel']};border-top:1px solid {P['border']};}}")
        inp_l = QHBoxLayout(inp_row); inp_l.setContentsMargins(10, 10, 10, 10); inp_l.setSpacing(8)
        self._inp = QLineEdit()
        self._inp.setPlaceholderText("Tanyakan sesuatu... (contoh: Kenapa ini berbahaya?)")
        self._inp.setMinimumHeight(38)
        self._inp.returnPressed.connect(self._on_send)
        inp_l.addWidget(self._inp, 1)
        self._btn_send = ModernButton("Send", "primary", icon="send", tooltip="Send (Enter)")
        self._btn_send.setMinimumHeight(38)
        self._btn_send.clicked.connect(self._on_send)
        inp_l.addWidget(self._btn_send)
        layout.addWidget(inp_row)

    # ── Chat bubble helpers ────────────────────────────────────────────────
    def _append_bubble(self, text: str, role: str):
        """role: 'user' | 'assistant' | 'system'"""
        is_user = role == "user"
        is_sys  = role == "system"
        self._chat_stack.setCurrentIndex(1)

        bubble = QFrame(); bubble.setObjectName("chatbubble")
        if is_user:
            bg, bd, fg = P["accent2"], P["accent2"], "#FFFFFF"
        elif is_sys:
            bg, bd, fg = "transparent", P["border"], P["text_label"]
        else:
            bg, bd, fg = P["bg_card"], P["border"], P["text_main"]
        bubble.setStyleSheet(
            f"QFrame#chatbubble{{background:{bg};border:1px solid {bd};border-radius:12px;}}")
        bbl = QVBoxLayout(bubble)
        bbl.setContentsMargins(14, 10, 14, 10)
        bbl.setSpacing(4)

        if not is_user and not is_sys:
            hdr = QHBoxLayout(); hdr.setSpacing(6)
            role_lbl = QLabel("AI SOC ANALYST")
            role_lbl.setStyleSheet(
                f"color:{P['accent']};font-size:11px;font-weight:700;background:transparent;border:none;")
            hdr.addWidget(role_lbl)
            hdr.addStretch()
            import datetime as _dt
            tl = QLabel(_dt.datetime.now().strftime("%H:%M"))
            tl.setStyleSheet(f"color:{P['text_dim']};font-size:11px;background:transparent;border:none;")
            hdr.addWidget(tl)
            cp = IconButton("copy", "Copy answer", size=24)
            cp.clicked.connect(lambda _=False, t=text: QApplication.clipboard().setText(t))
            hdr.addWidget(cp)
            bbl.addLayout(hdr)

        txt_lbl = QTextBrowser()
        txt_lbl.setOpenExternalLinks(False)
        _h = (f"{{color:{P['accent']};font-size:13px;font-weight:600;margin-top:10px;margin-bottom:2px;}}")
        txt_lbl.document().setDefaultStyleSheet(
            f"h1{_h} h2{_h} h3{_h} h4{_h}"
            f"p{{margin-top:2px;margin-bottom:6px;}}"
            f"li{{margin-bottom:3px;}}"
            f"code{{font-family:{_FONT_MONO};font-size:12px;background-color:{P['bg_input']};}}")
        txt_lbl.setMarkdown(text if (is_user or is_sys) else prettify_chat_markdown(text))
        if not (is_user or is_sys):
            _colorize_risk_level(txt_lbl.document())
        txt_lbl.setReadOnly(True)
        txt_lbl.setStyleSheet(
            f"QTextBrowser{{background:transparent;color:{fg};font-size:{'12' if is_sys else '13'}px;"
            f"border:none;padding:0px;}}")
        txt_lbl.setMinimumHeight(20)
        txt_lbl.document().setDocumentMargin(0)
        txt_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        txt_lbl.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        txt_lbl.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        txt_lbl.document().documentLayout().documentSizeChanged.connect(
            lambda sz, w=txt_lbl: w.setFixedHeight(int(sz.height()) + 10)
        )
        bbl.addWidget(txt_lbl)

        wrapper = QWidget()
        wrapper.setStyleSheet("background:transparent;")
        wl = QHBoxLayout(wrapper)
        wl.setContentsMargins(0, 0, 0, 0)
        if is_user:
            wl.addStretch()
            bubble.setMaximumWidth(480)
        else:
            bubble.setMaximumWidth(640)
        wl.addWidget(bubble)
        if not is_user:
            wl.addStretch()

        count = self._chat_layout.count()
        self._chat_layout.insertWidget(count - 1, wrapper)
        self._scroll_timer.start()

    def _scroll_to_bottom(self):
        area = getattr(self, "_chat_area", None)
        if self._shut_down or area is None or _sip.isdeleted(area):
            return
        bar = area.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _append_system_note(self, text: str):
        if self._shut_down or _sip.isdeleted(self):
            return
        self._append_bubble(text, "system")
        self._lbl_ctx.setText("Active Context")

    def shutdown(self, timeout_ms: int = 3000):
        """Stop timers and finish/stop every AI worker. Call from the owner's closeEvent."""
        self._shut_down = True
        self._scroll_timer.stop()
        workers = ([self._worker] if self._worker is not None else []) + list(self._retired)
        try:
            self._retire_worker()
        except RuntimeError as exc:
            log_event(f"SOCChatPanel.shutdown: widgets already gone: {exc}")
        for w in workers:
            w.requestInterruption()
            if not w.wait(timeout_ms):
                log_event("SOCChatPanel.shutdown: AI worker still running after "
                          f"{timeout_ms} ms — terminating thread at application exit")
                w.terminate()
                w.wait(500)
        self._retired.clear()

    # ── Send logic ─────────────────────────────────────────────────────────
    def _on_send(self):
        text = self._inp.text().strip()
        if not text:
            return
        self._inp.clear()
        self._send(text)

    def _send(self, user_text: str):
        if self._worker and self._worker.isRunning():
            self._append_bubble("AI Analyst masih memproses permintaan sebelumnya.", "system")
            return  # busy

        # Show user bubble
        self._append_bubble(user_text, "user")

        # Build context snippet
        ctx_json = ""
        if self._context:
            try:
                ctx_json = json.dumps(self._context, ensure_ascii=False, default=str)
            except Exception:
                ctx_json = str(self._context)
            if len(ctx_json) > 6000:
                ctx_json = ctx_json[:6000] + " …[TRUNCATED: konteks dipotong, sebagian data TIDAK TERSEDIA]"

        if not self._context:
            fallback = (
                "Data analisis tidak tersedia. Mohon jalankan analisis terlebih dahulu "
                "sebelum bertanya kepada AI SOC Analyst."
            )
            self._append_bubble(fallback, "assistant")
            return

        # System prompt
        sys_prompt = (
            "Kamu adalah Senior SOC Analyst berpengalaman 10 tahun. "
            "Jawab SELALU dalam Bahasa Indonesia profesional. "
            "Boleh gunakan istilah teknis Inggris (IOC, CVE, MITRE, dll). "
            "Jangan hallusinasi — hanya analisis data yang diberikan. "
            "Bedakan secara eksplisit: FAKTA TERCATAT (ada di data), INDIKASI, HIPOTESIS, "
            "dan DATA TIDAK TERSEDIA. Jangan menyatakan ancaman 'confirmed' bila evidence tidak cukup; "
            "field yang kosong/None disebut tidak tersedia, bukan ditebak. "
            "Jangan overreact jika tidak ada ancaman nyata. "
            "Gunakan format wajib berikut:\n\n"
            "**Analisis:**\n[penjelasan kontekstual]\n\n"
            "**Risiko:** LOW / MEDIUM / HIGH / CRITICAL\n\n"
            "**Alasan:**\n[mengapa dianggap demikian]\n\n"
            "**Rekomendasi:**\n[langkah konkret yang harus dilakukan]\n\n"
            f"=== KONTEKS ANALISIS [{self._module.upper()}] ===\n{ctx_json}"
        )

        # Build messages with memory (last 5 turns)
        messages = [{"role": "system", "content": sys_prompt}]
        messages += self._history[-10:]  # last 5 exchanges = 10 messages
        messages.append({"role": "user", "content": user_text})

        # Update history
        self._history.append({"role": "user", "content": user_text})
        if len(self._history) > 10:
            self._history = self._history[-10:]

        # Start worker
        self._loading.setVisible(True)
        self._set_dot(P["accent"])
        self._btn_send.setEnabled(False)
        self._inp.setEnabled(False)
        w = ChatWorker(messages)
        self._worker = w
        w.reply_ready.connect(lambda t, w=w: self._on_reply(t) if w is self._worker else None)
        w.error.connect(lambda e, w=w: self._on_error(e) if w is self._worker else None)
        w.start()

    def _on_reply(self, text: str):
        if _sip.isdeleted(self):
            return                      # window closed while the request was in flight
        self._loading.setVisible(False)
        self._set_dot(P["low"])
        self._btn_send.setEnabled(True)
        self._inp.setEnabled(True)
        self._append_bubble(text, "assistant")
        self._history.append({"role": "assistant", "content": text})
        if len(self._history) > 10:
            self._history = self._history[-10:]

    def _on_error(self, err: str):
        if _sip.isdeleted(self):
            return
        self._loading.setVisible(False)
        self._btn_send.setEnabled(True)
        self._inp.setEnabled(True)
        self._set_dot(P["critical"])
        self._append_bubble(f"⚠️ Error: {err}", "system")


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 14 — MAIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════════════════════════
# SMOOTH SPLITTER — enterprise-grade panel resize UX
#   • wide interactive hitbox with a slim visual line
#   • hover / drag glow feedback + cursor change
#   • realtime drag (QSplitter handles the actual geometry — no jitter)
#   • double-click / button collapse-restore with a short eased animation
#   • proportional sizing that survives window resizes
#   • layout persistence via QSettings
# ════════════════════════════════════════════════════════════════════════════

class SmoothSplitterHandle(QSplitterHandle):
    """Custom handle: thin line visually, wide drag hitbox, hover/drag glow,
    proper cursor feedback and an optional collapse/restore button.

    NOTE: this class only owns visuals, cursor, hover state and the optional
    double-click / button collapse action. Actual resize dragging is left
    entirely to QSplitter's built-in mouse handling (mousePressEvent /
    mouseMoveEvent / mouseReleaseEvent are NOT overridden for dragging),
    which is what keeps the drag perfectly realtime and jitter-free.
    """

    _LINE_NORMAL = P["border2"]
    _LINE_HOVER  = P["accent"]
    _LINE_DRAG   = P["accent2"]

    def __init__(self, orientation, parent):
        super().__init__(orientation, parent)
        self.setMouseTracking(True)
        self._hovered = False
        self._dragging = False
        self.setCursor(Qt.SizeHorCursor if orientation == Qt.Horizontal else Qt.SizeVerCursor)

        # Small optional collapse/restore button, only visible on hover.
        self._collapse_btn = QPushButton("‹", self)
        self._collapse_btn.setCursor(Qt.PointingHandCursor)
        self._collapse_btn.setFocusPolicy(Qt.NoFocus)
        self._collapse_btn.setFixedSize(14, 32)
        self._collapse_btn.setToolTip("Collapse / restore this panel (double-click the handle)")
        self._collapse_btn.setStyleSheet(
            f"QPushButton{{background:{P['bg_card']};color:{P['text_label']};"
            f"border:1px solid {P['border2']};border-radius:4px;font-size:11px;padding:0;}}"
            f"QPushButton:hover{{background:{_tint(P['accent'], 45)};color:{P['accent']};"
            f"border-color:{P['accent']};}}"
        )
        self._collapse_btn.hide()
        self._collapse_btn.clicked.connect(self._on_collapse_clicked)

    # ── hover / drag state (visual only) ────────────────────────────────
    def enterEvent(self, event):
        self._hovered = True
        self._collapse_btn.show()
        self._position_button()
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hovered = False
        self._collapse_btn.hide()
        self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        # Only flag drag state for the glow effect; let QSplitterHandle do
        # the actual, realtime resize work itself.
        self._dragging = True
        self.update()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self._dragging = False
        self.update()
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):
        self._on_collapse_clicked()
        super().mouseDoubleClickEvent(event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._position_button()

    def _position_button(self):
        x = (self.width() - self._collapse_btn.width()) // 2
        y = (self.height() - self._collapse_btn.height()) // 2
        self._collapse_btn.move(max(0, x), max(0, y))

    def _on_collapse_clicked(self):
        splitter = self.splitter()
        if isinstance(splitter, SmoothSplitter):
            splitter.toggle_collapse_at(self)

    def set_collapsed_glyph(self, collapsed: bool):
        self._collapse_btn.setText("›" if collapsed else "‹")

    # ── painting: slim line, wide hitbox, glow feedback ─────────────────
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        rect = self.rect()
        horizontal = self.orientation() == Qt.Horizontal

        if self._dragging:
            color, line_w, glow = QColor(self._LINE_DRAG), 3, True
        elif self._hovered:
            color, line_w, glow = QColor(self._LINE_HOVER), 2, True
        else:
            color, line_w, glow = QColor(self._LINE_NORMAL), 1, False

        cx, cy = rect.center().x(), rect.center().y()

        if glow:
            glow_color = QColor(color)
            glow_color.setAlpha(60)
            painter.setPen(Qt.NoPen)
            painter.setBrush(glow_color)
            if horizontal:
                painter.drawRoundedRect(cx - 4, rect.top(), 8, rect.height(), 3, 3)
            else:
                painter.drawRoundedRect(rect.left(), cy - 4, rect.width(), 8, 3, 3)

        pen = QPen(color)
        pen.setWidth(line_w)
        pen.setCapStyle(Qt.RoundCap)
        painter.setPen(pen)
        if horizontal:
            painter.drawLine(cx, rect.top() + 2, cx, rect.bottom() - 2)
        else:
            painter.drawLine(rect.left() + 2, cy, rect.right() - 2, cy)
        # grip dots: a resting-state affordance so the drag handle is discoverable
        if not self._hovered and not self._dragging:
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(P["text_dim"]))
            for k in (-8, 0, 8):
                if horizontal:
                    painter.drawEllipse(QPointF(cx, cy + k), 1.5, 1.5)
                else:
                    painter.drawEllipse(QPointF(cx + k, cy), 1.5, 1.5)
        painter.end()


class SmoothSplitter(QSplitter):
    """QSplitter tuned for a smooth, modern, enterprise-grade resize UX.

    - Wide (8-12px) interactive hitbox via setHandleWidth(), slim visual line
      drawn by SmoothSplitterHandle.
    - setOpaqueResize(True) + no per-move animation => panels follow the
      mouse in realtime with zero lag/jitter.
    - Optional proportional sizing that is preserved across window resizes.
    - Double-click / button collapse-restore uses a short QVariantAnimation
      (150-250ms, OutCubic) — animation is used ONLY for collapse/expand,
      never for live dragging.
    - Layout can be persisted/restored via QSettings.
    """

    ANIM_MS = 200

    def __init__(self, orientation=Qt.Horizontal, parent=None):
        super().__init__(orientation, parent)
        self.setHandleWidth(10)             # slim line, ~10px drag hitbox
        self.setChildrenCollapsible(False)  # no accidental "vanishing" panels
        self.setOpaqueResize(True)          # realtime, non-delayed drag
        self._proportions = None            # list[float] summing to ~1.0
        self._collapsed_sizes = {}          # widget index -> size before collapse
        self._anim = None                   # active QVariantAnimation

    def createHandle(self):
        return SmoothSplitterHandle(self.orientation(), self)

    # ── proportional sizing ──────────────────────────────────────────────
    def set_initial_proportions(self, proportions):
        """proportions: list[float] (one per child widget) summing to ~1.0."""
        self._proportions = list(proportions)
        self._apply_proportions()

    def _apply_proportions(self):
        if not self._proportions:
            return
        total = self.width() if self.orientation() == Qt.Horizontal else self.height()
        total = max(total, 1)
        sizes = [max(1, int(total * p)) for p in self._proportions]
        self.setSizes(sizes)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Re-derive proportions from the *current* sizes on every resize so
        # panels grow/shrink together, keeping Main Content dominant, without
        # fighting the user mid-drag.
        if self._proportions and not self._is_dragging():
            total = sum(self.sizes())
            if total > 0:
                self._proportions = [max(1, s) / total for s in self.sizes()]

    def _is_dragging(self):
        for i in range(1, self.count()):
            h = self.handle(i)
            if isinstance(h, SmoothSplitterHandle) and h._dragging:
                return True
        return False

    # ── collapse / restore (animated) ────────────────────────────────────
    def toggle_collapse_at(self, handle):
        """Collapse/restore the widget that sits AFTER the given handle."""
        idx = None
        for i in range(1, self.count()):
            if self.handle(i) is handle:
                idx = i
                break
        if idx is None:
            return

        sizes = self.sizes()
        collapsing = sizes[idx] > 4
        if collapsing:
            self._collapsed_sizes[idx] = sizes[idx]
            self._animate_size(idx, sizes[idx], 0)
            handle.set_collapsed_glyph(True)
        else:
            widget = self.widget(idx)
            fallback = widget.minimumWidth() if widget and widget.minimumWidth() > 0 else 260
            target = self._collapsed_sizes.get(idx, fallback)
            self._animate_size(idx, sizes[idx], target)
            handle.set_collapsed_glyph(False)

    def _animate_size(self, idx, start, end):
        anim = QVariantAnimation(self)
        anim.setStartValue(int(start))
        anim.setEndValue(int(end))
        anim.setDuration(self.ANIM_MS)
        anim.setEasingCurve(QEasingCurve.OutCubic)

        def _step(value):
            sizes = self.sizes()
            if idx >= len(sizes):
                return
            delta = value - sizes[idx]
            sizes[idx] = value
            # Compensate into the stretchy "main content" panel (index 0)
            # so the overall splitter width never changes mid-animation.
            main_idx = 0 if idx != 0 else (1 if self.count() > 1 else 0)
            sizes[main_idx] = max(50, sizes[main_idx] - delta)
            self.setSizes(sizes)

        anim.valueChanged.connect(_step)
        self._anim = anim
        anim.start()

    # ── persistence ───────────────────────────────────────────────────────
    def save_layout(self, settings: QSettings, key: str):
        sizes = self.sizes()
        settings.setValue(key, ",".join(str(s) for s in sizes))

    def restore_layout(self, settings: QSettings, key: str) -> bool:
        raw = settings.value(key, None)
        if not raw:
            return False
        try:
            sizes = [int(x) for x in str(raw).split(",") if x != ""]
        except ValueError:
            return False
        if len(sizes) != self.count() or sum(sizes) <= 0:
            return False
        self.setSizes(sizes)
        total = sum(sizes)
        self._proportions = [s / total for s in sizes]
        return True


def load_app_icon() -> "QIcon":
    """Multi-size guardian_ai icon (ICO → PNG fallback). Never raises."""
    ic = QIcon()
    for rel in (ICON_REL_PATH, PNG_REL_PATH):
        path = resource_path(rel)
        if os.path.isfile(path):
            ic = QIcon(path)
            if not ic.isNull():
                return ic
    print(f"[WARN] guardian_ai icon not found under {resource_path('assets')}", flush=True)
    return ic


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("guardian_ai — AI Security Operations Center")
        self.setWindowIcon(load_app_icon())
        # Minimum width accounts for sidebar (232px expanded) + Main Content's
        # own 500px minimum, so the compact/responsive breakpoints below are
        # actually reachable rather than blocked by the window itself.
        self.resize(1400, 860); self.setMinimumSize(760, 640)
        self._settings = QSettings("guardian_ai", "UI")
        self._build()
        self._build_menu()
        if self._settings.value("sidebar_collapsed", False, type=bool):
            self._sb_user_set = True
            self._set_sidebar_collapsed(True, animate=False)
        safe_single_shot(self, 0, self._init_splitter_layout)

    def _build(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QHBoxLayout(central); root.setContentsMargins(0,0,0,0); root.setSpacing(0)

        # ── Sidebar (collapsible; painted nav buttons, sectioned) ───────────
        sb = QWidget(); sb.setObjectName("sidebar"); self._sb = sb
        sb.setFixedWidth(self._SIDEBAR_WIDTH)
        sb.setStyleSheet(
            f"QWidget#sidebar{{background:{P['sidebar_bg']};border-right:1px solid {P['border']};}}"
        )
        sbl = QVBoxLayout(sb); sbl.setContentsMargins(0, 0, 0, 0); sbl.setSpacing(0)

        # Brand block (height matches the global header so the two rules line up)
        logo = QWidget(); logo.setObjectName("sblogo"); logo.setFixedHeight(64)
        logo.setStyleSheet(
            f"QWidget#sblogo{{background:transparent;border-bottom:1px solid {P['border']};}}"
        )
        self._sb_logo_l = ll2 = QHBoxLayout(logo)
        ll2.setContentsMargins(14, 8, 12, 8); ll2.setSpacing(10)
        mark = QLabel(); mark.setFixedSize(36, 36)
        mark.setStyleSheet("background:transparent;border:none;")
        _mk = QPixmap(resource_path(PNG_REL_PATH))
        if not _mk.isNull():
            _dpr = self.devicePixelRatioF() if hasattr(self, "devicePixelRatioF") else 1.0
            _mk = _mk.scaled(int(36 * _dpr), int(36 * _dpr), Qt.KeepAspectRatio, Qt.SmoothTransformation)
            _mk.setDevicePixelRatio(_dpr)
            mark.setPixmap(_mk)
        self._brand_text = QWidget(); self._brand_text.setStyleSheet("background:transparent;")
        txt = QVBoxLayout(self._brand_text); txt.setContentsMargins(0, 0, 0, 0); txt.setSpacing(0)
        brand = QLabel("guardian_ai")
        brand.setStyleSheet(
            f"color:{P['text_main']};font-weight:700;font-size:17px;"
            f"background:transparent;border:none;"
        )
        sub = QLabel("AI Security Operations Center")
        sub.setWordWrap(True)
        sub.setStyleSheet(
            f"color:{P['text_label']};font-size:11px;"
            f"background:transparent;border:none;"
        )
        txt.addWidget(brand); txt.addWidget(sub)
        ll2.addWidget(mark); ll2.addWidget(self._brand_text, 1)
        sbl.addWidget(logo)

        self._nav_btns = []
        sbl.addSpacing(6)
        sbl.addWidget(SidebarSection("OVERVIEW"))
        nav_items = [
            ("dashboard", "Dashboard",        0),
            ("cti",       "CTI",              1),
            ("malware",   "Malware Analysis", 2),
            ("forensics", "Forensics",        3),
        ]
        for icon, label, idx in nav_items:
            if idx == 1:
                sbl.addWidget(SidebarSection("SECURITY MODULES"))
            btn = SidebarButton(icon, label)
            btn.setText(label)                      # a11y / legacy text; painting uses its own label
            btn.setToolTip(f"{label}  (Ctrl+{idx + 1})")
            btn.clicked.connect(lambda _, i=idx: self._switch(i))
            sbl.addWidget(btn)
            self._nav_btns.append(btn)

        sbl.addWidget(SidebarSection("TOOLS"))
        self._btn_chat_toggle = SidebarButton("ai", "AI SOC Analyst")
        self._btn_chat_toggle.clicked.connect(self._toggle_chat)
        sbl.addWidget(self._btn_chat_toggle)

        self._btn_history_toggle = SidebarButton("history", "Analysis History")
        self._btn_history_toggle.clicked.connect(self._toggle_history)
        sbl.addWidget(self._btn_history_toggle)

        sbl.addStretch()

        # Footer
        foot_frame = QFrame(); self._sb_footer = foot_frame
        foot_frame.setStyleSheet(
            f"QFrame{{background:transparent;border-top:1px solid {P['border']};}}"
        )
        foot_l = QVBoxLayout(foot_frame); foot_l.setContentsMargins(16, 10, 16, 10); foot_l.setSpacing(2)
        powered_lbl = QLabel("AI analysis powered by Groq")
        powered_lbl.setStyleSheet(
            f"color:{P['text_dim']};font-size:11px;background:transparent;border:none;"
        )
        foot_l.addWidget(powered_lbl)
        import datetime as _dt
        ver_lbl = QLabel(f"guardian_ai v2.0  •  {_dt.date.today().year}")
        ver_lbl.setStyleSheet(
            f"color:{P['text_dim']};font-size:11px;background:transparent;border:none;"
        )
        foot_l.addWidget(ver_lbl)
        sbl.addWidget(foot_frame)
        root.addWidget(sb)

        # ── Right column: global header + (pages | chat | history) ───────────
        right = QWidget(); right.setObjectName("rightcol")
        rcol = QVBoxLayout(right); rcol.setContentsMargins(0, 0, 0, 0); rcol.setSpacing(0)
        self._header = HeaderBar(); self._header.setFixedHeight(64)
        self._header.menu_clicked.connect(self._toggle_sidebar)
        rcol.addWidget(self._header)
        self._refresh_system_status()


        # ── Main splitter: pages | chat panel | history panel ─────────────
        self._main_splitter = SmoothSplitter(Qt.Horizontal)
        rcol.addWidget(self._main_splitter, 1)
        root.addWidget(right, 1)

        # Pages
        self.pages = QStackedWidget()
        self.pg_dash    = DashboardPage()
        self.pg_cti     = CTIPage()
        self.pg_malware = MalwarePage()
        self.pg_forensics = ForensicsPage()
        for pg in [self.pg_dash, self.pg_cti, self.pg_malware, self.pg_forensics]:
            self.pages.addWidget(pg)
        self.pages.setMinimumWidth(500)
        self._main_splitter.addWidget(self.pages)

        # ── AI Chatbot Panel ───────────────────────────────────────────────
        self._chat_panel = SOCChatPanel()
        self._chat_panel.setMinimumWidth(280)
        self._chat_panel.setMaximumWidth(550)
        self._chat_panel.setObjectName("chatpanel")   # scoped: a bare QSS would cascade into every child
        self._chat_panel.setStyleSheet(f"QWidget#chatpanel{{background:{P['bg_dark']};border-left:1px solid {P['border']};}}")
        self._main_splitter.addWidget(self._chat_panel)

        # ── Analysis History Panel ─────────────────────────────────────────
        self._history_panel = AnalysisHistoryPanel()
        self._history_panel.setMinimumWidth(260)
        self._history_panel.setMaximumWidth(500)
        self._history_panel.setObjectName("historypanel")
        self._history_panel.setStyleSheet(f"QWidget#historypanel{{background:{P['sidebar_bg']};border-left:1px solid {P['border']};}}")
        self._main_splitter.addWidget(self._history_panel)

        # Main Content must never collapse to 0; the two side panels may
        # (double-click the handle, the small ‹/› button, or a hard drag —
        # standard Qt collapsible behavior). setChildrenCollapsible(False)
        # above still stops *accidental* micro-jitter collapse on the other
        # handle pairs; this is a deliberate, per-panel opt-in.
        self._main_splitter.setCollapsible(0, False)
        self._main_splitter.setCollapsible(1, True)
        self._main_splitter.setCollapsible(2, True)

        # Sensible default proportions (Main 65% / AI 18% / History 17%);
        # actual sizing is applied once the window has a real width, and
        # restored from the last saved layout when available — see
        # _init_splitter_layout(), called via QTimer.singleShot(0, ...).
        self._default_proportions = [0.65, 0.18, 0.17]
        self._chat_visible = True
        self._history_visible = True

        # Wire forensics → CTI integration
        self.pg_forensics.cti_lookup_requested.connect(self._goto_cti)

        # Wire dashboard quick-nav actions
        self.pg_dash.goto_cti.connect(self._goto_cti)
        self.pg_dash.goto_history.connect(self._open_history_panel)
        self.pg_dash.goto_chat.connect(self._open_chat_panel)

        # Wire analysis context → chatbot
        self.pg_cti.context_ready.connect(self._chat_panel.set_context)
        self.pg_malware.context_ready.connect(self._chat_panel.set_context)
        self.pg_forensics.context_ready.connect(self._chat_panel.set_context)

        # Wire analysis done → dashboard refresh
        self.pg_cti.context_ready.connect(lambda *_: self.pg_dash.refresh_now())
        self.pg_malware.context_ready.connect(lambda *_: self.pg_dash.refresh_now())
        self.pg_forensics.context_ready.connect(lambda *_: self.pg_dash.refresh_now())

        # Wire analysis done → history panel refresh
        self.pg_cti.context_ready.connect(lambda *_: self._history_panel.refresh())
        self.pg_malware.context_ready.connect(lambda *_: self._history_panel.refresh())
        self.pg_forensics.context_ready.connect(lambda *_: self._history_panel.refresh())

        # Wire history load → re-display analysis results
        self._history_panel.load_requested.connect(self._reload_from_history)

        # Wire Investigation Workflow: Investigate → owning module,
        # Explain → AI SOC Analyst. Timeline is handled inside the history
        # panel itself since nothing else needs to react to it.
        self._history_panel.investigate_requested.connect(self._investigate_from_history)
        self._history_panel.explain_requested.connect(self._explain_from_history)

        for i in range(4):
            QShortcut(QKeySequence(f"Ctrl+{i + 1}"), self, activated=lambda i=i: self._switch(i))
        QShortcut(QKeySequence("Ctrl+B"), self, activated=self._toggle_sidebar)

        self._switch(0)
        self._update_toggle_labels()

    # ── System status (honest: reflects configured integrations) ──────────
    _SERVICES = [("virustotal", "VirusTotal"), ("abuseipdb", "AbuseIPDB"), ("shodan", "Shodan"),
                 ("hybrid_analysis", "Hybrid Analysis"), ("groq", "Groq AI")]

    def _refresh_system_status(self):
        try:
            flags = [(name, bool(is_api_key_configured(key))) for key, name in self._SERVICES]
        except Exception:
            flags = [(name, False) for _, name in self._SERVICES]
        n = sum(1 for _, ok in flags if ok)
        if n == len(flags):
            text, color = "SYSTEM STATUS: ONLINE", P["low"]
        elif n == 0:
            text, color = "SYSTEM STATUS: LOCAL ONLY", P["medium"]
        else:
            text, color = f"SYSTEM STATUS: PARTIAL · {n}/{len(flags)} INTEGRATIONS", P["medium"]
        tip = "Local analysis engines: available\n" + "\n".join(
            f"{'✔' if ok else '✖'} {name}: {'configured' if ok else 'not configured (feature disabled)'}"
            for name, ok in flags)
        self._header.set_status(text, color, tip)

    # ── Collapsible sidebar ───────────────────────────────────────────────
    _SIDEBAR_COLLAPSED = 68
    _sb_collapsed = False
    _sb_user_set = False
    _sb_anim = None

    def _toggle_sidebar(self):
        self._sb_user_set = True
        self._set_sidebar_collapsed(not self._sb_collapsed, animate=True)

    def _set_sidebar_collapsed(self, collapsed: bool, animate: bool = True):
        self._sb_collapsed = collapsed
        self._settings.setValue("sidebar_collapsed", collapsed)
        target = self._SIDEBAR_COLLAPSED if collapsed else self._SIDEBAR_WIDTH
        if self._sb_anim is not None:
            self._sb_anim.stop()
            self._sb_anim = None

        def _finish():
            self._sb.setFixedWidth(target)
            self._brand_text.setVisible(not collapsed)
            self._sb_footer.setVisible(not collapsed)
            self._sb_logo_l.setContentsMargins(14 if not collapsed else 16, 8, 12 if not collapsed else 8, 8)
            self._header.menu_btn.setToolTip("Expand sidebar (Ctrl+B)" if collapsed else "Collapse sidebar (Ctrl+B)")
            self._sb_anim = None

        if collapsed:                      # hide text first so it never clips mid-animation
            self._brand_text.setVisible(False)
            self._sb_footer.setVisible(False)
        if not animate or not self.isVisible():
            _finish()
            return
        anim = QVariantAnimation(self)
        anim.setDuration(180)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.setStartValue(self._sb.width())
        anim.setEndValue(target)
        anim.valueChanged.connect(lambda v: self._sb.setFixedWidth(int(v)))
        anim.finished.connect(_finish)
        self._sb_anim = anim
        anim.start()

    def _init_splitter_layout(self):
        """Applied once the window has real geometry (see QTimer.singleShot
        in __init__). Restores the user's last saved layout if one exists,
        otherwise falls back to the default proportional split."""
        # Panels the user explicitly closed last time stay closed (responsive mode below can
        # still hide more on small windows, but never re-opens what the user closed).
        if not self._settings.value("chat_visible", True, type=bool):
            self._chat_panel.setVisible(False); self._chat_visible = False
        if not self._settings.value("history_visible", True, type=bool):
            self._history_panel.setVisible(False); self._history_visible = False
        self._update_toggle_labels()
        if not self._main_splitter.restore_layout(self._settings, "splitter_sizes"):
            self._main_splitter.set_initial_proportions(self._default_proportions)
        self._apply_responsive_mode()

    def _build_menu(self):
        menubar = self.menuBar()
        view_menu = menubar.addMenu("&View")
        reset_action = QAction("Reset Layout", self)
        reset_action.setStatusTip("Restore Main Content / AI Analyst / History to their default proportions")
        reset_action.triggered.connect(self._reset_layout)
        view_menu.addAction(reset_action)

    def _reset_layout(self):
        self._chat_visible = True
        self._history_visible = True
        self._chat_panel.setVisible(True)
        self._history_panel.setVisible(True)
        self._main_splitter.set_initial_proportions(self._default_proportions)
        self._update_toggle_labels()
        self._save_panel_visibility()

    _compact_applied = False
    _midwidth_applied = False

    def _apply_responsive_mode(self):
        """Narrow windows favor Main Content and make the side panels
        collapsible; very narrow windows switch to compact mode.

        Compact mode collapses the side panels ONCE when the window shrinks
        below the threshold (and keeps the visibility flags in sync), so the
        sidebar buttons can immediately re-open them and a later resize does
        not fight the user's choice."""
        width = self.width()
        if width < 1100 and hasattr(self, "_sb") and not self._sb_user_set and not self._sb_collapsed:
            self._sb_user_set = True          # one-shot: later resizes never fight the user
            self._set_sidebar_collapsed(True, animate=False)
        if width < 900:
            if not self._compact_applied:
                self._compact_applied = True
                if not self._chat_panel.isHidden():
                    self._chat_panel.setVisible(False)
                if not self._history_panel.isHidden():
                    self._history_panel.setVisible(False)
                self._chat_visible = False
                self._history_visible = False
                self._update_toggle_labels()
        else:
            self._compact_applied = False
        # Mid-width tier (laptops, e.g. 1366x768 / 1280x720): three side-by-side panels
        # leave the main content too narrow, so the history panel starts collapsed. It is
        # one click away in the sidebar and a later resize does not fight the user's choice.
        if width < 1400:
            if not self._midwidth_applied:
                self._midwidth_applied = True
                if not self._history_panel.isHidden():
                    self._history_panel.setVisible(False)
                    self._history_visible = False
                    self._btn_history_toggle.setToolTip("Show Analysis History")
        else:
            self._midwidth_applied = False

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._apply_responsive_mode()

    def closeEvent(self, event):
        self._main_splitter.save_layout(self._settings, "splitter_sizes")
        self._chat_panel.shutdown()      # stop AI timers/workers before widgets are destroyed
        try:
            stuck = stop_all_threads(self.pg_dash, self.pg_cti, self.pg_malware, self.pg_forensics,
                                     self.pg_forensics.attack_graph_tab, self._chat_panel,
                                     self._history_panel)
            if stuck:
                log_event(f"closeEvent: threads still running at shutdown: {stuck}")
        except Exception as exc:
            log_event(f"closeEvent: thread shutdown error: {type(exc).__name__}: {exc}")
        super().closeEvent(event)

    # ── Panel visibility: one source of truth = the widget's real state ──────
    _CHAT_NAME = "AI SOC Analyst"
    _HISTORY_NAME = "Analysis History"

    def _update_toggle_labels(self):
        """Feature name is constant; only the [ON]/[OFF] suffix follows the real
        panel visibility. Never builds the label from the previous label text."""
        chat_on = not self._chat_panel.isHidden()
        hist_on = not self._history_panel.isHidden()
        self._chat_visible, self._history_visible = chat_on, hist_on
        self._btn_chat_toggle.setText(f"  🤖  {self._CHAT_NAME}  [{'ON' if chat_on else 'OFF'}]")
        self._btn_history_toggle.setText(f"  📋  {self._HISTORY_NAME}  [{'ON' if hist_on else 'OFF'}]")
        self._btn_chat_toggle.set_state(chat_on)       # painted ON/OFF pill (text above kept for a11y/tests)
        self._btn_history_toggle.set_state(hist_on)
        self._btn_chat_toggle.setToolTip(f"{'Hide' if chat_on else 'Show'} {self._CHAT_NAME}")
        self._btn_history_toggle.setToolTip(f"{'Hide' if hist_on else 'Show'} {self._HISTORY_NAME}")

    def _ensure_panel_open(self, which: str):
        """Show a side panel AND give it real pixels. Fixes the 'visible but 0 px wide'
        first-click failure: when the window is too narrow for main + both panels,
        the other panel is closed so the requested one is actually usable."""
        panels = {"chat": (self._chat_panel, 1), "history": (self._history_panel, 2)}
        panel, idx = panels[which]
        other_panel, other_idx = panels["history" if which == "chat" else "chat"]
        panel.setVisible(True)
        sp = self._main_splitter
        total = max(sp.width(), self.width() - self._sidebar_width_hint())
        main_min = self.pages.minimumWidth()
        need = main_min + panel.minimumWidth() + (0 if other_panel.isHidden() else other_panel.minimumWidth())
        if total < need:
            other_panel.setVisible(False)
        sizes = [0, 0, 0]
        sizes[idx] = max(panel.minimumWidth(), int(total * self._default_proportions[idx]))
        if not other_panel.isHidden():
            cur = sp.sizes()[other_idx]
            sizes[other_idx] = max(other_panel.minimumWidth(), cur)
        sizes[0] = max(main_min, total - sizes[1] - sizes[2])
        sp.setSizes(sizes)
        self._update_toggle_labels()

    _SIDEBAR_WIDTH = 232   # expanded width (collapsed: _SIDEBAR_COLLAPSED)

    def _sidebar_width_hint(self) -> int:
        return self._sb.width() if hasattr(self, "_sb") else self._SIDEBAR_WIDTH

    def _save_panel_visibility(self):
        self._settings.setValue("chat_visible", bool(self._chat_visible))
        self._settings.setValue("history_visible", bool(self._history_visible))

    def _toggle_chat(self):
        if self._chat_panel.isHidden():
            self._ensure_panel_open("chat")
        else:
            self._chat_panel.setVisible(False)
            self._update_toggle_labels()
        self._save_panel_visibility()       # user action → remembered across launches

    def _toggle_history(self):
        if self._history_panel.isHidden():
            self._ensure_panel_open("history")
            self._history_panel.refresh()
        else:
            self._history_panel.setVisible(False)
            self._update_toggle_labels()
        self._save_panel_visibility()

    def _open_history_panel(self):
        """Dashboard 'View All' / Investigation Log: always opens the history
        panel with usable width and (re)loads the list."""
        self._ensure_panel_open("history")
        self._history_panel.refresh()

    def _open_chat_panel(self):
        """Dashboard 'Ask AI Analyst'."""
        self._ensure_chat_open()

    def _reload_from_history(self, module: str, data: dict):
        """Re-display a previously saved analysis from history."""
        if module == "cti":
            self._switch(1)
            self.pg_cti._last_result = data
            self.pg_cti._display(data)
        elif module == "malware":
            self._switch(2)
            self.pg_malware._last_result = data
            self.pg_malware._display(data)
        elif module == "forensics":
            self._switch(3)
            self.pg_forensics._last_forensics_result = data
            self.pg_forensics._display(data)
            self.pg_forensics._display_timeline(data)

    def _investigate_from_history(self, module: str, entry: dict):
        """Investigate button entry point. Reuses each page's own display/
        run methods — HistoryPanel and MainWindow never duplicate CTI,
        malware or forensics logic here."""
        try:
            log_event(f"History investigate clicked: module={module} analysis_id={entry.get('id')}")
            try:
                data = json.loads(entry.get("raw_json") or "{}")
            except Exception:
                data = {}
            if module == "cti":
                self._switch(1)
                ioc = (entry.get("ioc") or "").strip()
                info = normalize_input(ioc) if ioc else {"type": "unknown"}
                if ioc and info.get("type") not in ("file_path", "unknown"):
                    # Live re-investigation, as requested by the spec.
                    self.pg_cti.inp.setText(ioc)
                    self.pg_cti._run()
                else:
                    # No usable IOC (or legacy entry) — fall back to the
                    # stored result rather than failing outright.
                    self.pg_cti._last_result = data
                    self.pg_cti._display(data)
            elif module == "malware":
                self._switch(2)
                # Historical result only — the original sample file is very
                # likely gone by now, so we never assume it still exists.
                self.pg_malware._last_result = data
                self.pg_malware._display(data)
            elif module == "forensics":
                self._switch(3)
                self.pg_forensics._last_forensics_result = data
                self.pg_forensics._display(data)
                self.pg_forensics._display_timeline(data)
            else:
                QMessageBox.information(self, "Investigate", "Modul analisis tidak dikenali.")
        except Exception as ex:
            log_event(f"History investigate error: {ex}")
            import traceback; log_event(traceback.format_exc())
            QMessageBox.warning(
                self, "Investigate",
                "Tidak dapat membuka analisis ini.\nDetail teknis telah disimpan di log."
            )

    def _ensure_chat_open(self):
        """Make the AI panel genuinely visible and sized (hidden by compact mode,
        toggled off, or collapsed to 0 px in the splitter)."""
        self._ensure_panel_open("chat")

    def _explain_from_history(self, module: str, context: dict):
        """Explain button entry point. Opens the AI SOC Analyst panel if it
        is hidden, injects the selected history record as context, and
        auto-asks the analyst to explain it."""
        try:
            log_event(
                f"History explain clicked: module={module} analysis_id={context.get('analysis_id')}"
            )
            self._ensure_chat_open()
            self._chat_panel.explain_context(module, context)
        except Exception as ex:
            log_event(f"History explain error: {ex}")
            import traceback; log_event(traceback.format_exc())
            QMessageBox.warning(
                self, "Explain",
                "AI SOC Analyst sedang tidak tersedia.\nHistorical analysis tetap dapat dilihat."
            )

    _PAGE_META = [
        ("Dashboard",        "Security overview · real-time"),
        ("CTI",              "Cyber Threat Intelligence"),
        ("Malware Analysis", "Static Analysis & Threat Intelligence"),
        ("Forensics",        "WAF / NGFW / PCAP log investigation"),
    ]

    def _switch(self, idx):
        self.pages.setCurrentIndex(idx)
        for i, btn in enumerate(self._nav_btns):
            btn.setObjectName("btn_sidebar_active" if i==idx else "btn_sidebar")
            btn.setStyle(btn.style())
            btn.update()
        if hasattr(self, "_header") and 0 <= idx < len(self._PAGE_META):
            self._header.set_page(*self._PAGE_META[idx])

    def _goto_cti(self, ioc: str):
        """Navigate to CTI page, prefill IOC, auto-run analysis."""
        self._switch(1)
        clean = (ioc or "").strip()
        info = normalize_input(clean)
        if info["type"] in ("file_path", "unknown"):
            log_event(f"Invalid IOC from Forensics: {clean}")
            QMessageBox.warning(self, "IOC", "Skipped (not valid IOC)")
            return
        self.pg_cti.inp.setText(info["value"])
        self.pg_cti._run()


# ========================
# MAIN / ENTRY POINT
# ========================

if __name__ == "__main__":
    import traceback

    # ── [1] Global exception hook — prevents silent crashes ───────────────────
    # Non-reentrant by design: if this hook is triggered again while it is
    # already running (e.g. a RecursionError leaves almost no stack budget
    # left for traceback.format_exception/logging), it falls straight back
    # to the interpreter's own original hook instead of recursing into
    # itself — this is what "Error in sys.excepthook ... lost sys.stderr"
    # means: the hook itself failed while handling an exception.
    ORIGINAL_EXCEPTHOOK = sys.__excepthook__
    _exc_state = {"handling": False, "dialog_open": False}

    def _show_fatal_error_dialog(msg: str):
        if _exc_state["dialog_open"]:
            return
        _exc_state["dialog_open"] = True
        try:
            QMessageBox.critical(None, "guardian_ai — Fatal Error", msg[:2000])
        except Exception:
            pass
        finally:
            _exc_state["dialog_open"] = False

    def exception_hook(exctype, value, tb):
        if _exc_state["handling"]:
            try:
                ORIGINAL_EXCEPTHOOK(exctype, value, tb)
            except Exception:
                pass
            return

        _exc_state["handling"] = True
        try:
            try:
                msg = "".join(traceback.format_exception(exctype, value, tb))
            except Exception:
                msg = f"{getattr(exctype, '__name__', exctype)}: {value}"

            try:
                sys.__stderr__.write(f"\n[CRITICAL] Unhandled exception:\n{msg}\n")
                sys.__stderr__.flush()
            except Exception:
                pass

            try:
                log_event(f"[CRITICAL] Unhandled exception:\n{msg}")
            except Exception:
                pass

            # Defer the modal dialog to the next event-loop iteration instead
            # of opening it synchronously from inside the hook. This avoids
            # nesting a modal Qt event loop on top of whatever call stack was
            # active when the exception happened (relevant right after a
            # near-stack-exhausting RecursionError).
            try:
                QTimer.singleShot(0, lambda m=msg: _show_fatal_error_dialog(m))
            except Exception:
                pass
        finally:
            _exc_state["handling"] = False

    sys.excepthook = exception_hook

    # ── [2] Debug flag ────────────────────────────────────────────────────────
    DEBUG = "--debug" in sys.argv
    def dbg(msg):
        if DEBUG:
            print(msg, flush=True)

    print("[1] Starting guardian_ai...", flush=True)

    # ── [3] HiDPI (MUST be before QApplication) ───────────────────────────────
    try:
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    except Exception as e:
        print(f"[WARN] HiDPI flags failed: {e}", flush=True)

    set_windows_app_id()          # must precede QApplication for taskbar identity
    app = QApplication(sys.argv)
    app.setWindowIcon(load_app_icon())   # before any window is shown
    app.setApplicationName("guardian_ai")
    app.setApplicationDisplayName("guardian_ai — AI SOC Platform")

    # ── [4] Global palette ────────────────────────────────────────────────────
    try:
        pal = QPalette()
        pal.setColor(QPalette.Window,          QColor(P["bg_dark"]))
        pal.setColor(QPalette.WindowText,      QColor(P["text_main"]))
        pal.setColor(QPalette.Base,            QColor(P["bg_input"]))
        pal.setColor(QPalette.AlternateBase,   QColor(P["bg_card"]))
        pal.setColor(QPalette.Text,            QColor(P["text_main"]))
        pal.setColor(QPalette.BrightText,      QColor(P["text_bright"]))
        pal.setColor(QPalette.Button,          QColor(P["bg_card"]))
        pal.setColor(QPalette.ButtonText,      QColor(P["text_main"]))
        pal.setColor(QPalette.Highlight,       QColor(P["accent"]))
        pal.setColor(QPalette.HighlightedText, QColor("#000d1a"))
        pal.setColor(QPalette.ToolTipBase,     QColor(P["bg_card2"]))
        pal.setColor(QPalette.ToolTipText,     QColor(P["text_main"]))
        app.setPalette(pal)
        dbg("[2] Palette applied.")
    except Exception as e:
        print(f"[WARN] Palette setup failed (non-fatal): {e}", flush=True)

    # ── [5] Stylesheet (safe fallback) ────────────────────────────────────────
    try:
        app.setStyleSheet(STYLESHEET)
        dbg("[3] Stylesheet applied.")
    except Exception as e:
        print(f"[WARN] Stylesheet failed, using default: {e}", flush=True)

    # ── [6] Splash screen ─────────────────────────────────────────────────────
    from PyQt5.QtWidgets import QSplashScreen
    from PyQt5.QtGui import QPixmap, QPainter, QFont, QColor as _QC, QPen
    from PyQt5.QtCore import Qt as _Qt

    _splash = None
    try:
        splash_pm = QPixmap(600, 340)
        splash_pm.fill(_QC(P["bg_dark"]))
        painter = QPainter(splash_pm)
        painter.setRenderHint(QPainter.Antialiasing)

        # Background gradient
        grad = QLinearGradient(0, 0, 600, 340)
        grad.setColorAt(0,   _QC("#090d1a"))
        grad.setColorAt(0.5, _QC("#0e1628"))
        grad.setColorAt(1,   _QC("#090d1a"))
        painter.fillRect(0, 0, 600, 340, grad)

        # Accent glow circle
        glow_grad = QRadialGradient(300, 170, 200)
        glow_grad.setColorAt(0,   _QC(0, 212, 255, 20))
        glow_grad.setColorAt(0.6, _QC(0, 212, 255, 6))
        glow_grad.setColorAt(1,   _QC(0, 0, 0, 0))
        painter.fillRect(0, 0, 600, 340, glow_grad)

        # Top accent line
        painter.setPen(QPen(_QC("#00d4ff"), 2))
        painter.drawLine(0, 0, 600, 0)

        # Logo text (safe font fallback)
        try:
            font_big = QFont("Segoe UI", 36, QFont.Bold)
        except Exception:
            font_big = QFont("Arial", 36, QFont.Bold)
        painter.setFont(font_big)
        painter.setPen(_QC("#E8EEF8"))
        _logo = QPixmap(resource_path(PNG_REL_PATH))
        if not _logo.isNull():
            _logo = _logo.scaled(88, 88, _Qt.KeepAspectRatio, _Qt.SmoothTransformation)
            painter.drawPixmap(300 - 44, 52, _logo)
            painter.drawText(0, 134, 600, 50, _Qt.AlignHCenter | _Qt.AlignVCenter, "guardian_ai")
        else:
            painter.drawText(0, 0, 600, 200, _Qt.AlignHCenter | _Qt.AlignVCenter, "guardian_ai")

        # Subtitle
        try:
            font_sub = QFont("Segoe UI", 12)
        except Exception:
            font_sub = QFont("Arial", 12)
        painter.setFont(font_sub)
        painter.setPen(_QC("#5a6a8a"))
        painter.drawText(0, 188, 600, 40, _Qt.AlignHCenter | _Qt.AlignVCenter,
                         "AI-Powered Security Operations Center")

        # Loading label
        try:
            font_load = QFont("Segoe UI", 9)
        except Exception:
            font_load = QFont("Arial", 9)
        painter.setFont(font_load)
        painter.setPen(_QC("#2e3f6e"))
        painter.drawText(0, 295, 600, 30, _Qt.AlignHCenter | _Qt.AlignVCenter,
                         "Initializing modules…")

        # Bottom border
        painter.setPen(QPen(_QC("#1a2744"), 1))
        painter.drawLine(0, 339, 600, 339)
        painter.end()

        _splash = QSplashScreen(splash_pm, _Qt.WindowStaysOnTopHint)
        _splash.show()
        app.processEvents()
        print("[2] Splash screen displayed.", flush=True)

    except Exception as e:
        print(f"[WARN] Splash screen failed (non-fatal): {e}", flush=True)
        _splash = None

    # ── [7] Splash status helper ──────────────────────────────────────────────
    def _splash_msg(msg: str):
        """Update splash message text safely (no blocking)."""
        if _splash is not None:
            try:
                _splash.showMessage(
                    msg,
                    _Qt.AlignHCenter | _Qt.AlignBottom,
                    _QC("#00d4ff"),
                )
                app.processEvents()
            except Exception:
                pass

    # ── [8] Main window launch — called via QTimer (non-blocking) ─────────────
    _main_window = None   # keep reference → prevents garbage collection

    def _launch_main_window():
        global _main_window
        print("[3] Loading modules...", flush=True)
        _splash_msg("Initializing CTI Engine…")
        app.processEvents()

        _splash_msg("Initializing Malware Engine…")
        app.processEvents()

        _splash_msg("Initializing Forensics…")
        app.processEvents()

        _splash_msg("Loading Dashboard…")
        app.processEvents()

        print("[4] Initializing MainWindow...", flush=True)
        try:
            _main_window = MainWindow()
            _main_window.show()
            if _splash is not None:
                _splash.finish(_main_window)
            print("[5] App running — MainWindow visible.", flush=True)
        except Exception as e:
            err = traceback.format_exc()
            print(f"[CRITICAL] MainWindow init failed:\n{err}", flush=True)
            if _splash is not None:
                try:
                    _splash.close()
                except Exception:
                    pass
            try:
                QMessageBox.critical(
                    None,
                    "guardian_ai — Startup Error",
                    f"Failed to initialize main window:\n\n{str(e)}\n\nCheck console for full traceback.",
                )
            except Exception:
                pass
            sys.exit(1)

    # Use QTimer so the event loop starts first and splash renders properly
    QTimer.singleShot(800, _launch_main_window)

    # ── [9] Run event loop ────────────────────────────────────────────────────
    try:
        exit_code = app.exec_()
    except Exception as e:
        print(f"[CRITICAL] Event loop crashed:\n{traceback.format_exc()}", flush=True)
        exit_code = 1

    print(f"[6] App exited with code {exit_code}.", flush=True)
    sys.exit(exit_code)
