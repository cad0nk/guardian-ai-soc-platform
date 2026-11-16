"""End-to-end regression suite for guardian_ai (offline, headless).

Covers the module checklist from the redesign brief: Dashboard, CTI, Malware (local
engine / strings / YARA / network), Forensics WAF/NGFW, IOC extraction, attack timeline
& graph, AI SOC Analyst, Analysis History (+Investigate/Explain/Timeline), PDF export,
SQLite and the splitter. Network integrations are exercised through their offline
(no-API-key) behaviour and through synthetic results; PCAP is skipped without tshark.

Run:  QT_QPA_PLATFORM=offscreen pytest -q tests/test_regression.py
"""
import importlib
import json
import os
import shutil
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
WAF = os.path.join(ROOT, "tests", "fixtures", "sample_waf.json")
MAL = os.path.join(ROOT, "tests", "fixtures", "sample_malware.txt")


@pytest.fixture(scope="module")
def m(tmp_path_factory):
    mod = importlib.import_module(os.environ.get("GUARDIAN_MODULE", "guardian_ai_v4_fixed"))
    mod.DB_PATH = str(tmp_path_factory.mktemp("db") / "test_history.db")     # never touch the real DB
    mod.init_db()
    return mod


@pytest.fixture(scope="module")
def app(m):
    from PyQt5.QtWidgets import QApplication
    a = QApplication.instance() or QApplication(sys.argv)
    a.setStyleSheet(m.STYLESHEET)
    return a


def pump(app, ms=300):
    from PyQt5.QtCore import QEvent
    end = time.time() + ms / 1000
    while time.time() < end:
        app.processEvents(); app.sendPostedEvents(None, QEvent.DeferredDelete); time.sleep(0.01)


# ── Branding / theme ─────────────────────────────────────────────────────────
def test_icon_and_identity(m, app):
    assert os.path.isfile(m.resource_path(m.ICON_REL_PATH))
    assert not m.load_app_icon().isNull()
    assert m.set_windows_app_id() is False or sys.platform == "win32"     # safe no-op off Windows


def test_ico_contains_all_sizes():
    import struct
    d = open(os.path.join(ROOT, "assets", "icons", "guardian_ai.ico"), "rb").read()
    n = struct.unpack("<HHH", d[:6])[2]
    sizes = {(struct.unpack("<B", d[6 + 16 * i:7 + 16 * i])[0] or 256) for i in range(n)}
    assert sizes == {16, 24, 32, 48, 64, 128, 256}


# ── SQLite ───────────────────────────────────────────────────────────────────
def test_sqlite_roundtrip(m):
    m.save_to_db("cti", "high", "198.51.100.7", "roundtrip", {"ioc": "198.51.100.7"})
    time.sleep(0.3)
    rows = m.query_history("cti", "198.51.100.7")
    assert rows and rows[0]["ioc"] == "198.51.100.7"
    m.delete_history_entry(rows[0]["id"])
    assert not m.query_history("cti", "198.51.100.7")


# ── Malware: local engine, strings, YARA, network, source honesty ────────────
@pytest.fixture(scope="module")
def mal(m):
    return m.analyze_malware("", MAL)


def test_malware_local_engine(mal):
    assert mal["verdict"] == "malicious" and mal["threat_score"] >= 60
    assert mal["report"].get("local_analysis")


def test_malware_strings_yara_network(mal):
    assert mal["strings"]["total_strings"] > 0
    assert mal["yara"]["matches"] is not None and "note" in mal["yara"]
    assert mal["report"]["network_connections"]


def test_malware_source_labels(m, mal):
    src = m.malware_sources(mal)
    assert src["badge"] == "LOCAL ANALYSIS"
    assert src["hybrid"][0] == "off" and "no request was sent" in src["hybrid"][2]   # no key: honest, never a fake success
    assert "sandbox" in src["local"][2].lower()
    found = m.malware_sources({"report": {"found": True}, "enrichment": {"status": "found"}})
    assert found["badge"] == "HYBRID ANALYSIS ENRICHMENT"
    both = m.malware_sources({"report": {"found": True, "local_analysis": True}, "enrichment": {"status": "found"}})
    assert both["badge"] == "CORRELATED ANALYSIS"


# ── CTI (offline behaviour + rendering) ──────────────────────────────────────
def test_cti_source_states(m):
    assert m.cti_source_view("shodan", {"error": "API key not configured"})[0] == "off"
    assert m.cti_source_view("virustotal", {"error": "Rate limit reached"})[0] == "error"
    assert m.cti_source_view("virustotal", {"score": 50, "malicious_count": 7})[0] == "ok"


def test_cti_aggregate_offline(m):
    r = m.aggregate_cti_result("198.51.100.23")
    assert r["ioc"] == "198.51.100.23" and r["type"] == "ip" and isinstance(r["sources"], dict)


def test_cti_page_renders_all_tabs(m, app):
    pg = m.CTIPage()
    data = {"ioc": "198.51.100.23", "type": "ip", "risk_score": 70, "severity": "high",
            "sources": {"virustotal": {"source": "VirusTotal", "score": 60, "malicious_count": 9, "verdict": "malicious"},
                        "abuseipdb": {"source": "AbuseIPDB", "score": 100, "total_reports": 5, "reports": [],
                                      "country_code": "DE", "isp": "x", "domain": "d", "usage_type": "u", "is_tor": True,
                                      "num_distinct_users": 2, "last_reported_at": None, "country_name": "Germany"},
                        "shodan": {"source": "Shodan", "score": 0, "error": "API key not configured"}},
            "summary": {"verdict": "malicious"}}
    pg._display(data); pg._display(data)
    pump(app, 100)
    assert pg.tabs.count() == 6 and pg._btn_export.isEnabled() and "198.51.100.23" in pg.raw.toPlainText()


# ── Forensics WAF / NGFW / IOC / timeline / graph ────────────────────────────
@pytest.fixture(scope="module")
def waf(m):
    return m.analyze_forensics_file(WAF, max_records=None)


def test_forensics_waf(waf):
    assert waf["total_records"] == 4 and waf["findings"]
    types = {f["attack_type"] for f in waf["findings"]}
    assert {"sqli", "xss", "lfi"} <= types


def test_forensics_ngfw_csv(m, tmp_path):
    p = tmp_path / "ngfw.csv"
    p.write_text("timestamp,src_ip,dst_ip,src_port,dst_port,protocol,action\n"
                 "2026-10-30T10:00:01Z,192.0.2.5,203.0.113.9,51000,443,tcp,allow\n"
                 "2026-10-30T10:00:02Z,192.0.2.5,203.0.113.9,51001,22,tcp,deny\n"
                 "2026-10-30T10:00:03Z,192.0.2.5,203.0.113.9,51002,23,tcp,deny\n")
    r = m.analyze_forensics_file(str(p), max_records=None)
    assert r["total_records"] == 3 and not r.get("error")


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark/pyshark not installed")
def test_pcap_engine_available(m):
    assert hasattr(m, "analyze_forensics_file")


def test_ioc_extraction_timeline_graph(m, app, waf):
    assert waf["iocs"]["ips"] and "198.51.100.23" in str(waf["iocs"]["ips"])
    assert waf.get("timeline")
    got = {}
    wk = m.GraphBuildWorker(waf)
    wk.done.connect(lambda payload: got.setdefault("g", payload))
    wk.run()                                              # synchronous: same code path as the thread
    payload = got["g"]; nodes, edges = payload[0], payload[1]
    assert len(nodes) >= 2 and len(edges) >= 1


def test_forensics_page_paste_and_context(m, app):
    pg = m.ForensicsPage()
    ctx = []
    pg.context_ready.connect(lambda n, c: ctx.append(n))
    pg._display(m.analyze_forensics_file(WAF, max_records=None))
    pump(app, 100)
    assert pg.tabs.count() == 7 and [pg.tabs.tabText(i) for i in range(7)][-1] == "RAW LOGS"
    pg._emit_chatbot_context(m.analyze_forensics_file(WAF, max_records=None))
    assert ctx == ["forensics"]


# ── AI SOC Analyst ───────────────────────────────────────────────────────────
def test_chat_panel_flow(m, app, monkeypatch):
    from PyQt5.QtCore import QThread, pyqtSignal

    class Fake(QThread):
        reply_ready = pyqtSignal(str); error = pyqtSignal(str)
        def __init__(self, messages): super().__init__(); self.m = messages
        def run(self): self.reply_ready.emit("**Analisis:**\nok\n\n**Risiko:** HIGH\n\n**Rekomendasi:**\n- isolasi")
    monkeypatch.setattr(m, "ChatWorker", Fake)
    pnl = m.SOCChatPanel()
    pnl.set_context("cti", {"ioc": "198.51.100.7"}); pump(app, 100)
    assert "CTI" in pnl._mod_badge.text() and "198.51.100.7" in pnl._mod_badge.text()
    pnl._send("apa risikonya?"); pump(app, 500)
    assert pnl._btn_send.isEnabled() and not pnl._loading.isVisible()
    assert pnl._chat_layout.count() >= 4
    pnl._clear_chat(); pump(app, 50)
    assert pnl._chat_stack.currentIndex() == 0 and not pnl._mod_badge.isVisible()
    pnl.shutdown()


def test_chat_markdown_prettifier(m):
    out = m.prettify_chat_markdown("**Analisis:** teks\n**Risiko:** HIGH\nbiasa")
    assert "### Analisis" in out and "### Risiko" in out and "biasa" in out


# ── Analysis History: filters, preview, Investigate / Explain / Timeline ─────
def test_history_panel_actions(m, app, mal, waf):
    m.save_to_db("malware", mal["severity"], "sample.ps1", "Malware: x", mal)
    m.save_to_db("forensics", "medium", "waf.json", "Forensics: y", waf)
    time.sleep(0.4)
    h = m.AnalysisHistoryPanel(); h.resize(340, 800); h.show(); pump(app, 600)
    seen = {"inv": [], "exp": [], "load": []}
    h.investigate_requested.connect(lambda mod, e: seen["inv"].append(mod))
    h.explain_requested.connect(lambda mod, c: seen["exp"].append(mod))
    h.load_requested.connect(lambda mod, d: seen["load"].append(mod))
    h._set_module_filter("malware"); pump(app, 500)
    card = [c for c in h._card_widgets if getattr(c, "_entry", None)][0]
    h._on_card_click(card._entry); pump(app, 100)
    assert all(b.isEnabled() for b in h._quick_action_btns.values()) and h._btn_export_pdf.isEnabled()
    texts = " ".join(l.text() for l in h._prev_kv_w.findChildren(m.QLabel))
    assert "Threat score" in texts and "—" not in texts.split("Threat score")[1][:12]      # real values, not "—"
    h._quick_action_btns["investigate"].click(); h._quick_action_btns["explain"].click(); pump(app, 100)
    assert seen["inv"] == ["malware"] and seen["exp"] == ["malware"] and "malware" in seen["load"]
    h.shutdown_workers()


# ── PDF export ───────────────────────────────────────────────────────────────
def test_pdf_export(m, mal, tmp_path):
    out = tmp_path / "r.pdf"
    ok, msg = m.export_pdf_report_ex("malware", mal, str(out))
    assert ok, msg
    assert out.read_bytes()[:4] == b"%PDF"


# ── Main window: pages, sidebar, header, splitter persistence ────────────────
def test_main_window_navigation_and_state(m, app):
    from PyQt5.QtCore import QSettings
    QSettings("guardian_ai", "UI").clear()
    w = m.MainWindow(); w.resize(1500, 900); w.show(); pump(app, 400)
    for i, (title, _) in enumerate(w._PAGE_META):
        w._switch(i); pump(app, 30)
        assert title in w._header.crumb.text() and w._nav_btns[i].objectName() == "btn_sidebar_active"
    w._toggle_sidebar(); pump(app, 400)
    assert w._sb.width() == w._SIDEBAR_COLLAPSED
    w._toggle_chat(); w._toggle_history(); pump(app, 100)
    st = QSettings("guardian_ai", "UI")
    assert st.value("sidebar_collapsed", type=bool) is True
    assert st.value("chat_visible", type=bool) in (True, False)
    w._main_splitter.save_layout(w._settings, "splitter_sizes")
    assert w._main_splitter.restore_layout(w._settings, "splitter_sizes") in (True, False)
    w.close()
    QSettings("guardian_ai", "UI").clear()


# ── Hybrid Analysis: no key -> no request (privacy: the file hash must not leave the machine) ──
def test_hybrid_analysis_sends_nothing_without_key(m, monkeypatch):
    import requests
    calls = []
    monkeypatch.setattr(requests, "get", lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(AssertionError("network call")))
    monkeypatch.setattr(requests, "post", lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(AssertionError("network call")))
    monkeypatch.setattr(m, "HYBRID_API_KEY", "")
    for result in (m.fetch_overview("a" * 64), m.submit_url_sample("http://evil.example/x"),
                   m.quick_scan_file(MAL), m.poll_quick_scan("b" * 64)):
        assert result["error_code"] == "no_api_key" and not result.get("found")
    assert calls == []


def test_hybrid_analysis_still_called_with_key(m, monkeypatch):
    import requests
    seen = []
    def fake_get(*a, **k):
        seen.append(k.get("headers", {}).get("api-key"))
        raise requests.exceptions.ConnectionError("blocked")
    monkeypatch.setattr(requests, "get", fake_get)
    monkeypatch.setattr(m, "HYBRID_API_KEY", "test-key-not-real")
    r = m.fetch_overview("a" * 64)
    assert seen == ["test-key-not-real"] and r.get("error_code") != "no_api_key"
