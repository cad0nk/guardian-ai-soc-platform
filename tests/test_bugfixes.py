"""Regression tests for the bugs found during the guardian_ai UI redesign.

Run:  QT_QPA_PLATFORM=offscreen pytest -q tests/test_bugfixes.py
"""
import importlib
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
SAMPLE = os.path.join(ROOT, "tests", "fixtures", "sample_waf.json")


@pytest.fixture(scope="module")
def m():
    return importlib.import_module(os.environ.get("GUARDIAN_MODULE", "guardian_ai_v4_fixed"))


@pytest.fixture(scope="module")
def qapp():
    from PyQt5.QtWidgets import QApplication
    return QApplication.instance() or QApplication(sys.argv)


# ── Bug 2: pasted JSON array / CSV were parsed as ONE text line ──────────────
def test_paste_json_array_matches_file_upload(m):
    text = open(SAMPLE, encoding="utf-8").read()
    pasted = m.analyze_pasted_log_streaming(text, None)
    uploaded = m.analyze_forensics_file(SAMPLE, max_records=None)
    assert pasted["total_records"] == uploaded["total_records"] == 4
    key = lambda r: sorted((f["attack_type"], f["src_ip"]) for f in r["findings"])
    assert key(pasted) == key(uploaded)


def test_paste_ndjson_and_text_unchanged(m):
    nd = "\n".join(json.dumps(r) for r in json.load(open(SAMPLE, encoding="utf-8")))
    assert m._pasted_log_suffix(nd) == ".log"
    assert m.analyze_pasted_log_streaming(nd, None)["total_records"] == 4
    syslog = "Oct 30 10:00:01 fw1 DROP src=198.51.100.7, dst=198.51.100.8, proto=tcp\nOct 30 10:00:02 fw1 ACCEPT src=198.51.100.7, dst=198.51.100.9, proto=tcp"
    assert m._pasted_log_suffix(syslog) == ".log"      # prose with commas is NOT csv


def test_paste_csv_detected(m):
    csv_text = ("timestamp,src_ip,dst_ip,url,method,status_code\n"
                "2026-10-30T10:00:01Z,198.51.100.23,192.0.2.10,/login.php?id=1,GET,403\n"
                "2026-10-30T10:00:02Z,198.51.100.23,192.0.2.10,/admin,GET,404\n")
    assert m._pasted_log_suffix(csv_text) == ".csv"
    assert m.analyze_pasted_log_streaming(csv_text, None)["total_records"] == 2


# ── Bug 1: forensics chatbot context never emitted (iocs["total"] is an int) ──
def test_forensics_chatbot_context_emitted_with_real_fields(m, qapp):
    page = m.ForensicsPage()
    got = []
    page.context_ready.connect(lambda name, ctx: got.append((name, ctx)))
    result = m.analyze_forensics_file(SAMPLE, max_records=None)
    assert isinstance(result["iocs"].get("total"), int)      # the value that used to crash
    page._emit_chatbot_context(result)
    assert got, "context_ready was not emitted"
    name, ctx = got[0]
    assert name == "forensics"
    assert ctx["analysis_result"]["total_findings"] == len(result["findings"])
    assert ctx["analysis_result"]["total_iocs"] == sum(
        len(v) for v in result["iocs"].values() if isinstance(v, list))
    # fields must be populated (they used to be blank: wrong key names)
    assert all(x.split(":")[0].strip() for x in ctx["findings"])
    assert all(x.split("|")[1].strip() for x in ctx["timeline"])


# ── QSS hex8 shim ────────────────────────────────────────────────────────────
def test_qss_hex8_rewritten():
    from ui.styles.qss_compat import fix_qss
    assert fix_qss("color:#FF454514;") == "color:rgba(255,69,69,20);"
    assert fix_qss("color:#00C8EA;") == "color:#00C8EA;"


# ── Attack Graph: force layout must stay compact (nodes without edges used to drift ~2000px) ──
def test_force_layout_is_bounded_and_nodes_do_not_overlap(m):
    import itertools, math
    pytest.importorskip("numpy")
    for n, edges in ((12, [("n0", "n1"), ("n1", "n2")]), (12, []), (30, [(f"n{i}", f"n{i+1}") for i in range(29)])):
        ids = [f"n{i}" for i in range(n)]
        pos = m._force_layout_np(ids, edges)
        xs, ys = [p[0] for p in pos.values()], [p[1] for p in pos.values()]
        assert max(xs) - min(xs) < 1800 and max(ys) - min(ys) < 1800
        assert min(math.dist(a, b) for a, b in itertools.combinations(pos.values(), 2)) > 60
