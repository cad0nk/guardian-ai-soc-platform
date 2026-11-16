"""Shared pytest isolation for guardian_ai.

Guarantees the test-suite is hermetic:
  * Qt runs headless (offscreen) and uses a throw-away QSettings location, so running the
    tests never touches your real window layout / panel preferences.
  * Any API keys found in the environment or in a local .env are ignored.
  * All outbound HTTP is blocked: external services behave as "unreachable", exactly like
    an offline machine. Nothing in the suite talks to VirusTotal, AbuseIPDB, Shodan,
    Hybrid Analysis, Groq or WHOIS servers.
"""
import importlib
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session", autouse=True)
def _hermetic_environment(tmp_path_factory):
    import requests
    from PyQt5.QtCore import QSettings

    QSettings.setDefaultFormat(QSettings.IniFormat)
    QSettings.setPath(QSettings.IniFormat, QSettings.UserScope,
                      str(tmp_path_factory.mktemp("qsettings")))

    mod = importlib.import_module(os.environ.get("GUARDIAN_MODULE", "guardian_ai_v4_fixed"))
    mod._CONFIG = mod._default_config()          # no real keys, whatever the developer has in .env
    for _name in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY", "HYBRID_API_KEY", "GROQ_API_KEY"):
        setattr(mod, _name, "")                  # module-level copies were read at import time

    def _blocked(*_args, **_kwargs):
        raise requests.exceptions.ConnectionError("network disabled in tests")

    mp = pytest.MonkeyPatch()
    mp.setattr(requests.sessions.Session, "request", _blocked)
    yield
    mp.undo()
