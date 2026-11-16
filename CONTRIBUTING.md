# Contributing

Thanks for your interest! guardian_ai is a personal portfolio project, but focused improvements are welcome.

## Set up
```powershell
git clone https://github.com/USERNAME/guardian-ai-soc-platform.git
cd guardian-ai-soc-platform
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m pytest
```
See [docs/INSTALLATION.md](docs/INSTALLATION.md). You do **not** need any API key to develop or run the tests.

## Workflow
1. Open an issue first for anything non-trivial.
2. Create a branch from `main`: `fix/<short-description>`, `feat/<short-description>` or `docs/<short-description>`.
3. Make small, focused commits. Suggested message style: `fix: ...`, `feat: ...`, `docs: ...`, `test: ...`, `chore: ...`.
4. Add or update tests; run `python -m pytest` locally.
5. Open a pull request using the template and keep it small.

## Code style
- Python 3.12, PEP 8, readable names, short docstrings for non-obvious logic.
- UI colours, fonts and spacing come from `ui/styles/` - do not hardcode new palettes in pages.
- Network and heavy parsing **must not** run on the Qt UI thread (use the existing `Worker`/`LogParseWorker` pattern).
- Never let an analysis function raise into the UI; return an error result instead.
- No new hard dependency without discussion; optional features must degrade gracefully.

## Tests and fixtures
- The suite is hermetic: no network, no real keys (`tests/conftest.py`). Keep it that way.
- Fixtures must be **synthetic and inert**: use RFC 5737 documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `.example` domains. Never commit real logs, samples, hostnames or indicators from a real environment.
- Tests that need TShark must skip cleanly when it is missing.

## Pull request checklist
- [ ] Tests pass locally
- [ ] No secrets, real IOCs or personal data
- [ ] Docs / CHANGELOG updated if behaviour changed

## Bug reports
Use the *Bug report* issue template. Redact `debug.log` before attaching it.

## Security reports
Do **not** use public issues - follow [SECURITY.md](SECURITY.md).
