# Security Policy

## Supported versions
| Version | Supported |
|---|---|
| `main` / latest release | Yes |
| Older releases | No |

## Reporting a vulnerability
Please **do not open a public issue** for security problems.

- Use GitHub's private reporting: **Security -> Report a vulnerability** on this repository
  (`https://github.com/USERNAME/guardian-ai-soc-platform/security/advisories/new`), or
- Contact the maintainer at: `<security contact - TODO(owner): add an address you are comfortable publishing>`

Please include: affected version/commit, steps to reproduce, expected vs. actual impact, and any suggested fix.
**Do not include real credentials, customer data or live malware.**

## Responsible disclosure
This is a personal/portfolio project maintained on a best-effort basis. Reports are acknowledged as soon as practical; please allow
reasonable time to fix an issue before disclosing it publicly. No bug bounty is offered.

## API key handling
- Keys are read **only** from environment variables or a local `.env` file. They are never hardcoded and never bundled in the executable.
- `.env` is git-ignored. Use `.env.example` as a template.
- If you ever commit or share a key by accident, **revoke/rotate it at the provider immediately**. Removing it from a later commit does not remove it from Git history.
- The test-suite ignores real keys and blocks outbound HTTP.

## Sensitive logs and data
- Logs analysed in guardian_ai can contain IP addresses, user agents, URLs and other personal or confidential data.
  Analyse only data you are authorised to process.
- `debug.log` and `soc_history.db` are created locally and may contain indicators from your investigations. They are git-ignored; review and redact them before sharing.
- When using the AI SOC Analyst or Hybrid Analysis, data derived from your analysis is sent to those third-party services.
  Do not submit confidential files or logs unless your policy allows it.
- Use only synthetic data in public demos and screenshots.

## Safe malware analysis
- Never execute samples. guardian_ai performs **static** analysis only.
- Files in `tests/fixtures/` are inert text fixtures (documentation IPs, `.example` domains). They must not be run.
- Handle real samples in an isolated environment (VM without network), and never commit samples to this repository.

## Authorised use only
Use guardian_ai only on systems, files and logs you own or are explicitly authorised to examine.
