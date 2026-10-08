# SentinelScan — Lightweight Web Vulnerability Scanner

A course-project web vulnerability scanner with a dashboard, CLI, same-site crawler, modular checks, JSON reports, scan history, and unit tests.

## Safety
Only scan localhost or intentionally vulnerable labs for which you have authorization. The UI requires an explicit permission confirmation and the CLI requires `--i-have-permission`.

## Run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python backend/app.py
```

Open http://127.0.0.1:5000

For OWASP Juice Shop:

```powershell
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Then scan http://localhost:3000 from the dashboard.

## CLI

```powershell
python scanner.py http://localhost:3000 --i-have-permission -o report.json
```

Options: `--delay`, `--max-pages`, `--timeout`.

## Implemented checks

- HTTP instead of HTTPS — A02
- Missing HSTS — A02
- Missing CSP — A05
- Missing X-Frame-Options — A05
- Missing X-Content-Type-Options — A05
- Directory listing — A05
- Exposed .env/.git/phpinfo indicators — A05
- Server/X-Powered-By disclosure — A06
- Cookie Secure/HttpOnly/SameSite — A07
- Login form over HTTP — A07
- External scripts without SRI — A08
- CORS wildcard/reflection — A01
- Reflected harmless marker — A03
- SQL error signature after harmless quote probe — A03

A09 and A10 are documented as limitations because they are not safely testable by this lightweight remote scanner.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Architecture

Browser Dashboard -> Flask API -> Scan Manager -> Crawler -> Modular Checks -> JSON/SQLite
