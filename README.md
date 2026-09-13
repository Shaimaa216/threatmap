# ThreatMap — Intelligent IP Threat Intelligence & Network Analytics Platform

**Turn IP addresses into actionable security insights.**

ThreatMap is an open-source web application for IP intelligence and lightweight security analysis. It uses the official **IP2Location.io API as a core data source** for IP geolocation, network intelligence, and proxy/security signals.

> Built for the IP2Location Programming Contest 2026.

## Features

- IPv4 and IPv6 lookup
- IP2Location.io geolocation and network intelligence
- Application-level ThreatMap Risk Score (0–100)
- Proxy, VPN, Tor and threat indicators when supplied by the API plan
- Interactive Leaflet map
- Dashboard with risk distribution and recent activity
- Bulk CSV analysis (up to 100 unique IPs per upload)
- CSV export
- SQLite search history
- Responsive cybersecurity-style UI
- Basic pytest coverage
- No API key in frontend code or database

## Screenshots

Add screenshots here after running the application:

```text
docs/screenshots/dashboard.png
docs/screenshots/analyzer.png
docs/screenshots/bulk.png
```

## Technology Stack

- Backend: Python, FastAPI
- Frontend: HTML5, CSS3, JavaScript
- Database: SQLite
- Maps: Leaflet.js + OpenStreetMap tiles
- Charts: Chart.js
- IP intelligence: IP2Location.io
- HTTP client: httpx
- Tests: pytest

## Architecture

```text
Browser
  |
  | HTTP / JSON
  v
FastAPI
  |---- IP validation
  |---- IP2Location.io service
  |---- ThreatMap risk engine
  |---- SQLite history
  |
  +---- Static frontend
       |---- Dashboard
       |---- IP Analyzer
       |---- Bulk Analysis
       |---- History
```

All IP2Location.io requests are made server-side. The API key is never sent to browser JavaScript.

## Installation

### 1. Clone

```bash
git clone https://github.com/Shaimaa216/threatmap.git
cd threatmap
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure IP2Location.io

Copy `.env.example` to `.env`:

```bash
copy .env.example .env
```

or on macOS/Linux:

```bash
cp .env.example .env
```

Then set:

```env
IP2LOCATION_API_KEY=your_real_api_key
REQUEST_TIMEOUT=10
```

IP2Location.io's documentation describes the IP geolocation REST endpoint and its IPv4/IPv6 support. Returned fields can include country, region, city, coordinates, time zone, ASN, AS information, ISP, domain, usage type and proxy/security information depending on the plan. See the official documentation:
https://www.ip2location.io/ip2location-documentation

## Run locally

```bash
uvicorn backend.main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## IP Analyzer

1. Open **IP Analyzer**.
2. Enter an IPv4 or IPv6 address.
3. Click **Analyze IP**.
4. ThreatMap calls IP2Location.io through the FastAPI backend.
5. The UI displays location, network intelligence, security indicators, map information and the ThreatMap Risk Score.

## Bulk Analysis

Create a CSV:

```csv
ip
8.8.8.8
1.1.1.1
8.8.4.4
```

Then:

1. Open **Bulk Analysis**.
2. Upload the CSV.
3. Run analysis.
4. Review the results.
5. Download the result CSV.

Invalid IPs are reported per row instead of crashing the whole request. Duplicate IPs in one upload are removed before API requests.

## Risk Score Methodology

The **ThreatMap Risk Score** is an application-level heuristic from 0 to 100.

Signals may include:

- Tor indicator
- VPN indicator
- Public proxy
- Web proxy
- Residential proxy
- Spammer indicator
- Web crawler / AI crawler indicators
- Consumer privacy network
- IP2Location proxy threat field
- Data center / hosting usage

Classification:

- **0–29:** Low Risk
- **30–59:** Medium Risk
- **60–100:** High Risk

The score is intentionally transparent and explainable.

**Important:** the ThreatMap Risk Score is not a definitive statement that an IP is malicious. It is a heuristic security signal based only on available IP2Location information.

## API limitations

IP2Location.io usage limits depend on the account/plan. Bulk analysis therefore:

- removes duplicate IPs before lookup
- limits a single CSV upload to 100 unique IPs
- processes requests sequentially to avoid unnecessary bursts
- surfaces API rate-limit errors clearly

For larger-scale production workloads, the backend should use an approved IP2Location bulk workflow or a queue with appropriate account limits.

## Security notes

- Never commit `.env`.
- Never put the IP2Location API key in frontend JavaScript.
- Do not store API keys in SQLite.
- Treat geolocation as approximate intelligence.
- Do not use the risk score as the sole basis for blocking or attribution.
- Keep dependencies updated.
- Add authentication/rate limiting before exposing a public production deployment.

## Project structure

```text
threatmap/
├── backend/
│   ├── __init__.py
│   ├── main.py
│   ├── ip2location.py
│   ├── risk_engine.py
│   ├── database.py
│   └── config.py
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── tests/
│   ├── test_risk_engine.py
│   └── test_validation.py
├── data/
├── requirements.txt
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

## Future improvements

- IP2Location bulk endpoint integration where suitable for the selected plan
- Background jobs for large uploads
- Authentication and per-user history
- Redis caching
- Configurable scoring rules
- PDF security reports
- ASN relationship visualizations
- Alerting and SIEM integrations
- Deployment with HTTPS and production security headers

## License

MIT License. See `LICENSE`.

## IP2Location attribution

ThreatMap uses **IP2Location.io** for IP intelligence and security-related IP data.

Official documentation:
https://www.ip2location.io/ip2location-documentation

IP2Location is a trademark of IP2Location.com. ThreatMap is an independent open-source project.
