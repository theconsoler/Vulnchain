<div align="center">


```
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██║  ██║██╔══██╗██║████╗  ██║
██║   ██║██║   ██║██║     ██╔██╗ ██║██║     ███████║███████║██║██╔██╗ ██║
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║     ██╔══██║██╔══██║██║██║╚██╗██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║╚██████╗██║  ██║██║  ██║██║██║ ╚████║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
```

**Attack Path Based Vulnerability Prioritization Engine**

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04-orange?style=flat-square&logo=ubuntu)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-60%20Passing-success?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?style=flat-square&logo=flask)
![NetworkX](https://img.shields.io/badge/Graph-NetworkX-blue?style=flat-square)

*Ranks CVEs by actual attack path impact, not CVSS score*

</div>

---

## The Problem VulnChain Solves

Standard vulnerability scanners return hundreds of findings ranked by CVSS score. CVSS was never designed for prioritization -- it scores vulnerabilities in a vacuum with no knowledge of your network topology, asset criticality, or real-world exploit probability.

**Security teams patch the wrong things first. VulnChain fixes this.**

A CVSS 9.8 vulnerability on an isolated internal host scores lower than a CVSS 7.5 vulnerability sitting on 47 attack paths leading to your domain controller. That is the core insight VulnChain operationalizes.

---

## How It Works

```
Scanner Output (.nessus / .xml / .csv)
        |
        v
[Phase 1] Parser ──── Normalizes Nessus, OpenVAS, Qualys into unified schema
        |
        v
[Phase 2] Graph Builder ── Builds directed NetworkX topology graph
          Nodes: hosts  |  Edges: inferred network connectivity
        |
        v
[Phase 3] Enrichment ──── Queries NVD API for CVSS v3.1
          Queries EPSS API for real-world exploit probability (0.0 - 1.0)
        |
        v
[Phase 4] Scorer ─────── Computes attack path impact score per vulnerability
          Ranks by: (cvss/10) × epss × criticality × betweenness_centrality
        |
        v
[Phase 5] Output ─────── Interactive Pyvis graph + HTML/PDF remediation report
        |
        v
[Phase 6] Dashboard ──── Flask web UI with bcrypt auth, JWT sessions,
          background pipeline, real-time progress, scan delta comparison
```

---

## Scoring Formula

```
base_score         = (cvss_v3 / 10.0) × epss_score × asset_criticality
exploit_multiplier = 1.5  if active exploit confirmed  else 1.0
centrality_mult    = 1.0 + (betweenness_centrality × 2.0)
final_score        = base_score × exploit_multiplier × centrality_mult
```

| Data Source | Purpose |
|---|---|
| NVD (NIST) | CVSS v3.1 base scores |
| EPSS (FIRST.org) | Real-world exploit probability |
| NetworkX | Betweenness centrality calculation |

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Language | Python 3.11 | Core development |
| Graph Engine | NetworkX 3.3 | Attack path modeling |
| Data Validation | Pydantic v2 | Schema enforcement |
| CVE Data | NVD REST API v2.0 | CVSS v3.1 enrichment |
| Exploit Probability | EPSS API | Real-world exploit scoring |
| Visualization | Pyvis | Interactive attack graph |
| Report Generation | Jinja2 + WeasyPrint | HTML + PDF reports |
| Web Framework | Flask 3.0 | Web dashboard |
| Authentication | bcrypt + JWT | Secure session management |
| Rate Limiting | Flask-Limiter | Brute force protection |
| Database | SQLite | User and job storage |
| Testing | pytest | 60 unit tests |

---

## Supported Scanner Formats

| Scanner | Format | Notes |
|---|---|---|
| Tenable Nessus | `.nessus` (XML) | Full support |
| OpenVAS / GVM | `.xml` | Full support |
| Qualys VM | `.csv` | Standard VM export |

---

## Installation

### Requirements
- Ubuntu 22.04 LTS
- Python 3.11
- 2GB RAM minimum

### Setup

```bash
# Clone the repository
git clone https://github.com/theconsoler/Vulnchain.git
cd Vulnchain

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install WeasyPrint system dependencies
sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0

# Configure environment
cp .env.example .env
nano .env
# Fill in SECRET_KEY, JWT_SECRET_KEY, NVD_API_KEY

# Create your first user
python create_user.py --username analyst --password YourPassword

# Start the server
python run.py
```

Open `http://localhost:5000` in your browser.

---

## Environment Variables

```bash
# Generate secure keys
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python3 -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_hex(32))"
```

Get a free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key

---

## CLI Usage

```bash
source venv/bin/activate

# Phase 1: Parse scanner file
python main.py samples/sample_nessus.xml

# Phase 2: Build topology graph
python build_graph.py

# Phase 3: Enrich with NVD + EPSS
python enrich_graph.py

# Phase 4: Score vulnerabilities
python score_vulns.py

# Phase 5: Generate report
python generate_report.py
```

---

## Web Dashboard Features

- Shodan-inspired login with bcrypt authentication
- JWT session tokens stored in httpOnly cookies
- Rate-limited login (5 attempts per minute per IP)
- Background pipeline with real-time progress polling
- Interactive attack graph visualization
- Sortable, filterable vulnerability table with pagination
- Scan delta comparison (new vs resolved vulnerabilities)
- HTML and PDF report downloads
- Dark / light theme toggle

---

## Project Structure

```
vulnchain/
├── app/                    Flask application (auth, routes, pipeline)
├── enrichment/             NVD + EPSS API clients with local caching
├── graph/                  NetworkX graph construction and topology
├── models/                 Pydantic vulnerability schema
├── parsers/                Nessus, OpenVAS, Qualys parsers
├── reporting/              Pyvis graph + Jinja2 report generator
├── scoring/                Attack path scoring engine
├── static/                 CSS and JavaScript
├── templates/              Jinja2 HTML templates
├── tests/                  60 pytest unit tests
├── samples/                Sample scanner files for testing
├── output/                 Generated reports (gitignored)
├── main.py                 Phase 1 CLI entry point
├── build_graph.py          Phase 2 CLI entry point
├── enrich_graph.py         Phase 3 CLI entry point
├── score_vulns.py          Phase 4 CLI entry point
├── generate_report.py      Phase 5 CLI entry point
└── run.py                  Flask web server
```

---

## Running Tests

```bash
source venv/bin/activate
pytest tests/ -v
# Expected: 60 passed
```

---

## Known Limitations

- **Topology inference is approximate** -- VulnChain infers connectivity from subnet proximity and service exposure. It does not read firewall rules or VLAN configs. Attack paths are best-effort models.
- **Single-file pipeline** -- Multi-scanner file merging is on the roadmap.
- **No false positive management** -- Planned for a future release.

---

## Security Design

- Passwords bcrypt hashed with cost factor 12
- JWT tokens expire after 24 hours
- JWT stored in httpOnly cookies -- not localStorage
- Login rate-limited to 5 attempts per minute per IP
- Secret keys loaded from environment only -- app refuses to start without them
- Uploaded files saved with UUID filenames, deleted after pipeline completes

---

## Author

**Piyush Kumar Sahoo** (theconsoler)
B.Tech Computer Science and Engineering (Cyber Security) -- Sri Sri University Graduate

[![GitHub](https://img.shields.io/badge/GitHub-theconsoler-black?style=flat-square&logo=github)](https://github.com/theconsoler)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-piyush--kumar--sahoo--soc-blue?style=flat-square&logo=linkedin)](https://linkedin.com/in/piyush-kumar-sahoo-soc)
[![YouTube](https://img.shields.io/badge/YouTube-blue__trace--19-red?style=flat-square&logo=youtube)](https://youtube.com/@blue_trace-19)
[![Medium](https://img.shields.io/badge/Medium-the__consoler__-black?style=flat-square&logo=medium)](https://medium.com/@the_consoler_)

---

## License

MIT License -- see [LICENSE](LICENSE) for details.

---

<div align="center">

*VulnChain -- Because patching the wrong vulnerability first is not a strategy.*

</div>
