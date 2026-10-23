# Security Log Analytics Dashboard

A security log analytics pipeline and interactive detection dashboard. Parses raw OpenSSH logs into structured events, stores and enriches them with GeoIP data in PostgreSQL, detects attack patterns using SQL window functions mapped to the MITRE ATT&CK framework, and visualizes security metrics in a Streamlit dashboard.

---

## Architecture & Tech Stack

- **Data Ingestion & Parsing:** Python regex parser extracting structured authentication events from raw SSH syslog streams.
- **Database:** PostgreSQL with relational schema, analytical indexing, and GeoIP enrichment.
- **Detection Engine:** SQL window functions and aggregations mapped to MITRE ATT&CK techniques.
- **Visualization:** Streamlit + Plotly interactive analytics dashboard.
- **DevOps & CI:** Docker Compose containerization and GitHub Actions automated testing workflow.

---

## 5-Day Build Plan & Progress

- [x] **Day 1: Setup, Data, and Parser**
  - Project structure, requirements, and virtual environment setup
  - Loghub OpenSSH sample acquisition and licensing documentation
  - Regex parser for failed passwords, invalid users, and accepted logins
  - Pytest unit test suite and CLI execution summary
- [ ] **Day 2: Schema, Loading, and GeoIP Enrichment**
- [ ] **Day 3: Detection Rules (MITRE ATT&CK Mapping)**
- [ ] **Day 4: Streamlit Analytics Dashboard**
- [ ] **Day 5: Docker Containerization, CI/CD, and Production Deployment**

---

## Repository Structure

```
security-log-dashboard/
├── parser/            # Log parser, DB loader, GeoIP enrichment, unit tests
├── sql/               # Database schema and SQL detection rules
│   └── rules/         # MITRE ATT&CK detection queries
├── app/               # Streamlit interactive dashboard
├── data/              # Sample SSH logs and dataset attribution
├── docs/              # Architectural documentation and screenshots
├── .github/workflows/ # GitHub Actions CI automation
├── docker-compose.yml # Container orchestration
├── requirements.txt   # Python project dependencies
└── README.md          # Project documentation
```

---

## Quickstart (Day 1)

### 1. Setup Environment
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run the SSH Log Parser CLI
```bash
python parser/ssh_parser.py data/OpenSSH_2k.log
```

### 3. Run Unit Tests
```bash
pytest -v
```
