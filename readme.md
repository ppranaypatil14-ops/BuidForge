# DepScan AI — Software Supply Chain Security Analyzer

> Automated Supply Chain Risk Engine, Dependency DAG Reasoning, and Attack Indicator Analyzer for Enterprise DevSecOps.

DepScan is an enterprise-grade Software Supply Chain Security Analyzer built for **PS14: Software Supply Chain Security Analyzer**. It identifies risky dependencies, suspicious package behaviors, and active supply chain attack vectors across polyglot repositories with a **Zero Code Execution Guarantee**.
It also features a beautifully designed modern web dashboard (website) for visualizing supply chain risks, complete with an interactive landing page.

---

## 🎯 Problem Statement 14 (PS14) Capabilities

| Expected Capability | Engine Module | Implementation Highlights |
|---|---|---|
| **1. Dependency Graph** | `backend.graph.dependency_graph` | NetworkX directed acyclic graph (DAG), multi-hop transitive chains from `package-lock.json` (v1/v2/v3), deterministic ancestor blast-radius calculations, and propagation path tracing. |
| **2. Known Vulnerabilities** | `backend.scanner.osv` | Live correlation via OSV.dev batch API across npm, PyPI, Maven, Go, and Cargo. Version range filtering, CVSS scoring, and offline fallback database. |
| **3. Typosquatting & Confusion** | `backend.scanner.heuristics` | 150+ popular ecosystem packages, Unicode Homoglyph / Confusable detection (Cyrillic lookalikes), separator confusion (`_` vs `-`), combosquatting affixes, and internal namespace collision. |
| **4. Package Reputation** | `backend.scanner.reputation` | Freshness analysis (< 14 days old), version jump spikes (`>= 50.0.0`), deprecated libraries (`request`, `left-pad`), and disposable author domains (`tempmail`). |
| **5. Build Provenance** | `backend.scanner.provenance` | **CI/CD Workflow Auditing** (`.github/workflows/*.yml` unpinned actions, `permissions: write-all`, `curl \| bash`, `pull_request_target`), **Python `setup.py` AST inspection** (reverse shells, subprocesses, base64 payloads), and lockfile integrity. |
| **6. Prioritized Remediation** | `backend.remediation` & `backend.ai` | P0–P3 deterministic prioritization tiers, **CycloneDX v1.5 JSON SBOM**, **SARIF v2.1.0 report**, **CI/CD Quality Gate**, and Gemini-powered Git unified diff patches. |

---

## 🛡️ Zero Code Execution Guarantee

In compliance with advanced security standards, DepScan **never executes untrusted code**:
* 100% static parsing via AST inspection, JSON/TOML decoders, and regex analyzers.
* No `npm install`, `pip install`, `setup.py develop`, or `eval()` are ever triggered during scans.
* Impervious to malicious code bombs planted in organizer-provided challenge repositories.

---

## 🚀 Quick Start


### 1. Standalone CLI Runner (CI/CD & Evaluators)
```bash
# Terminal scan with ANSI summary table
python -m backend.cli ./demo-repository

# Export standard CycloneDX SBOM + SARIF report
python -m backend.cli ./demo-repository --sbom sbom.cdx.json --sarif results.sarif

# Enforce CI/CD Quality Gate (exits with code 1 on P0/Critical findings, 0 on clean)
python -m backend.cli ./demo-repository --gate
```

### 2. Running the REST API Server
```bash
# Start FastAPI backend
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
* **Landing Page:** `http://127.0.0.1:8000/`
* **Interactive Dashboard:** `http://127.0.0.1:8000/dashboard`
* **OpenAPI Documentation:** `http://127.0.0.1:8000/docs`

---

## 📡 REST API Specifications

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scans` | Ingest and analyze a GitHub repository or local workspace |
| `POST` | `/api/v1/scans/upload` | Ingest and analyze a `.zip` repository archive securely |
| `GET` | `/api/v1/scans/{id}/results` | Retrieve detailed findings, dependencies, and security scores |
| `GET` | `/api/v1/scans/{id}/graph` | Expose directed NetworkX dependency graph and blast radii |
| `GET` | `/api/v1/scans/{id}/sbom.cdx.json` | Export NTIA-compliant CycloneDX v1.5 JSON SBOM |
| `GET` | `/api/v1/scans/{id}/sarif` | Export SARIF v2.1.0 document for GitHub Code Scanning |
| `POST` | `/api/v1/scans/{id}/gate` | Evaluate scan against customizable CI/CD pipeline policies |
| `POST` | `/api/v1/scans/{id}/explain` | Generate AI threat intelligence synthesis and unified patch diff |

---

## 🧪 Test Suite

```bash
python -m pytest
```
**184 automated tests passing (100% GREEN)** covering AST visitors, scanners, parsers, APIs, and CLI workflows.
