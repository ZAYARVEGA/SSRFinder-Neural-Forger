# SSRFinder

<p align="center">
<pre>
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                       ║
║   ███████╗███████╗██████╗ ███████╗     ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗   ║
║   ██╔════╝██╔════╝██╔══██╗██╔════╝     ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗  ║
║   ███████╗███████╗██████╔╝█████╗       █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝  ║
║   ╚════██║╚════██║██╔══██╗██╔══╝       ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗  ║
║   ███████║███████║██║  ██║██║          ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║  ║
║   ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝          ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝  ║
║                                                                                       ║
║                                     Version 0.2.5 Beta                                ║
║                                                                                       ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝
</pre>
</p>

**Advanced SSRF vulnerability detection tool** with payload injection, IP range scanning, confidence-based scoring, and response analysis. Includes **Neural Forger**, an optional ML-powered extension that adds machine learning pre-analysis and combined confidence scoring.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [SSRFinder Usage](#ssrfinder-usage)
  - [Request File Format](#request-file-format)
  - [Basic Scan](#basic-scan)
  - [URL Mode](#url-mode)
  - [IP Range Scanning](#ip-range-scanning)
  - [Single IP Port Scan](#single-ip-port-scan)
  - [Single URL Testing](#single-url-testing)
  - [Response Viewing](#response-viewing)
  - [URL Encoding](#url-encoding)
  - [Custom Wordlists](#custom-wordlists)
  - [Investigation Workflow](#investigation-workflow)
- [Neural Forger Extension](#neural-forger-extension)
  - [What Neural Forger Adds](#what-neural-forger-adds)
  - [ML Inspection Mode](#ml-inspection-mode)
  - [ML-Enhanced Injection](#ml-enhanced-injection)
  - [Payload Strategies](#payload-strategies)
  - [Output Formats](#output-formats)
  - [Proxy Support](#proxy-support)
  - [GUI Interface](#gui-interface)
- [Architecture](#architecture)
- [Confidence Levels](#confidence-levels)
- [All Parameters Reference](#all-parameters-reference)
- [Exit Codes](#exit-codes)
- [Running Tests](#running-tests)
- [License](#license)

---

## Overview

SSRFinder is a penetration testing tool for detecting Server-Side Request Forgery (SSRF) vulnerabilities. It works by injecting payloads into HTTP request parameters and analyzing the responses to determine if the target application is making server-side requests to attacker-controlled URLs.

**Neural Forger** is an optional extension that adds a machine learning layer on top of SSRFinder. It analyzes HTTP request structure (parameter names, endpoint patterns, authentication) to predict SSRF vulnerability before any payloads are sent, then combines ML confidence with injection test results for more accurate assessments.

Both tools work independently — SSRFinder runs standalone without Neural Forger, while Neural Forger imports and extends SSRFinder's core modules.

## Features

### SSRFinder (Base Tool)
- 🎯 Payload injection with 14 built-in SSRF payloads (localhost, cloud metadata, IPv6, encoded IPs)
- 🔍 IP range scanning (`192.168.1.1-254`) across configurable ports
- 🔗 Single IP multi-port scanning with 8 default ports
- 📋 Raw HTTP request file parsing (from Burp Suite, OWASP ZAP, etc.)
- 📊 Confidence-based scoring system (HIGH / MEDIUM-HIGH / MEDIUM / LOW)
- 👁️ HTTP response viewing for high-confidence findings
- 🔐 Single and double URL encoding support
- 📝 Custom payload wordlists
- 🤫 Quiet mode for scripting

### Neural Forger (Extension)
- 🧠 ML pre-analysis mode — analyze requests without sending payloads
- 🔎 Automatic parameter discovery (query, body, JSON)
- 📈 Combined ML + injection confidence scoring (30/70 weight)
- 🎯 ML-recommended payload strategies based on 40-example training dataset
- 📄 Multiple output formats (text, JSON, XML)
- 🌐 Proxy support (Burp Suite, OWASP ZAP)
- 🖥️ Python GUI (tkinter)
- ⚠️ Critical finding detection (cloud metadata access)
- ⏱️ Response timing analysis

## Installation

```bash
# Clone the repository
git clone https://github.com/zayarvega/ssrfinder.git
cd ssrfinder

# Install dependencies
pip install requests colorama
```

**Requirements:**
- Python 3.8+
- `requests` — HTTP request handling
- `colorama` — Terminal colored output

> **Note:** Neural Forger's ML detector has zero external dependencies — it uses hardcoded feature weights, no scikit-learn or numpy required.

## Quick Start

```bash
# 1. Create a request file with an injection marker
cat > request.txt << 'EOF'
GET /api/fetch?url=SSRF HTTP/1.1
Host: target.example.com
Content-Type: application/json
EOF

# 2. Run SSRFinder
python3 main.py -r request.txt -p url

# 3. Or run with Neural Forger for ML analysis
python3 neuralforger-main.py -r request.txt -p url
```

---

## SSRFinder Usage

### Request File Format

SSRFinder reads raw HTTP requests (as captured by Burp Suite, OWASP ZAP, or similar tools). Place an injection marker (`SSRF` or `***`) where you want payloads injected:

```http
GET /api/fetch?url=SSRF HTTP/1.1
Host: target.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
Content-Type: application/json
```

The marker can be in the URL, headers, or request body:

```http
POST /api/webhook HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded

callback_url=SSRF&event=push
```

### Basic Scan

Scan with the 14 built-in default payloads:

```bash
python3 main.py -r request.txt -p url
```

### URL Mode

Test directly without a request file:

```bash
python3 main.py -u "http://target.example.com/api/fetch?url=SSRF" -p url
```

### IP Range Scanning

Scan an entire subnet to find internal services:

```bash
# Scan 192.168.1.1 through 192.168.1.50 on default ports
python3 main.py -r request.txt -p url --ip-range 192.168.1.1-50

# With custom ports
python3 main.py -r request.txt -p url --ip-range 10.0.0.1-20 -P 80,443,8080,9200

# Quiet mode for clean output
python3 main.py -r request.txt -p url --ip-range 192.168.1.1-254 -q
```

### Single IP Port Scan

Focus on one IP across multiple ports:

```bash
# Default ports: 80, 443, 8080, 8443, 3000, 5000, 8000, 9000
python3 main.py -r request.txt -p url --ip 192.168.1.5

# Custom ports
python3 main.py -r request.txt -p url --ip 192.168.1.5 -P 22,80,443,3306,5432,6379,8080,9200
```

### Single URL Testing

Test one specific payload directly:

```bash
python3 main.py -r request.txt -p url --single-url "http://192.168.1.5:8080/admin"
```

### Response Viewing

View HTTP response content for high-confidence findings:

```bash
python3 main.py -r request.txt -p url --show-response
python3 main.py -r request.txt -p url -s  # Short form
```

### URL Encoding

Apply encoding to bypass WAF/filters:

```bash
# Single URL encoding
python3 main.py -r request.txt -p url --encode single

# Double URL encoding
python3 main.py -r request.txt -p url --encode double
```

### Custom Wordlists

Use your own payload file:

```bash
python3 main.py -r request.txt -p url -w custom_payloads.txt
```

Wordlist format (one payload per line, `#` for comments):

```
# Localhost payloads
http://127.0.0.1
http://localhost
http://0.0.0.0
# Cloud metadata
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
```

### Investigation Workflow

A typical SSRF hunt goes through 3 phases — broad scan, then narrow, then deep:

```bash
# Phase 1: Broad scan to find responsive IPs
python3 main.py -r request.txt -p url --ip-range 192.168.1.1-50 -q

# Phase 2: Found 192.168.1.5 — scan all its ports
python3 main.py -r request.txt -p url --ip 192.168.1.5 -s

# Phase 3: Found port 8080 — deep dive with response viewing
python3 main.py -r request.txt -p url --single-url "http://192.168.1.5:8080/admin" -s
```

---

## Neural Forger Extension

```
    _   __                     __   ______
   / | / /__  __  _________  / /  / ____/___  _________ ____  _____
  /  |/ / _ \/ / / / ___/ _ \/ /  / /_  / __ \/ ___/ __ `/ _ \/ ___/
 / /|  /  __/ /_/ / /  / __ / /  / __/ / /_/ / /  / /_/ /  __/ /
/_/ |_/\___/\__,_/_/  /_/ /_/_/  /_/    \____/_/   \__, /\___/_/
                                                   /____/
   ML-Powered SSRF Detection Framework v1.0.0
```

Neural Forger extends SSRFinder with machine learning capabilities. It uses SSRFinder's core engine (request parsing, payload injection, network utilities) and adds ML analysis on top.

### What Neural Forger Adds

| Feature | SSRFinder | Neural Forger |
|---------|:---------:|:-------------:|
| Payload injection | ✅ | ✅ (via SSRFinder) |
| IP range scanning | ✅ | ✅ (via SSRFinder) |
| Confidence scoring | Basic (label-based) | Enhanced (numeric 0-100%) |
| ML pre-analysis | ❌ | ✅ |
| Parameter discovery | ❌ | ✅ (auto-discovers url, callback, webhook...) |
| Payload strategies | Default or wordlist | ml-recommended, ml-only, all, custom |
| Output formats | Text only | Text, JSON, XML |
| Proxy support | ❌ | ✅ |
| Response timing | ❌ | ✅ |
| Critical detection | ❌ | ✅ (cloud metadata alerts) |
| GUI | ❌ | ✅ (Python/tkinter) |

### ML Inspection Mode

Analyze a request without sending any payloads — useful for reconnaissance:

```bash
python3 neuralforger-main.py -r request.txt -i
```

Output:

```
========================================================================
ML ANALYSIS RESULTS
========================================================================

  Vulnerability Probability: 95%
  Risk Level: CRITICAL

  SUSPICIOUS PARAMETERS IDENTIFIED:

  Parameter: url
    Location: query
    Confidence: 95%
    Reason: Parameter name is 'url' (primary SSRF indicator)

  RECOMMENDED PAYLOADS (by dataset success rate):

  1. http://localhost/admin
     Priority: HIGH | Success Rate: 37%
  2. http://169.254.169.254/latest/meta-data/
     Priority: CRITICAL | Success Rate: 27%
  3. http://192.168.1.1
     Priority: MEDIUM | Success Rate: 7%
  4. http://metadata.google.internal/computeMetadata/v1/
     Priority: CRITICAL | Success Rate: 3%
  5. http://169.254.169.254/metadata/instance?api-version=2021-02-01
     Priority: CRITICAL | Success Rate: 2%

[+] Proceed with detailed injection testing using:
    neuralforger -r request.txt -p url
```

The ML model evaluates:
- **Parameter names** — `url`, `webhook`, `callback`, `redirect`, `fetch`, `proxy`, `src`, `dest`, `load`, `download` and 20+ others
- **Endpoint patterns** — `/api/`, `/fetch`, `/proxy`, `/webhook`, `/download`
- **Authentication** — presence of `Authorization`, `Cookie`, `X-API-Key` headers (reduces risk score)
- **HTTP method** — POST slightly increases risk
- **Protocol** — HTTPS slightly reduces risk

### ML-Enhanced Injection

Run injection testing with ML pre-analysis and combined confidence scoring:

```bash
python3 neuralforger-main.py -r request.txt -p url
```

Neural Forger first runs ML analysis, then uses SSRFinder's injection engine. Results show combined confidence:

```
[*] ML Pre-Analysis: 95% vulnerability probability
[*] Target Parameter: url
[*] Strategy: ml-recommended
[*] Testing 19 payloads...

[+] Payload: http://localhost/admin
    Response: 200 (4,521 bytes)
    Response Time: 142ms
    Confidence Score: 89.6%
    Status: VULNERABLE
```

The combined score weights ML at 30% and injection at 70%:

```
FINAL ASSESSMENT
  Vulnerability Status: CONFIRMED
  Combined Confidence: 89.6%
  Severity: HIGH

  ML Prediction: 95%
  Injection Confidence: 92.0%
  ML Prediction Accuracy: CORRECT
```

### Payload Strategies

Control how payloads are selected:

```bash
# ML-recommended (default): ML payloads first, then defaults
python3 neuralforger-main.py -r request.txt -p url --payload-strategy ml-recommended

# ML-only: only use payloads recommended by the ML model
python3 neuralforger-main.py -r request.txt -p url --payload-strategy ml-only

# All: ML payloads + full default list, deduplicated
python3 neuralforger-main.py -r request.txt -p url --payload-strategy all

# Custom: use your own wordlist
python3 neuralforger-main.py -r request.txt -p url --payload-strategy custom -w payloads.txt
```

### Output Formats

```bash
# JSON output
python3 neuralforger-main.py -r request.txt -p url --format json -o results.json

# XML output
python3 neuralforger-main.py -r request.txt -p url --format xml -o results.xml

# Text file
python3 neuralforger-main.py -r request.txt -p url -o results.txt
```

### Proxy Support

Route traffic through Burp Suite or OWASP ZAP:

```bash
python3 neuralforger-main.py -r request.txt -p url --proxy http://127.0.0.1:8080
```

### GUI Interface

Launch the graphical interface:

```bash
python3 neuralforger-gui.py
```

The GUI provides:
- Request file editor with syntax highlighting
- Injection marker insertion
- Toggle between SSRFinder (base) and Neural Forger (ML) modes
- Visual command builder with all parameters
- Live output terminal
- File browser for request files and wordlists

---

## Architecture

SSRFinder is the **base application** with 15 Python files. Neural Forger is an **extension** with 10 additional `neuralforger-*.py` files that import from SSRFinder's modules.

```
SSRFinder (standalone)              Neural Forger (extension)
========================            ================================

main.py (entry point)               neuralforger-main.py (entry point)
├── banner.py                       ├── neuralforger-banner.py
├── cli_parser.py                   ├── neuralforger-cli.py
├── config.py ◄──────────────────────── neuralforger-config.py
├── ssrfinder_class.py              ├── neuralforger-ml.py
│   ├── request_parser.py ◄──────────── │ (imports parse_raw_request)
│   ├── request_sender.py ◄──────────── │ (imports create_session, send_request)
│   ├── injection_handler.py ◄────────── │ (imports find/replace_injection_point)
│   ├── payload_generator.py ◄─────────── │ (imports generate_payloads)
│   ├── confidence_calculator.py ◄───── neuralforger-confidence.py
│   ├── response_formatter.py ◄──────── │ (imports format_response_preview)
│   └── summary_printer.py          ├── neuralforger-output.py
├── network_parser.py ◄─────────────── │ (imports parse_ip_range, parse_ports)
├── url_encoding.py ◄───────────────── │ (imports url_encode, add_path)
└── __init__.py                     ├── neuralforger-detector.py (ML engine)
                                    ├── neuralforger-gui.py
                                    └── neuralforger-test.py
```

**Key design principle:** SSRFinder knows nothing about Neural Forger. It works completely independently. Neural Forger imports SSRFinder's modules and extends them — it never duplicates functionality.

### File Descriptions

#### SSRFinder Base (15 files)

| File | Purpose |
|------|---------|
| `main.py` | Entry point, CLI validation, error handling |
| `banner.py` | ASCII art banner display |
| `cli_parser.py` | argparse configuration for all SSRFinder options |
| `config.py` | Constants: version, injection markers, default ports, default payloads |
| `ssrfinder_class.py` | Main orchestrator: baseline, payload testing, result processing |
| `request_parser.py` | Raw HTTP request file parsing (method, URL, headers, body) |
| `request_sender.py` | HTTP session management and request sending |
| `injection_handler.py` | Injection marker detection (`SSRF`, `***`) and replacement |
| `payload_generator.py` | Payload generation from defaults, wordlists, IP ranges, ports |
| `confidence_calculator.py` | Label-based confidence scoring (HIGH, MEDIUM, LOW, etc.) |
| `response_formatter.py` | HTTP response content display |
| `summary_printer.py` | Scan results summary and follow-up suggestions |
| `network_parser.py` | IP range and port string parsing |
| `url_encoding.py` | Single/double URL encoding and path appending |
| `__init__.py` | Package init, exports SSRFinder class |

#### Neural Forger Extension (10 files)

| File | Purpose |
|------|---------|
| `neuralforger-main.py` | Entry point, orchestrates ML + injection workflow using SSRFinder's core |
| `neuralforger-banner.py` | Neural Forger ASCII banner (standalone) |
| `neuralforger-cli.py` | Extended CLI with `-i`, `--payload-strategy`, `--proxy`, `--format`, etc. |
| `neuralforger-config.py` | Extends `config.py` with ML thresholds, strategies, exit codes |
| `neuralforger-detector.py` | ML engine: feature extraction, scoring, payload recommendations (zero deps) |
| `neuralforger-ml.py` | ML integration layer: parameter discovery, MLResult, MLAnalyzer class |
| `neuralforger-confidence.py` | Extends `confidence_calculator.py` with numeric scores and ML+injection weighting |
| `neuralforger-output.py` | Professional output formatter: text/JSON/XML, file output, progress bars |
| `neuralforger-gui.py` | Python tkinter GUI for both SSRFinder and Neural Forger |
| `neuralforger-test.py` | Integration test suite (65 tests covering both SSRFinder and NF) |

---

## Confidence Levels

### SSRFinder (label-based)

| Level | Criteria | Meaning |
|-------|----------|---------|
| **HIGH** | Status 200 + response size diff > 10% | Strong SSRF indication |
| **MEDIUM-HIGH** | Redirect (3xx) or 201/202 + size diff | Likely SSRF, needs verification |
| **MEDIUM** | 401/403 + size diff | Server processed internal request |
| **LOW-MEDIUM** | 404 + size diff | Possible internal connection |
| **LOW** | 5xx + size diff | Failed SSRF attempt |
| **VERY-LOW** | 4xx client errors | Likely false positive |

### Neural Forger (numeric 0-100%)

| Severity | Score | Meaning |
|----------|-------|---------|
| **CRITICAL** | 90-100% | Confirmed exploitation |
| **HIGH** | 75-89% | Strong vulnerability indicators |
| **MEDIUM** | 50-74% | Moderate indicators, manual verification needed |
| **LOW** | 25-49% | Weak indicators, likely false positive |
| **INFO** | 0-24% | No significant indicators |

The combined confidence formula: `combined = (ML × 0.30) + (injection × 0.70)`

---

## All Parameters Reference

### SSRFinder

```
python3 main.py [options]

Required (one of):
  -r, --request FILE       Raw HTTP request file
  -u, --url URL            Target URL with injection marker

Required:
  -p, --param NAME         Parameter name to test

Payload options (mutually exclusive):
  -w, --wordlist FILE      Custom payload wordlist
  --ip-range RANGE         IP range (e.g., 192.168.1.1-254)
  --ip ADDRESS             Single IP, all ports
  --single-url URL         Test one specific URL

Options:
  -t, --timeout SECONDS    Request timeout (default: 5)
  -P, --port PORTS         Custom ports (e.g., 80,443,8000-9000)
  --path PATH              Append path to payloads (e.g., /admin)
  --encode {none,single,double}  URL encoding
  -s, --show-response      Show response content for high findings
  -q, --quiet              Quiet mode
```

### Neural Forger (extends SSRFinder)

```
python3 neuralforger-main.py [options]

All SSRFinder options plus:

Operation modes:
  -i, --inspect            ML analysis only (no injection)

ML options:
  --payload-strategy TYPE  ml-recommended | all | ml-only | custom
  --confidence-threshold N Minimum ML confidence to proceed (default: 70)

Network:
  --proxy URL              HTTP/HTTPS proxy

Output:
  -v, --verbose            Verbose mode with ML reasoning
  --format {text,json,xml} Output format
  -o, --output FILE        Save results to file

Info:
  -m, --manual             Show detailed manual
  --version                Show version
```

---

## Exit Codes

| Code | SSRFinder | Neural Forger |
|------|-----------|---------------|
| `0` | Normal exit | No vulnerability found |
| `1` | Error | Error |
| `2` | — | Vulnerability confirmed (≥1 HIGH finding) |

---

## Running Tests

Neural Forger includes an integration test suite that validates both SSRFinder's base modules and the NF extension:

```bash
python3 neuralforger-test.py
```

```
========================================================================
NEURAL FORGER - INTEGRATION TEST SUITE
Testing SSRFinder base + Neural Forger extension
========================================================================

[*] Testing ML Detector...
  [PASS] detect_ssrf: url param -> vulnerable
  [PASS] detect_ssrf: safe endpoint -> not vulnerable
  ...

[*] Testing SSRFinder + NeuralForger Integration...
  [PASS] config: NF imports SSRFinder defaults
  [PASS] config: NF markers superset of SSRFinder
  [PASS] confidence: both agree on 200+diff

========================================================================
Results: 65/65 passed, 0/65 failed
========================================================================
```

---

## Disclaimer

This tool is designed for **authorized security testing and research purposes only**. Only use SSRFinder and Neural Forger against systems you have explicit permission to test. Unauthorized access to computer systems is illegal. The authors are not responsible for any misuse of this tool.


