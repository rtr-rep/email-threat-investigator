# Email Threat Investigator / PhishTriage Project Blueprint

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build a user-friendly phishing/email investigation tool that analyzes suspicious `.eml` files, explains risk in plain English, and produces analyst-ready evidence reports.

**Architecture:** Start with a local Python CLI and tested analysis modules, then add a simple Streamlit web UI for non-technical users. Keep detection explainable: every risk score must map to a human-readable finding and recommended action.

**Tech Stack:** Python 3.12+, stdlib `email` parser, Typer or argparse for CLI, pytest, rich optional for terminal output, Streamlit later for UI, Markdown reports.

---

## Product principle

The tool must answer three questions for a non-technical user:

1. Is this email suspicious?
2. Why is it suspicious?
3. What should I do next?

Technical details are useful, but they should sit behind plain-English findings.

---

## MVP scope

### Input

- `.eml` file uploaded or passed by path.
- Future: pasted headers/body.
- Future: mailbox integration, but not in v1.

### Output

- Verdict: Low / Suspicious / High Risk / Dangerous.
- Risk score: 0-100.
- Plain-English explanation.
- Evidence list.
- Recommended next actions.
- Extracted indicators of compromise.
- Markdown report.

---

## Core features

### 1. Email parser

Extract from `.eml`:

- From
- To
- Subject
- Date
- Reply-To
- Return-Path
- Message-ID
- Received headers
- Authentication-Results
- plain text body
- HTML body
- links
- attachment metadata

### 2. Suspicious reply detection

Flag reply-path/BEC risks:

- `Reply-To` differs from `From`.
- `Reply-To` domain is unrelated to visible sender domain.
- Corporate-looking sender replies to a free-mail provider.
- `Return-Path` differs suspiciously from `From`.
- Display name impersonates a known organization but address does not match.
- Body asks the user to reply with payment, credentials, phone number, bank details, or urgent confirmation.

Example finding:

> High risk: this email claims to be from Microsoft, but replies go to `microsoft-helpdesk-verify@gmail.com`, not a Microsoft domain.

### 3. Authentication/header analysis

Parse/flag:

- SPF pass/fail/softfail/neutral/missing.
- DKIM pass/fail/missing.
- DMARC pass/fail/missing.
- DKIM/DMARC alignment with visible From domain.
- suspicious Message-ID domain mismatch.
- missing Authentication-Results when expected.

### 4. Header Hop Timeline / Email Route Reconstruction

Reconstruct the observed delivery route from `Received` headers.

User-facing label:

- Email journey

Analyst-facing label:

- Header Hop Timeline

Attempt to classify visible stages where possible:

- MUA: Mail User Agent, sender/client, often only inferred from `X-Mailer`, `User-Agent`, or Message-ID.
- MSA: Mail Submission Agent, first authenticated submission server, often inferred.
- MTA: Mail Transfer Agent, visible relay hops in Received headers.
- MDA: Mail Delivery Agent, delivery/mailbox server, sometimes visible.
- MUA: recipient mail client, usually not present in `.eml` headers.

Flag route anomalies:

- missing or too few Received headers.
- timestamp order inconsistencies.
- large unexplained gaps between hops.
- private/internal IP leakage.
- first public sending IP unrelated to sender domain.
- HELO/EHLO hostname mismatch.
- no reverse DNS if enriched later.
- Authentication-Results contradicting route/sender claims.

Plain-English example:

> The email says it came from `example-bank.com`, but the first visible sending server is `unknown-vps-host.net`. That does not look like normal mail infrastructure for the claimed sender.

### 5. URL/link analysis

Extract and flag:

- visible link text vs actual `href` mismatch.
- URL shorteners.
- IP-address URLs.
- punycode/lookalike domains.
- suspicious TLDs.
- login/reset/payment keywords.
- suspicious redirects later, using safe HEAD/GET rules.

### 6. Attachment analysis

For MVP, no malware execution or sandboxing.

Extract:

- filename.
- MIME type.
- extension.
- size.
- SHA256 hash.

Flag:

- suspicious extensions: `.exe`, `.scr`, `.js`, `.vbs`, `.hta`, `.lnk`, `.iso`, `.img`, `.docm`, `.xlsm`.
- MIME/extension mismatch.
- double extensions: `invoice.pdf.exe`.

### 7. Risk scoring

Transparent scoring. Every point creates an explanation.

Initial scoring proposal:

- SPF fail: +15
- DKIM fail: +10
- DKIM missing for corporate sender: +5
- DMARC fail: +20
- Reply-To domain mismatch: +20
- free-mail Reply-To for corporate sender: +25
- Return-Path mismatch: +10
- visible URL text differs from destination: +25
- URL shortener: +10
- IP-address URL: +20
- suspicious attachment extension: +30
- double extension attachment: +25
- urgent credential/payment language: +10
- route anomaly: +15
- Message-ID domain mismatch: +10

Verdicts:

- 0-20: Low
- 21-45: Suspicious
- 46-70: High Risk
- 71-100: Dangerous

---

## Non-technical user experience

### CLI first

Command:

```bash
phishtriage analyze samples/fake-invoice.eml --out reports/fake-invoice-report.md
```

Terminal output:

```text
Verdict: HIGH RISK
Score: 68/100

Why this is suspicious:
- Replies go to a Gmail address, but the email claims to be from a company domain.
- DMARC failed.
- The email asks for urgent payment confirmation.
- One attachment has a suspicious double extension.

Recommended action:
- Do not reply.
- Do not open the attachment.
- Report the email to IT/security.
- If you already replied, contact your security/helpdesk team.

Report written to: reports/fake-invoice-report.md
```

### Web UI later

Use Streamlit:

- upload `.eml`.
- show big verdict card.
- show “Why this matters” in plain English.
- show “What to do now”.
- expandable technical details.
- email route timeline visualization.
- download Markdown report.

---

## Repository structure

```text
email-threat-investigator/
  README.md
  pyproject.toml
  src/
    phishtriage/
      __init__.py
      cli.py
      models.py
      parser.py
      reply_analyzer.py
      auth_analyzer.py
      route_analyzer.py
      url_analyzer.py
      attachment_analyzer.py
      content_analyzer.py
      scoring.py
      report.py
  samples/
    benign-newsletter.eml
    legitimate-company-email.eml
    suspicious-reply-to-bec.eml
    fake-microsoft-login.eml
    fake-invoice-attachment.eml
    route-anomaly-spoof.eml
  reports/
    README.md
  tests/
    test_parser.py
    test_reply_analyzer.py
    test_auth_analyzer.py
    test_route_analyzer.py
    test_url_analyzer.py
    test_attachment_analyzer.py
    test_scoring.py
    test_report.py
  docs/
    investigation-playbook.md
    detection-rules.md
    plans/
      2026-06-03-project-blueprint.md
```

---

## Milestones

### Milestone 1: Suspicious Reply & Sender Identity Analyzer

Goal: smallest useful demo.

Build:

- parse `.eml` headers.
- extract From, Reply-To, Return-Path, Message-ID, Subject, body text.
- detect Reply-To mismatch.
- detect free-mail Reply-To for corporate sender.
- detect suspicious reply-request language.
- produce risk score and plain-English findings.
- generate Markdown report.

Demo command:

```bash
phishtriage analyze samples/suspicious-reply-to-bec.eml
```

### Milestone 2: Header Hop Timeline

Build:

- parse Received headers.
- preserve order.
- extract server names, IPs, timestamps where possible.
- classify likely MTA hops.
- flag timestamp/order anomalies.
- output plain-English email journey.

### Milestone 3: URL and Attachment Analysis

Build:

- HTML/body URL extraction.
- visible text vs href mismatch detection.
- URL shortener/IP URL flags.
- attachment metadata and suspicious extension flags.

### Milestone 4: Report Quality

Build:

- polished Markdown report template.
- IOC table.
- recommended actions by risk level.
- sample reports committed to repo.

### Milestone 5: Streamlit UI

Build:

- `.eml` upload.
- verdict card.
- findings list.
- email route timeline.
- download report.

### Milestone 6: Optional Threat Intel Enrichment

Add only after local MVP works:

- URLhaus.
- VirusTotal, behind user-supplied API key.
- WHOIS/domain age.
- ASN/geolocation.

---

## First implementation tasks

### Task 1: Create project skeleton

**Objective:** Set up package, tests, and CLI entrypoint.

**Files:**

- Create: `pyproject.toml`
- Create: `src/phishtriage/__init__.py`
- Create: `src/phishtriage/cli.py`
- Create: `tests/test_cli.py`

**TDD:** Write CLI help test first, verify failure, implement minimal CLI, verify pass.

### Task 2: Create sample BEC email

**Objective:** Add a safe synthetic `.eml` sample for reply-path detection.

**Files:**

- Create: `samples/suspicious-reply-to-bec.eml`
- Create: `tests/fixtures/README.md`

**Verification:** Parser tests use this sample; no real personal data.

### Task 3: Parse core email fields

**Objective:** Convert `.eml` into a structured `EmailAnalysisInput` model.

**Files:**

- Create: `src/phishtriage/models.py`
- Create: `src/phishtriage/parser.py`
- Create: `tests/test_parser.py`

**TDD behavior:** Given the BEC sample, parser returns From, Reply-To, Return-Path, Message-ID, Subject, text body.

### Task 4: Detect suspicious Reply-To

**Objective:** Flag mismatched reply destination and explain it.

**Files:**

- Create: `src/phishtriage/reply_analyzer.py`
- Create: `tests/test_reply_analyzer.py`

**TDD behavior:** Corporate sender with Gmail Reply-To returns high-risk finding.

### Task 5: Add scoring model

**Objective:** Convert findings into a score and verdict.

**Files:**

- Create: `src/phishtriage/scoring.py`
- Create: `tests/test_scoring.py`

**TDD behavior:** Reply-To mismatch + free-mail reply gives Suspicious/High Risk verdict depending thresholds.

### Task 6: Generate Markdown report

**Objective:** Produce a readable report for non-technical users.

**Files:**

- Create: `src/phishtriage/report.py`
- Create: `tests/test_report.py`

**TDD behavior:** Report includes verdict, why suspicious, recommended action, and technical evidence.

### Task 7: Wire CLI analyze command

**Objective:** Run full Milestone 1 from terminal.

**Files:**

- Modify: `src/phishtriage/cli.py`
- Modify: `tests/test_cli.py`

**Verification:**

```bash
uv run pytest -q
uv run phishtriage analyze samples/suspicious-reply-to-bec.eml --out reports/suspicious-reply-to-bec-report.md
```

Expected:

- tests pass.
- report file created.
- output gives plain-English risk summary.

---

## GitHub/LinkedIn positioning

README opening:

> Email Threat Investigator is a Python phishing triage toolkit that analyzes suspicious `.eml` files, detects reply-path fraud, reconstructs email delivery routes from headers, extracts indicators of compromise, and generates plain-English investigation reports for non-technical users and SOC analysts.

LinkedIn post angle:

> I’m building a small phishing investigation tool that turns a suspicious email into a clear risk report: reply-path anomalies, authentication failures, suspicious links, attachment indicators, and an email route timeline. The goal is simple: make email threat triage understandable for non-technical users while showing the evidence an analyst would need.

---

## What not to build first

Avoid in v1:

- live Gmail/Outlook integration.
- automatic quarantine/deletion.
- malware sandboxing.
- paid API dependency.
- LLM-only verdicts.
- enterprise SIEM integration.

Keep the first release local, explainable, testable, and demo-friendly.
