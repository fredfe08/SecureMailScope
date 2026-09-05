# SecureMailScope

SecureMailScope is an AI-assisted email security posture analysis system designed to evaluate the security configuration of email services.

## Current Architecture

```text
M1 Network Evidence
        |
        v
M2 TLS Scanner
        |
        v
M3 SPF / DKIM / DMARC
        |
        v
   evidence.json
        |
        v
   analyzer.py
        |
        v
   analysis.json
```

## Current Modules

### `main.py`

Coordinates the scanning pipeline.

It runs:

1. TLS scanning
2. SPF checking
3. DKIM checking
4. DMARC checking
5. Security analysis

All evidence is maintained in a single `evidence.json` file.

### `tls_scanner.py`

Collects TLS and certificate information from the email service endpoint.

It checks information such as:

* TLS version
* Cipher
* Cipher strength
* Certificate validity
* Certificate expiration
* Certificate hostname matching
* STARTTLS support

### `spf_checker.py`

Checks the domain's Sender Policy Framework (SPF) record and evaluates its policy.

### `dkim_checker.py`

Checks common DomainKeys Identified Mail (DKIM) selectors.

A selector not being found is treated as inconclusive and does not automatically reduce the security score.

### `dmarc_checker.py`

Checks the domain's Domain-based Message Authentication, Reporting, and Conformance (DMARC) record and evaluates its policy.

### `domain_utils.py`

Determines the organizational domain used for SPF, DKIM and DMARC checks.

For example:

```text
imap.gmail.com
       |
       v
   gmail.com
```

### `analyzer.py`

Analyzes the combined `evidence.json`.

It does not perform network, TLS or DNS scans.

It produces:

* Security findings
* Security score
* Risk level
* Score breakdown

## Output

The analyzer generates:

```text
analysis.json
```

Example:

```json
{
  "security_score": 50,
  "risk_level": "HIGH"
}
```

The score is calculated from the findings rather than being hardcoded.

## Scoring

The current scoring system starts at:

```text
100 points
```

and deducts points according to detected security issues.

The current risk thresholds are:

```text
80-100  → LOW
60-79   → MEDIUM
40-59   → HIGH
0-39    → CRITICAL
```

The scoring system is a project-defined heuristic and should not be treated as an industry certification.

## Installation

Create and activate a Python virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Running the Pipeline

Run:

```powershell
python main.py
```

The pipeline updates:

```text
evidence.json
```

and generates:

```text
analysis.json
```

## Testing

Run the complete test suite:

```powershell
python -m unittest discover -v
```

The tests are designed to avoid depending on real Internet/DNS availability by using mocked conditions where appropriate.

## Example Current Test Result

```text
Ran 11 tests

OK
```

## Project Status

Current backend analysis pipeline:

* Network evidence integration: implemented
* TLS analysis: implemented
* SPF analysis: implemented
* DKIM analysis: implemented
* DMARC analysis: implemented
* Combined evidence architecture: implemented
* Security scoring: implemented
* Risk classification: implemented
* Automated tests: passing

Future components include the user interface, AI-generated reporting and final end-to-end integration.
