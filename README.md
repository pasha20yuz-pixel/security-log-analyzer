# Security Log Analyzer

[![Tests](https://github.com/pasha20yuz-pixel/security-log-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/pasha20yuz-pixel/security-log-analyzer/actions/workflows/tests.yml)

A Python-based security log analyzer for detecting suspicious authentication activity.

The project parses authentication logs, analyzes login events, and detects common authentication attacks such as brute-force attempts and password spraying.

This project was built as a portfolio project to demonstrate Python development, testing, Git/GitHub workflow, CLI development, and practical information security concepts.

## Features

- Authentication log parsing
- Brute-force attack detection
- Password spraying detection
- Configurable detection threshold
- Configurable detection time window
- Human-readable CLI output
- JSON output
- CLI argument validation
- Invalid log data handling
- Automated tests with pytest
- 97.6% test coverage
- Code quality checks with Ruff
- GitHub Actions CI

## Detection Capabilities

### Brute Force

Detects repeated failed login attempts against the same user from the same IP address within a configurable time window.

Example:

```text
admin <- 192.168.1.10
admin <- 192.168.1.10
admin <- 192.168.1.10
```

Result:

```text
[HIGH] BRUTE_FORCE
User: admin
IP: 192.168.1.10
Failed attempts: 3
```

### Password Spraying

Detects multiple failed login attempts against different users from the same IP address within a configurable time window.

Example:

```text
10.0.0.50 -> admin
10.0.0.50 -> root
10.0.0.50 -> test
```

Result:

```text
[HIGH] PASSWORD_SPRAYING
User: *
IP: 10.0.0.50
Failed attempts: 3
```

## Architecture

```text
                    Authentication Log
                            |
                            v
                         Parser
                            |
                            v
                       LogEvent[]
                            |
                            v
                    Detection Engine
                     /              \
                    v                v
              Brute Force     Password Spraying
                    \                /
                     \              /
                      v            v
                       SecurityAlert[]
                              |
                              v
                             CLI
                         /         \
                        v           v
                      Text        JSON
```

### Components

- `parser.py` — parses raw authentication log lines into structured `LogEvent` objects and validates input.
- `analyzer.py` — contains brute-force and password-spraying detection logic and creates `SecurityAlert` objects.
- `cli.py` — provides the command-line interface, argument validation, file loading, and text/JSON output.

## Project Structure

```text
security-log-analyzer/
|
+-- .github/
|   +-- workflows/
|       +-- tests.yml
|
+-- examples/
|   +-- auth.log
|
+-- src/
|   +-- seclog/
|       +-- __init__.py
|       +-- analyzer.py
|       +-- cli.py
|       +-- parser.py
|
+-- tests/
|   +-- test_analyzer.py
|   +-- test_cli.py
|   +-- test_parser.py
|
+-- .gitignore
+-- pyproject.toml
+-- README.md
+-- requirements.txt
```

## Requirements

- Python 3.11+
- Git
- pytest
- pytest-cov
- Ruff

The project currently has no external runtime dependencies.

## Installation

```bash
git clone https://github.com/pasha20yuz-pixel/security-log-analyzer.git
cd security-log-analyzer
python -m venv .venv
```

### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m pip install -r requirements.txt
```

## Usage

Run the analyzer against the example log:

```bash
python -m seclog.cli examples/auth.log
```

Example output:

```text
Security Log Analyzer
==============================
Events analyzed: 13
Alerts detected: 3

[HIGH] BRUTE_FORCE
User: admin
IP: 192.168.1.10
Failed attempts: 3

[HIGH] BRUTE_FORCE
User: root
IP: 10.0.0.5
Failed attempts: 3

[HIGH] PASSWORD_SPRAYING
User: *
IP: 10.0.0.50
Failed attempts: 3
```

## CLI Demo

Example of running the analyzer:

![CLI Demo](docs/cli-demo.png)

## Configuration

### Detection Threshold

The default threshold is 3 failed attempts.

```bash
python -m seclog.cli examples/auth.log --threshold 5
```

### Detection Time Window

The detection window is specified in seconds.

```bash
python -m seclog.cli examples/auth.log --window 120
```

Parameters can be combined:

```bash
python -m seclog.cli examples/auth.log --threshold 5 --window 120
```

## JSON Output

```bash
python -m seclog.cli examples/auth.log --format json
```

Example:

```json
{
  "events_analyzed": 13,
  "alerts_detected": 3,
  "alerts": [
    {
      "alert_type": "BRUTE_FORCE",
      "severity": "HIGH",
      "username": "admin",
      "ip_address": "192.168.1.10",
      "failed_attempts": 3
    },
    {
      "alert_type": "BRUTE_FORCE",
      "severity": "HIGH",
      "username": "root",
      "ip_address": "10.0.0.5",
      "failed_attempts": 3
    },
    {
      "alert_type": "PASSWORD_SPRAYING",
      "severity": "HIGH",
      "username": "*",
      "ip_address": "10.0.0.50",
      "failed_attempts": 3
    }
  ]
}
```

## Testing

Run the complete test suite:

```bash
python -m pytest
```

Current result:

```text
31 passed
```

The tests cover log parsing, invalid input, brute-force detection, password spraying, time windows, custom thresholds, state resets, CLI behavior, JSON output, and log-file loading.

## Test Coverage

The current test coverage is **97.6%**.

Run:

```bash
python -m pytest --cov=seclog --cov-report=term-missing
```

Current coverage:

```text
src\\seclog\\__init__.py       100%
src\\seclog\\analyzer.py      100%
src\\seclog\\cli.py           96%
src\\seclog\\parser.py        94%
TOTAL                           97.60%
```

The project requires at least 90% coverage in `pyproject.toml`.

## Code Quality

The project uses Ruff for static analysis and linting.

```powershell
.\.venv\Scripts\ruff.exe check .
```

Expected result:

```text
All checks passed!
```

## Continuous Integration

GitHub Actions automatically runs the test suite using:

```text
.github/workflows/tests.yml
```

## Example Log Format

The analyzer expects structured authentication events in the following form:

```text
timestamp EVENT_TYPE user=USERNAME ip=IP_ADDRESS
```

Example:

```text
2026-08-13 10:15:21 LOGIN_FAILED user=admin ip=192.168.1.10
2026-08-13 10:15:31 LOGIN_FAILED user=admin ip=192.168.1.10
2026-08-13 10:15:41 LOGIN_FAILED user=admin ip=192.168.1.10
2026-08-13 10:16:00 LOGIN_SUCCESS user=admin ip=192.168.1.10
```

## Security Concepts Demonstrated

- Authentication monitoring
- Brute-force attacks
- Password spraying
- Suspicious login activity
- Time-window based detection
- Threshold-based detection
- Event correlation
- Security alert generation
- Log analysis
- Detection state management

The project is focused on defensive security and security monitoring.

## Design Principles

### Separation of Concerns

Parsing, detection logic, and CLI functionality are separated into different modules.

### Structured Data

Authentication events and security alerts are represented as structured Python objects instead of raw strings.

### Configurable Detection

Thresholds and time windows are configurable.

### Testability

The detection engine is separated from the CLI, making individual detection functions easy to test.

### Input Validation

Invalid input is rejected instead of silently producing potentially incorrect security results.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.11 | Core implementation |
| `argparse` | CLI argument parsing |
| `json` | Machine-readable output |
| `pytest` | Automated testing |
| `pytest-cov` | Test coverage |
| Ruff | Static analysis and linting |
| Git | Version control |
| GitHub | Repository hosting |
| GitHub Actions | Continuous integration |

## Current Status

The project currently provides:

- Working authentication log parser
- Brute-force detection
- Password spraying detection
- Configurable detection parameters
- Human-readable CLI output
- JSON output
- 31 passing tests
- 97.6% test coverage
- Ruff checks
- GitHub Actions CI

## Future Improvements

- Account enumeration detection
- Suspicious successful login detection
- Additional authentication attack patterns
- Support for additional log formats
- Exporting alerts to files
- More detailed incident information
- Additional security alert types
- Coverage improvements toward 100%
- Additional CI quality checks
- Performance improvements for large log files

## Author

### Pavel Yuzhalkin

Information Security student at Peter the Great St. Petersburg Polytechnic University.

GitHub: https://github.com/pasha20yuz-pixel

Project repository: https://github.com/pasha20yuz-pixel/security-log-analyzer
