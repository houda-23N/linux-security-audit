# Linux Security Audit Toolkit

A Python-based Linux security auditing tool that performs automated security checks, identifies potentially risky configurations, calculates an overall security score, and generates an HTML security assessment report.

## Overview

The Linux Security Audit Toolkit was developed to automate common Linux security assessment tasks and provide a structured view of potential security weaknesses.

The tool collects information from the local Linux system and analyzes areas such as:

* User accounts and administrative privileges
* SSH configuration
* Network exposure
* Running services
* Firewall configuration
* Sensitive file permissions
* Authentication and security logs

Detected issues are classified by severity and processed by a risk engine that calculates an overall security score and risk level.

The tool can also generate an HTML report containing the audit results, security score, risk assessment, and identified findings.

> **Note:** This tool is intended for authorized security auditing of systems that you own or have permission to assess.

## Features

* Automated Linux security assessment
* System and environment information collection
* Local user and privilege auditing
* SSH security configuration analysis
* Network listening-port and exposure analysis
* Running systemd service analysis
* UFW firewall configuration assessment
* Sensitive file permission checks
* Authentication and security log analysis
* Severity-based security findings
* Custom risk scoring engine
* Overall security score from 0 to 100
* Risk-level classification
* HTML security assessment reports
* Configurable report output path
* Command-line interface
* Automated test suite with pytest

## Security Checks

### 1. System Information

Collects basic information about the audited Linux system, including:

* Operating system
* OS release
* Kernel version
* Hostname
* Current user
* CPU architecture
* Python version
* System uptime

### 2. User & Privilege Audit

Examines local user and group information and identifies users belonging to privileged groups such as:

* `sudo`
* `adm`

This helps identify accounts that may have administrative or elevated access.

### 3. SSH Security

Analyzes the SSH server configuration for potentially insecure settings, including:

* Root SSH login
* Password authentication
* Empty-password authentication

Higher-risk configurations are reported as security findings.

### 4. Network Exposure

Examines Linux `/proc` network tables to identify listening TCP and UDP sockets.

The tool identifies common services and flags ports that may require additional security review, including services such as:

* Telnet
* FTP
* SMB
* RDP
* MySQL
* PostgreSQL
* Redis
* VNC

The tool distinguishes between sockets bound broadly, such as `0.0.0.0` or `::`, and locally bound services.

> A flagged port does not automatically mean that a vulnerability exists. It indicates that the service or exposure should be reviewed.

### 5. Running Services

Analyzes currently running systemd services and identifies services that may deserve additional security review, including:

* Telnet
* FTP
* SMB
* NetBIOS
* Redis
* MySQL
* PostgreSQL
* CUPS

### 6. Firewall Audit

Checks the status and configuration of the UFW firewall.

The audit examines:

* Whether UFW is installed
* Whether the firewall is active
* Default incoming policy
* Default outgoing policy
* Configured firewall rules

### 7. File Permissions

Audits permissions and ownership information for sensitive system paths, including:

```text
/etc/passwd
/etc/shadow
/etc/group
/etc/sudoers
/etc/ssh
```

The tool identifies potentially dangerous permissions such as world-writable sensitive files.

### 8. Security Logs

Analyzes recent authentication-related events from the system journal or authentication logs.

The audit looks for events such as:

* Failed password authentication
* Invalid users
* Authentication failures
* Successful password logins
* Successful public-key logins

The results provide basic visibility into authentication activity on the system.

## Architecture

The application follows a modular architecture where each security area is implemented as a separate Python module.

```text
                    ┌─────────────────┐
                    │    audit.py     │
                    │   CLI / Engine  │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
        Security Modules  Security Modules  Security Modules
              │              │              │
              └──────────────┼──────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   Risk Engine   │
                    │    risk.py      │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Security Score  │
                    │  & Risk Level   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │  HTML Reporter  │
                    │   report.py     │
                    └─────────────────┘
```

### Audit Flow

1. `audit.py` starts the audit and coordinates the different modules.
2. Security modules collect and analyze information from the local Linux system.
3. Individual findings are assigned severity levels.
4. The risk engine calculates the total risk points.
5. Risk points are converted into a security score.
6. The score is mapped to an overall risk level.
7. The report generator creates a structured HTML security report.

## Project Structure

```text
linux-security-audit/
├── audit.py
├── requirements.txt
├── README.md
├── LICENSE
├── pytest.ini
│
├── modules/
│   ├── __init__.py
│   ├── system.py
│   ├── users.py
│   ├── ssh.py
│   ├── network.py
│   ├── services.py
│   ├── firewall.py
│   ├── permissions.py
│   ├── logs.py
│   ├── risk.py
│   └── report.py
│
├── reports/
├── screenshots/
│
└── tests/
    ├── test_risk.py
    ├── test_ssh.py
    ├── test_services.py
    ├── test_network.py
    ├── test_firewall.py
    ├── test_permissions.py
    ├── test_logs.py
    ├── test_report.py
    └── test_users.py
```

### Main Components

| Component        | Responsibility                                |
| ---------------- | --------------------------------------------- |
| `audit.py`       | Main application and command-line interface   |
| `system.py`      | Collects system information                   |
| `users.py`       | Audits users, groups, and privileged accounts |
| `ssh.py`         | Analyzes SSH configuration                    |
| `network.py`     | Examines listening network sockets            |
| `services.py`    | Analyzes running systemd services             |
| `firewall.py`    | Checks UFW firewall configuration             |
| `permissions.py` | Audits sensitive file permissions             |
| `logs.py`        | Analyzes authentication-related logs          |
| `risk.py`        | Calculates risk points, score, and risk level |
| `report.py`      | Generates HTML security reports               |
| `tests/`         | Automated unit tests for the project          |

## Requirements

* Linux operating system
* Python 3.10 or newer
* `pip`
* `venv`
* Git
* `systemd` for service analysis
* `ufw` for firewall analysis
* `sudo` access for checks that require elevated privileges

The toolkit is designed and tested in a Linux Mint virtual machine environment.

## Installation

### 1. Clone the Repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd linux-security-audit
```

Replace `<YOUR_GITHUB_REPOSITORY_URL>` with the URL of your GitHub repository.

### 2. Create a Virtual Environment

```bash
python3 -m venv .venv
```

### 3. Activate the Virtual Environment

```bash
source .venv/bin/activate
```

After activation, your terminal should show:

```text
(.venv)
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Verify the Installation

Run:

```bash
python3 audit.py --version
```

Expected output:

```text
audit.py 1.0.0
```

You can also display the available command-line options:

```bash
python3 audit.py --help
```

## Running the Audit

Run the complete security audit with:

```bash
python3 audit.py
```

The tool collects information from the local system, analyzes security configurations, calculates the risk assessment, and generates an HTML report.

### Generate a Report at a Custom Location

```bash
python3 audit.py --report reports/my_security_report.html
```

### Run Without Generating an HTML Report

```bash
python3 audit.py --no-report
```

### Run in Quiet Mode

```bash
python3 audit.py --quiet
```

Quiet mode suppresses audit progress messages while keeping the final security assessment visible.

## Command-Line Options

| Option          | Description                                     |
| --------------- | ----------------------------------------------- |
| `--help`        | Display command-line help                       |
| `--version`     | Display the application version                 |
| `--report PATH` | Generate an HTML report at the specified path   |
| `--no-report`   | Run the audit without generating an HTML report |
| `--quiet`       | Suppress audit progress messages                |

### Example

```bash
python3 audit.py --report reports/security_report.html
```

This runs the audit and saves the generated HTML report to:

```text
reports/security_report.html
```

## Risk Scoring

The toolkit uses a custom heuristic risk-scoring system to summarize identified security findings.

Each finding is assigned a severity level and corresponding risk points.

| Severity   | Risk Points |
| ---------- | ----------: |
| `CRITICAL` |          25 |
| `HIGH`     |          15 |
| `MEDIUM`   |           8 |
| `LOW`      |           3 |
| `INFO`     |           0 |

The total risk points are calculated by adding the points assigned to all detected findings.

The security score is then calculated as:

```text
Security Score = 100 - Total Risk Points
```

The score cannot fall below `0`.

### Risk Levels

| Security Score | Risk Level |
| -------------: | ---------- |
|         90–100 | LOW        |
|          70–89 | MEDIUM     |
|          40–69 | HIGH       |
|           0–39 | CRITICAL   |

The risk level provides a high-level summary of the findings detected during the audit.

> **Important:** This scoring system is a project-defined heuristic and is not an official industry-standard security benchmark. It is intended to provide a consistent way to summarize and compare findings produced by this toolkit.

## Permissions

Some security checks access system resources that may require elevated privileges.

For example, firewall information and certain system logs may require `sudo` access.

Run the toolkit only on systems that you own or are explicitly authorized to assess.

The toolkit is designed as a read-only auditing tool. It collects and analyzes system information but does not intentionally modify system security configurations.

## Testing

The project includes an automated test suite using `pytest`.

Run all tests with:

```bash
pytest
```

The test suite covers major components of the toolkit, including:

* Risk scoring
* Risk-level classification
* SSH analysis
* Service analysis
* Network analysis
* Firewall analysis
* File permission analysis
* Log analysis
* User and privilege analysis
* HTML report generation

A successful test run confirms that the implemented audit modules behave as expected under the tested conditions.

## Output

The toolkit produces two main types of output:

### Terminal Output

The command-line interface displays:

* Security score
* Overall risk level
* Risk explanation
* Risk points
* Finding counts by severity
* Detected security findings

### HTML Report

The generated HTML report provides a structured security assessment containing:

* System information
* Security score
* Overall risk level
* Risk points
* Severity summary
* Security findings
* Security recommendations where applicable

Reports can be generated using the default output path or a custom path specified with the `--report` option.

## Example Workflow

A typical assessment workflow is:

```bash
# Clone the repository
git clone <YOUR_GITHUB_REPOSITORY_URL>

# Enter the project directory
cd linux-security-audit

# Create a virtual environment
python3 -m venv .venv

# Activate the environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the test suite
pytest

# Run the security audit
python3 audit.py

# Generate a custom report
python3 audit.py --report reports/security_assessment.html
```

## Security Considerations

This project is intended for defensive security assessment and educational purposes.

The toolkit performs local security checks and reports potentially risky configurations. A finding should be investigated in the context of the specific system rather than treated as proof of a vulnerability.

For example, an exposed network service may be intentional, and a service identified for review is not necessarily insecure.

Always verify findings before making configuration changes.

## Limitations

The toolkit provides a focused set of local Linux security checks and should not be considered a complete vulnerability scanner or enterprise security assessment platform.

Current limitations include:

* The assessment is performed locally on the target Linux system.
* Network analysis is based on locally available Linux network information.
* Service detection focuses on selected systemd services.
* Firewall analysis focuses on UFW.
* Log analysis focuses on recent authentication-related events.
* Risk scoring uses a custom project-defined heuristic.
* Detected configurations require contextual investigation.
* The tool does not replace professional penetration testing, vulnerability management, or security monitoring solutions.

## Future Improvements

Potential future improvements include:

* Additional Linux security checks
* More comprehensive SSH analysis
* CVE and vulnerability database integration
* More detailed network-service fingerprinting
* Improved authentication-event analysis
* JSON report generation
* CSV report generation
* Additional firewall support
* Configuration baseline comparison
* Historical audit comparison
* Automated remediation recommendations
* Improved HTML report visualizations
* Expanded test coverage
* CI/CD integration
* Containerized deployment

## Ethical Use

This project is intended for:

* Cybersecurity education
* Defensive security assessment
* Linux hardening
* Security research
* Authorized security auditing

Do not use this toolkit to assess systems without proper authorization.

The user is responsible for ensuring that all security testing and auditing activities comply with applicable laws, policies, and organizational requirements.

## License

This project is licensed under the MIT License.

See the `LICENSE` file for the full license text.

