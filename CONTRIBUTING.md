# Contributing

Thank you for your interest in contributing to the Linux Security Audit Toolkit.

Contributions that improve the project's reliability, security, documentation, testing, or functionality are welcome.

## Before Contributing

Please:

1. Read the project README.
2. Understand the intended security-assessment scope of the toolkit.
3. Make sure your changes do not introduce unsafe behavior.
4. Test your changes before submitting them.

## Development Setup

Clone the repository and create a Python virtual environment:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd linux-security-audit

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Running Tests

Run the automated test suite with:

```bash
pytest
```

All existing tests should pass before submitting a change.

## Making Changes

When adding or modifying functionality:

* Keep the code modular and readable.
* Follow standard Python practices.
* Add tests for new functionality where appropriate.
* Avoid hard-coded assumptions about a specific Linux system.
* Handle permission errors and missing system resources safely.
* Do not expose sensitive system information in reports or test output.

## Commit Messages

Use clear and descriptive commit messages.

Examples:

```text
Add SSH configuration checks
Improve firewall analysis
Add tests for network module
Update security assessment documentation
```

## Pull Requests

Pull requests should include:

* A clear description of the change.
* The reason for the change.
* Relevant testing information.
* Any limitations or known issues.

Please keep pull requests focused on a specific improvement whenever possible.

## Security-Related Contributions

Security-related changes should be reviewed carefully to ensure that they do not introduce vulnerabilities, unsafe system modifications, or unintended behavior.

Do not include real passwords, private keys, tokens, credentials, or other sensitive information in issues, commits, pull requests, tests, or screenshots.

For reporting potential security vulnerabilities, please follow the project's security disclosure guidance.

## Responsible Use

This toolkit is intended for authorized security assessments and educational purposes.

Only use it on systems that you own or have explicit permission to assess.
