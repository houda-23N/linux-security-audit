from modules.report import (
    get_severity_class,
    generate_findings_html,
    generate_html_report,
    save_html_report
)


def test_severity_class():
    assert get_severity_class("CRITICAL") == "critical"
    assert get_severity_class("HIGH") == "high"
    assert get_severity_class("MEDIUM") == "medium"
    assert get_severity_class("LOW") == "low"
    assert get_severity_class("INFO") == "info"


def test_findings_html_contains_finding():
    findings = [
        {
            "severity": "HIGH",
            "issue": "Test security issue."
        }
    ]

    html = generate_findings_html(findings)

    assert "Test security issue." in html
    assert "HIGH" in html


def test_findings_html_handles_empty_findings():
    html = generate_findings_html([])

    assert isinstance(html, str)
    assert html != ""


def test_html_report_contains_system_information():
    results = {
        "system_info": {
            "Operating System": "Linux",
            "Hostname": "test-machine",
            "Architecture": "x86_64"
        },
        "risk": {
            "security_score": 90,
            "risk_level": "LOW",
            "risk_points": 10,
            "risk_explanation": "Low risk.",
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 1,
                "LOW": 0,
                "INFO": 0
            }
        },
        "findings": []
    }

    html = generate_html_report(results)

    assert "Linux" in html
    assert "test-machine" in html
    assert "x86_64" in html


def test_html_report_contains_security_score():
    results = {
        "system_info": {},
        "risk": {
            "security_score": 75,
            "risk_level": "MEDIUM",
            "risk_points": 25,
            "risk_explanation": "Medium risk.",
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0
            }
        },
        "findings": []
    }

    html = generate_html_report(results)

    assert "75" in html
    assert "MEDIUM" in html
    assert "25" in html


def test_html_report_contains_findings():
    results = {
        "system_info": {},
        "risk": {
            "security_score": 50,
            "risk_level": "HIGH",
            "risk_points": 50,
            "risk_explanation": "High risk.",
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0
            }
        },
        "findings": [
            {
                "severity": "HIGH",
                "issue": "Password authentication is enabled."
            }
        ]
    }

    html = generate_html_report(results)

    assert "Password authentication is enabled." in html
    assert "HIGH" in html


def test_html_report_escapes_html_content():
    results = {
        "system_info": {
            "Hostname": "<script>alert('test')</script>"
        },
        "risk": {
            "security_score": 100,
            "risk_level": "LOW",
            "risk_points": 0,
            "risk_explanation": "Low risk.",
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0
            }
        },
        "findings": []
    }

    html = generate_html_report(results)

    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_save_html_report_creates_file(tmp_path):
    results = {
        "system_info": {
            "Operating System": "Linux"
        },
        "risk": {
            "security_score": 100,
            "risk_level": "LOW",
            "risk_points": 0,
            "risk_explanation": "Low risk.",
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0
            }
        },
        "findings": []
    }

    report_path = tmp_path / "security_report.html"

    save_html_report(
        results,
        str(report_path)
    )

    assert report_path.exists()

    content = report_path.read_text()

    assert "<html" in content
    assert "Linux" in content
