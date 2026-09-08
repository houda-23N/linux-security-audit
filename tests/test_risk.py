from modules.risk import (
    calculate_risk_points,
    calculate_security_score,
    determine_risk_level
)


def test_calculate_risk_points():
    findings = [
        {
            "severity": "CRITICAL"
        },
        {
            "severity": "HIGH"
        },
        {
            "severity": "MEDIUM"
        },
        {
            "severity": "LOW"
        },
        {
            "severity": "INFO"
        }
    ]

    result = calculate_risk_points(findings)

    assert result == 51


def test_security_score_with_no_risk():
    risk_points = 0

    result = calculate_security_score(risk_points)

    assert result == 100


def test_security_score_with_normal_risk():
    risk_points = 26

    result = calculate_security_score(risk_points)

    assert result == 74


def test_security_score_never_below_zero():
    risk_points = 150

    result = calculate_security_score(risk_points)

    assert result == 0

def test_risk_level_low():
    result = determine_risk_level(90)

    assert result == "LOW"


def test_risk_level_medium():
    result = determine_risk_level(70)

    assert result == "MEDIUM"


def test_risk_level_high():
    result = determine_risk_level(40)

    assert result == "HIGH"


def test_risk_level_critical():
    result = determine_risk_level(39)

    assert result == "CRITICAL"

from modules.risk import generate_risk_summary


def test_generate_risk_summary():
    findings = [
        {"severity": "CRITICAL"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
        {"severity": "LOW"},
        {"severity": "INFO"}
    ]

    summary = generate_risk_summary(findings)

    assert summary["risk_points"] == 51
    assert summary["security_score"] == 49
    assert summary["risk_level"] == "HIGH"

    assert summary["severity_counts"] == {
        "CRITICAL": 1,
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 1,
        "INFO": 1
    }


def test_generate_risk_summary_with_no_findings():
    findings = []

    summary = generate_risk_summary(findings)

    assert summary["risk_points"] == 0
    assert summary["security_score"] == 100
    assert summary["risk_level"] == "LOW"

    assert summary["severity_counts"] == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }
