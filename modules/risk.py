SEVERITY_POINTS = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0
}


def calculate_risk_points(findings):
    """Calculate total risk points from security findings."""

    total_points = 0

    for finding in findings:
        severity = finding.get("severity", "INFO").upper()

        points = SEVERITY_POINTS.get(severity, 0)

        total_points += points

    return total_points


def calculate_security_score(risk_points):
    """Convert risk points into a security score from 0 to 100."""

    score = 100 - risk_points

    if score < 0:
        score = 0

    return score


def determine_risk_level(score):
    """Determine the overall risk level from the security score."""

    if score >= 90:
        return "LOW"

    if score >= 70:
        return "MEDIUM"

    if score >= 40:
        return "HIGH"

    return "CRITICAL"


def count_findings_by_severity(findings):
    """Count findings by severity."""

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for finding in findings:
        severity = finding.get("severity", "INFO").upper()

        if severity in counts:
            counts[severity] += 1

    return counts


def generate_risk_summary(findings):
    """Generate a complete risk assessment summary."""

    risk_points = calculate_risk_points(findings)

    score = calculate_security_score(risk_points)

    risk_level = determine_risk_level(score)

    severity_counts = count_findings_by_severity(findings)

    return {
        "risk_points": risk_points,
        "security_score": score,
        "risk_level": risk_level,
        "severity_counts": severity_counts
    }
