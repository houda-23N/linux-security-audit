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

def get_risk_explanation(risk_level):
    """Return a human-readable explanation of the risk level."""

    explanations = {
        "LOW": (
            "The system has a relatively low number of "
            "identified security concerns. Continue applying "
            "regular security updates and monitoring."
        ),

        "MEDIUM": (
            "The system has security findings that should be "
            "reviewed and addressed. Higher-severity findings "
            "should be prioritized."
        ),

        "HIGH": (
            "The system has significant security concerns that "
            "should be addressed as soon as possible."
        ),

        "CRITICAL": (
            "The system has serious security weaknesses that "
            "require immediate attention and remediation."
        )
    }

    return explanations.get(
        risk_level,
        "No risk assessment explanation is available."
    )

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

    risk_explanation = get_risk_explanation(risk_level)

    severity_counts = count_findings_by_severity(findings)

    return {
        "risk_points": risk_points,
        "security_score": score,
        "risk_level": risk_level,
        "risk_explanation": risk_explanation,
        "severity_counts": severity_counts
    }
