from datetime import datetime
from html import escape
import os

def get_severity_class(severity):
    """Return a CSS class based on finding severity."""

    severity = severity.upper()

    if severity == "CRITICAL":
        return "critical"

    if severity == "HIGH":
        return "high"

    if severity == "MEDIUM":
        return "medium"

    if severity == "LOW":
        return "low"

    return "info"


def generate_findings_html(findings):
    """Convert security findings into HTML."""

    if not findings:
        return """
        <div class="no-findings">
            No security findings were detected.
        </div>
        """

    html = ""

    for number, finding in enumerate(findings, start=1):

        severity = finding.get(
            "severity",
            "INFO"
        ).upper()

        issue = escape(
            str(finding.get("issue", "Unknown issue"))
        )

        severity_class = get_severity_class(
            severity
        )

        html += f"""
        <div class="finding {severity_class}">
            <div class="finding-header">
                <span class="finding-number">
                    #{number}
                </span>

                <span class="severity {severity_class}">
                    {escape(severity)}
                </span>
            </div>

            <div class="finding-description">
                {issue}
            </div>
        </div>
        """

    return html


def generate_html_report(results):
    """Generate a complete HTML security assessment report."""

    system_info = results["system_info"]
    risk = results["risk"]
    findings = results["findings"]

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    score = risk["security_score"]
    risk_level = risk["risk_level"]
    risk_points = risk["risk_points"]

    severity_counts = risk["severity_counts"]

    findings_html = generate_findings_html(
        findings
    )

    html = f"""<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>Linux Security Assessment</title>

    <style>

        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: #f4f6f8;
            color: #222;
        }}

        .container {{
            max-width: 1100px;
            margin: 40px auto;
            padding: 20px;
        }}

        .header {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}

        .header h1 {{
            margin: 0 0 10px 0;
        }}

        .timestamp {{
            color: #666;
        }}

        .score-card {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 20px;
        }}

        .score {{
            font-size: 56px;
            font-weight: bold;
        }}

        .risk-level {{
            font-size: 24px;
            font-weight: bold;
            margin-top: 10px;
        }}

        .risk-points {{
            color: #666;
            margin-top: 10px;
        }}

        .section {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}

        .section h2 {{
            margin-top: 0;
        }}

        .system-info {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }}

        .info-item {{
            padding: 12px;
            background: #f4f6f8;
            border-radius: 6px;
        }}

        .severity-grid {{
            display: grid;
            grid-template-columns:
                repeat(5, 1fr);
            gap: 10px;
        }}

        .severity-box {{
            padding: 20px;
            text-align: center;
            border-radius: 8px;
            background: #f4f6f8;
        }}

        .severity-number {{
            font-size: 28px;
            font-weight: bold;
        }}

        .finding {{
            border-left: 5px solid #999;
            background: #f8f8f8;
            padding: 15px;
            margin-bottom: 12px;
            border-radius: 5px;
        }}

        .finding.critical {{
            border-left-color: #8b0000;
        }}

        .finding.high {{
            border-left-color: #d9534f;
        }}

        .finding.medium {{
            border-left-color: #f0ad4e;
        }}

        .finding.low {{
            border-left-color: #5bc0de;
        }}

        .finding.info {{
            border-left-color: #5cb85c;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }}

        .severity {{
            font-weight: bold;
        }}

        .finding-description {{
            line-height: 1.5;
        }}

        .no-findings {{
            padding: 20px;
            background: #f4f6f8;
            border-radius: 6px;
        }}

        @media (max-width: 700px) {{

            .system-info {{
                grid-template-columns: 1fr;
            }}

            .severity-grid {{
                grid-template-columns: 1fr 1fr;
            }}

        }}

    </style>

</head>

<body>

<div class="container">

    <div class="header">

        <h1>
            Linux Security Assessment
        </h1>

        <div class="timestamp">
            Generated: {timestamp}
        </div>

    </div>


    <div class="score-card">

        <div class="score">
            {score}/100
        </div>

        <div class="risk-level">
            Risk Level: {escape(risk_level)}
        </div>

        <div class="risk-points">
            Risk Points: {risk_points}
        </div>

    </div>


    <div class="section">

        <h2>
            System Information
        </h2>

        <div class="system-info">
"""

    for key, value in system_info.items():

        html += f"""
            <div class="info-item">

                <strong>
                    {escape(str(key))}
                </strong>

                <br>

                {escape(str(value))}

            </div>
        """

    html += f"""
        </div>

    </div>


    <div class="section">

        <h2>
            Findings Summary
        </h2>

        <div class="severity-grid">

            <div class="severity-box">
                <div class="severity-number">
                    {severity_counts["CRITICAL"]}
                </div>
                CRITICAL
            </div>

            <div class="severity-box">
                <div class="severity-number">
                    {severity_counts["HIGH"]}
                </div>
                HIGH
            </div>

            <div class="severity-box">
                <div class="severity-number">
                    {severity_counts["MEDIUM"]}
                </div>
                MEDIUM
            </div>

            <div class="severity-box">
                <div class="severity-number">
                    {severity_counts["LOW"]}
                </div>
                LOW
            </div>

            <div class="severity-box">
                <div class="severity-number">
                    {severity_counts["INFO"]}
                </div>
                INFO
            </div>

        </div>

    </div>


    <div class="section">

        <h2>
            Security Findings
        </h2>

        {findings_html}

    </div>

</div>

</body>

</html>
"""

    return html


def save_html_report(results, output_path):
    """Generate and save the HTML report."""

    html = generate_html_report(results)

    directory = os.path.dirname(output_path)

    if directory:
        os.makedirs(
            directory,
            exist_ok=True
        )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

    return output_path
