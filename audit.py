from modules.system import get_system_info
from modules.users import get_users, get_privileged_users
from modules.ssh import read_ssh_config, analyze_ssh_security
from modules.network import (
    get_listening_ports,
    analyze_network_security
)
from modules.services import (
    get_running_services,
    analyze_services
)
from modules.firewall import (
    get_ufw_status,
    analyze_firewall
)
from modules.permissions import (
    audit_sensitive_permissions,
    analyze_permissions
)
from modules.logs import (
    get_recent_security_logs,
    analyze_security_logs
)
from modules.risk import generate_risk_summary
from modules.report import save_html_report

def run_audit():
    """Run all security audit modules."""

    all_findings = []

    print("\n================================")
    print("       LINUX SECURITY AUDIT")
    print("================================")

    # -----------------------------
    # SYSTEM INFORMATION
    # -----------------------------

    print("\n[1/8] Collecting system information...")

    system_info = get_system_info()

    print(
        f"System: "
        f"{system_info['Operating System']} "
        f"{system_info['OS Release']}"
    )

    print(
        f"Hostname: "
        f"{system_info['Hostname']}"
    )

    # -----------------------------
    # USER AUDIT
    # -----------------------------

    print("\n[2/8] Auditing users and privileges...")

    users = get_users()
    privileged_users = get_privileged_users(users)

    print(f"Users detected: {len(users)}")
    print(
        f"Privileged users detected: "
        f"{len(privileged_users)}"
    )

    # -----------------------------
    # SSH AUDIT
    # -----------------------------

    print("\n[3/8] Auditing SSH configuration...")

    ssh_config = read_ssh_config()
    ssh_findings = analyze_ssh_security(ssh_config)

    all_findings.extend(ssh_findings)

    print(
        f"SSH findings: "
        f"{len(ssh_findings)}"
    )

    # -----------------------------
    # NETWORK AUDIT
    # -----------------------------

    print("\n[4/8] Auditing network exposure...")

    connections = get_listening_ports()
    network_findings = analyze_network_security(connections)

    all_findings.extend(network_findings)

    print(
        f"Listening sockets: "
        f"{len(connections)}"
    )

    print(
        f"Network findings: "
        f"{len(network_findings)}"
    )

    # -----------------------------
    # SERVICES AUDIT
    # -----------------------------

    print("\n[5/8] Auditing running services...")

    services = get_running_services()
    service_findings = analyze_services(services)

    all_findings.extend(service_findings)

    print(
        f"Running services: "
        f"{len(services)}"
    )

    print(
        f"Service findings: "
        f"{len(service_findings)}"
    )

    # -----------------------------
    # FIREWALL AUDIT
    # -----------------------------

    print("\n[6/8] Auditing firewall configuration...")

    firewall = get_ufw_status()
    firewall_findings = analyze_firewall(firewall)

    all_findings.extend(firewall_findings)

    print(
        f"Firewall findings: "
        f"{len(firewall_findings)}"
    )

    # -----------------------------
    # FILE PERMISSIONS AUDIT
    # -----------------------------

    print("\n[7/8] Auditing sensitive file permissions...")

    permission_results = audit_sensitive_permissions()
    permission_findings = analyze_permissions(
        permission_results
    )

    all_findings.extend(permission_findings)

    print(
        f"Permission findings: "
        f"{len(permission_findings)}"
    )

    # -----------------------------
    # SECURITY LOG AUDIT
    # -----------------------------

    print("\n[8/8] Auditing security logs...")

    logs = get_recent_security_logs()
    log_findings = analyze_security_logs(logs)

    all_findings.extend(log_findings)

    print(
        f"Security log findings: "
        f"{len(log_findings)}"
    )

    # -----------------------------
    # RISK ASSESSMENT
    # -----------------------------

    risk_summary = generate_risk_summary(
        all_findings
    )

    return {
        "system_info": system_info,
        "users": users,
        "privileged_users": privileged_users,
        "ssh": ssh_config,
        "network": connections,
        "services": services,
        "firewall": firewall,
        "permissions": permission_results,
        "logs": logs,
        "findings": all_findings,
        "risk": risk_summary
    }


def display_results(results):
    """Display the final audit results."""

    risk = results["risk"]

    print("\n================================")
    print("        SECURITY RESULTS")
    print("================================")

    print(
        f"\nSecurity Score: "
        f"{risk['security_score']}/100"
    )

    print(
        f"Risk Level: "
        f"{risk['risk_level']}"
    )

    print(
        f"Risk Points: "
        f"{risk['risk_points']}"
    )

    print("\n=== FINDINGS BY SEVERITY ===")

    for severity, count in (
        risk["severity_counts"].items()
    ):
        print(
            f"{severity}: "
            f"{count}"
        )

    print("\n=== SECURITY FINDINGS ===")

    if not results["findings"]:
        print("No security findings detected.")

    for finding in results["findings"]:
        print(
            f"[{finding['severity']}] "
            f"{finding['issue']}"
        )


def main():
    """Program entry point."""

    results = run_audit()

    display_results(results)

    report_path = "reports/security_report.html"

    save_html_report(
        results,
        report_path
    )

    print("\n================================")
    print("        REPORT GENERATED")
    print("================================")

    print(
        f"\nHTML report saved to:"
    )

    print(report_path)


if __name__ == "__main__":
    main()
