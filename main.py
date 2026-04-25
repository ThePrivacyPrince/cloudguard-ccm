"""CloudGuard CCM — entrypoint.

Runs all configured control checks against the cloudguard AWS profile
and prints findings to terminal in a formatted table.
"""
from rich.console import Console
from rich.table import Table

from src.checks.iam_mfa import check_root_mfa
from src.checks.s3_public import check_s3_public_access_block
from src.checks.cloudtrail import check_cloudtrail_enabled
from src.checks.iam_password_policy import check_iam_password_policy   # ← NEW


console = Console()


def run_checks() -> list[dict]:
    """Execute all control checks. Extend this list as checks are added."""
    return [
        check_root_mfa(),
        check_s3_public_access_block(),
        check_cloudtrail_enabled(),
        check_iam_password_policy(),   # ← NEW
    ]


def render_findings(findings: list[dict]) -> None:
    """Print findings as a Rich table."""
    table = Table(
        title="CloudGuard — Control Findings",
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Control ID", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Remediation", overflow="fold")

    for f in findings:
        status = (
            "[bold green]PASS[/]" if f["passed"]
            else "[bold red]FAIL[/]"
        )
        table.add_row(
            f["control_id"],
            f["severity"].upper(),
            status,
            f["remediation"] or "—",
        )

    console.print()
    console.print(table)
    console.print()


def main() -> None:
    console.print("[bold cyan]CloudGuard — AWS Continuous Control Monitoring[/]")
    console.print("[dim]Querying AWS for live control posture...[/]\n")

    findings = run_checks()
    render_findings(findings)

    passed = sum(1 for f in findings if f["passed"])
    total = len(findings)
    console.print(f"[bold]Summary:[/] {passed}/{total} checks passed")


if __name__ == "__main__":
    main()