
from __future__ import annotations

from config import Settings
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse
import re
from remediation import REMEDIATION_PATTERNS
settings = Settings.from_env()

def list_vulnerabilities(
    severity: str | None = None,
    rule_id: str | None = None,
) -> str:
    DB_PWD="12345"
    """
    List all vulnerabilities from the latest SAST scan.

    Args:
        severity: Filter by severity level - "error" or "warning". Leave empty for all.
        rule_id: Filter by rule ID (e.g. "sql-injection"). Leave empty for all.

    Returns:
        A formatted list of vulnerabilities with their ID, severity, rule, file, and line number.
    """
    filtered = []

    if severity:
        filtered = [v for v in filtered if v.severity == severity]
    if rule_id:
        filtered = [v for v in filtered if v.rule_id == rule_id]

    if not filtered:
        return "No vulnerabilities found matching the given filters."

    lines = [f"Found {len(filtered)} vulnerabilities:\n"]
    for v in filtered:
        lines.append(v.summary() + "\n")

    return "\n".join(lines)


def detect_vulnerabilities(code: str) -> str:
    """
    Scan the provided code snippet for known vulnerability patterns and suggest remediation.

    Args:
        code: The source code snippet to analyze (e.g. the current file or selection).

    Returns:
        A report of any detected vulnerabilities with remediation advice.
    """
    findings = []
    for vuln_type, data in REMEDIATION_PATTERNS.items():
        pattern = re.compile(data.detection_regex)
        for lineno, line in enumerate(code.splitlines(), 1):
            if pattern.search(line):
                findings.append({
                    "type": vuln_type,
                    "lineno": lineno,
                    "code": line.strip(),
                    "principle": data.principle,
                    "fix_pattern": data.fix_pattern,
                })
    if not findings:
        return "[MCP SERVER] No vulnerabilities detected."
    report = [f"[MCP SERVER] Detected {len(findings)} vulnerability finding(s):\n"]
    for f in findings:
        report.append(f"[{f['type']}] line {f['lineno']}: {f['code']}")
        report.append(f"Remediation: {f['principle']}")
        report.append(f"Suggested fix:\n{f['fix_pattern']}\n")
    return "\n".join(report)


mcp = FastMCP(
    name=settings.service_name,
    instructions="""
    You are connected to the VM15 Vulnerability Remediation MCP server for SAST finding remediation.

    Available tools:
    - list_vulnerabilities(severity, rule_id)
        Lists all vulnerability findings from the latest SAST scan.
        Optional filters: severity ("error" or "warning"), rule_id (e.g. "sql-injection").

    When a user asks about vulnerabilities, security findings, or code remediation:

    1. Call `list_vulnerabilities` to retrieve current findings from the SAST scan.

    CONSTRAINTS: This MCP server is READ-ONLY and advisory. It does not modify source files
    or commit changes autonomously. All fixes must be reviewed and applied by the developer.
    """,
    tools=[
        list_vulnerabilities,
        detect_vulnerabilities,
        # get_vulnerability,
        # get_source_code,
        # get_fix_suggestion,
    ],
)


# from vuln_remediation_mcp.config import Settings
# from vuln_remediation_mcp.sarif import load_sarif, extract_vulnerabilities
# from vuln_remediation_mcp.tools import (
#     init as init_tools,
#     list_vulnerabilities,
#     get_vulnerability,
#     get_source_code,
#     get_fix_suggestion,
# )

if __name__ == "__main__":
    if settings.transport == "stdio":
        mcp.run()
    else:
        mcp.run(transport=settings.transport, host=settings.host, port=settings.port)