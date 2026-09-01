#!/usr/bin/env python3
"""
access-matrix-auditor

Reads a role-permission matrix and reports segregation of duties
conflicts, excessive privilege, and orphaned permissions.

Read-only. Reports findings, changes nothing.
"""

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

GRANTED_VALUES = {"y", "yes", "x", "1", "true", "granted"}

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


class AuditorError(Exception):
    """Expected, handled failure."""


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}[self.value]


@dataclass
class Finding:
    check: str
    severity: Severity
    subject: str
    detail: str
    rule_id: Optional[str] = None
    rationale: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out = {
            "check": self.check,
            "severity": self.severity.value,
            "subject": self.subject,
            "detail": self.detail,
        }
        if self.rule_id:
            out["rule_id"] = self.rule_id
        if self.rationale:
            out["rationale"] = self.rationale
        return out


@dataclass
class Matrix:
    roles: List[str]
    permissions: List[str]
    grants: Dict[str, Set[str]] = field(default_factory=dict)

    def permissions_for(self, role: str) -> Set[str]:
        return self.grants.get(role, set())

    def roles_with(self, permission: str) -> List[str]:
        return [r for r in self.roles if permission in self.grants.get(r, set())]


@dataclass
class Rules:
    sod_rules: List[Dict[str, Any]] = field(default_factory=list)
    write_patterns: List[str] = field(default_factory=list)
    readonly_role_patterns: List[str] = field(default_factory=list)
    wildcard_permissions: List[str] = field(default_factory=list)


def load_matrix(path: Path) -> Matrix:
    if not path.exists():
        raise AuditorError(f"Matrix file not found: {path}")

    try:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.reader(handle)
            try:
                header = next(reader)
            except StopIteration:
                raise AuditorError(f"Matrix file is empty: {path}") from None

            if len(header) < 2:
                raise AuditorError(
                    "Matrix needs at least two columns: a permission column and one role column"
                )

            roles = [h.strip() for h in header[1:] if h.strip()]
            if not roles:
                raise AuditorError("No role columns found in the header row")

            permissions: List[str] = []
            grants: Dict[str, Set[str]] = {role: set() for role in roles}

            for line_no, row in enumerate(reader, start=2):
                if not row or not row[0].strip():
                    continue

                permission = row[0].strip()
                if permission in permissions:
                    raise AuditorError(
                        f"Duplicate permission '{permission}' at line {line_no}"
                    )
                permissions.append(permission)

                for index, role in enumerate(roles, start=1):
                    if index >= len(row):
                        continue
                    if row[index].strip().lower() in GRANTED_VALUES:
                        grants[role].add(permission)

    except csv.Error as exc:
        raise AuditorError(f"Could not parse CSV ({path}): {exc}") from exc
    except OSError as exc:
        raise AuditorError(f"Could not read {path}: {exc}") from exc

    if not permissions:
        raise AuditorError("Matrix has a header but no permission rows")

    return Matrix(roles=roles, permissions=permissions, grants=grants)


def load_rules(path: Optional[Path]) -> Rules:
    if path is None:
        return Rules()

    if not path.exists():
        raise AuditorError(f"Rules file not found: {path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AuditorError(f"Rules file is not valid JSON ({path}): {exc}") from exc
    except OSError as exc:
        raise AuditorError(f"Could not read {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise AuditorError("Rules file must be a JSON object")

    sod = raw.get("sod_rules", [])
    if not isinstance(sod, list):
        raise AuditorError("'sod_rules' must be a list")

    for index, rule in enumerate(sod):
        if not isinstance(rule, dict):
            raise AuditorError(f"sod_rules[{index}] is not an object")
        for required in ("permission_a", "permission_b"):
            if required not in rule:
                raise AuditorError(f"sod_rules[{index}] is missing '{required}'")

    return Rules(
        sod_rules=sod,
        write_patterns=raw.get("write_patterns", []),
        readonly_role_patterns=raw.get("readonly_role_patterns", []),
        wildcard_permissions=raw.get("wildcard_permissions", []),
    )


def check_sod(matrix: Matrix, rules: Rules) -> List[Finding]:
    findings: List[Finding] = []

    for rule in rules.sod_rules:
        perm_a = rule["permission_a"]
        perm_b = rule["permission_b"]
        rule_id = rule.get("id", "SOD-??")

        missing = [p for p in (perm_a, perm_b) if p not in matrix.permissions]
        if missing:
            findings.append(
                Finding(
                    check="rule_coverage",
                    severity=Severity.INFO,
                    subject=rule_id,
                    detail=f"Rule references permissions not in the matrix: {', '.join(missing)}",
                )
            )
            continue

        try:
            severity = Severity(str(rule.get("severity", "HIGH")).upper())
        except ValueError:
            severity = Severity.HIGH

        for role in matrix.roles:
            held = matrix.permissions_for(role)
            if perm_a in held and perm_b in held:
                findings.append(
                    Finding(
                        check="sod_conflict",
                        severity=severity,
                        subject=role,
                        detail=f"holds both '{perm_a}' and '{perm_b}'",
                        rule_id=rule_id,
                        rationale=rule.get("rationale"),
                    )
                )

    return findings


def check_excessive_privilege(matrix: Matrix, rules: Rules) -> List[Finding]:
    if not rules.readonly_role_patterns or not rules.write_patterns:
        return []

    findings: List[Finding] = []

    for role in matrix.roles:
        role_lower = role.lower()
        if not any(pattern.lower() in role_lower for pattern in rules.readonly_role_patterns):
            continue

        write_perms = sorted(
            perm
            for perm in matrix.permissions_for(role)
            if any(perm.lower().startswith(p.lower()) for p in rules.write_patterns)
        )

        if write_perms:
            shown = ", ".join(write_perms[:5])
            if len(write_perms) > 5:
                shown += f", and {len(write_perms) - 5} more"
            plural = "s" if len(write_perms) != 1 else ""
            findings.append(
                Finding(
                    check="excessive_privilege",
                    severity=Severity.HIGH,
                    subject=role,
                    detail=f"name suggests read-only but holds {len(write_perms)} write permission{plural}: {shown}",
                )
            )

    return findings


def check_orphan_permissions(matrix: Matrix) -> List[Finding]:
    findings: List[Finding] = []
    for permission in matrix.permissions:
        if not matrix.roles_with(permission):
            findings.append(
                Finding(
                    check="orphan_permission",
                    severity=Severity.LOW,
                    subject=permission,
                    detail="assigned to no role",
                )
            )
    return findings


def check_unused_roles(matrix: Matrix) -> List[Finding]:
    findings: List[Finding] = []
    for role in matrix.roles:
        if not matrix.permissions_for(role):
            findings.append(
                Finding(
                    check="unused_role",
                    severity=Severity.LOW,
                    subject=role,
                    detail="holds no permissions",
                )
            )
    return findings


def check_wildcards(matrix: Matrix, rules: Rules) -> List[Finding]:
    if not rules.wildcard_permissions:
        return []

    findings: List[Finding] = []
    wildcard_set = {w.lower() for w in rules.wildcard_permissions}

    for permission in matrix.permissions:
        if permission.lower() not in wildcard_set:
            continue
        for role in matrix.roles_with(permission):
            findings.append(
                Finding(
                    check="wildcard_grant",
                    severity=Severity.MEDIUM,
                    subject=role,
                    detail=f"holds broad permission '{permission}'",
                )
            )

    return findings


def run_checks(matrix: Matrix, rules: Rules) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(check_sod(matrix, rules))
    findings.extend(check_excessive_privilege(matrix, rules))
    findings.extend(check_wildcards(matrix, rules))
    findings.extend(check_orphan_permissions(matrix))
    findings.extend(check_unused_roles(matrix))

    findings.sort(key=lambda f: (f.severity.rank, f.check, f.subject))
    return findings


def render_text(matrix: Matrix, findings: List[Finding]) -> str:
    lines: List[str] = []
    lines.append("ACCESS MATRIX AUDIT")
    lines.append("=" * 60)
    lines.append(f"Roles:       {len(matrix.roles)}")
    lines.append(f"Permissions: {len(matrix.permissions)}")
    lines.append(f"Findings:    {len(findings)}")
    lines.append("")

    if not findings:
        lines.append("No findings.")
        lines.append("")
        lines.append("Note: this means the matrix passed the rules you supplied.")
        lines.append("It does not mean the rules are complete.")
        return "\n".join(lines)

    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1

    summary = "  ".join(
        f"{sev}: {counts[sev]}" for sev in ("HIGH", "MEDIUM", "LOW", "INFO") if sev in counts
    )
    lines.append(summary)
    lines.append("")

    current_check = None
    for finding in findings:
        if finding.check != current_check:
            current_check = finding.check
            heading = current_check.replace("_", " ").upper()
            lines.append("-" * 60)
            lines.append(heading)
            lines.append("-" * 60)

        prefix = f"[{finding.severity.value}]"
        if finding.rule_id:
            prefix += f" {finding.rule_id}"
        lines.append(f"{prefix}  {finding.subject}")
        lines.append(f"       {finding.detail}")
        if finding.rationale:
            lines.append(f"       Why: {finding.rationale}")
        lines.append("")

    return "\n".join(lines)


def render_json(matrix: Matrix, findings: List[Finding]) -> str:
    payload = {
        "summary": {
            "roles": len(matrix.roles),
            "permissions": len(matrix.permissions),
            "findings": len(findings),
            "high": sum(1 for f in findings if f.severity is Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity is Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity is Severity.LOW),
        },
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="Audit a role-permission matrix for SoD conflicts and excessive privilege.",
    )
    parser.add_argument("--matrix", "-m", required=True, help="Path to matrix CSV")
    parser.add_argument("--rules", "-r", default=None, help="Path to rules JSON")
    parser.add_argument("--output", "-o", default=None, help="Write report to file")
    parser.add_argument(
        "--format", "-f", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()

    try:
        matrix = load_matrix(Path(args.matrix))
        rules = load_rules(Path(args.rules) if args.rules else None)
        findings = run_checks(matrix, rules)

        if args.format == "json":
            report = render_json(matrix, findings)
        else:
            report = render_text(matrix, findings)

        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(report, encoding="utf-8")
            print(f"Report written to {out_path}", file=sys.stderr)
        else:
            print(report)

        has_high = any(f.severity is Severity.HIGH for f in findings)
        return EXIT_FINDINGS if has_high else EXIT_OK

    except AuditorError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
