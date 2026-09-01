# access-matrix-auditor

Reads a role-permission matrix and reports segregation of duties conflicts, excessive privilege, and orphaned permissions.

## Why this exists

Every system I write requirements for has a Roles and Permissions section. It is usually a table someone filled in quickly, and nobody checks it against itself.

The conflicts are the kind that show up in an audit two years later: the clerk who can both create a vendor and approve a payment to that vendor, the "read only" role that quietly accumulated write access.

Finding these at requirement stage costs nothing. Finding them in an audit costs a remediation project.

## What it checks

| Check | What it finds |
|---|---|
| SoD conflict | One role holding both sides of a rule that should be split |
| Excessive privilege | Roles with write access that the naming suggests should not have it |
| Orphan permission | Permissions assigned to no role |
| Unused role | Roles with no permissions at all |
| Wildcard grant | Roles holding a permission that implies broad access |

## Usage

```bash
python auditor.py --matrix examples/access-matrix.csv --rules examples/sod-rules.json
```

With a text report written to file:

```bash
python auditor.py --matrix examples/access-matrix.csv --rules examples/sod-rules.json --output report.txt
```

JSON output for pipelines:

```bash
python auditor.py --matrix examples/access-matrix.csv --rules examples/sod-rules.json --format json
```

## Input format

**Matrix CSV** — first column is the permission name, remaining columns are roles. Cell values `Y`, `YES`, `X`, or `1` mean granted.

```csv
Permission,AP Clerk,AP Manager,Read Only Auditor
create_vendor,Y,Y,
approve_payment,Y,Y,
view_ledger,Y,Y,Y
```

**SoD rules JSON** — pairs of permissions that should not sit in the same role.

```json
{
  "sod_rules": [
    {
      "id": "SOD-01",
      "permission_a": "create_vendor",
      "permission_b": "approve_payment",
      "severity": "HIGH",
      "rationale": "A user who can create a vendor and approve payments to it can route funds to an entity they control."
    }
  ],
  "write_patterns": ["create_", "update_", "delete_", "approve_", "post_"],
  "readonly_role_patterns": ["auditor", "viewer", "read only", "readonly"]
}
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No HIGH severity findings |
| 1 | HIGH severity findings present |
| 2 | Input or runtime error |

Useful if you want this in a pipeline that blocks on unresolved conflicts.

## What I don't know yet

This checks a matrix against rules you supply. It does not know what your rules should be — that comes from your control framework, your auditors, or your regulator.

It also only sees roles, not people. A user assigned two roles that are individually clean can still hold a conflicting pair between them. Handling user-to-role assignment is the next thing I want to add, and I have not worked out how to model inherited or nested roles yet.

I am learning this area, not practising it professionally. The checks here come from reading about SoD in financial controls, not from running an audit.

## Requirements

Python 3.9+. No external packages.
