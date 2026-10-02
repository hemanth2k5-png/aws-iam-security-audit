import csv
import json
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}
FIELDS = ["severity", "category", "resource", "description", "remediation"]
TEMPLATE_DIR = Path(__file__).parent / "templates"


def normalize(finding):
    """Force every finding into one shape, whatever the check returned."""
    return {
        "severity": finding.get("severity", "Low"),
        "category": finding.get("category", "Unknown"),
        "resource": finding.get("resource", "Unknown"),
        "description": finding.get("description") or finding.get("detail", ""),
        "remediation": finding.get("remediation", "Review this finding."),
    }


def prepare(findings):
    normalized = [normalize(f) for f in findings]
    return sorted(
        normalized,
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 3), f["category"], f["resource"]),
    )


def summarize(findings):
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def mask_account(account_id):
    return "****" + account_id[-4:]


def _safe_csv(value):
    """Stop spreadsheet apps from treating a cell as a formula."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def write_json(findings, path, meta):
    payload = {"metadata": meta, "findings": findings}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(findings, path):
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        for f in findings:
            writer.writerow({k: _safe_csv(f[k]) for k in FIELDS})


def write_html(findings, path, meta, counts):
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html.j2")
    html = template.render(findings=findings, counts=counts, **meta)
    path.write_text(html, encoding="utf-8")


def write_all(findings, account_id, profile, region, out_dir="reports",
              formats=("json", "csv", "html")):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%d-%H%M%S")
    counts = summarize(findings)
    meta = {
        "generated": now.strftime("%Y-%m-%d %H:%M UTC"),
        "account": mask_account(account_id),
        "profile": profile,
        "region": region,
    }
    paths = {}
    if "json" in formats:
        paths["json"] = out / f"audit-{stamp}.json"
        write_json(findings, paths["json"], meta)
    if "csv" in formats:
        paths["csv"] = out / f"audit-{stamp}.csv"
        write_csv(findings, paths["csv"])
    if "html" in formats:
        paths["html"] = out / f"audit-{stamp}.html"
        write_html(findings, paths["html"], meta, counts)
    return paths