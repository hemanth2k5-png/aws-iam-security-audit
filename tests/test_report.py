from report import _safe_csv, mask_account, normalize, prepare, summarize, write_all


def test_normalize_maps_detail_to_description():
    result = normalize({"resource": "x", "category": "MFA", "severity": "High", "detail": "No MFA"})
    assert result["description"] == "No MFA"
    assert result["remediation"] == "Review this finding."


def test_prepare_sorts_high_before_medium_before_low():
    raw = [
        {"severity": "Low", "category": "A", "resource": "1"},
        {"severity": "High", "category": "A", "resource": "2"},
        {"severity": "Medium", "category": "A", "resource": "3"},
    ]
    assert [f["severity"] for f in prepare(raw)] == ["High", "Medium", "Low"]


def test_summarize_counts_by_severity():
    counts = summarize([{"severity": "High"}, {"severity": "High"}, {"severity": "Low"}])
    assert counts == {"High": 2, "Medium": 0, "Low": 1}


def test_mask_account_keeps_last_four_digits():
    assert mask_account("123456789012") == "****9012"


def test_csv_cells_starting_with_formula_characters_are_neutralized():
    assert _safe_csv("=cmd()") == "'=cmd()"
    assert _safe_csv("+1") == "'+1"
    assert _safe_csv("normal") == "normal"


def test_write_all_creates_requested_formats(tmp_path):
    findings = prepare([{"severity": "High", "category": "T", "resource": "r", "description": "d"}])
    paths = write_all(findings, "123456789012", "p", "us-east-1", out_dir=str(tmp_path))
    assert set(paths) == {"json", "csv", "html"}
    assert all(p.exists() and p.stat().st_size > 0 for p in paths.values())


def test_write_all_respects_format_selection(tmp_path):
    paths = write_all([], "123456789012", "p", "us-east-1", out_dir=str(tmp_path), formats=("json",))
    assert set(paths) == {"json"}


def test_html_report_escapes_resource_names(tmp_path):
    findings = prepare([{
        "severity": "High", "category": "T",
        "resource": "<script>alert(1)</script>", "description": "d",
    }])
    paths = write_all(findings, "123456789012", "p", "us-east-1", out_dir=str(tmp_path))
    html = paths["html"].read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html