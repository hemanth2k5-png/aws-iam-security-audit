import pytest

from main import parse_args


def test_defaults():
    args = parse_args([])
    assert args.profile == "audit-tool"
    assert args.format == "all"
    assert args.min_severity == "Low"
    assert args.fail_on == "none"
    assert args.quiet is False


def test_options_are_parsed():
    args = parse_args(["--profile", "other", "--fail-on", "High", "--quiet", "--format", "html"])
    assert args.profile == "other"
    assert args.fail_on == "High"
    assert args.quiet is True
    assert args.format == "html"


def test_invalid_severity_is_rejected():
    with pytest.raises(SystemExit):
        parse_args(["--fail-on", "Critical"])