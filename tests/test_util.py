from zairo._util import max_severity, normalize_cwe, normalize_severity, severity_rank


def test_normalize_severity_passes_through_known_values():
    for level in ("low", "medium", "high", "critical"):
        assert normalize_severity(level) == level
        assert normalize_severity(level.upper()) == level
        assert normalize_severity(f"  {level}  ") == level


def test_normalize_severity_defaults_unrecognized_to_medium():
    assert normalize_severity(None) == "medium"
    assert normalize_severity("") == "medium"
    assert normalize_severity("catastrophic") == "medium"


def test_severity_rank_is_ordered_low_to_critical():
    ranks = [severity_rank(s) for s in ("low", "medium", "high", "critical")]
    assert ranks == sorted(ranks)


def test_max_severity_picks_highest_across_all_findings():
    vulnerabilities = {
        "n1": [{"severity": "low"}, {"severity": "high"}],
        "n2": [{"severity": "medium"}],
    }
    assert max_severity(vulnerabilities) == "high"


def test_max_severity_none_when_no_findings():
    assert max_severity({}) is None
    assert max_severity({"n1": []}) is None


def test_normalize_cwe_accepts_common_formats():
    assert normalize_cwe("CWE-78") == "CWE-78"
    assert normalize_cwe("cwe-78") == "CWE-78"
    assert normalize_cwe("cwe:78") == "CWE-78"
    assert normalize_cwe("78") == "CWE-78"
    assert normalize_cwe("CWE-078") == "CWE-78"
    assert normalize_cwe(" CWE-78 - OS Command Injection") == "CWE-78"


def test_normalize_cwe_none_when_unusable():
    assert normalize_cwe(None) is None
    assert normalize_cwe("") is None
    assert normalize_cwe("not applicable") is None
