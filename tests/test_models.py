from vulntriage.models import CVE, RankedCVE, min_fix_version


def test_cve_fields() -> None:
    cve = CVE(
        id="CVE-2023-32681",
        package="requests",
        installed_version="2.28.0",
        fix_versions=["2.31.0"],
        aliases=["PYSEC-2023-74"],
        description="Test description",
    )
    assert cve.id == "CVE-2023-32681"
    assert cve.package == "requests"
    assert cve.installed_version == "2.28.0"
    assert cve.fix_versions == ("2.31.0",)
    assert cve.aliases == ("PYSEC-2023-74",)
    assert cve.description == "Test description"


def test_ranked_cve_fields() -> None:
    cve = CVE(
        id="CVE-2023-32681",
        package="requests",
        installed_version="2.28.0",
        fix_versions=["2.31.0"],
        aliases=[],
        description="",
    )
    ranked = RankedCVE(
        rank=1,
        cve=cve,
        real_risk="HIGH",
        reasoning="Direct dependency used in every HTTP request.",
        fix_command="pip install requests==2.31.0",
    )
    assert ranked.rank == 1
    assert ranked.cve is cve
    assert ranked.real_risk == "HIGH"
    assert ranked.reasoning == "Direct dependency used in every HTTP request."
    assert ranked.fix_command == "pip install requests==2.31.0"


def test_cve_equality() -> None:
    cve1 = CVE("id", "pkg", "1.0", [], [], "desc")
    cve2 = CVE("id", "pkg", "1.0", [], [], "desc")
    assert cve1 == cve2


def test_min_fix_version_single() -> None:
    assert min_fix_version(["2.31.0"]) == "2.31.0"


def test_min_fix_version_picks_lowest() -> None:
    assert min_fix_version(["2.31.0", "2.28.2", "3.0.0"]) == "2.28.2"


def test_min_fix_version_empty_returns_none() -> None:
    assert min_fix_version([]) is None


def test_min_fix_version_pre_release_ordered() -> None:
    # 1.0.0a1 < 1.0.0 in semver
    result = min_fix_version(["1.0.0", "1.0.0a1"])
    assert result == "1.0.0a1"


def test_ranked_cve_code_changes_default_empty() -> None:
    cve = CVE("CVE-2023-1", "pkg", "1.0", [], [], "")
    ranked = RankedCVE(rank=1, cve=cve, real_risk="LOW", reasoning="r", fix_command="")
    assert ranked.code_changes == ""


def test_cve_coerces_list_to_tuple() -> None:
    """CVE.__post_init__ converts list inputs to tuples — frozen guarantee holds."""
    cve = CVE(
        id="CVE-2023-1",
        package="pkg",
        installed_version="1.0",
        fix_versions=["2.0", "3.0"],
        aliases=["GHSA-x"],
        description="",
    )
    assert isinstance(cve.fix_versions, tuple)
    assert isinstance(cve.aliases, tuple)
    assert cve.fix_versions == ("2.0", "3.0")
    assert cve.aliases == ("GHSA-x",)


def test_cve_accepts_tuple_directly() -> None:
    cve = CVE(
        id="CVE-2023-2",
        package="pkg",
        installed_version="1.0",
        fix_versions=("2.0",),
        aliases=(),
        description="",
    )
    assert cve.fix_versions == ("2.0",)
    assert cve.aliases == ()


def test_cve_empty_iterables_become_empty_tuple() -> None:
    cve = CVE("CVE-2023-3", "pkg", "1.0", [], [], "")
    assert cve.fix_versions == ()
    assert cve.aliases == ()
