from vulntriage.models import CVE, RankedCVE


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
    assert cve.fix_versions == ["2.31.0"]
    assert cve.aliases == ["PYSEC-2023-74"]
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
