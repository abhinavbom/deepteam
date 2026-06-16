import pytest
from deepteam.frameworks import NIST
from deepteam.red_teamer.risk_assessment import RiskAssessment
from deepteam.vulnerabilities import BaseVulnerability
from deepteam.attacks import BaseAttack
from deepteam.frameworks.risk_category import RiskCategory
from deepteam.frameworks.nist.risk_categories import NIST_CATEGORIES
from deepteam import red_team

EXPECTED_CATEGORIES = {
    "measurement_methods",
    "validity_reliability",
    "safety",
    "security_resilience",
    "privacy",
    "fairness_bias",
    "emergent_risk",
    "impact_transparency",
}

# Pinned from the NIST AI RMF 1.0 MEASURE function (NIST AI 100-1). Source of
# truth the framework's tactic_id/technique_ids are validated against: every
# category's tactic_id must be a real MEASURE category, and every cited
# technique_id must be a real MEASURE subcategory owned by that category.
NIST_MEASURE_CATEGORIES = {"MEASURE 1", "MEASURE 2", "MEASURE 3", "MEASURE 4"}

NIST_SUBCATEGORY_OWNERS = {
    "MEASURE 1.1": {"MEASURE 1"},
    "MEASURE 1.2": {"MEASURE 1"},
    "MEASURE 1.3": {"MEASURE 1"},
    "MEASURE 2.5": {"MEASURE 2"},
    "MEASURE 2.6": {"MEASURE 2"},
    "MEASURE 2.7": {"MEASURE 2"},
    "MEASURE 2.10": {"MEASURE 2"},
    "MEASURE 2.11": {"MEASURE 2"},
    "MEASURE 3.1": {"MEASURE 3"},
    "MEASURE 3.2": {"MEASURE 3"},
    "MEASURE 4.1": {"MEASURE 4"},
    "MEASURE 4.2": {"MEASURE 4"},
    "MEASURE 4.3": {"MEASURE 4"},
}


class TestNIST:

    def test_nist_init(self):
        """Test that NIST framework can be instantiated."""
        framework = NIST()
        assert framework is not None

    def test_nist_name(self):
        """Test that NIST framework has correct name."""
        framework = NIST()
        assert (
            framework.name
            == framework.get_name()
            == "NIST AI Risk Management Framework (AI RMF)"
        )

    def test_nist_description(self):
        """Description reflects the realigned MEASURE structure, not the old
        four-category (M.1-M.4) wording."""
        desc = NIST().description
        assert "four measurement categories" not in desc
        assert "MEASURE 1" in desc and "MEASURE 4" in desc

    def test_nist_default_categories(self):
        """All eight MEASURE categories are included by default."""
        framework = NIST()
        assert set(framework.categories) == EXPECTED_CATEGORIES

    def test_nist_partial_categories(self):
        """Framework can be created with a limited set of categories."""
        framework = NIST(categories=["safety", "privacy"])
        assert set(framework.categories) == {"safety", "privacy"}

    def test_nist_vulnerabilities_exist(self):
        for risk_category in NIST_CATEGORIES:
            assert hasattr(risk_category, "vulnerabilities")
            assert risk_category.vulnerabilities is not None
            assert len(risk_category.vulnerabilities) > 0

    def test_nist_vulnerabilities_are_instances(self):
        for risk_category in NIST_CATEGORIES:
            for vuln in risk_category.vulnerabilities:
                assert isinstance(vuln, BaseVulnerability)

    def test_nist_attacks_exist(self):
        for risk_category in NIST_CATEGORIES:
            assert hasattr(risk_category, "attacks")
            assert risk_category.attacks is not None
            assert len(risk_category.attacks) > 0

    def test_nist_attacks_are_instances(self):
        for risk_category in NIST_CATEGORIES:
            for attack in risk_category.attacks:
                assert isinstance(attack, BaseAttack)

    def test_nist_category_vulnerability_mapping(self):
        categories = NIST_CATEGORIES
        assert {c.name for c in categories} == EXPECTED_CATEGORIES
        for risk_category in categories:
            assert isinstance(risk_category, RiskCategory)
            assert all(
                isinstance(v, BaseVulnerability)
                for v in risk_category.vulnerabilities
            )

    def test_nist_category_attack_mapping(self):
        categories = NIST_CATEGORIES
        assert {c.name for c in categories} == EXPECTED_CATEGORIES
        for risk_category in categories:
            assert isinstance(risk_category, RiskCategory)
            assert all(isinstance(a, BaseAttack) for a in risk_category.attacks)

    def test_nist_traceability_ids_valid_and_owned(self):
        """tactic_id must be a real MEASURE category and every technique_id must
        be a real MEASURE subcategory officially owned by that category."""
        for rc in NIST_CATEGORIES:
            assert (
                rc.tactic_id in NIST_MEASURE_CATEGORIES
            ), f"{rc.name}: tactic_id {rc.tactic_id} is not a real MEASURE category"
            assert rc.technique_ids, f"{rc.name}: no technique_ids"
            for tech in rc.technique_ids:
                assert (
                    tech in NIST_SUBCATEGORY_OWNERS
                ), f"{rc.name}: {tech} is not a known NIST AI RMF MEASURE subcategory"
                assert rc.tactic_id in NIST_SUBCATEGORY_OWNERS[tech], (
                    f"{rc.name}: subcategory {tech} is owned by "
                    f"{sorted(NIST_SUBCATEGORY_OWNERS[tech])}, "
                    f"not tactic_id {rc.tactic_id}"
                )

    def test_nist_rejects_unknown_category(self):
        """Unsupported categories fail loudly instead of yielding an empty
        mapping (e.g. the renamed-away 'measure_1')."""
        with pytest.raises(ValueError):
            NIST(categories=["measure_1"])
        with pytest.raises(ValueError):
            NIST(categories=["safety", "not_a_real_category"])

    def test_nist_test_cases_carry_measure_ids(self):
        """Generated test cases are stamped with their category's MEASURE ids so
        red-team output is traceable back to the AI RMF (offline check of the
        red_teamer stamping path, no network calls)."""
        from deepteam.test_case import RTTestCase
        from deepteam.red_teamer.red_teamer import RedTeamer

        rc = NIST(categories=["security_resilience"]).risk_categories[0]
        assert rc.tactic_id == "MEASURE 2"
        cases = [
            RTTestCase(vulnerability="BFLA"),
            RTTestCase(vulnerability="SSRF"),
        ]
        RedTeamer._apply_risk_category_metadata(cases, rc)
        for tc in cases:
            assert tc.tactic_id == rc.tactic_id
            assert tc.technique_ids == rc.technique_ids
            assert tc.technique_ids  # non-empty

    def test_nist_no_custom_vulnerability(self):
        """Curated vulns should replace generic CustomVulnerability."""
        vuln_names = [
            v.__class__.__name__
            for rc in NIST_CATEGORIES
            for v in rc.vulnerabilities
        ]
        assert "CustomVulnerability" not in vuln_names

    def test_nist_vulnerability_names_present(self):
        """Key curated NIST vulnerabilities are present across the categories."""
        vuln_names = []
        for risk_category in NIST_CATEGORIES:
            vuln_names.extend(
                [v.__class__.__name__ for v in risk_category.vulnerabilities]
            )
        expected_vulns = [
            "SystemReconnaissance",
            "DebugAccess",
            "Misinformation",
            "Robustness",
            "PersonalSafety",
            "IllegalActivity",
            "GraphicContent",
            "ChildProtection",
            "Toxicity",
            "PromptLeakage",
            "SSRF",
            "ShellInjection",
            "SQLInjection",
            "UnexpectedCodeExecution",
            "BFLA",
            "BOLA",
            "RBAC",
            "ExcessiveAgency",
            "ExploitToolAgent",
            "ToolMetadataPoisoning",
            "ToolOrchestrationAbuse",
            "IndirectInstruction",
            "AgentIdentityAbuse",
            "InsecureInterAgentCommunication",
            "PIILeakage",
            "CrossContextRetrieval",
            "Bias",
            "Fairness",
            "Ethics",
            "GoalTheft",
            "RecursiveHijacking",
            "AutonomousAgentDrift",
            "IntellectualProperty",
            "Competition",
            "ExternalSystemAbuse",
        ]
        for name in expected_vulns:
            assert name in vuln_names, f"Missing vulnerability {name}"

    def test_nist_attack_names_present(self):
        """Key NIST attacks are present across the categories."""
        attack_names = []
        for risk_category in NIST_CATEGORIES:
            attack_names.extend(
                [a.__class__.__name__ for a in risk_category.attacks]
            )
        expected_attacks = [
            "PromptInjection",
            "PromptProbing",
            "Roleplay",
            "Multilingual",
            "GrayBox",
            "BadLikertJudge",
            "ContextPoisoning",
            "SystemOverride",
            "GoalRedirection",
            "PermissionEscalation",
            "AuthorityEscalation",
            "EmbeddedInstructionJSON",
            "Base64",
            "ROT13",
            "Leetspeak",
            "LinguisticConfusion",
            "AdversarialPoetry",
            "CrescendoJailbreaking",
            "LinearJailbreaking",
            "SequentialJailbreak",
        ]
        for name in expected_attacks:
            assert name in attack_names, f"Expected attack {name} not found"

    def test_nist_attack_weights_valid(self):
        for risk_category in NIST_CATEGORIES:
            for attack in risk_category.attacks:
                assert hasattr(attack, "weight")
                assert isinstance(attack.weight, int)
                assert 1 <= attack.weight <= 3

    @pytest.mark.parametrize(
        "category", ["measurement_methods", "security_resilience"]
    )
    def test_nist_framework_with_red_team(self, category):
        """NIST integrates with the red_team pipeline. Uses fixed, explicit
        categories (not random) so failures are reproducible."""

        def mock_model_callback(prompt: str, turns=None) -> str:
            return "This request violates internal policy."

        risk_assessment = red_team(
            model_callback=mock_model_callback,
            framework=NIST(categories=[category]),
            async_mode=False,
            ignore_errors=False,
        )
        assert isinstance(risk_assessment, RiskAssessment)
        assert risk_assessment is not None
