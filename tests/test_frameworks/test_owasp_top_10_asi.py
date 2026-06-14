from deepteam.frameworks import OWASP_ASI_2026
from deepteam.red_teamer.risk_assessment import RiskAssessment
from deepteam.vulnerabilities import (
    AgentIdentityAbuse,
    AutonomousAgentDrift,
    BaseVulnerability,
    CrossContextRetrieval,
    IndirectInstruction,
    IntellectualProperty,
    PIILeakage,
)
from deepteam.attacks import BaseAttack
from deepteam.frameworks.owasp_top_10_agentic.risk_categories import (
    OWASP_ASI_CATEGORIES,
)
from deepteam.frameworks.risk_category import RiskCategory
from deepteam import red_team


class TestOWASP:
    @staticmethod
    def _get_category(category_name):
        return next(
            category
            for category in OWASP_ASI_CATEGORIES
            if category.name == category_name
        )

    @staticmethod
    def _get_vulnerability(category, vulnerability_class):
        return next(
            vulnerability
            for vulnerability in category.vulnerabilities
            if isinstance(vulnerability, vulnerability_class)
        )

    @staticmethod
    def _get_type_values(vulnerability):
        return [
            vulnerability_type.value
            for vulnerability_type in vulnerability.types
        ]

    def test_owasp_asi_2026_init(self):
        """Test that OWASP ASI 2026 framework can be instantiated."""
        framework = OWASP_ASI_2026()
        assert framework is not None

    def test_owasp_asi_2026_name(self):
        """Test that OWASP ASI 2026 framework has correct name."""
        framework = OWASP_ASI_2026()
        assert (
            framework.name
            == framework.get_name()
            == "OWASP Top 10 for Agentic Applications 2026"
        )

    def test_owasp_asi_2026_description(self):
        """Test that OWASP ASI 2026 framework has correct description."""
        framework = OWASP_ASI_2026()
        assert (
            framework.description
            == "A comprehensive list of the most critical security risks associated with agentic AI applications. The 2026 edition focuses on failures introduced by goal hijacking, tool usage, delegated trust, supply-chain compromise, memory persistence, inter-agent communication, cascading failures, human-agent trust exploitation, and rogue-agent behavior. Each risk category is evaluated using realistic attack techniques and typed vulnerability assessments aligned with agent reasoning and behavior."
        )

    def test_owasp_asi_2026_default_categories(self):
        """Test that all 10 OWASP LLM categories are included by default."""
        framework = OWASP_ASI_2026()
        assert set(framework.categories) == {
            "ASI_01",
            "ASI_02",
            "ASI_03",
            "ASI_04",
            "ASI_05",
            "ASI_06",
            "ASI_07",
            "ASI_08",
            "ASI_09",
            "ASI_10",
        }

    def test_owasp_asi_2026_partial_categories(self):
        """Test that framework can be created with limited categories."""
        framework = OWASP_ASI_2026(categories=["ASI_01", "ASI_02"])
        assert set(framework.categories) == {"ASI_01", "ASI_02"}

    def test_owasp_asi_2026_vulnerabilities_exist(self):
        """Test that vulnerabilities are defined and populated."""
        for risk_category in OWASP_ASI_CATEGORIES:
            assert hasattr(risk_category, "vulnerabilities")
            assert risk_category.vulnerabilities is not None
            assert len(risk_category.vulnerabilities) > 0

    def test_owasp_asi_2026_vulnerabilities_are_instances(self):
        """Test that all vulnerabilities are instances of BaseVulnerability."""
        for risk_category in OWASP_ASI_CATEGORIES:
            for vuln in risk_category.vulnerabilities:
                assert isinstance(vuln, BaseVulnerability)

    def test_owasp_asi_2026_attacks_exist(self):
        """Test that attacks are defined and populated."""
        for risk_category in OWASP_ASI_CATEGORIES:
            assert hasattr(risk_category, "attacks")
            assert risk_category.attacks is not None
            assert len(risk_category.attacks) > 0

    def test_owasp_asi_2026_attacks_are_instances(self):
        """Test that all attacks are instances of BaseAttack."""
        for risk_category in OWASP_ASI_CATEGORIES:
            for attack in risk_category.attacks:
                assert isinstance(attack, BaseAttack)

    def test_owasp_asi_2026_vulnerability_types_present(self):
        """Test that key vulnerabilities are present."""
        vuln_names = []
        for risk_category in OWASP_ASI_CATEGORIES:
            vuln_names.extend(
                [v.__class__.__name__ for v in risk_category.vulnerabilities]
            )
        expected_vulns = [
            "Ethics",
            "ExternalSystemAbuse",
            "Misinformation",
            "PIILeakage",
            "PromptLeakage",
            "BFLA",
            "BOLA",
            "RBAC",
            "DebugAccess",
            "ShellInjection",
            "SQLInjection",
            "SSRF",
            "GoalTheft",
            "RecursiveHijacking",
            "Robustness",
            "ExcessiveAgency",
            "IndirectInstruction",
            "ToolOrchestrationAbuse",
            "AgentIdentityAbuse",
            "ToolMetadataPoisoning",
            "UnexpectedCodeExecution",
            "InsecureInterAgentCommunication",
            "CrossContextRetrieval",
            "ExploitToolAgent",
            "AutonomousAgentDrift",
        ]
        for name in expected_vulns:
            assert name in vuln_names, f"Missing vulnerability {name}"

    def test_owasp_asi_2026_attack_types_present(self):
        """Test that key attacks are included."""
        attack_names = []
        for risk_category in OWASP_ASI_CATEGORIES:
            attack_names.extend(
                [a.__class__.__name__ for a in risk_category.attacks]
            )
        expected_attacks = [
            "AuthorityEscalation",
            "BadLikertJudge",
            "Base64",
            "EmbeddedInstructionJSON",
            "EmotionalManipulation",
            "GoalRedirection",
            "GrayBox",
            "InputBypass",
            "PermissionEscalation",
            "PromptInjection",
            "PromptProbing",
            "Roleplay",
            "ROT13",
            "ContextPoisoning",
            "CrescendoJailbreaking",
            "LinearJailbreaking",
            "SyntheticContextInjection",
            "SystemOverride",
            "TreeJailbreaking",
        ]
        for attack in expected_attacks:
            assert attack in attack_names, f"Expected attack {attack} not found"

    def test_owasp_asi_04_excludes_intellectual_property(self):
        """Test that ASI04 is mapped to supply-chain risks, not IP imitation."""
        asi_04 = self._get_category("ASI_04")

        assert not any(
            isinstance(vulnerability, IntellectualProperty)
            for vulnerability in asi_04.vulnerabilities
        )

    def test_owasp_asi_03_includes_persistent_identity_poisoning(self):
        """Test that ASI03 covers all agent-identity-abuse subtypes."""
        asi_03 = self._get_category("ASI_03")
        identity_abuse = self._get_vulnerability(asi_03, AgentIdentityAbuse)

        assert "persistent_identity_poisoning" in self._get_type_values(
            identity_abuse
        )

    def test_owasp_asi_06_covers_context_memory_and_persistence(self):
        """Test that ASI06 covers context, memory, and persistence surfaces."""
        asi_06 = self._get_category("ASI_06")
        vulnerability_classes = [
            vulnerability.__class__ for vulnerability in asi_06.vulnerabilities
        ]
        drift = self._get_vulnerability(asi_06, AutonomousAgentDrift)

        assert IndirectInstruction in vulnerability_classes
        assert CrossContextRetrieval in vulnerability_classes
        assert PIILeakage in vulnerability_classes
        assert "objective_persistence" in self._get_type_values(drift)

    def test_owasp_asi_10_includes_objective_persistence(self):
        """Test that ASI10 covers all autonomous-agent-drift subtypes."""
        asi_10 = self._get_category("ASI_10")
        drift = self._get_vulnerability(asi_10, AutonomousAgentDrift)

        assert set(drift.ALLOWED_TYPES) == set(self._get_type_values(drift))

    def test_owasp_asi_2026_vulnerability_subtypes_are_valid(self):
        """Test that configured subtype values belong to each vulnerability."""
        for risk_category in OWASP_ASI_CATEGORIES:
            for vulnerability in risk_category.vulnerabilities:
                allowed_types = set(vulnerability.ALLOWED_TYPES)
                configured_types = set(self._get_type_values(vulnerability))

                assert allowed_types
                assert configured_types.issubset(allowed_types)

    def test_owasp_asi_2026_attack_weights_defined(self):
        """Test that all attacks have a valid weight."""
        for risk_category in OWASP_ASI_CATEGORIES:
            for attack in risk_category.attacks:
                assert hasattr(attack, "weight")
                assert isinstance(attack.weight, int)
                assert attack.weight >= 1

    def test_owasp_asi_2026_category_vulnerability_mapping(self):
        """Test that all categories map to vulnerabilities properly."""
        categories = OWASP_ASI_CATEGORIES
        assert set([category.name for category in categories]) == {
            "ASI_01",
            "ASI_02",
            "ASI_03",
            "ASI_04",
            "ASI_05",
            "ASI_06",
            "ASI_07",
            "ASI_08",
            "ASI_09",
            "ASI_10",
        }
        for risk_category in categories:
            assert isinstance(risk_category, RiskCategory)
            assert all(
                isinstance(v, BaseVulnerability)
                for v in risk_category.vulnerabilities
            )

    def test_owasp_asi_2026_category_attack_mapping(self):
        """Test that all categories map to attacks properly."""
        categories = OWASP_ASI_CATEGORIES
        assert set([category.name for category in categories]) == {
            "ASI_01",
            "ASI_02",
            "ASI_03",
            "ASI_04",
            "ASI_05",
            "ASI_06",
            "ASI_07",
            "ASI_08",
            "ASI_09",
            "ASI_10",
        }
        for risk_category in categories:
            assert isinstance(risk_category, RiskCategory)
            assert all(isinstance(a, BaseAttack) for a in risk_category.attacks)

    def test_owasp_asi_2026_framework_with_red_team(self):
        """Test that OWASP ASI 2026 framework integrates correctly with red_team function."""

        # Simple mock model for testing
        def mock_model_callback(prompt: str, turns=None) -> str:
            return "I am a safe AI model and cannot perform unsafe actions."

        risk_assessment = red_team(
            model_callback=mock_model_callback,
            framework=OWASP_ASI_2026(categories=["ASI_01"]),
            async_mode=False,
            ignore_errors=False,
        )

        assert isinstance(risk_assessment, RiskAssessment)
        assert risk_assessment is not None
