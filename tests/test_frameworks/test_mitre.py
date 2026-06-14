import pytest
from deepteam.frameworks import MITRE
from deepteam.red_teamer.risk_assessment import RiskAssessment
from deepteam.vulnerabilities import BaseVulnerability
from deepteam.attacks import BaseAttack
from deepteam.frameworks.risk_category import RiskCategory
from deepteam.frameworks.mitre.risk_categories import MITRE_CATEGORIES
from deepteam import red_team


EXPECTED_CATEGORIES = {
    "reconnaissance",
    "initial_access",
    "execution",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "collection",
    "ml_attack_staging",
    "exfiltration",
    "impact",
    "command_and_control",
}

# Pinned from MITRE ATLAS v5.6.0 (mitre-atlas/atlas-data, dist/ATLAS.yaml).
# This is the source of truth the framework's tactic_id/technique_ids are
# validated against. Subtechniques (e.g. AML.T0085.000) inherit their parent
# technique's tactics. If you cite a new technique in risk_categories.py, add
# it here with its real owning tactic(s).
ATLAS_TACTIC_IDS = {
    "AML.TA0000",  # AI Model Access
    "AML.TA0001",  # AI Attack Staging
    "AML.TA0002",  # Reconnaissance
    "AML.TA0003",  # Resource Development
    "AML.TA0004",  # Initial Access
    "AML.TA0005",  # Execution
    "AML.TA0006",  # Persistence
    "AML.TA0007",  # Defense Evasion
    "AML.TA0008",  # Discovery
    "AML.TA0009",  # Collection
    "AML.TA0010",  # Exfiltration
    "AML.TA0011",  # Impact
    "AML.TA0012",  # Privilege Escalation
    "AML.TA0013",  # Credential Access
    "AML.TA0014",  # Command and Control
    "AML.TA0015",  # Lateral Movement
}

ATLAS_TECHNIQUE_OWNERS = {
    "AML.T0010": {"AML.TA0004"},
    "AML.T0013": {"AML.TA0008"},
    "AML.T0014": {"AML.TA0008"},
    "AML.T0015": {"AML.TA0004", "AML.TA0007", "AML.TA0011"},
    "AML.T0018": {"AML.TA0001", "AML.TA0006"},
    "AML.T0024": {"AML.TA0010"},
    "AML.T0029": {"AML.TA0011"},
    "AML.T0031": {"AML.TA0011"},
    "AML.T0034": {"AML.TA0011"},
    "AML.T0043": {"AML.TA0001"},
    "AML.T0048": {"AML.TA0011"},
    "AML.T0049": {"AML.TA0004"},
    "AML.T0050": {"AML.TA0005"},
    "AML.T0051": {"AML.TA0005"},
    "AML.T0053": {"AML.TA0005", "AML.TA0012"},
    "AML.T0054": {"AML.TA0007", "AML.TA0012"},
    "AML.T0055": {"AML.TA0013"},
    "AML.T0056": {"AML.TA0010"},
    "AML.T0057": {"AML.TA0010"},
    "AML.T0068": {"AML.TA0007"},
    "AML.T0069": {"AML.TA0008"},
    "AML.T0071": {"AML.TA0007"},
    "AML.T0072": {"AML.TA0014"},
    "AML.T0082": {"AML.TA0013"},
    "AML.T0084": {"AML.TA0008"},
    "AML.T0085": {"AML.TA0009"},
    "AML.T0085.000": {"AML.TA0009"},  # subtechnique of AML.T0085
    "AML.T0085.001": {"AML.TA0009"},  # subtechnique of AML.T0085
    "AML.T0086": {"AML.TA0010"},
    "AML.T0093": {"AML.TA0004", "AML.TA0006"},
    "AML.T0096": {"AML.TA0014"},
    "AML.T0098": {"AML.TA0013"},
    "AML.T0101": {"AML.TA0011"},
    "AML.T0102": {"AML.TA0001"},
    "AML.T0108": {"AML.TA0014"},
}


class TestMITRE:

    def test_mitre_init(self):
        """Test that MITRE ATLAS framework can be instantiated."""
        framework = MITRE()
        assert framework is not None

    def test_mitre_name(self):
        """Test that MITRE ATLAS framework has correct name."""
        framework = MITRE()
        assert framework.name == framework.get_name() == "MITRE ATLAS"

    def test_mitre_description(self):
        """Test that MITRE ATLAS framework has correct description."""
        framework = MITRE()
        assert (
            framework.description
            == "A structured knowledge base of adversarial tactics, techniques, and procedures (TTPs) used against AI systems, mapping DeepTeam's curated vulnerabilities and attacks onto the MITRE ATLAS™ matrix. Tests the prompt-testable ATLAS tactics: reconnaissance, initial access, execution, privilege escalation, defense evasion, credential access, collection, AI attack staging, exfiltration, impact, and command & control. Each category traces back to its ATLAS tactic and representative techniques; training-time, offline, and adversary-side tactics (resource development, AI model access, persistence, lateral movement) are out of scope for live-prompt testing."
        )

    def test_mitre_default_categories(self):
        """Test that all MITRE categories are included by default."""
        framework = MITRE()
        assert set(framework.categories) == EXPECTED_CATEGORIES

    def test_mitre_partial_categories(self):
        """Test that MITRE can be initialized with limited categories."""
        framework = MITRE(categories=["reconnaissance", "impact"])
        assert set(framework.categories) == {"reconnaissance", "impact"}

    def test_mitre_vulnerabilities_exist(self):
        """Test that MITRE framework defines vulnerabilities."""
        for risk_category in MITRE_CATEGORIES:
            assert hasattr(risk_category, "vulnerabilities")
            assert len(risk_category.vulnerabilities) > 0

    def test_mitre_vulnerabilities_are_instances(self):
        """Test that all vulnerabilities are instances of BaseVulnerability."""
        for risk_category in MITRE_CATEGORIES:
            for vuln in risk_category.vulnerabilities:
                assert isinstance(vuln, BaseVulnerability)

    def test_mitre_attacks_exist(self):
        """Test that MITRE framework defines attacks."""
        for risk_category in MITRE_CATEGORIES:
            assert hasattr(risk_category, "attacks")
            assert len(risk_category.attacks) > 0

    def test_mitre_attacks_are_instances(self):
        """Test that all attacks are instances of BaseAttack."""
        for risk_category in MITRE_CATEGORIES:
            for attack in risk_category.attacks:
                assert isinstance(attack, BaseAttack)

    def test_mitre_category_vulnerability_mapping(self):
        """Test that all categories map to vulnerabilities properly."""
        categories = MITRE_CATEGORIES
        assert {category.name for category in categories} == EXPECTED_CATEGORIES
        for risk_category in categories:
            assert isinstance(risk_category, RiskCategory)
            assert all(
                isinstance(v, BaseVulnerability)
                for v in risk_category.vulnerabilities
            )

    def test_mitre_category_attack_mapping(self):
        """Test that all categories map to attacks properly."""
        categories = MITRE_CATEGORIES
        assert {category.name for category in categories} == EXPECTED_CATEGORIES
        for risk_category in categories:
            assert isinstance(risk_category, RiskCategory)
            assert all(isinstance(v, BaseAttack) for v in risk_category.attacks)

    def test_mitre_traceability_ids_valid_and_owned(self):
        """tactic_id + technique_ids must be real ATLAS 5.6.0 IDs, and every
        cited technique must be officially owned by its category's tactic_id."""
        for rc in MITRE_CATEGORIES:
            assert (
                rc.tactic_id in ATLAS_TACTIC_IDS
            ), f"{rc.name}: tactic_id {rc.tactic_id} is not a real ATLAS tactic"
            assert rc.technique_ids, f"{rc.name}: no technique_ids"
            for tech in rc.technique_ids:
                assert (
                    tech in ATLAS_TECHNIQUE_OWNERS
                ), f"{rc.name}: {tech} is not a known ATLAS 5.6.0 technique"
                assert rc.tactic_id in ATLAS_TECHNIQUE_OWNERS[tech], (
                    f"{rc.name}: technique {tech} is owned by "
                    f"{sorted(ATLAS_TECHNIQUE_OWNERS[tech])}, "
                    f"not tactic_id {rc.tactic_id}"
                )

    def test_mitre_rejects_unknown_category(self):
        """Unsupported categories fail loudly instead of yielding an empty
        mapping (e.g. the deliberately-removed 'resource_development')."""
        with pytest.raises(ValueError):
            MITRE(categories=["resource_development"])
        with pytest.raises(ValueError):
            MITRE(categories=["reconnaissance", "not_a_real_tactic"])

    def test_mitre_test_cases_carry_atlas_ids(self):
        """Generated test cases are stamped with their category's ATLAS IDs so
        red-team output is traceable back to the matrix (offline check of the
        red_teamer stamping path, no network calls)."""
        from deepteam.test_case import RTTestCase
        from deepteam.red_teamer.red_teamer import RedTeamer

        rc = MITRE(categories=["execution"]).risk_categories[0]
        assert rc.tactic_id == "AML.TA0005"
        cases = [
            RTTestCase(vulnerability="UnexpectedCodeExecution"),
            RTTestCase(vulnerability="ShellInjection"),
        ]
        RedTeamer._apply_risk_category_metadata(cases, rc)
        for tc in cases:
            assert tc.tactic_id == rc.tactic_id
            assert tc.technique_ids == rc.technique_ids
            assert tc.technique_ids  # non-empty

    def test_mitre_vulnerability_names_present(self):
        """Test that key curated MITRE vulnerabilities are present."""
        vuln_names = []
        for risk_category in MITRE_CATEGORIES:
            vuln_names.extend(
                [v.__class__.__name__ for v in risk_category.vulnerabilities]
            )
        expected_vulns = [
            "SystemReconnaissance",
            "Competition",
            "PromptLeakage",
            "IndirectInstruction",
            "DebugAccess",
            "ToolMetadataPoisoning",
            "UnexpectedCodeExecution",
            "ShellInjection",
            "SQLInjection",
            "SSRF",
            "ExploitToolAgent",
            "ExcessiveAgency",
            "RBAC",
            "BFLA",
            "BOLA",
            "AgentIdentityAbuse",
            "Robustness",
            "PIILeakage",
            "CrossContextRetrieval",
            "Misinformation",
            "IntellectualProperty",
            "ExternalSystemAbuse",
            "RecursiveHijacking",
            "AutonomousAgentDrift",
            "GoalTheft",
            "ToolOrchestrationAbuse",
            "IllegalActivity",
            "GraphicContent",
            "InsecureInterAgentCommunication",
        ]
        for name in expected_vulns:
            assert (
                name in vuln_names
            ), f"Expected vulnerability {name} not found"

    def test_mitre_no_custom_vulnerability(self):
        """Curated vulns should replace generic CustomVulnerability."""
        vuln_names = [
            v.__class__.__name__
            for rc in MITRE_CATEGORIES
            for v in rc.vulnerabilities
        ]
        assert "CustomVulnerability" not in vuln_names

    def test_mitre_attack_names_present(self):
        """Test that key MITRE attacks are present."""
        attack_names = []
        for risk_category in MITRE_CATEGORIES:
            attack_names.extend(
                [a.__class__.__name__ for a in risk_category.attacks]
            )
        expected_attacks = [
            "Roleplay",
            "PromptInjection",
            "PromptProbing",
            "GrayBox",
            "Multilingual",
            "EmbeddedInstructionJSON",
            "SyntheticContextInjection",
            "GoalRedirection",
            "SystemOverride",
            "Base64",
            "PermissionEscalation",
            "AuthorityEscalation",
            "ROT13",
            "Leetspeak",
            "AdversarialPoetry",
            "CharacterStream",
            "LinguisticConfusion",
            "ContextPoisoning",
            "CrescendoJailbreaking",
            "LinearJailbreaking",
            "TreeJailbreaking",
            "SequentialJailbreak",
            "BadLikertJudge",
        ]
        for name in expected_attacks:
            assert name in attack_names, f"Expected attack {name} not found"

    def test_mitre_attack_weights_valid(self):
        """Test that all attacks have valid weights."""
        for risk_category in MITRE_CATEGORIES:
            for attack in risk_category.attacks:
                assert hasattr(attack, "weight")
                assert isinstance(attack.weight, int)
                assert 1 <= attack.weight <= 3

    @pytest.mark.parametrize("category", ["reconnaissance", "exfiltration"])
    def test_mitre_framework_with_red_team(self, category):
        """Test MITRE ATLAS integration with red_team pipeline.

        Uses fixed, explicit categories (not random) so failures are
        reproducible.
        """

        def mock_model_callback(prompt: str, turns=None) -> str:
            return "This request violates internal policy."

        risk_assessment = red_team(
            model_callback=mock_model_callback,
            framework=MITRE(categories=[category]),
            async_mode=False,
            ignore_errors=False,
        )
        assert isinstance(risk_assessment, RiskAssessment)
        assert risk_assessment is not None
