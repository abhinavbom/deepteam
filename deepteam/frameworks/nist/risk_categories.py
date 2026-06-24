from deepteam.frameworks.risk_category import RiskCategory
from deepteam.vulnerabilities import (
    AgentIdentityAbuse,
    AutonomousAgentDrift,
    BFLA,
    BOLA,
    Bias,
    ChildProtection,
    Competition,
    CrossContextRetrieval,
    DebugAccess,
    Ethics,
    ExcessiveAgency,
    ExploitToolAgent,
    ExternalSystemAbuse,
    Fairness,
    GoalTheft,
    GraphicContent,
    IllegalActivity,
    IndirectInstruction,
    InsecureInterAgentCommunication,
    IntellectualProperty,
    Misinformation,
    PIILeakage,
    PersonalSafety,
    PromptLeakage,
    RBAC,
    RecursiveHijacking,
    Robustness,
    SQLInjection,
    SSRF,
    ShellInjection,
    SystemReconnaissance,
    ToolMetadataPoisoning,
    ToolOrchestrationAbuse,
    Toxicity,
    UnexpectedCodeExecution,
)

from deepteam.attacks.single_turn import (
    AdversarialPoetry,
    AuthorityEscalation,
    Base64,
    ContextPoisoning,
    EmbeddedInstructionJSON,
    GoalRedirection,
    GrayBox,
    Leetspeak,
    LinguisticConfusion,
    Multilingual,
    PermissionEscalation,
    PromptInjection,
    PromptProbing,
    ROT13,
    Roleplay,
    SystemOverride,
)

from deepteam.attacks.multi_turn import (
    BadLikertJudge,
    CrescendoJailbreaking,
    LinearJailbreaking,
    SequentialJailbreak,
)

# Each category maps to a single NIST AI RMF *trustworthy characteristic* /
# MEASURE subcategory. ``tactic_id`` is the parent MEASURE category (e.g.
# "MEASURE 2") and every id in ``technique_ids`` is a real MEASURE subcategory
# *owned by that category* (strict subset), pinned to the AI RMF 1.0 primary
# source (NIST AI 100-1, nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf) and
# enforced by test_nist.py. This mirrors the MITRE ATLAS module's one-tactic-
# per-category design so each generated test case carries a precise subcategory
# id. Vulnerability selections favour deepteam's curated, judge-backed
# vulnerabilities over generic CustomVulnerability so attacks and scoring
# inherit the per-vuln template/judge tuning (zero CustomVulnerability). Only
# the prompt-testable slice of the MEASURE function is represented; see nist.py
# for the functions/subcategories deliberately left out of scope.

NIST_CATEGORIES = [
    RiskCategory(
        name="measurement_methods",
        _display_name="Measurement Methods & Independent Assessment (NIST AI RMF MEASURE 1)",
        description="The independent-assessment surface of the MEASURE function: what an external assessor or non-developer reviewer can enumerate, fingerprint, or expose about the AI system when selecting and validating risk metrics (MEASURE 1.1-1.3).",
        tactic_id="MEASURE 1",
        technique_ids=["MEASURE 1.1", "MEASURE 1.2", "MEASURE 1.3"],
        attacks=[
            PromptProbing(weight=3),
            GrayBox(weight=2),
            Roleplay(
                weight=2,
                role="Independent assessor validating risk metrics before sign-off",
                persona="Non-developer AI risk assessor",
            ),
            Multilingual(weight=1),
        ],
        vulnerabilities=[
            SystemReconnaissance(
                types=[
                    "model_fingerprinting",
                    "infrastructure_fingerprinting",
                    "tool_enumeration",
                    "retrieval_config",
                    "database_schema",
                    "file_metadata",
                ]
            ),
            DebugAccess(
                types=[
                    "development_endpoint_access",
                    "administrative_interface_exposure",
                    "debug_mode_bypass",
                    "configuration_disclosure",
                ]
            ),
        ],
    ),
    RiskCategory(
        name="validity_reliability",
        _display_name="Valid & Reliable (NIST AI RMF MEASURE 2.5)",
        description="Evaluate that the AI system is valid and reliable: resistant to hijacking, not over-relied upon, and free of confabulated or unsupported output (MEASURE 2.5).",
        tactic_id="MEASURE 2",
        technique_ids=["MEASURE 2.5"],
        attacks=[
            GrayBox(weight=2),
            PromptProbing(weight=2),
            BadLikertJudge(weight=2),
            Multilingual(weight=1),
            PromptInjection(weight=1),
        ],
        vulnerabilities=[
            Misinformation(
                types=[
                    "factual_errors",
                    "unsupported_claims",
                    "expertize_misrepresentation",
                ]
            ),
            Robustness(types=["input_overreliance", "hijacking"]),
        ],
    ),
    RiskCategory(
        name="safety",
        _display_name="Safe (NIST AI RMF MEASURE 2.6)",
        description="Evaluate AI system safety: the system should not produce content that enables physical harm, illegal activity, or graphic/abusive material, and should protect minors (MEASURE 2.6).",
        tactic_id="MEASURE 2",
        technique_ids=["MEASURE 2.6"],
        attacks=[
            CrescendoJailbreaking(weight=2),
            LinearJailbreaking(weight=2),
            SequentialJailbreak(weight=2),
            Roleplay(
                weight=2,
                role="Safety tester performing red-team scenarios",
                persona="Security researcher",
            ),
            AdversarialPoetry(weight=2),
            BadLikertJudge(weight=1),
        ],
        vulnerabilities=[
            PersonalSafety(
                types=[
                    "bullying",
                    "self_harm",
                    "unsafe_practices",
                    "dangerous_challenges",
                    "stalking",
                ]
            ),
            IllegalActivity(
                types=[
                    "cybercrime",
                    "violent_crimes",
                    "non_violent_crimes",
                    "illegal_drugs",
                    "weapons",
                ]
            ),
            GraphicContent(
                types=[
                    "sexual_content",
                    "graphic_content",
                    "pornographic_content",
                ]
            ),
            ChildProtection(
                types=[
                    "age_verification",
                    "data_privacy",
                    "exposure_interaction",
                ]
            ),
            Toxicity(types=["profanity", "insults", "threats", "mockery"]),
        ],
    ),
    RiskCategory(
        name="security_resilience",
        _display_name="Secure & Resilient (NIST AI RMF MEASURE 2.7)",
        description="Evaluate AI system security and resilience: resistance to prompt/credential leakage, injection and code execution, broken access control, and the agent/tool/RAG attack surface (MEASURE 2.7). This is the broadest MEASURE characteristic and the primary security red-team surface.",
        tactic_id="MEASURE 2",
        technique_ids=["MEASURE 2.7"],
        attacks=[
            PromptInjection(weight=3),
            EmbeddedInstructionJSON(weight=2),
            SystemOverride(weight=2),
            GoalRedirection(weight=2),
            PermissionEscalation(weight=2),
            AuthorityEscalation(
                weight=2,
                role="Platform administrator performing an urgent production hotfix",
            ),
            ContextPoisoning(weight=2),
            Base64(weight=1),
            ROT13(weight=1),
            Leetspeak(weight=1),
        ],
        vulnerabilities=[
            PromptLeakage(
                types=[
                    "secrets_and_credentials",
                    "instructions",
                    "guard_exposure",
                    "permissions_and_roles",
                ]
            ),
            ShellInjection(
                types=[
                    "command_injection",
                    "system_command_execution",
                    "shell_escape_sequences",
                ]
            ),
            SQLInjection(
                types=[
                    "blind_sql_injection",
                    "union_based_injection",
                    "error_based_injection",
                ]
            ),
            SSRF(
                types=[
                    "internal_service_access",
                    "cloud_metadata_access",
                    "port_scanning",
                ]
            ),
            UnexpectedCodeExecution(
                types=[
                    "eval_usage",
                    "shell_command_execution",
                    "unauthorized_code_execution",
                ]
            ),
            ExcessiveAgency(types=["functionality", "permissions", "autonomy"]),
            RBAC(
                types=[
                    "role_bypass",
                    "privilege_escalation",
                    "unauthorized_role_assumption",
                ]
            ),
            BFLA(
                types=[
                    "function_bypass",
                    "authorization_bypass",
                    "function_chaining_escalation",
                    "legacy_function_exploitation",
                ]
            ),
            BOLA(
                types=[
                    "object_access_bypass",
                    "cross_customer_access",
                    "unauthorized_object_manipulation",
                ]
            ),
            IndirectInstruction(
                types=[
                    "rag_injection",
                    "document_embedded_instructions",
                    "tool_output_injection",
                    "cross_context_injection",
                ]
            ),
            AgentIdentityAbuse(
                types=[
                    "identity_inheritance",
                    "cross_agent_trust_abuse",
                    "agent_impersonation",
                ]
            ),
            ToolMetadataPoisoning(
                types=["description_deception", "schema_manipulation"]
            ),
            ExploitToolAgent(
                types=[
                    "privilege_escalation",
                    "data_destruction",
                    "financial_manipulation",
                ]
            ),
            InsecureInterAgentCommunication(
                types=[
                    "message_injection",
                    "message_spoofing",
                    "agent_in_the_middle",
                    "message_replay",
                ]
            ),
            ToolOrchestrationAbuse(
                types=[
                    "tool_budget_exhaustion",
                    "recursive_tool_calls",
                    "cross_tool_state_leakage",
                ]
            ),
            ExternalSystemAbuse(
                types=[
                    "data_exfiltration",
                    "internal_spoofing",
                    "communications_spam",
                ]
            ),
        ],
    ),
    RiskCategory(
        name="privacy",
        _display_name="Privacy-Enhanced (NIST AI RMF MEASURE 2.10)",
        description="Evaluate privacy risk: the system should not disclose personal data directly or obliquely, leak it across sessions, or expose another tenant's/user's data through retrieval (MEASURE 2.10).",
        tactic_id="MEASURE 2",
        technique_ids=["MEASURE 2.10"],
        attacks=[
            PromptProbing(weight=3),
            PromptInjection(weight=2),
            Multilingual(weight=2),
            ContextPoisoning(weight=2),
            Base64(weight=1),
        ],
        vulnerabilities=[
            PIILeakage(
                types=[
                    "direct_disclosure",
                    "api_and_database_access",
                    "session_leak",
                    "social_manipulation",
                    "redaction_bypass",
                ]
            ),
            CrossContextRetrieval(
                types=["tenant", "user", "role", "aggregation"]
            ),
        ],
    ),
    RiskCategory(
        name="fairness_bias",
        _display_name="Fair with Harmful Bias Managed (NIST AI RMF MEASURE 2.11)",
        description="Evaluate fairness and harmful bias: the system should treat protected groups consistently, apply procedures equitably, and uphold ethical commitments (MEASURE 2.11).",
        tactic_id="MEASURE 2",
        technique_ids=["MEASURE 2.11"],
        attacks=[
            Roleplay(
                weight=2,
                role="Researcher eliciting differential treatment across groups",
                persona="Social-science researcher",
            ),
            PromptInjection(weight=2),
            LinguisticConfusion(weight=2),
            BadLikertJudge(weight=2),
            Multilingual(weight=1),
        ],
        vulnerabilities=[
            Bias(types=["race", "gender", "religion", "politics"]),
            Fairness(
                types=[
                    "equality_consistency",
                    "procedural_opportunity",
                    "temporal_outcome",
                ]
            ),
            Ethics(
                types=[
                    "harm_prevention",
                    "moral_integrity",
                    "responsible_transparency",
                ]
            ),
        ],
    ),
    RiskCategory(
        name="emergent_risk",
        _display_name="Emergent & Hard-to-Measure Risk Tracking (NIST AI RMF MEASURE 3)",
        description="Track existing, unanticipated, and emergent AI risks — especially agentic behaviours that are difficult to assess with currently available measurement techniques: goal drift, reward hacking, runaway autonomy, recursive goal hijacking, and goal extraction (MEASURE 3.1-3.2).",
        tactic_id="MEASURE 3",
        technique_ids=["MEASURE 3.1", "MEASURE 3.2"],
        attacks=[
            CrescendoJailbreaking(weight=2),
            GoalRedirection(weight=2),
            SystemOverride(weight=2),
            ContextPoisoning(weight=2),
            SequentialJailbreak(weight=1),
            PromptInjection(weight=1),
        ],
        vulnerabilities=[
            AutonomousAgentDrift(
                types=["goal_drift", "reward_hacking", "runaway_autonomy"]
            ),
            RecursiveHijacking(
                types=[
                    "goal_propagation_attacks",
                    "recursive_objective_chaining",
                    "self_modifying_goals",
                ]
            ),
            GoalTheft(types=["escalating_probing", "social_engineering"]),
        ],
    ),
    RiskCategory(
        name="impact_transparency",
        _display_name="Impact, Transparency & Business Outcomes (NIST AI RMF MEASURE 4)",
        description="Connect measurement to deployment impact and stakeholder trust: the system should not damage business standing through discreditation or market manipulation, nor reproduce protected intellectual property (MEASURE 4.1-4.3).",
        tactic_id="MEASURE 4",
        technique_ids=["MEASURE 4.1", "MEASURE 4.2", "MEASURE 4.3"],
        attacks=[
            PromptProbing(weight=2),
            BadLikertJudge(weight=2),
            Roleplay(
                weight=2,
                role="Stakeholder feedback simulation (user reports / complaints)",
                persona="End user",
            ),
            PromptInjection(weight=1),
        ],
        vulnerabilities=[
            Competition(
                types=[
                    "discreditation",
                    "competitor_mention",
                    "confidential_strategies",
                    "market_manipulation",
                ]
            ),
            IntellectualProperty(
                types=[
                    "imitation",
                    "copyright_violations",
                    "trademark_infringement",
                    "patent_disclosure",
                ]
            ),
        ],
    ),
]
