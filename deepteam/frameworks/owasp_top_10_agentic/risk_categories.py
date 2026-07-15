from typing import List
from deepteam.frameworks.risk_category import RiskCategory
from deepteam.vulnerabilities import (
    Ethics,
    ExternalSystemAbuse,
    Misinformation,
    PIILeakage,
    PromptLeakage,
    BFLA,
    BOLA,
    RBAC,
    DebugAccess,
    ShellInjection,
    SQLInjection,
    SSRF,
    GoalTheft,
    RecursiveHijacking,
    Robustness,
    ExcessiveAgency,
    IndirectInstruction,
    ToolOrchestrationAbuse,
    AgentIdentityAbuse,
    ToolMetadataPoisoning,
    UnexpectedCodeExecution,
    InsecureInterAgentCommunication,
    CrossContextRetrieval,
    ExploitToolAgent,
    AutonomousAgentDrift,
)
from deepteam.attacks.single_turn import (
    AuthorityEscalation,
    Base64,
    EmbeddedInstructionJSON,
    EmotionalManipulation,
    GoalRedirection,
    GrayBox,
    InputBypass,
    PermissionEscalation,
    PromptInjection,
    PromptProbing,
    Roleplay,
    ROT13,
    ContextPoisoning,
    SyntheticContextInjection,
    SystemOverride,
)
from deepteam.attacks.multi_turn import (
    BadLikertJudge,
    CrescendoJailbreaking,
    LinearJailbreaking,
    TreeJailbreaking,
)

OWASP_ASI_CATEGORIES: List[RiskCategory] = [
    RiskCategory(
        name="ASI_01",
        _display_name="ASI01:2026 Agent Goal Hijack",
        description="Attackers manipulate an agent's objectives, task selection, or decision pathways through direct prompts, indirect instructions, poisoned content, forged messages, or deceptive tool outputs.",
        attacks=[
            PromptInjection(weight=3),
            GoalRedirection(weight=3),
            LinearJailbreaking(weight=2),
            CrescendoJailbreaking(weight=2),
            TreeJailbreaking(weight=1),
            Roleplay(
                weight=1,
                role="System planner",
                persona="Authorized orchestrator",
            ),
        ],
        vulnerabilities=[
            GoalTheft(
                types=[
                    "escalating_probing",
                    "cooperative_dialogue",
                    "social_engineering",
                ]
            ),
            ExcessiveAgency(types=["functionality", "autonomy"]),
            Robustness(types=["hijacking", "input_overreliance"]),
            RecursiveHijacking(
                types=[
                    "self_modifying_goals",
                    "recursive_objective_chaining",
                    "goal_propagation_attacks",
                    "delegated_goal_inheritance",
                ]
            ),
            IndirectInstruction(
                types=[
                    "cross_context_injection",
                    "document_embedded_instructions",
                    "rag_injection",
                    "tool_output_injection",
                ]
            ),
        ],
    ),
    RiskCategory(
        name="ASI_02",
        _display_name="ASI02:2026 Tool Misuse & Exploitation",
        description="Agents misuse legitimate tools through unsafe composition, over-scoped access, recursive execution, excessive invocation, or unsafe delegation while operating within granted permissions.",
        attacks=[
            PromptInjection(weight=2),
            PermissionEscalation(weight=3),
            GoalRedirection(weight=2),
            AuthorityEscalation(weight=1, role="Tool operations lead"),
            Roleplay(
                weight=1, role="Automation agent", persona="Agent orchestrator"
            ),
        ],
        vulnerabilities=[
            ExcessiveAgency(types=["functionality", "permissions", "autonomy"]),
            BFLA(types=["function_bypass", "authorization_bypass"]),
            ToolOrchestrationAbuse(
                types=[
                    "recursive_tool_calls",
                    "unsafe_tool_composition",
                    "tool_budget_exhaustion",
                    "cross_tool_state_leakage",
                ]
            ),
            ExploitToolAgent(
                types=["financial_manipulation", "data_destruction"]
            ),
            CrossContextRetrieval(
                types=["tenant", "user", "role", "aggregation"]
            ),
            SSRF(types=["internal_service_access", "cloud_metadata_access"]),
            ExternalSystemAbuse(
                types=["data_exfiltration", "communications_spam"]
            ),
        ],
    ),
    RiskCategory(
        name="ASI_03",
        _display_name="ASI03:2026 Identity & Privilege Abuse",
        description="Attackers abuse delegated authority, ambiguous agent identity, inherited permissions, and trust assumptions to trigger unauthorized actions or access.",
        attacks=[
            AuthorityEscalation(weight=3, role="Privileged agent operator"),
            PermissionEscalation(weight=3),
            Roleplay(
                weight=2,
                role="Privileged agent",
                persona="Authorized priority agent",
            ),
            PromptProbing(weight=2),
        ],
        vulnerabilities=[
            BOLA(
                types=[
                    "object_access_bypass",
                    "cross_customer_access",
                    "unauthorized_object_manipulation",
                ]
            ),
            BFLA(
                types=["function_chaining_escalation", "authorization_bypass"]
            ),
            CrossContextRetrieval(
                types=["tenant", "user", "role", "aggregation"]
            ),
            RBAC(
                types=[
                    "role_bypass",
                    "privilege_escalation",
                    "unauthorized_role_assumption",
                    "effective_role_confusion",
                ]
            ),
            PromptLeakage(
                types=[
                    "guard_exposure",
                    "permissions_and_roles",
                    "secrets_and_credentials",
                ]
            ),
            AgentIdentityAbuse(
                types=[
                    "agent_impersonation",
                    "cross_agent_trust_abuse",
                    "identity_inheritance",
                    "persistent_identity_poisoning",
                ]
            ),
            ExternalSystemAbuse(types=["internal_spoofing"]),
        ],
    ),
    RiskCategory(
        name="ASI_04",
        _display_name="ASI04:2026 Agentic Supply Chain Vulnerabilities",
        description="Compromise of external agents, tools, MCP servers, schemas, metadata, prompts, or dependencies that agents dynamically trust, import, or execute.",
        attacks=[
            PromptInjection(weight=2),
            EmbeddedInstructionJSON(weight=3),
            SyntheticContextInjection(
                target_information=(
                    "agent supply-chain trust context, MCP registry metadata, "
                    "tool manifests, and imported agent dependencies"
                ),
                weight=2,
            ),
            GrayBox(weight=2),
            Roleplay(
                weight=1,
                role="Security researcher",
                persona="Agent supply-chain auditor",
            ),
        ],
        vulnerabilities=[
            ToolMetadataPoisoning(
                types=[
                    "schema_manipulation",
                    "description_deception",
                    "permission_misrepresentation",
                    "registry_poisoning",
                ]
            ),
            ExploitToolAgent(
                types=["privilege_escalation", "data_destruction"]
            ),
            InsecureInterAgentCommunication(
                types=["message_injection", "agent_in_the_middle"]
            ),
            UnexpectedCodeExecution(types=["unauthorized_code_execution"]),
        ],
    ),
    RiskCategory(
        name="ASI_05",
        _display_name="ASI05:2026 Unexpected Code Execution (RCE)",
        description="Agent-generated or agent-triggered code, command, database, network, or debug execution occurs without sufficient validation, sanitization, isolation, or approval.",
        attacks=[
            PromptInjection(weight=3),
            SystemOverride(weight=2),
            InputBypass(weight=2),
            Base64(weight=2),
            ROT13(weight=1),
            GrayBox(weight=1),
        ],
        vulnerabilities=[
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
            DebugAccess(
                types=[
                    "debug_mode_bypass",
                    "development_endpoint_access",
                    "administrative_interface_exposure",
                    "configuration_disclosure",
                ]
            ),
            UnexpectedCodeExecution(
                types=[
                    "unauthorized_code_execution",
                    "shell_command_execution",
                    "eval_usage",
                ]
            ),
        ],
    ),
    RiskCategory(
        name="ASI_06",
        _display_name="ASI06:2026 Memory & Context Poisoning",
        description="Attackers poison or exploit memory, retrieved context, session state, or shared contextual data to influence future reasoning, tool use, or cross-session behavior.",
        attacks=[
            PromptInjection(weight=2),
            ContextPoisoning(weight=3),
            SyntheticContextInjection(
                target_information=(
                    "agent memory, retrieved context, session state, and "
                    "cross-session decision history"
                ),
                weight=2,
            ),
            EmbeddedInstructionJSON(weight=2),
            CrescendoJailbreaking(weight=1),
        ],
        vulnerabilities=[
            IndirectInstruction(
                types=[
                    "rag_injection",
                    "tool_output_injection",
                    "document_embedded_instructions",
                    "cross_context_injection",
                ]
            ),
            CrossContextRetrieval(
                types=["tenant", "user", "role", "aggregation"]
            ),
            PIILeakage(types=["session_leak", "api_and_database_access"]),
            PromptLeakage(types=["instructions", "permissions_and_roles"]),
            Misinformation(types=["factual_errors", "unsupported_claims"]),
            Robustness(types=["input_overreliance", "hijacking"]),
            AutonomousAgentDrift(types=["objective_persistence"]),
        ],
    ),
    RiskCategory(
        name="ASI_07",
        _display_name="ASI07:2026 Insecure Inter-Agent Communication",
        description="Attackers manipulate, spoof, intercept, or poison messages exchanged between agents, planners, executors, tools, and external protocol peers.",
        attacks=[
            EmbeddedInstructionJSON(weight=3),
            SyntheticContextInjection(
                target_information=(
                    "planner-to-executor messages, peer-agent handoffs, "
                    "tool responses, and protocol envelopes"
                ),
                weight=2,
            ),
            Roleplay(
                weight=2, role="Planner", persona="Critical Thinking Agent"
            ),
            LinearJailbreaking(weight=2),
            CrescendoJailbreaking(weight=1),
        ],
        vulnerabilities=[
            InsecureInterAgentCommunication(
                types=[
                    "agent_in_the_middle",
                    "message_injection",
                    "message_spoofing",
                    "message_replay",
                ]
            ),
            AgentIdentityAbuse(
                types=[
                    "agent_impersonation",
                    "cross_agent_trust_abuse",
                    "identity_inheritance",
                ]
            ),
            RecursiveHijacking(
                types=[
                    "goal_propagation_attacks",
                    "delegated_goal_inheritance",
                ]
            ),
            ToolOrchestrationAbuse(types=["cross_tool_state_leakage"]),
            ExternalSystemAbuse(types=["internal_spoofing"]),
        ],
    ),
    RiskCategory(
        name="ASI_08",
        _display_name="ASI08:2026 Cascading Failures",
        description="Small agent failures, poisoned outputs, hallucinated facts, unsafe tool calls, or ambiguous handoffs propagate across connected systems and produce large-scale impact.",
        attacks=[
            PromptInjection(weight=2),
            ContextPoisoning(weight=3),
            GoalRedirection(weight=2),
            LinearJailbreaking(weight=1),
            CrescendoJailbreaking(weight=1),
        ],
        vulnerabilities=[
            Robustness(types=["hijacking", "input_overreliance"]),
            ToolOrchestrationAbuse(
                types=[
                    "recursive_tool_calls",
                    "unsafe_tool_composition",
                    "tool_budget_exhaustion",
                    "cross_tool_state_leakage",
                ]
            ),
            RecursiveHijacking(
                types=[
                    "goal_propagation_attacks",
                    "recursive_objective_chaining",
                    "delegated_goal_inheritance",
                ]
            ),
            InsecureInterAgentCommunication(
                types=[
                    "message_injection",
                    "agent_in_the_middle",
                    "message_replay",
                ]
            ),
            ExcessiveAgency(types=["functionality", "autonomy"]),
            Misinformation(types=["factual_errors", "unsupported_claims"]),
            ExternalSystemAbuse(
                types=["data_exfiltration", "communications_spam"]
            ),
        ],
    ),
    RiskCategory(
        name="ASI_09",
        _display_name="ASI09:2026 Human-Agent Trust Exploitation",
        description="Attackers exploit human over-reliance on agents through authority framing, deceptive explanations, social engineering, misleading confidence, or human-in-the-loop pressure.",
        attacks=[
            AuthorityEscalation(weight=3, role="Executive approver"),
            EmotionalManipulation(weight=2),
            Roleplay(
                weight=2, persona="Authoritative expert", role="Human Agent"
            ),
            PromptProbing(weight=1),
            BadLikertJudge(weight=1),
        ],
        vulnerabilities=[
            Ethics(types=["moral_integrity", "responsible_transparency"]),
            Misinformation(
                types=["expertize_misrepresentation", "unsupported_claims"]
            ),
            GoalTheft(types=["social_engineering"]),
            AgentIdentityAbuse(
                types=["agent_impersonation", "identity_inheritance"]
            ),
            PIILeakage(types=["social_manipulation"]),
        ],
    ),
    RiskCategory(
        name="ASI_10",
        _display_name="ASI10:2026 Rogue Agents",
        description="Agents act beyond intended objectives due to goal drift, reward hacking, collusion, persistence, self-modifying goals, or emergent autonomous behavior.",
        attacks=[
            GoalRedirection(weight=3),
            LinearJailbreaking(weight=2),
            CrescendoJailbreaking(weight=2),
            TreeJailbreaking(weight=1),
        ],
        vulnerabilities=[
            RecursiveHijacking(
                types=[
                    "goal_propagation_attacks",
                    "self_modifying_goals",
                    "recursive_objective_chaining",
                    "delegated_goal_inheritance",
                ]
            ),
            AutonomousAgentDrift(
                types=[
                    "agent_collusion",
                    "goal_drift",
                    "objective_persistence",
                    "reward_hacking",
                    "runaway_autonomy",
                ]
            ),
            ExcessiveAgency(types=["autonomy"]),
            InsecureInterAgentCommunication(
                types=["message_spoofing", "message_injection"]
            ),
            Misinformation(types=["factual_errors", "unsupported_claims"]),
            ExternalSystemAbuse(types=["data_exfiltration"]),
        ],
    ),
]
