from typing import List, Literal
from deepteam.frameworks import AISafetyFramework
from deepteam.frameworks.mitre.risk_categories import MITRE_CATEGORIES

"""
MITRE ATLAS™ (Adversarial Threat Landscape for Artificial-Intelligence Systems)
================================================================================

MITRE ATLAS™ is a structured knowledge base of adversarial tactics, techniques,
and procedures (TTPs) used against AI and ML systems. It extends MITRE ATT&CK®
to the AI threat surface, describing how adversaries manipulate, exploit, or
misuse AI models and agents across the attack lifecycle.

DeepTeam's MITRE module maps the project's curated, judge-backed vulnerabilities
and attacks onto the ATLAS matrix so each generated test case traces back to a
real ATLAS tactic (``tactic_id``) and representative techniques (``technique_ids``).
Tactic/technique IDs follow the official ATLAS data (mitre-atlas/atlas-data).

Tactics covered (prompt-testable against a deployed LLM/agent). Each deepteam
category maps to the ATLAS tactic that actually owns its cited techniques, which
is not always the tactic the colloquial name suggests:
1. Reconnaissance & Discovery (AML.TA0008) — model/system/agent profiling
   (ATLAS Reconnaissance, AML.TA0002, is pre-attack OSINT and not prompt-testable)
2. Initial Access (AML.TA0004) — prompt injection, poisoned retrieval, exposed surfaces
3. Execution (AML.TA0005) — code/command/tool execution via the model
4. Privilege Escalation (AML.TA0012) — role/authorization/identity abuse
5. Defense Evasion (AML.TA0007) — guardrail/detection bypass via obfuscation & jailbreaks
6. Credential Access (AML.TA0013) — secret/credential theft
7. Collection (AML.TA0009) — cross-tenant/user/session data aggregation
8. AI Attack Staging (AML.TA0001) — adversarial-data crafting & context poisoning
9. Exfiltration (AML.TA0010) — data/model/system-prompt theft
10. Impact (AML.TA0011) — manipulation, degradation, External Harms
11. Command & Control (AML.TA0014) — covert agent control/signalling channels

Out of scope for live-prompt testing (pre-attack OSINT, training-time, offline,
infrastructure, or adversary-side tactics): Reconnaissance (AML.TA0002, OSINT),
Resource Development (AML.TA0003), AI Model Access (AML.TA0000), Persistence
(AML.TA0006), and Lateral Movement (AML.TA0015).

Each category includes:
- Attacks: tactic-aligned adversarial techniques for exploiting/bypassing the system
- Vulnerabilities: AI-specific weaknesses leveraged at that stage of the lifecycle

Reference: https://atlas.mitre.org
"""


class MITRE(AISafetyFramework):
    name = "MITRE ATLAS"
    description = "A structured knowledge base of adversarial tactics, techniques, and procedures (TTPs) used against AI systems, mapping DeepTeam's curated vulnerabilities and attacks onto the MITRE ATLAS™ matrix. Tests the prompt-testable ATLAS tactics: reconnaissance, initial access, execution, privilege escalation, defense evasion, credential access, collection, AI attack staging, exfiltration, impact, and command & control. Each category traces back to its ATLAS tactic and representative techniques; training-time, offline, and adversary-side tactics (resource development, AI model access, persistence, lateral movement) are out of scope for live-prompt testing."
    ALLOWED_TYPES = [
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
    ]

    def __init__(
        self,
        categories: List[
            Literal[
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
            ]
        ] = [
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
        ],
    ):
        invalid = [c for c in categories if c not in self.ALLOWED_TYPES]
        if invalid:
            raise ValueError(
                f"Unknown MITRE ATLAS category/categories: {invalid}. "
                f"Valid categories are: {self.ALLOWED_TYPES}. "
                "Note: pre-attack, training-time, offline, and adversary-side "
                "tactics (e.g. 'resource_development', 'persistence') are not "
                "prompt-testable and are intentionally not supported."
            )
        self.categories = categories
        self.risk_categories = []
        self.vulnerabilities = []
        self.attacks = []
        for category in categories:
            for risk_category in MITRE_CATEGORIES:
                if risk_category.name == category:
                    self.risk_categories.append(risk_category)
                    self.vulnerabilities.extend(risk_category.vulnerabilities)
                    self.attacks.extend(risk_category.attacks)

    def get_name(self):
        return self.name
