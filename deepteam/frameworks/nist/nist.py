from typing import List, Literal
from deepteam.frameworks import AISafetyFramework
from deepteam.vulnerabilities import BaseVulnerability
from deepteam.attacks import BaseAttack
from deepteam.frameworks.nist.risk_categories import NIST_CATEGORIES

"""
NIST AI Risk Management Framework (AI RMF) 1.0
===============================================

The NIST AI Risk Management Framework (AI RMF) is a structured methodology from the U.S. National
Institute of Standards and Technology that guides organizations in identifying, evaluating, and
mitigating risks in artificial intelligence systems. It promotes trustworthy AI by focusing on
governance, measurement, and continuous risk tracking across the AI lifecycle.

DeepTeam's implementation maps the project's curated, judge-backed vulnerabilities and attacks onto
the prompt-testable slice of the MEASURE function, one category per NIST AI RMF MEASURE subcategory
(mirroring the MITRE ATLAS module's one-tactic-per-category design) so each generated test case
traces back to a real MEASURE subcategory id.

The eight prompt-testable MEASURE categories:
- measurement_methods (MEASURE 1): independent assessment, metric selection & validation
- validity_reliability (MEASURE 2.5): valid & reliable — hijacking, over-reliance, confabulation
- safety (MEASURE 2.6): safe — physical harm, illegal activity, graphic content, minor protection
- security_resilience (MEASURE 2.7): secure & resilient — the broad security red-team surface
- privacy (MEASURE 2.10): privacy-enhanced — direct, oblique, and cross-tenant data disclosure
- fairness_bias (MEASURE 2.11): fair with harmful bias managed
- emergent_risk (MEASURE 3): emergent & hard-to-measure agentic risk tracking
- impact_transparency (MEASURE 4): impact, transparency & business outcomes

Governance (GOVERN/MAP/MANAGE) and offline or process-only MEASURE subcategories are out of scope
for live-prompt testing; see risk_categories.py for the per-category source-of-truth ids.

Each category includes:
- Attacks: techniques for testing AI system resilience and detecting vulnerabilities
- Vulnerabilities: weaknesses that can be exploited in AI systems

Reference: https://www.nist.gov/itl/ai-risk-management-framework
"""

_NIST_CATEGORY_NAMES = [
    "measurement_methods",
    "validity_reliability",
    "safety",
    "security_resilience",
    "privacy",
    "fairness_bias",
    "emergent_risk",
    "impact_transparency",
]


class NIST(AISafetyFramework):
    name = "NIST AI Risk Management Framework (AI RMF)"
    description = "A structured methodology from NIST (AI RMF 1.0) for identifying, evaluating, and mitigating risks in AI systems. DeepTeam's implementation maps curated, judge-backed vulnerabilities and attacks onto the prompt-testable slice of the MEASURE function, pinning each category to a NIST AI RMF MEASURE subcategory: measurement methods & independent assessment (MEASURE 1), the trustworthy characteristics valid & reliable (MEASURE 2.5), safe (MEASURE 2.6), secure & resilient (MEASURE 2.7), privacy-enhanced (MEASURE 2.10) and fair with harmful bias managed (MEASURE 2.11), emergent & hard-to-measure risk tracking (MEASURE 3), and impact, transparency & business outcomes (MEASURE 4). Governance and offline or process-only subcategories are out of scope for live-prompt testing."
    ALLOWED_TYPES = list(_NIST_CATEGORY_NAMES)

    def __init__(
        self,
        categories: List[
            Literal[
                "measurement_methods",
                "validity_reliability",
                "safety",
                "security_resilience",
                "privacy",
                "fairness_bias",
                "emergent_risk",
                "impact_transparency",
            ]
        ] = list(_NIST_CATEGORY_NAMES),
    ):
        invalid = [c for c in categories if c not in self.ALLOWED_TYPES]
        if invalid:
            raise ValueError(
                f"Unknown NIST AI RMF category/categories: {invalid}. "
                f"Valid categories are: {self.ALLOWED_TYPES}. "
                "Note: governance (GOVERN/MAP/MANAGE) and offline or "
                "process-only MEASURE subcategories are not prompt-testable "
                "and are intentionally not supported."
            )
        self.categories = categories
        self.risk_categories = []
        self.vulnerabilities = []
        self.attacks = []
        for category in categories:
            for risk_category in NIST_CATEGORIES:
                if risk_category.name == category:
                    self.risk_categories.append(risk_category)
                    self.vulnerabilities.extend(risk_category.vulnerabilities)
                    self.attacks.extend(risk_category.attacks)

    def get_name(self):
        return self.name
