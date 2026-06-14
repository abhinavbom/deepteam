from typing import List, Optional
from deepteam.vulnerabilities import (
    BaseVulnerability,
)
from deepteam.attacks import BaseAttack
from dataclasses import dataclass


@dataclass
class RiskCategory:
    name: str
    vulnerabilities: List[BaseVulnerability]
    attacks: List[BaseAttack]
    description: Optional[str] = None
    _display_name: Optional[str] = None
    # Optional traceability back to an external taxonomy (e.g. MITRE ATLAS).
    # tactic_id is the parent tactic (e.g. "AML.TA0005"); technique_ids are
    # the specific techniques exercised by this category (e.g. ["AML.T0050"]).
    tactic_id: Optional[str] = None
    technique_ids: Optional[List[str]] = None
