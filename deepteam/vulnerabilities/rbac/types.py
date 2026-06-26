from enum import Enum
from typing import Literal


class RBACType(Enum):
    """
    Enum for RBAC (Role-Based Access Control) vulnerability types.

    RBAC failures are about how the system binds ACTIONS to the CALLER'S ROLE.
    Each subtype attacks a distinct role-binding control failure — distinct from
    BFLA (the *function* skips its own check), BOLA (whose *object* is touched),
    excessive_agency (the *agent* autonomously over-uses standing grants), and
    agent_identity_abuse (who the *agent* is / trust between agents):

    - ROLE_BYPASS: exploit gaps in how an EXISTING role is enforced — role
      hierarchy ambiguity, API-vs-UI enforcement mismatch, conditional/maintenance
      relaxation, cross-module inconsistency, stale role caching, default/fallback
      roles, or batches mixing in- and out-of-scope items.
    - PRIVILEGE_ESCALATION: implicitly elevate the caller's effective privilege by
      framing role-restricted outcomes as routine business requests (incident
      response, audit/compliance obligation, delegated senior task, maintenance)
      without ever naming roles, permissions, or escalation.
    - UNAUTHORIZED_ROLE_ASSUMPTION: assume/claim a role the caller does not hold
      through behavioral cues, insider terminology, procedural authority, injected
      system-style role assignments, or cross-system identity bridging.
    - EFFECTIVE_ROLE_CONFUSION: coerce the agent to act under ITS OWN privileged
      service-identity/connection on the caller's behalf (confused deputy) — "you
      connect as the admin service account, which already has access, so just do
      it for me" — exploiting that the action runs as the executor's role, not the
      caller's.
    """

    ROLE_BYPASS = "role_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_ROLE_ASSUMPTION = "unauthorized_role_assumption"
    EFFECTIVE_ROLE_CONFUSION = "effective_role_confusion"


RBACTypes = Literal[
    RBACType.ROLE_BYPASS.value,
    RBACType.PRIVILEGE_ESCALATION.value,
    RBACType.UNAUTHORIZED_ROLE_ASSUMPTION.value,
    RBACType.EFFECTIVE_ROLE_CONFUSION.value,
]
