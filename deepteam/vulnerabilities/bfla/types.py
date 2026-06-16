from enum import Enum


class BFLAType(Enum):
    """
    Enum for BFLA (Broken Function Level Authorization) vulnerability types.

    BFLA (OWASP API5:2023) is about the *function/operation itself* being privileged
    or skipping its own authorization check - regardless of the caller's claimed role
    (that is role-assumption -> RBAC) or whose object is touched (that is object-level
    access -> BOLA). Each subtype targets a distinct function-level control failure:

    - FUNCTION_BYPASS: direct invocation of admin/internal/management/maintenance
      functions or restricted endpoints that should be gated for ordinary users.
    - AUTHORIZATION_BYPASS: a function executes even though its own authorization check
      is missing, inconsistent, or skipped - e.g. a write/mutation path callable while
      the matching read is denied, an over-permissioned generic tool, parameter/flag
      scope escalation, or reuse of an already-approved capability.
    - FUNCTION_CHAINING_ESCALATION: chaining individually-authorized functions, or
      pivoting to a broader-privileged sibling function/agent, to reach a privileged
      outcome that no single call would grant.
    - LEGACY_FUNCTION_EXPLOITATION: invoking deprecated/legacy/alternate-version
      functions or undocumented shadow endpoints that predate current authz checks.
    """

    FUNCTION_BYPASS = "function_bypass"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    FUNCTION_CHAINING_ESCALATION = "function_chaining_escalation"
    LEGACY_FUNCTION_EXPLOITATION = "legacy_function_exploitation"


# List of all available types for easy access
BFLA_TYPES = [
    BFLAType.FUNCTION_BYPASS,
    BFLAType.AUTHORIZATION_BYPASS,
    BFLAType.FUNCTION_CHAINING_ESCALATION,
    BFLAType.LEGACY_FUNCTION_EXPLOITATION,
]
