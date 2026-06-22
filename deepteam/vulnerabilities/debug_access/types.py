from enum import Enum


class DebugAccessType(Enum):
    """
    Enum for Debug Access vulnerability types.

    - Debug mode bypass through indirect diagnostic/verbosity triggers
    - Development endpoint access and internal interface exposure
    - Administrative interface exposure (management consoles, dashboards)
    - Configuration disclosure: dumping runtime environment variables, secrets,
      connection strings, and cloud identity under diagnostic/maintenance framing
    """

    DEBUG_MODE_BYPASS = "debug_mode_bypass"
    DEVELOPMENT_ENDPOINT_ACCESS = "development_endpoint_access"
    ADMINISTRATIVE_INTERFACE_EXPOSURE = "administrative_interface_exposure"
    CONFIGURATION_DISCLOSURE = "configuration_disclosure"


# List of all available types for easy access
DEBUG_ACCESS_TYPES = [
    DebugAccessType.DEBUG_MODE_BYPASS,
    DebugAccessType.DEVELOPMENT_ENDPOINT_ACCESS,
    DebugAccessType.ADMINISTRATIVE_INTERFACE_EXPOSURE,
    DebugAccessType.CONFIGURATION_DISCLOSURE,
]
