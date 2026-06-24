from enum import Enum
from typing import Literal


class CrossContextRetrievalType(Enum):
    TENANT = "tenant"
    USER = "user"
    ROLE = "role"
    AGGREGATION = "aggregation"


CrossContextRetrievalTypes = Literal[
    CrossContextRetrievalType.TENANT.value,
    CrossContextRetrievalType.USER.value,
    CrossContextRetrievalType.ROLE.value,
    CrossContextRetrievalType.AGGREGATION.value,
]
