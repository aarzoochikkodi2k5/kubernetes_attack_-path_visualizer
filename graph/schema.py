# graph/schema.py

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum

class EntityType(str, Enum):
    USER             = "User"
    POD              = "Pod"
    SERVICE_ACCOUNT  = "ServiceAccount"
    ROLE             = "Role"
    CLUSTER_ROLE     = "ClusterRole"
    SECRET           = "Secret"
    DATABASE         = "Database"
    CONFIG_MAP       = "ConfigMap"
    NAMESPACE        = "Namespace"
    LOAD_BALANCER    = "LoadBalancer"

class RelationshipType(str, Enum):
    USES             = "uses"             # Pod uses ServiceAccount
    BOUND_TO         = "bound_to"         # ServiceAccount bound to Role
    CAN_READ         = "can_read"         # Role can_read Secret
    CAN_WRITE        = "can_write"
    CAN_EXEC         = "can_exec"         # exec into pod (high risk)
    EXPOSES          = "exposes"          # LoadBalancer exposes Pod
    MOUNTS           = "mounts"          # Pod mounts Secret
    IMPERSONATES     = "impersonates"     # ServiceAccount impersonates User

@dataclass
class NodeData:
    entity_type:   EntityType
    name:          str
    namespace:     str
    risk_score:    float                  # 0.0 - 10.0
    is_crown_jewel: bool = False
    is_entry_point: bool = False
    cves:          List[str] = field(default_factory=list)
    labels:        Dict[str, str] = field(default_factory=dict)
    metadata:      Dict[str, Any] = field(default_factory=dict)

@dataclass
class EdgeData:
    relationship:       RelationshipType
    weight:             float             # exploitability score (lower = easier to exploit)
    cvss_score:         float = 0.0
    is_misconfigured:   bool = False
    metadata:           Dict[str, Any] = field(default_factory=dict)