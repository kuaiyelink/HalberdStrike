"""发现/漏洞数据模型"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class FindingType(str, Enum):
    PORT = "port"
    SERVICE = "service"
    VULNERABILITY = "vuln"
    CREDENTIAL = "credential"
    FILE = "file"
    MISC = "misc"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str
    ptt_node_id: Optional[str] = None
    type: FindingType
    severity: Severity = Severity.INFO
    title: str
    description: str = ""
    evidence: str = ""
    cve_id: Optional[str] = None
    remediation: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)
