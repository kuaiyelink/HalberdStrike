"""操作日志数据模型"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ModuleType(str, Enum):
    REASONING = "reasoning"
    GENERATION = "generation"
    PARSING = "parsing"


class ActionType(str, Enum):
    LLM_CALL = "llm_call"
    TOOL_EXEC = "tool_exec"
    USER_INPUT = "user_input"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ApprovalSource(str, Enum):
    AUTO = "auto"
    USER = "user"


class ActionLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str
    ptt_node_id: Optional[str] = None
    module: ModuleType
    action_type: ActionType
    command: Optional[str] = None
    raw_output: str = ""
    parsed_result: Dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.LOW
    approved_by: ApprovalSource = ApprovalSource.AUTO
    timestamp: datetime = Field(default_factory=datetime.now)
    duration_seconds: float = 0.0
