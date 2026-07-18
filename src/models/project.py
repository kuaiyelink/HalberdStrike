"""项目/会话数据模型"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class ProjectStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"


class Project(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    target: str
    scope: List[str] = Field(default_factory=list)
    status: ProjectStatus = ProjectStatus.ACTIVE
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    def pause(self):
        self.status = ProjectStatus.PAUSED
        self.updated_at = datetime.now()

    def resume(self):
        self.status = ProjectStatus.ACTIVE
        self.updated_at = datetime.now()

    def complete(self):
        self.status = ProjectStatus.COMPLETED
        self.updated_at = datetime.now()
