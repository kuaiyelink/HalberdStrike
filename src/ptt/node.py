"""渗透测试任务树 - 节点定义"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class NodeStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class PTTNode(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    name: str
    description: str = ""
    status: NodeStatus = NodeStatus.PENDING
    priority: float = 0.5
    findings: List[str] = Field(default_factory=list)
    parent_id: Optional[str] = None
    children: List["PTTNode"] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # 依赖关系: 只有当 depends_on 列表中的所有节点完成后才可执行
    depends_on: List[str] = Field(default_factory=list)
    # UCB 统计
    attempt_count: int = 0        # 被选中执行的次数
    reward: float = 0.0           # 累计奖励值 (成功+1, 失败-0.5, 发现漏洞+2)

    def add_child(self, child: "PTTNode") -> "PTTNode":
        """添加子节点"""
        child.parent_id = self.id
        self.children.append(child)
        self.updated_at = datetime.now()
        return child

    def is_leaf(self) -> bool:
        """是否为叶节点"""
        return len(self.children) == 0

    def mark_in_progress(self):
        self.status = NodeStatus.IN_PROGRESS
        self.updated_at = datetime.now()

    def mark_completed(self, findings: Optional[List[str]] = None):
        self.status = NodeStatus.COMPLETED
        if findings:
            self.findings.extend(findings)
        self.updated_at = datetime.now()

    def mark_failed(self, reason: str = ""):
        self.status = NodeStatus.FAILED
        if reason:
            self.findings.append(f"[FAILED] {reason}")
        self.updated_at = datetime.now()

    def mark_skipped(self, reason: str = ""):
        self.status = NodeStatus.SKIPPED
        if reason:
            self.findings.append(f"[SKIPPED] {reason}")
        self.updated_at = datetime.now()

    def to_display_str(self, indent: int = 0) -> str:
        """生成树形显示字符串"""
        status_icons = {
            NodeStatus.PENDING: "⏳",
            NodeStatus.IN_PROGRESS: "🔄",
            NodeStatus.COMPLETED: "✅",
            NodeStatus.FAILED: "❌",
            NodeStatus.SKIPPED: "⏭️",
        }
        icon = status_icons.get(self.status, "?")
        prefix = "  " * indent + ("├── " if indent > 0 else "")
        line = f"{prefix}{icon} [{self.id}] {self.name} (pri={self.priority:.1f})"
        lines = [line]

        if self.findings:
            for f in self.findings[-3:]:
                lines.append("  " * (indent + 1) + f"  💡 {f}")

        for child in self.children:
            lines.append(child.to_display_str(indent + 1))

        return "\n".join(lines)

    def to_summary(self, max_depth: int = 3, current_depth: int = 0) -> str:
        """生成供LLM使用的自然语言摘要"""
        if current_depth >= max_depth:
            return f"[{self.id}] {self.name} ({self.status.value})"

        parts = [f"[{self.id}] {self.name} ({self.status.value})"]

        if self.findings:
            recent = self.findings[-3:]
            parts.append(f"  发现: {'; '.join(recent)}")

        for child in self.children:
            child_summary = child.to_summary(max_depth, current_depth + 1)
            for line in child_summary.split("\n"):
                parts.append("  " + line)

        return "\n".join(parts)
