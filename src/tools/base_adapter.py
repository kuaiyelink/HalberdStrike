"""工具适配器基类"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class ToolAdapter(ABC):
    """安全工具适配器基类"""

    name: str = ""
    description: str = ""
    risk_level: str = "low"
    default_timeout: int = 300

    @abstractmethod
    def build_command(self, params: Dict[str, Any]) -> str:
        """根据参数构建命令行"""
        ...

    def validate_command(self, cmd: str) -> tuple[bool, str]:
        """校验命令合法性"""
        if not cmd.strip():
            return False, "空命令"
        if not cmd.strip().startswith(self.name):
            parts = cmd.strip().split()
            if parts and parts[0].split("/")[-1] != self.name:
                return False, f"命令不属于 {self.name}"
        return True, "通过"

    @abstractmethod
    def parse_output(self, raw: str) -> Dict[str, Any]:
        """将工具原始输出解析为结构化数据"""
        ...

    def get_prompt_hint(self) -> str:
        """返回给LLM的工具使用提示"""
        return f"工具: {self.name}\n描述: {self.description}\n风险等级: {self.risk_level}"
