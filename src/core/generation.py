"""生成模块 - 扮演初级测试员，将子任务转化为可执行命令"""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.llm.base import LLMProvider
from src.llm.context_manager import ContextManager
from src.tools.generic_adapter import get_all_tool_hints
from src.utils.logger import get_logger

logger = get_logger("halberdstrike.core.generation")

PROMPTS_DIR = Path(__file__).parent.parent.parent / "config" / "prompts"


class GenerationModule:
    """生成模块 - CoT任务分解与命令生成

    职责:
    1. 接收推理模块下发的子任务
    2. 通过思维链将任务分解为步骤
    3. 为每个步骤生成精确的终端命令
    """

    SESSION_ID = "generation"

    def __init__(self, provider: LLMProvider, context_manager: ContextManager,
                 target: str):
        self.provider = provider
        self.context = context_manager
        self.target = target
        self._prompt_template = self._load_prompt()
        self._init_session()

    def _load_prompt(self) -> str:
        path = PROMPTS_DIR / "generation_system.txt"
        if path.exists():
            return path.read_text(encoding="utf-8")
        return "你是一位渗透测试执行者。请以JSON格式回复可执行的命令。"

    @staticmethod
    def _detect_os_platform() -> str:
        """检测当前运行环境"""
        if os.name == 'nt':
            return f"Windows ({platform.version()})，命令行使用 cmd/PowerShell，参数必须用双引号"
        return f"Linux ({platform.platform()})，命令行使用 bash"

    def _init_session(self):
        """初始化生成模块会话"""
        tool_hints = get_all_tool_hints()
        system_prompt = (
            self._prompt_template
            .replace("{target}", self.target)
            .replace("{tool_hints}", tool_hints)
            .replace("{os_platform}", self._detect_os_platform())
        )
        self.context.create_session(self.SESSION_ID, system_prompt)
        logger.info(f"生成模块会话已初始化, 目标: {self.target}")

    def generate_commands(self, task_name: str, task_description: str,
                          context_info: str = "") -> Dict[str, Any]:
        """为给定任务生成可执行命令

        Args:
            task_name: 任务名称
            task_description: 任务详细描述
            context_info: 额外上下文信息（如之前的发现）

        Returns:
            包含步骤和命令的字典
        """
        user_msg = f"任务: {task_name}\n描述: {task_description}\n"
        if context_info:
            user_msg += f"\n相关上下文:\n{context_info}\n"
        user_msg += "\n请将此任务分解为具体步骤并生成可执行命令。"

        self.context.add_message(self.SESSION_ID, "user", user_msg)
        messages = self.context.get_messages(self.SESSION_ID)

        result = self.provider.chat_json(messages)
        self.context.add_message(self.SESSION_ID, "assistant", str(result))

        if result.get("parse_error"):
            logger.warning("生成模块返回解析错误，尝试提取命令")
            return self._extract_commands_fallback(result.get("raw_response", ""))

        steps = result.get("steps", [])
        for step in steps:
            if "command" not in step:
                step["command"] = ""
            if "timeout" not in step:
                step["timeout"] = 300
            if "risk_level" not in step:
                step["risk_level"] = "low"

        logger.info(f"生成 {len(steps)} 个执行步骤 for '{task_name}'")
        return result

    def refine_command(self, original_command: str, error_info: str) -> Dict[str, Any]:
        """当命令执行失败时，根据错误信息修正命令

        Args:
            original_command: 原始命令
            error_info: 错误信息

        Returns:
            修正后的命令信息
        """
        user_msg = (
            f"上一条命令执行失败:\n"
            f"命令: {original_command}\n"
            f"错误: {error_info}\n\n"
            f"请分析失败原因并生成修正后的命令。以JSON格式回复:\n"
            f'{{"analysis": "失败原因分析", "corrected_command": "修正后的命令", '
            f'"timeout": 300, "risk_level": "low"}}'
        )

        self.context.add_message(self.SESSION_ID, "user", user_msg)
        messages = self.context.get_messages(self.SESSION_ID)

        result = self.provider.chat_json(messages)
        self.context.add_message(self.SESSION_ID, "assistant", str(result))

        logger.info(f"命令修正完成: {result.get('corrected_command', 'N/A')[:80]}")
        return result

    def _extract_commands_fallback(self, raw: str) -> Dict[str, Any]:
        """从非结构化LLM输出中尽力提取命令"""
        import re
        commands = re.findall(r"`([^`]+)`", raw)
        if not commands:
            commands = re.findall(r"(?:^|\n)\$?\s*((?:nmap|gobuster|nikto|sqlmap|hydra|msfconsole|searchsploit|curl|wget|enum4linux)\s+.+)", raw)

        steps = []
        for i, cmd in enumerate(commands):
            cmd = cmd.strip()
            if cmd and len(cmd) > 3:
                steps.append({
                    "step_number": i + 1,
                    "description": f"执行: {cmd[:50]}",
                    "command": cmd,
                    "timeout": 300,
                    "risk_level": "low",
                    "expected_output": "待确认",
                })

        return {
            "task_understanding": "从非结构化输出中提取命令",
            "steps": steps,
            "notes": "此结果由fallback解析器生成，可能不完整",
        }
