"""解析模块 - 处理工具输出、网页内容、源码的解析与总结"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from src.llm.base import LLMProvider
from src.llm.context_manager import ContextManager
from src.utils.logger import get_logger

logger = get_logger("halberdstrike.core.parsing")

PROMPTS_DIR = Path(__file__).parent.parent.parent / "config" / "prompts"


class ParsingModule:
    """解析模块 - 信息提取与总结

    职责:
    1. 解析安全工具输出，提取关键信息
    2. 分析网页内容，识别技术栈和漏洞
    3. 审计源代码，发现安全问题
    4. 将冗长输出总结为简洁摘要
    """

    SESSION_ID = "parsing"

    def __init__(self, provider: LLMProvider, context_manager: ContextManager):
        self.provider = provider
        self.context = context_manager
        self._prompts = self._load_prompts()
        self.context.create_session(
            self.SESSION_ID,
            "你是一位渗透测试分析师，负责解析和总结各类安全测试输出。请始终以JSON格式回复。"
        )
        logger.info("解析模块已初始化")

    def _load_prompts(self) -> Dict[str, str]:
        prompts = {}
        for name in ["parsing_tool", "parsing_web", "parsing_code"]:
            path = PROMPTS_DIR / f"{name}.txt"
            if path.exists():
                prompts[name] = path.read_text(encoding="utf-8")
            else:
                prompts[name] = ""
        return prompts

    def parse_tool_output(self, tool_name: str, command: str,
                          raw_output: str) -> Dict[str, Any]:
        """解析安全工具的原始输出

        Args:
            tool_name: 工具名称
            command: 执行的命令
            raw_output: 原始输出文本

        Returns:
            结构化的解析结果
        """
        truncated = self._truncate(raw_output, max_chars=6000)

        prompt = self._prompts.get("parsing_tool", "")
        if prompt:
            user_msg = (
                prompt
                .replace("{tool_name}", tool_name)
                .replace("{command}", command)
                .replace("{raw_output}", truncated)
            )
        else:
            user_msg = (
                f"解析以下{tool_name}输出，提取关键发现:\n"
                f"命令: {command}\n"
                f"输出:\n{truncated}\n\n"
                f"以JSON格式回复，包含: key_findings, summary"
            )

        self.context.add_message(self.SESSION_ID, "user", user_msg)
        messages = self.context.get_messages(self.SESSION_ID)
        result = self.provider.chat_json(messages)

        if result.get("parse_error"):
            # 不将解析失败的原始内容存入会话，避免上下文污染
            clean_summary = f"{tool_name} 执行完成，输出 {len(raw_output)} 字符"
            self.context.add_message(self.SESSION_ID, "assistant",
                                     f'{{"summary": "{clean_summary}", "key_findings": ["{tool_name} 输出需要人工分析"]}}')
            result = {
                "key_findings": [f"{tool_name} 输出需要人工分析"],
                "summary": clean_summary,
            }
        else:
            self.context.add_message(self.SESSION_ID, "assistant", str(result))

        logger.info(f"工具输出解析完成: {result.get('summary', 'N/A')[:80]}")
        return result

    def parse_web_content(self, url: str, status_code: int,
                          content: str) -> Dict[str, Any]:
        """解析网页内容"""
        truncated = self._truncate(content, max_chars=6000)

        prompt = self._prompts.get("parsing_web", "")
        if prompt:
            user_msg = (
                prompt
                .replace("{url}", url)
                .replace("{status_code}", str(status_code))
                .replace("{content}", truncated)
            )
        else:
            user_msg = (
                f"分析以下网页内容:\nURL: {url}\n状态码: {status_code}\n"
                f"内容:\n{truncated}\n\n以JSON格式回复关键发现。"
            )

        self.context.add_message(self.SESSION_ID, "user", user_msg)
        messages = self.context.get_messages(self.SESSION_ID)
        result = self.provider.chat_json(messages)
        self.context.add_message(self.SESSION_ID, "assistant", str(result))

        logger.info(f"网页解析完成: {url}")
        return result

    def parse_source_code(self, filename: str, content: str) -> Dict[str, Any]:
        """审计源代码安全"""
        truncated = self._truncate(content, max_chars=6000)

        prompt = self._prompts.get("parsing_code", "")
        if prompt:
            user_msg = (
                prompt
                .replace("{filename}", filename)
                .replace("{content}", truncated)
            )
        else:
            user_msg = (
                f"审计以下代码的安全问题:\n文件: {filename}\n"
                f"代码:\n{truncated}\n\n以JSON格式回复安全发现。"
            )

        self.context.add_message(self.SESSION_ID, "user", user_msg)
        messages = self.context.get_messages(self.SESSION_ID)
        result = self.provider.chat_json(messages)
        self.context.add_message(self.SESSION_ID, "assistant", str(result))

        logger.info(f"源码审计完成: {filename}")
        return result

    def summarize(self, text: str, context: str = "") -> str:
        """通用文本总结"""
        truncated = self._truncate(text, max_chars=4000)
        user_msg = f"请用2-3句话总结以下内容的关键信息:\n"
        if context:
            user_msg += f"上下文: {context}\n"
        user_msg += f"\n{truncated}"

        self.context.add_message(self.SESSION_ID, "user", user_msg)
        messages = self.context.get_messages(self.SESSION_ID)
        result = self.provider.chat(messages)
        self.context.add_message(self.SESSION_ID, "assistant", result)

        return result.strip()

    def _truncate(self, text: str, max_chars: int = 4000) -> str:
        """截断长文本，保留首尾"""
        if len(text) <= max_chars:
            return text
        half = max_chars // 2
        return (
            text[:half]
            + f"\n\n... [内容截断, 原始长度 {len(text)} 字符] ...\n\n"
            + text[-half:]
        )
