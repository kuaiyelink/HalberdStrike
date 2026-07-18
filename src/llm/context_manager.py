"""LLM 上下文窗口管理"""

from __future__ import annotations

from typing import Dict, List, Optional

from src.llm.base import LLMProvider
from src.utils.logger import get_logger

logger = get_logger("halberdstrike.llm.context")


class ContextManager:
    """管理每个模块的独立会话上下文

    策略:
    - 每个模块维护独立消息历史
    - 超过token限制时，先将旧消息压缩为摘要再裁剪
    - 始终保留system prompt + 摘要 + 最近N轮对话
    """

    SUMMARY_MARKER = "[CONTEXT_SUMMARY]"

    def __init__(self, provider: LLMProvider, max_context_ratio: float = 0.7,
                 use_llm_summary: bool = True):
        self.provider = provider
        self.max_tokens = int(provider.context_window * max_context_ratio)
        self.use_llm_summary = use_llm_summary
        self._sessions: Dict[str, List[Dict[str, str]]] = {}

    def create_session(self, session_id: str, system_prompt: str):
        """创建新会话"""
        self._sessions[session_id] = [
            {"role": "system", "content": system_prompt}
        ]
        logger.debug(f"会话已创建: {session_id}")

    def get_session(self, session_id: str) -> Optional[List[Dict[str, str]]]:
        """获取会话消息列表"""
        return self._sessions.get(session_id)

    def add_message(self, session_id: str, role: str, content: str):
        """添加消息到会话"""
        if session_id not in self._sessions:
            logger.warning(f"会话不存在: {session_id}")
            return

        self._sessions[session_id].append({"role": role, "content": content})
        self._trim_if_needed(session_id)

    def update_system_prompt(self, session_id: str, system_prompt: str):
        """更新会话的system prompt（用于注入最新PTT摘要）"""
        if session_id not in self._sessions:
            return
        messages = self._sessions[session_id]
        if messages and messages[0]["role"] == "system":
            messages[0]["content"] = system_prompt
        else:
            messages.insert(0, {"role": "system", "content": system_prompt})

    def get_messages(self, session_id: str) -> List[Dict[str, str]]:
        """获取当前会话的完整消息列表"""
        return self._sessions.get(session_id, [])

    def clear_session(self, session_id: str):
        """清空会话（保留system prompt）"""
        if session_id not in self._sessions:
            return
        messages = self._sessions[session_id]
        if messages and messages[0]["role"] == "system":
            self._sessions[session_id] = [messages[0]]
        else:
            self._sessions[session_id] = []

    def _trim_if_needed(self, session_id: str):
        """当token超限时，将旧消息压缩为摘要而非直接丢弃"""
        messages = self._sessions[session_id]
        total_text = " ".join(m["content"] for m in messages)
        token_count = self.provider.get_token_count(total_text)

        if token_count <= self.max_tokens:
            return

        system_msg = messages[0] if messages[0]["role"] == "system" else None
        history = messages[1:] if system_msg else messages[:]

        # 找到已有的摘要消息位置
        existing_summary_idx = -1
        for i, m in enumerate(history):
            if m["role"] == "system" and self.SUMMARY_MARKER in m["content"]:
                existing_summary_idx = i
                break

        # 保留最近 keep_recent 轮对话，将更早的压缩
        keep_recent = 6  # 保留最近3轮 user+assistant 对话
        if len(history) <= keep_recent:
            # 消息太少无法压缩，回退到简单裁剪
            while token_count > self.max_tokens and len(history) > 2:
                history.pop(0)
                total_text = " ".join(
                    m["content"] for m in ([system_msg] if system_msg else []) + history
                )
                token_count = self.provider.get_token_count(total_text)
            self._sessions[session_id] = ([system_msg] if system_msg else []) + history
            logger.debug(f"会话 {session_id} 已裁剪(回退), 剩余: {len(self._sessions[session_id])}")
            return

        # 提取要压缩的旧消息
        old_messages = history[:-keep_recent]
        recent_messages = history[-keep_recent:]

        # 构建压缩用的文本
        old_text_parts = []
        existing_summary = ""
        for m in old_messages:
            if m["role"] == "system" and self.SUMMARY_MARKER in m["content"]:
                existing_summary = m["content"].replace(self.SUMMARY_MARKER, "").strip()
                continue
            prefix = "USER" if m["role"] == "user" else "AI"
            # 截取每条消息的关键信息
            content = m["content"][:800] if len(m["content"]) > 800 else m["content"]
            old_text_parts.append(f"[{prefix}] {content}")

        if not old_text_parts and not existing_summary:
            # 没有可压缩内容，简单裁剪
            self._sessions[session_id] = ([system_msg] if system_msg else []) + recent_messages
            return

        # 如果关闭 LLM 摘要，直接裁剪旧消息保留最近对话
        if not self.use_llm_summary:
            self._sessions[session_id] = ([system_msg] if system_msg else []) + recent_messages
            logger.debug(f"会话 {session_id} 已裁剪(快速模式), 剩余: {len(self._sessions[session_id])}")
            return

        old_dialogue = "\n".join(old_text_parts)
        compress_prompt = (
            f"以下是之前的对话历史。请提取关键信息（发现的端口/服务/漏洞/凭据/关键结果）"
            f"压缩为简洁的摘要，不超过500字。\n\n"
        )
        if existing_summary:
            compress_prompt += f"已有摘要:\n{existing_summary}\n\n新増对话:\n"
        compress_prompt += old_dialogue

        try:
            summary = self.provider.chat(
                [{"role": "user", "content": compress_prompt}],
                temperature=0.1,
                max_tokens=600,
            )
        except Exception as e:
            logger.warning(f"上下文压缩失败: {e}，回退到简单裁剪")
            self._sessions[session_id] = ([system_msg] if system_msg else []) + recent_messages
            return

        summary_msg = {
            "role": "system",
            "content": f"{self.SUMMARY_MARKER}\n历史摘要:\n{summary.strip()}"
        }

        self._sessions[session_id] = (
            ([system_msg] if system_msg else [])
            + [summary_msg]
            + recent_messages
        )

        new_total = " ".join(m["content"] for m in self._sessions[session_id])
        new_count = self.provider.get_token_count(new_total)
        logger.info(
            f"会话 {session_id} 已压缩: {token_count} -> {new_count} tokens, "
            f"消息 {len(messages)} -> {len(self._sessions[session_id])}"
        )
