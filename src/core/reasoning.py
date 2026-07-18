"""推理模块 - 扮演渗透测试组长，维护PTT和全局策略"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from src.llm.base import LLMProvider
from src.llm.context_manager import ContextManager
from src.ptt.node import NodeStatus, PTTNode
from src.ptt.tree import PTTree
from src.utils.logger import get_logger

logger = get_logger("halberdstrike.core.reasoning")

PROMPTS_DIR = Path(__file__).parent.parent.parent / "config" / "prompts"


class ReasoningModule:
    """推理模块 - 全局策略与PTT管理

    职责:
    1. 初始化PTT
    2. 根据执行结果更新PTT
    3. 选择下一个最优任务
    4. 判断测试是否完成
    """

    SESSION_ID = "reasoning"

    def __init__(self, provider: LLMProvider, context_manager: ContextManager):
        self.provider = provider
        self.context = context_manager
        self.tree = PTTree()
        self._prompt_template = self._load_prompt()

    def _load_prompt(self) -> str:
        path = PROMPTS_DIR / "reasoning_system.txt"
        if path.exists():
            return path.read_text(encoding="utf-8")
        logger.warning("推理模块prompt文件不存在，使用默认prompt")
        return "你是一位资深渗透测试组长。请以JSON格式回复。"

    def _build_system_prompt(self) -> str:
        """构建当前system prompt（注入PTT状态）"""
        ptt_summary = self.tree.get_tree_summary()
        return self._prompt_template.replace("{ptt_summary}", ptt_summary)

    def init_session(self, target: str) -> PTTNode:
        """初始化推理会话和PTT"""
        self.tree.init_tree(target)
        system_prompt = self._build_system_prompt()
        self.context.create_session(self.SESSION_ID, system_prompt)
        logger.info(f"推理模块会话已初始化, 目标: {target}")
        return self.tree.root

    def load_tree(self, tree: PTTree):
        """从已有PTT恢复"""
        self.tree = tree
        system_prompt = self._build_system_prompt()
        self.context.create_session(self.SESSION_ID, system_prompt)
        logger.info("推理模块已从存档恢复")

    def analyze_and_plan(self, execution_result: str,
                         current_node_id: Optional[str] = None) -> Dict[str, Any]:
        """分析执行结果，更新PTT，规划下一步

        Args:
            execution_result: 解析模块处理后的执行结果摘要
            current_node_id: 当前执行的PTT节点ID

        Returns:
            包含分析结果、新子任务、下一任务等信息的字典
        """
        self.context.update_system_prompt(self.SESSION_ID, self._build_system_prompt())

        user_msg = f"最新执行结果（节点 {current_node_id or '无'}）:\n{execution_result}\n\n"
        user_msg += "请分析当前状态，更新发现，并选择下一个要执行的任务。"

        self.context.add_message(self.SESSION_ID, "user", user_msg)
        messages = self.context.get_messages(self.SESSION_ID)

        result = self.provider.chat_json(messages)
        self.context.add_message(self.SESSION_ID, "assistant", str(result))

        if result.get("parse_error"):
            logger.warning("推理模块返回解析错误，使用默认规划")
            return self._fallback_plan()

        self._apply_reasoning_result(result, current_node_id)

        logger.info(f"推理分析完成: next_task={result.get('next_task_id')}, "
                    f"completed={result.get('is_completed')}")
        return result

    def _apply_reasoning_result(self, result: Dict[str, Any],
                                current_node_id: Optional[str] = None):
        """将推理结果应用到PTT"""
        if current_node_id:
            findings = result.get("updated_findings", [])
            self.tree.update_node(current_node_id, NodeStatus.COMPLETED, findings)

        new_subtasks = result.get("new_subtasks", [])
        if new_subtasks:
            parent_id = result.get("expand_node_id") or current_node_id
            if parent_id:
                self.tree.expand_node(parent_id, new_subtasks)

    def get_next_task(self) -> Optional[PTTNode]:
        """获取下一个待执行的任务"""
        return self.tree.select_next_task()

    def handle_user_guidance(self, guidance: str) -> Dict[str, Any]:
        """处理用户手动指导"""
        self.context.update_system_prompt(self.SESSION_ID, self._build_system_prompt())

        user_msg = (
            f"[人工指导] 测试人员给出了以下指导:\n{guidance}\n\n"
            "请根据此指导更新测试策略和PTT。"
        )
        self.context.add_message(self.SESSION_ID, "user", user_msg)
        messages = self.context.get_messages(self.SESSION_ID)

        result = self.provider.chat_json(messages)
        self.context.add_message(self.SESSION_ID, "assistant", str(result))

        if not result.get("parse_error"):
            self._apply_reasoning_result(result)

        logger.info("已处理用户指导")
        return result

    def _fallback_plan(self) -> Dict[str, Any]:
        """当LLM返回无法解析时的后备规划"""
        next_task = self.tree.select_next_task()
        return {
            "analysis": "LLM分析结果解析失败，使用自动选择策略",
            "updated_findings": [],
            "new_subtasks": [],
            "next_task_id": next_task.id if next_task else None,
            "next_task_description": next_task.name if next_task else "无待执行任务",
            "reasoning": "自动选择优先级最高的待执行任务",
            "is_completed": next_task is None,
        }

    def is_test_completed(self) -> bool:
        """检查测试是否完成"""
        return self.tree.is_completed()
