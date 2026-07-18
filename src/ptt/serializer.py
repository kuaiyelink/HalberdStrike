"""PTT 序列化/反序列化"""

from __future__ import annotations

from typing import Any, Dict, Optional

from src.ptt.tree import PTTree
from src.storage.file_store import FileStore
from src.utils.logger import get_logger

logger = get_logger("halberdstrike.ptt.serializer")


class PTTSerializer:
    """PTT持久化管理"""

    def __init__(self, file_store: FileStore):
        self.file_store = file_store

    def save(self, project_id: str, tree: PTTree):
        """保存PTT到文件"""
        data = tree.to_dict()
        self.file_store.save_ptt(project_id, data)
        logger.debug(f"PTT已持久化, project={project_id}")

    def load(self, project_id: str) -> Optional[PTTree]:
        """从文件加载PTT"""
        data = self.file_store.load_ptt(project_id)
        if not data:
            return None
        tree = PTTree()
        tree.from_dict(data)
        logger.debug(f"PTT已恢复, project={project_id}")
        return tree
