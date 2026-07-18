"""文件存储 - PTT JSON、报告等"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from src.utils.logger import get_logger

logger = get_logger("halberdstrike.filestore")


class FileStore:
    """文件系统存储管理"""

    def __init__(self, projects_dir: str, reports_dir: str):
        self.projects_dir = Path(projects_dir)
        self.reports_dir = Path(reports_dir)
        self.projects_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def _project_path(self, project_id: str) -> Path:
        p = self.projects_dir / project_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    def save_ptt(self, project_id: str, ptt_data: Dict[str, Any]):
        """保存PTT到JSON文件"""
        path = self._project_path(project_id) / "ptt.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(ptt_data, f, ensure_ascii=False, indent=2, default=str)
        logger.debug(f"PTT已保存: {path}")

    def load_ptt(self, project_id: str) -> Optional[Dict[str, Any]]:
        """从JSON文件加载PTT"""
        path = self._project_path(project_id) / "ptt.json"
        if not path.exists():
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_report(self, project_id: str, filename: str, content: str):
        """保存渗透测试报告"""
        report_dir = self.reports_dir / project_id
        report_dir.mkdir(parents=True, exist_ok=True)
        path = report_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info(f"报告已保存: {path}")
        return str(path)

    def save_tool_output(self, project_id: str, filename: str, content: str):
        """保存工具原始输出"""
        output_dir = self._project_path(project_id) / "outputs"
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return str(path)
