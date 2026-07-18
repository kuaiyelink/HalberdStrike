"""SQLite 数据库操作"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.models.action_log import ActionLog
from src.models.finding import Finding
from src.models.project import Project
from src.utils.logger import get_logger

logger = get_logger("halberdstrike.storage")


class Database:
    """SQLite 数据库管理"""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path).expanduser()
        self.conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()

    def connect(self):
        self.db_path = self.db_path.expanduser()
        parent = self.db_path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise OSError(
                f"无法创建数据库目录: {parent} ({e})"
            ) from e
        if not parent.is_dir():
            raise FileNotFoundError(f"数据库路径的父目录不存在: {parent}")
        if not os.access(parent, os.W_OK):
            raise PermissionError(f"数据库目录不可写: {parent}")

        try:
            self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        except sqlite3.OperationalError as e:
            raise sqlite3.OperationalError(
                f"{e} (数据库文件: {self.db_path.resolve()})"
            ) from e

        self.conn.row_factory = sqlite3.Row
        # 启用 WAL 模式：提升并发读写性能（部分网络盘/特殊挂载会失败，回退 DELETE）
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError:
            logger.warning("WAL 模式不可用，已回退为 DELETE journal: %s", self.db_path)
            self.conn.execute("PRAGMA journal_mode=DELETE")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-8000")  # 8MB cache
        self._create_tables()
        self._create_indexes()
        logger.info(f"数据库已连接(WAL): {self.db_path}")

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def _create_tables(self):
        if self.conn is None:
            raise RuntimeError("数据库未连接，请先调用 connect()")
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target TEXT NOT NULL,
                scope TEXT DEFAULT '[]',
                status TEXT DEFAULT 'active',
                created_at TEXT,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS action_logs (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                ptt_node_id TEXT,
                module TEXT NOT NULL,
                action_type TEXT NOT NULL,
                command TEXT,
                raw_output TEXT DEFAULT '',
                parsed_result TEXT DEFAULT '{}',
                risk_level TEXT DEFAULT 'low',
                approved_by TEXT DEFAULT 'auto',
                timestamp TEXT,
                duration_seconds REAL DEFAULT 0.0,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                ptt_node_id TEXT,
                type TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                evidence TEXT DEFAULT '',
                cve_id TEXT,
                remediation TEXT DEFAULT '',
                timestamp TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            );
        """)
        self.conn.commit()

    def _create_indexes(self):
        """创建索引加速常用查询"""
        if self.conn is None:
            return
        self.conn.executescript("""
            CREATE INDEX IF NOT EXISTS idx_action_logs_project
                ON action_logs(project_id, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_findings_project
                ON findings(project_id, severity);
            CREATE INDEX IF NOT EXISTS idx_findings_dedup
                ON findings(project_id, type, title);
            CREATE INDEX IF NOT EXISTS idx_action_logs_node
                ON action_logs(ptt_node_id);
        """)
        self.conn.commit()

    # ── Project CRUD ──

    def save_project(self, project: Project):
        if self.conn is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            self.conn.execute(
                """INSERT OR REPLACE INTO projects
                   (id, name, target, scope, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    project.id, project.name, project.target,
                    json.dumps(project.scope), project.status.value,
                    project.created_at.isoformat(), project.updated_at.isoformat(),
                ),
            )
            self.conn.commit()

    def get_project(self, project_id: str) -> Optional[Project]:
        if self.conn is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM projects WHERE id = ?", (project_id,)
            ).fetchone()
        if not row:
            return None
        return Project(
            id=row["id"], name=row["name"], target=row["target"],
            scope=json.loads(row["scope"]), status=row["status"],
            created_at=row["created_at"], updated_at=row["updated_at"],
        )

    def list_projects(self) -> List[Project]:
        if self.conn is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM projects ORDER BY updated_at DESC"
            ).fetchall()
        return [
            Project(
                id=r["id"], name=r["name"], target=r["target"],
                scope=json.loads(r["scope"]), status=r["status"],
                created_at=r["created_at"], updated_at=r["updated_at"],
            )
            for r in rows
        ]

    # ── ActionLog CRUD ──

    def save_action_log(self, log: ActionLog):
        if self.conn is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            self.conn.execute(
                """INSERT INTO action_logs
                   (id, project_id, ptt_node_id, module, action_type, command,
                    raw_output, parsed_result, risk_level, approved_by,
                    timestamp, duration_seconds)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    log.id, log.project_id, log.ptt_node_id,
                    log.module.value, log.action_type.value, log.command,
                    log.raw_output, json.dumps(log.parsed_result),
                    log.risk_level.value, log.approved_by.value,
                    log.timestamp.isoformat(), log.duration_seconds,
                ),
            )
            self.conn.commit()

    def get_action_logs(self, project_id: str, limit: int = 50) -> List[ActionLog]:
        if self.conn is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM action_logs WHERE project_id = ? ORDER BY timestamp DESC LIMIT ?",
                (project_id, int(limit)),
            ).fetchall()
        return [
            ActionLog(
                id=r["id"], project_id=r["project_id"],
                ptt_node_id=r["ptt_node_id"], module=r["module"],
                action_type=r["action_type"], command=r["command"],
                raw_output=r["raw_output"],
                parsed_result=json.loads(r["parsed_result"]),
                risk_level=r["risk_level"], approved_by=r["approved_by"],
                timestamp=r["timestamp"], duration_seconds=r["duration_seconds"],
            )
            for r in rows
        ]

    # ── Finding CRUD ──

    def save_finding(self, finding: Finding):
        """保存发现（自动去重：同项目+同类型+同标题视为重复）"""
        if self.conn is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            existing = self.conn.execute(
                "SELECT id FROM findings WHERE project_id = ? AND type = ? AND title = ?",
                (finding.project_id, finding.type.value, finding.title),
            ).fetchone()
            if existing:
                logger.debug(f"发现去重跳过: {finding.title[:60]}")
                return
            self.conn.execute(
                """INSERT INTO findings
                   (id, project_id, ptt_node_id, type, severity, title,
                    description, evidence, cve_id, remediation, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.id, finding.project_id, finding.ptt_node_id,
                    finding.type.value, finding.severity.value, finding.title,
                    finding.description, finding.evidence, finding.cve_id,
                    finding.remediation, finding.timestamp.isoformat(),
                ),
            )
            self.conn.commit()

    def save_findings_batch(self, findings: List[Finding]):
        """批量保存发现（去重 + 单次事务提交）"""
        if self.conn is None:
            raise RuntimeError("数据库未连接")
        if not findings:
            return
        with self._lock:
            inserted = 0
            for f in findings:
                existing = self.conn.execute(
                    "SELECT id FROM findings WHERE project_id = ? AND type = ? AND title = ?",
                    (f.project_id, f.type.value, f.title),
                ).fetchone()
                if existing:
                    continue
                self.conn.execute(
                    """INSERT INTO findings
                       (id, project_id, ptt_node_id, type, severity, title,
                        description, evidence, cve_id, remediation, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        f.id, f.project_id, f.ptt_node_id,
                        f.type.value, f.severity.value, f.title,
                        f.description, f.evidence, f.cve_id,
                        f.remediation, f.timestamp.isoformat(),
                    ),
                )
                inserted += 1
            self.conn.commit()
            logger.debug(f"批量保存发现: {inserted}/{len(findings)} 条(去重后)")

    def save_action_logs_batch(self, logs: List[ActionLog]):
        """批量保存操作日志（单次事务提交）"""
        if self.conn is None:
            raise RuntimeError("数据库未连接")
        if not logs:
            return
        with self._lock:
            self.conn.executemany(
                """INSERT INTO action_logs
                   (id, project_id, ptt_node_id, module, action_type, command,
                    raw_output, parsed_result, risk_level, approved_by,
                    timestamp, duration_seconds)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        log.id, log.project_id, log.ptt_node_id,
                        log.module.value, log.action_type.value, log.command,
                        log.raw_output, json.dumps(log.parsed_result),
                        log.risk_level.value, log.approved_by.value,
                        log.timestamp.isoformat(), log.duration_seconds,
                    )
                    for log in logs
                ],
            )
            self.conn.commit()
            logger.debug(f"批量保存日志: {len(logs)} 条")

    def delete_project(self, project_id: str):
        """删除项目及其关联数据"""
        if self.conn is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            self.conn.execute("DELETE FROM findings WHERE project_id = ?", (project_id,))
            self.conn.execute("DELETE FROM action_logs WHERE project_id = ?", (project_id,))
            self.conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            self.conn.commit()
        logger.info(f"项目已删除: {project_id}")

    def get_findings(self, project_id: str) -> List[Finding]:
        if self.conn is None:
            raise RuntimeError("数据库未连接")
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE project_id = ? ORDER BY severity, timestamp",
                (project_id,),
            ).fetchall()
        return [
            Finding(
                id=r["id"], project_id=r["project_id"],
                ptt_node_id=r["ptt_node_id"], type=r["type"],
                severity=r["severity"], title=r["title"],
                description=r["description"], evidence=r["evidence"],
                cve_id=r["cve_id"], remediation=r["remediation"],
                timestamp=r["timestamp"],
            )
            for r in rows
        ]
