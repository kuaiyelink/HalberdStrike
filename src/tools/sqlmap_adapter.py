"""SQLMap 工具适配器"""

from __future__ import annotations

import re
from typing import Any, Dict

from src.tools.base_adapter import ToolAdapter


class SqlmapAdapter(ToolAdapter):
    name = "sqlmap"
    description = "SQL注入自动检测和利用工具，支持多种数据库和注入技术"
    risk_level = "medium"
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> str:
        target_url = params.get("target_url", "")
        data = params.get("data", "")
        cookie = params.get("cookie", "")
        level = params.get("level", 3)
        risk = params.get("risk", 2)
        output_dir = params.get("output_dir", "")

        cmd = f"sqlmap -u \"{target_url}\" --batch --level={level} --risk={risk}"

        if data:
            cmd += f" --data=\"{data}\""
        if cookie:
            cmd += f" --cookie=\"{cookie}\""
        if output_dir:
            cmd += f" --output-dir={output_dir}"

        return cmd

    def parse_output(self, raw: str) -> Dict[str, Any]:
        result = {
            "injectable_params": [],
            "dbms": "",
            "databases": [],
            "tables": [],
            "vulnerabilities": [],
            "summary": "",
        }

        param_pattern = re.compile(r"Parameter:\s*(\S+)\s*\((\w+)\)")
        for match in param_pattern.finditer(raw):
            result["injectable_params"].append({
                "parameter": match.group(1),
                "type": match.group(2),
            })

        dbms_match = re.search(r"back-end DBMS:\s*(.+)", raw)
        if dbms_match:
            result["dbms"] = dbms_match.group(1).strip()

        db_pattern = re.compile(r"\[\*\]\s+(\w+)")
        for match in db_pattern.finditer(raw):
            db = match.group(1)
            if db not in ["information_schema", "performance_schema", "sys"]:
                result["databases"].append(db)

        vuln_types = re.findall(r"Type:\s*(.+)", raw)
        result["vulnerabilities"] = list(set(vuln_types))

        n_params = len(result["injectable_params"])
        if n_params > 0:
            result["summary"] = f"发现 {n_params} 个SQL注入点"
            if result["dbms"]:
                result["summary"] += f", DBMS: {result['dbms']}"
        else:
            if "not injectable" in raw.lower() or "no injection" in raw.lower():
                result["summary"] = "未发现SQL注入漏洞"
            else:
                result["summary"] = "SQL注入扫描完成，需进一步分析结果"

        return result

    def get_prompt_hint(self) -> str:
        return """工具: sqlmap
描述: SQL注入检测与利用
常用命令:
  - GET注入: sqlmap -u "http://<target>/page?id=1" --batch --level=3 --risk=2
  - POST注入: sqlmap -u "http://<target>/login" --data="user=a&pass=b" --batch
  - 枚举数据库: sqlmap -u "<url>" --dbs --batch
  - 枚举表: sqlmap -u "<url>" -D <db> --tables --batch
  - 导出数据: sqlmap -u "<url>" -D <db> -T <table> --dump --batch
注意: --batch 参数自动使用默认选项
风险等级: medium"""
