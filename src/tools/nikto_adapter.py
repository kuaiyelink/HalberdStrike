"""Nikto 工具适配器"""

from __future__ import annotations

import re
from typing import Any, Dict

from src.tools.base_adapter import ToolAdapter


class NiktoAdapter(ToolAdapter):
    name = "nikto"
    description = "Web服务器漏洞扫描器，检测危险文件、过时软件版本、服务器配置问题"
    risk_level = "low"
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> str:
        target = params.get("target", "")
        port = params.get("port", "")
        output_file = params.get("output_file", "")

        cmd = f"nikto -h {target}"
        if port:
            cmd += f" -p {port}"
        if output_file:
            cmd += f" -o {output_file}"

        return cmd

    def parse_output(self, raw: str) -> Dict[str, Any]:
        result = {
            "vulnerabilities": [],
            "server_info": "",
            "interesting_findings": [],
            "summary": "",
        }

        server_match = re.search(r"Server:\s*(.+)", raw)
        if server_match:
            result["server_info"] = server_match.group(1).strip()

        vuln_pattern = re.compile(r"\+\s*(OSVDB-\d+):\s*(.+)")
        for match in vuln_pattern.finditer(raw):
            result["vulnerabilities"].append({
                "id": match.group(1),
                "description": match.group(2).strip(),
            })

        finding_pattern = re.compile(r"\+\s*(/\S+):\s*(.+)")
        for match in finding_pattern.finditer(raw):
            result["interesting_findings"].append({
                "path": match.group(1),
                "info": match.group(2).strip(),
            })

        n_vuln = len(result["vulnerabilities"])
        n_find = len(result["interesting_findings"])
        result["summary"] = f"发现 {n_vuln} 个漏洞, {n_find} 个有趣发现"
        if result["server_info"]:
            result["summary"] += f" | Server: {result['server_info']}"

        return result

    def get_prompt_hint(self) -> str:
        return """工具: nikto
描述: Web服务器漏洞扫描
常用命令:
  - 基本扫描: nikto -h http://<target>
  - 指定端口: nikto -h <target> -p 8080
  - 保存输出: nikto -h <target> -o <file>
风险等级: low"""
