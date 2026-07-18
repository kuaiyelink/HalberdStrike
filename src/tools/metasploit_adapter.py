"""Metasploit 工具适配器"""

from __future__ import annotations

import re
from typing import Any, Dict

from src.tools.base_adapter import ToolAdapter


class MetasploitAdapter(ToolAdapter):
    name = "msfconsole"
    description = "Metasploit渗透测试框架，支持漏洞利用、Payload生成、后渗透模块"
    risk_level = "high"
    default_timeout = 300

    def build_command(self, params: Dict[str, Any]) -> str:
        module = params.get("module", "")
        options = params.get("options", {})
        action = params.get("action", "run")

        resource_cmds = []
        if module:
            resource_cmds.append(f"use {module}")
        for key, value in options.items():
            resource_cmds.append(f"set {key} {value}")
        resource_cmds.append(action)
        resource_cmds.append("exit")

        inline = "; ".join(resource_cmds)
        cmd = f"msfconsole -q -x \"{inline}\""
        return cmd

    def parse_output(self, raw: str) -> Dict[str, Any]:
        result = {
            "session_opened": False,
            "session_type": "",
            "exploit_success": False,
            "loot": [],
            "summary": "",
        }

        if "session" in raw.lower() and "opened" in raw.lower():
            result["session_opened"] = True
            result["exploit_success"] = True
            session_match = re.search(r"(Meterpreter|Command shell)\s+session\s+(\d+)\s+opened", raw)
            if session_match:
                result["session_type"] = session_match.group(1)

        if "exploit completed" in raw.lower():
            if "no session" not in raw.lower():
                result["exploit_success"] = True

        loot_pattern = re.compile(r"Loot:\s*(.+)")
        for match in loot_pattern.finditer(raw):
            result["loot"].append(match.group(1).strip())

        if result["session_opened"]:
            result["summary"] = f"漏洞利用成功！获得 {result['session_type']} 会话"
        elif result["exploit_success"]:
            result["summary"] = "漏洞利用已执行"
        else:
            result["summary"] = "漏洞利用未成功获得会话"

        return result

    def get_prompt_hint(self) -> str:
        return """工具: msfconsole
描述: Metasploit漏洞利用框架
常用命令格式 (通过 -x 传入):
  msfconsole -q -x "use <module>; set RHOSTS <target>; set LHOST <attacker_ip>; run; exit"
常用模块:
  - auxiliary/scanner/* : 扫描模块
  - exploit/* : 漏洞利用模块
  - post/* : 后渗透模块
风险等级: high (需要人工确认)"""
