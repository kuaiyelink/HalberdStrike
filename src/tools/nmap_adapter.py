"""Nmap 工具适配器"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from src.tools.base_adapter import ToolAdapter


class NmapAdapter(ToolAdapter):
    name = "nmap"
    description = "网络端口扫描和服务识别工具，支持TCP/UDP扫描、服务版本检测、OS指纹识别、NSE脚本扫描"
    risk_level = "low"
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> str:
        target = params.get("target", "")
        scan_type = params.get("scan_type", "full")
        output_file = params.get("output_file", "")

        if scan_type == "full":
            cmd = f"nmap -sV -sC -p- {target}"
        elif scan_type == "quick":
            cmd = f"nmap -sV --top-ports 1000 {target}"
        elif scan_type == "udp":
            cmd = f"nmap -sU --top-ports 100 {target}"
        elif scan_type == "vuln":
            cmd = f"nmap --script vuln {target}"
        elif scan_type == "os":
            cmd = f"nmap -O {target}"
        else:
            cmd = f"nmap {target}"

        if output_file:
            cmd += f" -oN {output_file}"

        return cmd

    def parse_output(self, raw: str) -> Dict[str, Any]:
        result = {
            "open_ports": [],
            "services": [],
            "os_info": "",
            "scripts": [],
            "summary": "",
        }

        port_pattern = re.compile(
            r"(\d+)/(tcp|udp)\s+(\w+)\s+(.*)"
        )
        for match in port_pattern.finditer(raw):
            port_info = {
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4).strip(),
            }
            result["open_ports"].append(port_info["port"])
            result["services"].append(port_info)

        os_match = re.search(r"OS details?:\s*(.+)", raw)
        if os_match:
            result["os_info"] = os_match.group(1).strip()

        script_pattern = re.compile(r"\|_?\s*(.+?):\s*(.+)")
        for match in script_pattern.finditer(raw):
            result["scripts"].append({
                "name": match.group(1).strip(),
                "output": match.group(2).strip(),
            })

        n_ports = len(result["open_ports"])
        ports_str = ", ".join(str(p) for p in result["open_ports"][:10])
        result["summary"] = f"发现 {n_ports} 个开放端口: {ports_str}"
        if result["os_info"]:
            result["summary"] += f" | OS: {result['os_info']}"

        return result

    def get_prompt_hint(self) -> str:
        return """工具: nmap
描述: 网络端口扫描和服务识别
常用命令:
  - 全端口扫描: nmap -sV -sC -p- <target>
  - 快速扫描: nmap -sV --top-ports 1000 <target>
  - UDP扫描: nmap -sU --top-ports 100 <target>
  - 漏洞脚本: nmap --script vuln <target>
  - OS识别: nmap -O <target>
输出保存: 添加 -oN <file> 参数
风险等级: low"""
