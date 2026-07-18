"""Hydra 工具适配器"""

from __future__ import annotations

import re
from typing import Any, Dict

from src.tools.base_adapter import ToolAdapter


class HydraAdapter(ToolAdapter):
    name = "hydra"
    description = "网络登录密码爆破工具，支持SSH、FTP、HTTP、SMB等多种协议"
    risk_level = "medium"
    default_timeout = 600

    def build_command(self, params: Dict[str, Any]) -> str:
        target = params.get("target", "")
        service = params.get("service", "ssh")
        username = params.get("username", "")
        user_list = params.get("user_list", "")
        password_list = params.get("password_list", "/usr/share/wordlists/rockyou.txt")
        threads = params.get("threads", 16)
        port = params.get("port", "")
        extra = params.get("extra", "")

        cmd = f"hydra"

        if username:
            cmd += f" -l {username}"
        elif user_list:
            cmd += f" -L {user_list}"

        cmd += f" -P {password_list} -t {threads}"

        if port:
            cmd += f" -s {port}"

        cmd += f" {target} {service}"

        if extra:
            cmd += f" {extra}"

        return cmd

    def parse_output(self, raw: str) -> Dict[str, Any]:
        result = {
            "credentials": [],
            "attempts": 0,
            "summary": "",
        }

        cred_pattern = re.compile(
            r"\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)"
        )
        for match in cred_pattern.finditer(raw):
            result["credentials"].append({
                "port": int(match.group(1)),
                "service": match.group(2),
                "host": match.group(3),
                "username": match.group(4),
                "password": match.group(5),
            })

        attempts_match = re.search(r"(\d+)\s+valid password", raw)
        if attempts_match:
            result["attempts"] = int(attempts_match.group(1))

        n = len(result["credentials"])
        if n > 0:
            creds = [f"{c['username']}:{c['password']}" for c in result["credentials"]]
            result["summary"] = f"发现 {n} 组有效凭据: {', '.join(creds[:5])}"
        else:
            result["summary"] = "未发现有效凭据"

        return result

    def get_prompt_hint(self) -> str:
        return """工具: hydra
描述: 网络登录密码爆破
常用命令:
  - SSH爆破: hydra -l <user> -P /usr/share/wordlists/rockyou.txt <target> ssh
  - FTP爆破: hydra -L <userlist> -P <passlist> <target> ftp
  - HTTP表单: hydra -l admin -P <passlist> <target> http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
  - SMB爆破: hydra -l <user> -P <passlist> <target> smb
风险等级: medium"""
