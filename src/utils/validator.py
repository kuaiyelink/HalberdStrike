"""命令和范围校验工具"""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import List, Optional

from src.utils.logger import get_logger

logger = get_logger("halberdstrike.validator")


class CommandValidator:
    """命令安全校验器"""

    DEFAULT_BLOCKED = [
        "rm -rf",
        "dd if=",
        "mkfs",
        "shutdown",
        "reboot",
        ":(){ :|:& };:",
        "fork",
        "> /dev/sd",
        "chmod 777 /",
    ]

    def __init__(self, blocked_commands: Optional[List[str]] = None):
        self.blocked = blocked_commands or self.DEFAULT_BLOCKED

    def validate(self, command: str) -> tuple[bool, str]:
        """校验命令是否安全。返回 (is_safe, reason)"""
        if not command or not command.strip():
            return False, "空命令"

        normalized_cmd = re.sub(r'\s+', ' ', command)

        for blocked in self.blocked:
            normalized_blocked = re.sub(r'\s+', ' ', blocked)

            pattern = r'(?:^|\s)' + re.escape(normalized_blocked) + r'(?:$|\s)'
            if re.search(pattern, normalized_cmd):
                return False, f"命令包含被禁止的操作: {blocked}"

            blocked_parts = normalized_blocked.split()
            if len(blocked_parts) >= 2:
                cmd_name = blocked_parts[0]
                cmd_args = blocked_parts[1:]

                escaped_name = re.escape(cmd_name)
                cmd_pattern = r'(?:^|\s)' + escaped_name + r'(?:$|\s|[;/|])'
                cmd_match = re.search(cmd_pattern, normalized_cmd)
                if cmd_match:
                    cmd_start = cmd_match.start()
                    remaining = normalized_cmd[cmd_start:].lstrip()

                    parts = re.split(r'[\s;/|]+', remaining, maxsplit=len(blocked_parts))
                    if len(parts) >= len(blocked_parts):
                        match_count = 0
                        for i, expected in enumerate(blocked_parts):
                            if i < len(parts) and expected == parts[i]:
                                match_count += 1

                        if match_count >= len(blocked_parts):
                            return False, f"命令包含被禁止的操作: {blocked}"

        return True, "通过"


class ScopeValidator:
    """网络范围校验器"""

    def __init__(self, scope: List[str]):
        self.networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.domains: List[str] = []
        for item in scope:
            host = self._extract_host(item)
            try:
                self.networks.append(ipaddress.ip_network(host, strict=False))
            except ValueError:
                self.domains.append(host.lower())

    @staticmethod
    def _extract_host(item: str) -> str:
        """从URL或带端口的地址中提取主机部分"""
        url_match = re.match(r"^https?://([^:/]+)", item)
        if url_match:
            return url_match.group(1)
        port_match = re.match(r"^([^:/]+):\d+$", item)
        if port_match:
            return port_match.group(1)
        return item

    def is_in_scope(self, target: str) -> bool:
        """检查目标是否在授权范围内"""
        try:
            addr = ipaddress.ip_address(target)
            return any(addr in net for net in self.networks)
        except ValueError:
            return target.lower() in self.domains or any(
                target.lower().endswith("." + d) for d in self.domains
            )

    def validate_command_target(self, command: str) -> tuple[bool, str]:
        """从命令中提取目标地址（IP + 域名）并校验范围"""
        # 校验 IP 地址
        ip_pattern = re.compile(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b"
        )
        found_ips = ip_pattern.findall(command)

        for ip_str in found_ips:
            try:
                if "/" in ip_str:
                    net = ipaddress.ip_network(ip_str, strict=False)
                    contained = any(
                        net.subnet_of(scope_net)
                        for scope_net in self.networks
                    )
                    if not contained:
                        return False, f"目标网段 {ip_str} 超出授权范围"
                else:
                    if not self.is_in_scope(ip_str):
                        return False, f"目标IP {ip_str} 不在授权范围内"
            except ValueError:
                continue

        # 校验域名/URL —— 仅匹配看起来像真实域名的字符串（至少两段+合法TLD）
        domain_pattern = re.compile(
            r"(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
            r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
            r"\.[a-zA-Z]{2,})(?:[:/\s]|$)"
        )
        # 排除常见非目标域名
        IGNORED_DOMAINS = {
            "github.com", "raw.githubusercontent.com", "google.com",
            "localhost", "exploit-db.com", "cvedetails.com",
            "nvd.nist.gov", "pypi.org", "npmjs.com",
        }
        # 排除文件扩展名误匹配
        FILE_EXTENSIONS = {
            "txt", "xml", "html", "json", "csv", "log", "conf",
            "cfg", "ini", "yml", "yaml", "md", "rst", "pdf",
            "nmap", "gnmap", "png", "jpg", "gif", "zip", "tar",
        }
        found_domains = domain_pattern.findall(command)
        for domain in found_domains:
            domain_lower = domain.lower()
            # 跳过看起来是文件名的匹配（如 scan.txt, output.xml）
            ext = domain_lower.rsplit(".", 1)[-1] if "." in domain_lower else ""
            if ext in FILE_EXTENSIONS:
                continue
            # 至少要有两段（如 example.com），单段+TLD 不算域名
            if domain_lower.count(".") < 1:
                continue
            if domain_lower in IGNORED_DOMAINS:
                continue
            if not self.is_in_scope(domain_lower):
                return False, f"目标域名 {domain} 不在授权范围内"

        return True, "通过"
