"""网络工具函数"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional


def is_valid_ip(addr: str) -> bool:
    """检查是否为合法IP地址"""
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """检查是否为合法CIDR表示"""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def parse_target(target: str) -> dict:
    """解析目标字符串，返回结构化信息

    支持格式: IP, CIDR, 域名, URL
    """
    result = {
        "raw": target,
        "type": "unknown",
        "host": target,
        "port": None,
        "scheme": None,
    }

    url_match = re.match(r"^(https?://)([^:/]+)(?::(\d+))?(.*)$", target)
    if url_match:
        result["scheme"] = url_match.group(1).replace("://", "")
        result["host"] = url_match.group(2)
        result["port"] = int(url_match.group(3)) if url_match.group(3) else None
        result["type"] = "url"
        return result

    if is_valid_ip(target):
        result["type"] = "ip"
        return result

    if is_valid_cidr(target):
        result["type"] = "cidr"
        return result

    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    if domain_pattern.match(target):
        result["type"] = "domain"
        return result

    return result
