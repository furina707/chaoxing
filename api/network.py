# -*- coding: utf-8 -*-
"""
网络代理检测与处理。

超星（chaoxing.com）是国内站点，通常应直连。但很多用户本机运行着
Clash/V2Ray 等代理软件，会在 Windows 注册表里设置系统代理
（如 http://127.0.0.1:7897）。requests 会读取该注册表代理，导致请求
被转发到本地代理，出现验证码接口返回 404、403 等异常。

本模块在程序启动时：
1. 检测当前生效的代理（环境变量 + 系统注册表）；
2. 若代理指向本地回环地址（127.0.0.1/localhost/::1），默认通过
   设置 NO_PROXY=* 绕过它，让所有请求直连；
3. 若要强制使用本地代理，可设置环境变量 CHAOXING_USE_PROXY=1；
4. 若显式设置了 NO_PROXY / no_proxy，则尊重用户的配置，不擅自修改。

需在任何 requests/httpx Session 创建之前调用 setup_proxy()。
"""

from __future__ import annotations

import os
import urllib.request

# 强制保留本地代理的开关
_USE_PROXY_ENV = "CHAOXING_USE_PROXY"

_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1", "[::1]")


def _extract_host(proxy_url: str) -> str:
    """从代理 URL 中提取主机名。"""
    if "://" in proxy_url:
        proxy_url = proxy_url.split("://", 1)[1]
    # 去掉路径
    host = proxy_url.split("/", 1)[0]
    if host.startswith("["):
        # IPv6 字面量，如 [::1]:7890 -> ::1
        host = host[1:].split("]", 1)[0]
    elif ":" in host:
        # IPv4 / 域名:端口
        host = host.rsplit(":", 1)[0]
    return host.lower()


def detect_proxy() -> dict:
    """返回当前检测到的代理信息。"""
    env_proxies = urllib.request.getproxies_environment()
    registry_proxies = urllib.request.getproxies_registry()
    effective = urllib.request.getproxies()
    return {
        "env": env_proxies,
        "registry": registry_proxies,
        "effective": effective,
        "has_proxy": bool(effective),
        "is_loopback": any(
            _extract_host(url) in _LOOPBACK_HOSTS for url in effective.values()
        ),
    }


def _user_set_no_proxy() -> bool:
    """用户是否显式设置了 NO_PROXY。"""
    return bool(os.environ.get("NO_PROXY") or os.environ.get("no_proxy"))


def setup_proxy(logger=None) -> dict:
    """
    在程序启动时调用，按需绕过本地代理。

    Args:
        logger: 可选的 loguru logger，用于输出检测信息。

    Returns:
        代理检测信息字典（见 detect_proxy）。
    """
    info = detect_proxy()

    def log(msg):
        if logger is not None:
            logger.info(msg)
        else:
            print(f"[network] {msg}")

    if not info["has_proxy"]:
        log("未检测到代理，请求将直连。")
        return info

    # 用户显式设置了 NO_PROXY，尊重其配置
    if _user_set_no_proxy():
        log("检测到 NO_PROXY 环境变量，尊重用户代理配置。")
        return info

    # 用户强制要求使用代理
    if os.environ.get(_USE_PROXY_ENV, "").strip().lower() in {"1", "true", "yes", "y", "on"}:
        log(f"检测到 {_USE_PROXY_ENV}=1，保留代理: {info['effective']}")
        return info

    # 本地回环代理（Clash/V2Ray 等）默认绕过
    if info["is_loopback"]:
        os.environ["NO_PROXY"] = "*"
        os.environ["no_proxy"] = "*"
        log(
            f"检测到本地代理 {info['effective']}，已自动绕过（NO_PROXY=*），请求将直连。"
            f"如需保留代理，请设置 {_USE_PROXY_ENV}=1。"
        )
    else:
        proxies = ", ".join(f"{k}={v}" for k, v in info["effective"].items())
        log(f"检测到非本地代理，保持现有配置: {proxies}")

    return info


if __name__ == "__main__":
    setup_proxy()
