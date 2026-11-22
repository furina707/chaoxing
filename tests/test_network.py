# -*- coding: utf-8 -*-
"""代理检测与绕过逻辑的回归测试。"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api import network  # noqa: E402


class ExtractHostTest(unittest.TestCase):
    def test_http_proxy(self):
        self.assertEqual(network._extract_host("http://127.0.0.1:7897"), "127.0.0.1")

    def test_https_proxy(self):
        self.assertEqual(network._extract_host("https://proxy.example.com:8080"), "proxy.example.com")

    def test_ipv6_loopback(self):
        self.assertIn(network._extract_host("http://[::1]:7890"), network._LOOPBACK_HOSTS)

    def test_no_port(self):
        self.assertEqual(network._extract_host("http://localhost"), "localhost")


class SetupProxyTest(unittest.TestCase):
    def test_loopback_proxy_is_bypassed(self):
        """本地回环代理应设置 NO_PROXY=*。"""
        env = {network._USE_PROXY_ENV: ""}
        info = {
            "has_proxy": True,
            "is_loopback": True,
            "effective": {"http": "http://127.0.0.1:7897"},
        }
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(network, "detect_proxy", return_value=info):
            network.setup_proxy()
            self.assertEqual(os.environ.get("NO_PROXY"), "*")
            self.assertEqual(os.environ.get("no_proxy"), "*")

    def test_force_use_proxy_keeps_it(self):
        """CHAOXING_USE_PROXY=1 时应保留代理。"""
        env = {network._USE_PROXY_ENV: "1"}
        info = {
            "has_proxy": True,
            "is_loopback": True,
            "effective": {"http": "http://127.0.0.1:7897"},
        }
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(network, "detect_proxy", return_value=info):
            network.setup_proxy()
            self.assertNotEqual(os.environ.get("NO_PROXY"), "*")

    def test_user_no_proxy_respected(self):
        """用户显式设置 NO_PROXY 时不应覆盖。"""
        env = {"NO_PROXY": "example.com", network._USE_PROXY_ENV: ""}
        info = {
            "has_proxy": True,
            "is_loopback": True,
            "effective": {"http": "http://127.0.0.1:7897"},
        }
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(network, "detect_proxy", return_value=info):
            network.setup_proxy()
            self.assertEqual(os.environ.get("NO_PROXY"), "example.com")


if __name__ == "__main__":
    unittest.main()
