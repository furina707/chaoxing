# -*- coding: utf-8 -*-
import os.path

import requests

from api.config import GlobalConst as gc


def save_cookies(session: requests.Session):
    buffer=""
    with open(gc.COOKIES_PATH, "w") as f:
        for k, v in session.cookies.items():
            buffer += f"{k}={v};"
        buffer = buffer.removesuffix(";")
        f.write(buffer)


def use_cookies() -> dict:
    if not os.path.exists(gc.COOKIES_PATH):
        return {}

    cookies={}
    try:
        with open(gc.COOKIES_PATH, "r") as f:
            buffer = f.read().strip()
            if not buffer:
                return {}
            for item in buffer.split(";"):
                item = item.strip()
                if not item or "=" not in item:
                    continue
                # 使用 partition 确保即使 value 中包含 = 也能正确解析，且不会因为缺少 = 而报错
                k, _, v = item.partition("=")
                cookies[k.strip()] = v.strip()
    except Exception:
        return {}

    return cookies
