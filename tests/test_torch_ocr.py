# -*- coding: utf-8 -*-
"""Python 3.15 torch OCR 后端的回归测试。

在 Python 3.15+ 上 ddddocr 无法安装（onnxruntime 无 cp315 wheel），
captcha.ocr_init() 应回退到基于 torch 的兼容后端。
"""
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.captcha import ocr_init  # noqa: E402


@unittest.skipIf(sys.version_info < (3, 15), "仅 Python 3.15+ 使用 torch 后端")
class TorchOcrBackendTest(unittest.TestCase):
    def test_ocr_init_returns_backend(self):
        """3.15 下应能初始化 torch OCR 后端（若已安装可选依赖）。"""
        ocr = ocr_init()
        if ocr is None:
            self.skipTest("未安装 torch OCR 可选依赖（torch/onnx2torch）")
        self.assertEqual(type(ocr).__name__, "TorchDdddOcr")

    def test_classification_returns_string(self):
        """对一张合成图片，识别接口应返回字符串而不是抛异常。"""
        from PIL import Image, ImageDraw

        ocr = ocr_init()
        if ocr is None:
            self.skipTest("未安装 torch OCR 可选依赖")
        img = Image.new("RGB", (160, 64), "white")
        ImageDraw.Draw(img).text((10, 15), "AB12", fill="black")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        result = ocr.classification(buf.getvalue())
        self.assertIsInstance(result, str)


class OcrInitInterfaceTest(unittest.TestCase):
    def test_ocr_init_never_raises(self):
        """无论依赖是否齐全，ocr_init 都不应抛出异常。"""
        try:
            ocr_init()
        except Exception as exc:  # pragma: no cover
            self.fail(f"ocr_init() 抛出了异常: {exc}")


if __name__ == "__main__":
    unittest.main()
