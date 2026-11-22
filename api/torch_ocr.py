# -*- coding: utf-8 -*-
"""
基于 PyTorch 的验证码识别后端（Python 3.15+ 专用）。

背景
----
ddddocr 依赖 onnxruntime，而 onnxruntime 目前最高只提供到 cp314 的 wheel，
Python 3.15 下无法安装。本模块改用 onnx2torch 把 ddddocr 自带的
``common.onnx``（beta 模型）转换成 PyTorch 模块并用 torch 推理，
从而在不安装 onnxruntime 的前提下恢复自动验证码识别。

onnx2torch 未实现 ONNX 的 LSTM 算子，这里注册一个自定义转换器补齐：
将 ONNX LSTM 的权重布局映射到 ``torch.nn.LSTM``。

注意：默认 DdddOcr() 使用的是量化模型 common_old.onnx，其量化算子
(DynamicQuantizeLinear 等)无法被 onnx2torch 转换；因此本后端使用
common.onnx + CHARSET_BETA，识别效果与 ddddocr(beta=True) 等价。

对外接口与 ddddocr.DdddOcr 保持一致：``classification(img_bytes) -> str``。
"""

from __future__ import annotations

import importlib.util
import os
from typing import Optional

from loguru import logger

_MODEL_NAME = "common.onnx"

# 这些导入延迟到真正需要 OCR 时执行，避免未安装 torch 时影响主程序启动。
_torch = None
_convert = None
_model = None
_charset = None


def _register_lstm_converter() -> None:
    """向 onnx2torch 注册 LSTM 转换器（仅注册一次）。"""
    import torch

    from onnx2torch.node_converters.registry import _CONVERTER_REGISTRY, OperationDescription
    from torch import nn

    desc = OperationDescription(domain="", operation_type="LSTM", version=11)
    if desc in _CONVERTER_REGISTRY:
        return

    from onnx2torch.utils.common import (
        OnnxMapping,
        OnnxToTorchModule,
        OperationConverterResult,
        get_const_value,
    )

    class OnnxLSTM(nn.Module, OnnxToTorchModule):
        """把 ONNX LSTM（双向）映射到 torch.nn.LSTM。"""

        def __init__(self, W, R, B, hidden_size: int, bidirectional: bool):
            super().__init__()
            self.lstm = nn.LSTM(
                input_size=W.shape[2],
                hidden_size=hidden_size,
                batch_first=False,
                bidirectional=bidirectional,
                bias=B is not None,
            )

            # ONNX 门顺序为 i, o, f, c；PyTorch 为 i, f, g, o。
            def reorder(w, gate_dim):
                i, o, f, c = w.chunk(4, dim=gate_dim)
                return torch.cat([i, f, c, o], dim=gate_dim)

            W = reorder(W.detach(), gate_dim=-2)  # [dir, 4H, input]
            R = reorder(R.detach(), gate_dim=-2)  # [dir, 4H, hidden]
            H = self.lstm.hidden_size
            with torch.no_grad():
                self.lstm.weight_ih_l0.copy_(W[0])
                self.lstm.weight_hh_l0.copy_(R[0])
                if B is not None:
                    # ONNX 偏置 [dir, 8H] = Wb(4H) + Rb(4H)
                    b = reorder(B.detach(), gate_dim=-1)
                    self.lstm.bias_ih_l0.copy_(b[0, : 4 * H])
                    self.lstm.bias_hh_l0.copy_(b[0, 4 * H :])
                if bidirectional:
                    self.lstm.weight_ih_l0_reverse.copy_(W[1])
                    self.lstm.weight_hh_l0_reverse.copy_(R[1])
                    if B is not None:
                        self.lstm.bias_ih_l0_reverse.copy_(b[1, : 4 * H])
                        self.lstm.bias_hh_l0_reverse.copy_(b[1, 4 * H :])

        def forward(self, x):
            out, (hn, cn) = self.lstm(x)
            # torch: [seq, batch, num_dir*H] -> ONNX: [seq, num_dir, batch, H]
            seq, batch, _ = out.shape
            H = self.lstm.hidden_size
            nd = 2 if self.lstm.bidirectional else 1
            y = out.view(seq, batch, nd, H).permute(0, 2, 1, 3).contiguous()
            return y, hn, cn

    def _lstm_converter(node, graph):
        attrs = node.attributes
        hidden = int(attrs.get("hidden_size", 0))
        bidirectional = attrs.get("direction", "forward") == "bidirectional"
        W = get_const_value(node.input_values[1], graph)
        R = get_const_value(node.input_values[2], graph)
        B = (
            get_const_value(node.input_values[3], graph)
            if len(node.input_values) > 3 and node.input_values[3]
            else None
        )
        return OperationConverterResult(
            torch_module=OnnxLSTM(W, R, B, hidden, bidirectional),
            onnx_mapping=OnnxMapping(
                inputs=(node.input_values[0],), outputs=node.output_values
            ),
        )

    # onnx2torch 对 LSTM 只识别 version 7 / 11；两个都注册以防 opset 不同。
    for version in (7, 11):
        key = OperationDescription(domain="", operation_type="LSTM", version=version)
        if key not in _CONVERTER_REGISTRY:
            _CONVERTER_REGISTRY[key] = _lstm_converter


def _load_charset() -> list:
    """加载 common.onnx 对应的字符集（CHARSET_BETA）。"""
    global _charset
    if _charset is not None:
        return _charset
    spec = importlib.util.find_spec("ddddocr")
    if spec is None or not spec.origin:
        raise RuntimeError("未找到 ddddocr 包，无法加载字符集")
    charsets_path = os.path.join(os.path.dirname(spec.origin), "charsets.py")
    cs_spec = importlib.util.spec_from_file_location("_ddddocr_charsets", charsets_path)
    cs = importlib.util.module_from_spec(cs_spec)
    cs_spec.loader.exec_module(cs)
    _charset = cs.CHARSET_BETA
    return _charset


def _load_model():
    """把 common.onnx 转换为 torch 模块并缓存。"""
    global _model, _torch, _convert
    if _model is not None:
        return _model
    try:
        import torch
        import onnx
        from onnx2torch import convert

        _torch = torch
        _convert = convert
        _register_lstm_converter()

        spec = importlib.util.find_spec("ddddocr")
        if spec is None or not spec.origin:
            raise RuntimeError("未找到 ddddocr 包")
        model_path = os.path.join(os.path.dirname(spec.origin), _MODEL_NAME)
        if not os.path.exists(model_path):
            raise RuntimeError(f"模型文件不存在: {model_path}")

        # 注意：onnx2torch 在 Windows 下用路径加载会触发 NamedTemporaryFile
        # 文件锁问题，因此先以 ModelProto 对象形式读入再转换。
        proto = onnx.load(model_path)
        module = convert(proto)
        module.eval()
        _model = module
        return _model
    except Exception as e:
        raise RuntimeError(f"torch OCR 模型加载失败: {e}") from e


def _ctc_decode(pred_indices) -> str:
    """CTC 解码：合并连续重复并跳过 blank(0)。"""
    charset = _load_charset()
    result = []
    prev = None
    for raw in pred_indices:
        idx = int(raw)
        if idx != prev and idx != 0 and 0 <= idx < len(charset):
            result.append(charset[idx])
        prev = idx
    return "".join(result)


class TorchDdddOcr:
    """与 ddddocr.DdddOcr 接口兼容的 torch 后端实现。"""

    def __init__(self, *args, **kwargs):
        _load_model()

    def classification(self, img: bytes) -> str:
        """识别图片验证码，返回识别出的文本。"""
        from PIL import Image

        model = _load_model()
        try:
            import io

            image = Image.open(io.BytesIO(img)).convert("RGB")
            # 与 ddddocr 默认模型一致的预处理：高度缩放到 64，灰度，/255。
            target_h = 64
            target_w = int(image.size[0] * (target_h / image.size[1]))
            image = image.resize((target_w, target_h))
            gray = image.convert("L")
            arr = _torch.from_numpy(
                __import__("numpy").array(gray, dtype="float32") / 255.0
            )
            arr = arr.unsqueeze(0).unsqueeze(0)  # [1, 1, 64, w]
            with _torch.no_grad():
                out = model(arr)
            # out: [seq, 1, classes]
            if out.dim() == 3 and out.shape[1] == 1:
                pred = _torch.argmax(out[:, 0, :], dim=1)
            else:
                pred = _torch.argmax(out, dim=-1).reshape(-1)
            return _ctc_decode(pred.cpu().numpy())
        except Exception as e:
            logger.warning(f"torch OCR 识别失败: {e}")
            return ""
