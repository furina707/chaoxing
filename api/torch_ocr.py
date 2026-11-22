# -*- coding: utf-8 -*-
"""
基于 PyTorch 的验证码识别后端（Python 3.15+）。

本项目只支持 Python 3.15+，而 ddddocr 依赖的 onnxruntime 没有 cp315 wheel，
因此不再使用 ddddocr，而是把它所用的 ONNX 验证码模型（``resource/captcha.onnx``）
和字符集（``resource/captcha_charset.json``）内置到项目中，直接通过
onnx2torch + torch 推理，完全不需要 onnxruntime。

onnx2torch 未实现 ONNX 的 LSTM 算子，这里注册一个自定义转换器补齐：
把 ONNX LSTM 的权重布局映射到 ``torch.nn.LSTM``。

对外接口：``TorchDdddOcr().classification(img_bytes) -> str``
"""

from __future__ import annotations

import json
import os
from typing import Optional

from loguru import logger

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODEL_PATH = os.path.join(_BASE_DIR, "resource", "captcha.onnx")
_CHARSET_PATH = os.path.join(_BASE_DIR, "resource", "captcha_charset.json")

_torch = None
_model = None
_charset = None


def _register_lstm_converter() -> None:
    """向 onnx2torch 注册 LSTM 转换器（仅注册一次）。"""
    import torch

    from onnx2torch.node_converters.registry import _CONVERTER_REGISTRY, OperationDescription
    from torch import nn

    for version in (7, 11):
        key = OperationDescription(domain="", operation_type="LSTM", version=version)
        if key in _CONVERTER_REGISTRY:
            continue

        from onnx2torch.utils.common import (
            OnnxMapping,
            OnnxToTorchModule,
            OperationConverterResult,
            get_const_value,
        )

        class OnnxLSTM(nn.Module, OnnxToTorchModule):
            """把 ONNX 双向 LSTM 映射到 torch.nn.LSTM。"""

            def __init__(self, W, R, B, hidden_size: int, bidirectional: bool):
                super().__init__()
                self.lstm = nn.LSTM(
                    input_size=W.shape[2],
                    hidden_size=hidden_size,
                    batch_first=False,
                    bidirectional=bidirectional,
                    bias=B is not None,
                )

                # ONNX 门顺序 i,o,f,c；PyTorch 为 i,f,g,o。
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
                # torch [seq, batch, num_dir*H] -> ONNX [seq, num_dir, batch, H]
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

        _CONVERTER_REGISTRY[key] = _lstm_converter


def _load_charset() -> list:
    """加载内置字符集。"""
    global _charset
    if _charset is None:
        with open(_CHARSET_PATH, "r", encoding="utf-8") as f:
            _charset = json.load(f)
    return _charset


def _load_model():
    """把内置 ONNX 模型转换成 torch 模块并缓存。"""
    global _model, _torch
    if _model is not None:
        return _model
    try:
        import torch
        import onnx
        from onnx2torch import convert

        _torch = torch
        _register_lstm_converter()

        if not os.path.exists(_MODEL_PATH):
            raise RuntimeError(f"模型文件不存在: {_MODEL_PATH}")
        # Windows 下 onnx2torch 以路径加载会触发 NamedTemporaryFile 文件锁问题，
        # 因此读入内存中的 ModelProto 再转换。
        proto = onnx.load(_MODEL_PATH)
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
    """验证码识别后端，接口与 ddddocr.DdddOcr 兼容。"""

    def __init__(self, *args, **kwargs):
        _load_model()

    def classification(self, img: bytes) -> str:
        """识别图片验证码，返回识别出的文本。"""
        import io

        import numpy as np
        from PIL import Image

        model = _load_model()
        try:
            image = Image.open(io.BytesIO(img)).convert("RGB")
            # 与模型训练一致的预处理：高度缩放到 64，灰度，归一化到 [0,1]。
            target_h = 64
            target_w = int(image.size[0] * (target_h / image.size[1]))
            image = image.resize((target_w, target_h))
            gray = np.array(image.convert("L"), dtype="float32") / 255.0
            arr = _torch.from_numpy(gray).unsqueeze(0).unsqueeze(0)  # [1,1,64,w]
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
