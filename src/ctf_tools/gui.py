import sys
import json
import time
from pathlib import Path
from typing import Callable, Dict, List, Tuple

from PyQt5 import QtCore, QtWidgets, QtGui

from . import (
    auto_decode,
    base32_decode,
    base32_encode,
    base64_decode,
    base64_encode,
    base64url_decode,
    base64url_encode,
    base16_encode,
    base16_decode,
    base58_encode,
    base58_decode,
    base85_encode,
    base85_decode,
    bacon_decode,
    bacon_encode,
    buddha_decode,
    buddha_encode,
    caesar_shift,
    convert_base,
    core_values_decode,
    core_values_encode,
    unicode_escape_decode,
    unicode_escape_encode,
    base64_decompress,
    base64_to_hex,
    brute_force_hash,
    lsb_extract,
    split_gif_frames,
    decode_qr,
    extract_exif,
    list_png_chunks,
    decrypt_ecb,
    encrypt_ecb,
    hash_data,
    html_entity_encode,
    html_entity_decode,
    morse_decode,
    morse_encode,
    pigpen_decode,
    pigpen_encode,
    quoted_printable_decode,
    quoted_printable_encode,
    rail_fence_decrypt,
    rail_fence_encrypt,
    reverse_string,
    rot13,
    atbash,
    hex_to_ascii,
    bin_to_ascii,
    simple_replace,
    swap_case,
    to_lower,
    to_upper,
    url_decode,
    url_encode,
    decode_bytes_best_effort,
)
from .stego_tools import binwalk_extract, detect_zip_pseudo_encryption
from .base_utils import registry as base_registry
from .ai_config import SUPPORTED_PROVIDERS, ProviderConfig, load_ai_config, save_ai_config
from .ai_assist import ai_assist_cipher, ai_assist_crypto, ai_assist_stego, render_ai_result
from .ai_client import AIError, call_ai_chat
from .history import log_event

SETTINGS_PATH = Path.home() / ".ctf_tools_gui.json"


class FileDropLineEdit(QtWidgets.QLineEdit):
    fileDropped = QtCore.pyqtSignal(str)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setAcceptDrops(True)
        self.setPlaceholderText("拖拽文件到此，或手动输入路径")

    def dragEnterEvent(self, event: QtGui.QDragEnterEvent) -> None:  # type: ignore
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event: QtGui.QDropEvent) -> None:  # type: ignore
        if event.mimeData().hasUrls():
            url = event.mimeData().urls()[0]
            path = url.toLocalFile()
            self.setText(path)
            self.fileDropped.emit(path)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("CTF 工具箱")
        self.resize(900, 600)
        self.settings = self._load_settings()
        self._ensure_setting_defaults()
        self.ai_config = load_ai_config()
        tabs = QtWidgets.QTabWidget()
        tabs.addTab(self._build_text_tab(), "文本编码/转换")
        tabs.addTab(self._build_crypto_tab(), "对称加密")
        tabs.addTab(self._build_file_tab(), "文件工具")
        tabs.addTab(self._build_auto_tab(), "无脑拖入解谜")
        tabs.addTab(self._build_ai_tab(), "AI 辅助解码")
        tabs.addTab(self._build_settings_tab(), "设置")
        self.setCentralWidget(tabs)

    def _build_auto_tab(self) -> QtWidgets.QWidget:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)

        self.auto_toggle = QtWidgets.QCheckBox("拖入后自动分析")
        self.auto_toggle.setChecked(self.settings.get("auto_analyze", True))

        self.auto_input = QtWidgets.QTextEdit()
        self.auto_input.setPlaceholderText("粘贴或输入文本 / 拖入文件以自动尝试解谜")

        self.auto_file_drop = FileDropLineEdit()
        self.auto_file_drop.fileDropped.connect(self._auto_handle_file_drop)
        self.auto_file_drop.setPlaceholderText("拖拽文件到此自动分析")

        auto_btn = QtWidgets.QPushButton("手动分析")
        auto_btn.clicked.connect(self._auto_analyze_input)
        ai_btn = QtWidgets.QPushButton("AI 辅助解码")
        ai_btn.clicked.connect(self._run_ai_cipher_assist)

        control_layout = QtWidgets.QHBoxLayout()
        control_layout.addWidget(self.auto_toggle)
        control_layout.addWidget(auto_btn)
        control_layout.addWidget(ai_btn)
        self.auto_output = QtWidgets.QTextEdit()
        self.auto_output.setReadOnly(True)

        layout.addWidget(QtWidgets.QLabel("文本输入"))
        layout.addWidget(self.auto_input, 2)
        layout.addLayout(control_layout)
        layout.addWidget(QtWidgets.QLabel("文件拖拽"))
        layout.addWidget(self.auto_file_drop)
        layout.addWidget(QtWidgets.QLabel("结果"))
        layout.addWidget(self.auto_output, 3)
        return widget

    def _build_ai_tab(self) -> QtWidgets.QWidget:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)

        # 配置区域
        config_group = QtWidgets.QGroupBox("API 配置")
        config_form = QtWidgets.QFormLayout(config_group)
        self.ai_tab_provider = QtWidgets.QComboBox()
        self.ai_tab_provider.addItems(SUPPORTED_PROVIDERS)
        self.ai_tab_provider.setCurrentText(self.ai_config.provider)
        self.ai_tab_api_key = QtWidgets.QLineEdit()
        self.ai_tab_api_key.setEchoMode(QtWidgets.QLineEdit.Password)
        self.ai_tab_api_key.setPlaceholderText("API Key（留空用环境变量）")
        self.ai_tab_base_url = QtWidgets.QLineEdit()
        self.ai_tab_base_url.setPlaceholderText("自定义 base_url（可选）")
        self.ai_tab_endpoint = QtWidgets.QLineEdit()
        self.ai_tab_endpoint.setPlaceholderText("自定义 endpoint/path（可选）")
        self.ai_tab_model = QtWidgets.QComboBox()
        self.ai_tab_model.setEditable(True)
        self._refresh_ai_models(self.ai_tab_provider.currentText())
        self.ai_tab_provider.currentTextChanged.connect(self._handle_ai_provider_change)
        self._load_ai_tab_fields(self.ai_tab_provider.currentText())

        btn_row = QtWidgets.QHBoxLayout()
        save_btn = QtWidgets.QPushButton("保存配置")
        save_btn.clicked.connect(self._save_ai_tab_config)
        test_btn = QtWidgets.QPushButton("测试连通性")
        test_btn.clicked.connect(self._test_ai_connection)
        clear_btn = QtWidgets.QPushButton("清空密钥")
        clear_btn.clicked.connect(self._clear_ai_key)
        btn_row.addWidget(save_btn)
        btn_row.addWidget(test_btn)
        btn_row.addWidget(clear_btn)

        config_form.addRow(QtWidgets.QLabel("服务商"), self.ai_tab_provider)
        config_form.addRow(QtWidgets.QLabel("API Key"), self.ai_tab_api_key)
        config_form.addRow(QtWidgets.QLabel("base_url"), self.ai_tab_base_url)
        config_form.addRow(QtWidgets.QLabel("endpoint"), self.ai_tab_endpoint)
        config_form.addRow(QtWidgets.QLabel("模型"), self.ai_tab_model)
        config_form.addRow(btn_row)

        config_ready_hint = QtWidgets.QLabel("已配置 API，可在设置页修改，或点击“修改配置”重新展开。")
        config_ready_hint.setStyleSheet("color: gray;")
        config_ready_hint.setVisible(False)

        # 任务区域
        task_group = QtWidgets.QGroupBox("AI 辅助分析")
        task_split = QtWidgets.QHBoxLayout(task_group)
        self.ai_task_combo = QtWidgets.QComboBox()
        self.ai_task_combo.addItems(["密文识别/解码", "哈希分析", "隐写建议"])
        self.ai_text_input = QtWidgets.QTextEdit()
        self.ai_text_input.setPlaceholderText("输入/粘贴密文或哈希等文本")
        self.ai_hint_input = QtWidgets.QLineEdit()
        self.ai_hint_input.setPlaceholderText("可选提示（如算法猜测、明文片段等）")
        self.ai_file_input = FileDropLineEdit()
        self.ai_file_input.setPlaceholderText("拖拽文件或点击选择（隐写/文件分析）")
        self.ai_file_input.fileDropped.connect(self._handle_ai_file_drop)
        file_btn = QtWidgets.QPushButton("选择文件")
        file_btn.clicked.connect(self._choose_ai_file)
        self.ai_output = QtWidgets.QTextEdit()
        self.ai_output.setReadOnly(True)
        run_btn = QtWidgets.QPushButton("执行 AI 分析")
        run_btn.clicked.connect(self._run_ai_tab_analysis)

        form_layout = QtWidgets.QGridLayout()
        form_layout.addWidget(QtWidgets.QLabel("任务类型"), 0, 0)
        form_layout.addWidget(self.ai_task_combo, 0, 1)
        form_layout.addWidget(QtWidgets.QLabel("文本输入"), 1, 0)
        form_layout.addWidget(self.ai_text_input, 1, 1, 2, 3)
        form_layout.addWidget(QtWidgets.QLabel("提示"), 3, 0)
        form_layout.addWidget(self.ai_hint_input, 3, 1, 1, 3)
        form_layout.addWidget(QtWidgets.QLabel("文件"), 4, 0)
        file_layout = QtWidgets.QHBoxLayout()
        file_layout.addWidget(self.ai_file_input)
        file_layout.addWidget(file_btn)
        form_layout.addLayout(file_layout, 4, 1, 1, 3)
        form_layout.addWidget(run_btn, 5, 3)

        task_split.addLayout(form_layout, 3)
        result_layout = QtWidgets.QVBoxLayout()
        result_layout.addWidget(QtWidgets.QLabel("结果"))
        result_layout.addWidget(self.ai_output, 1)
        task_split.addLayout(result_layout, 2)

        toggle_config_btn = QtWidgets.QPushButton("修改配置")
        toggle_config_btn.setFlat(True)
        toggle_config_btn.setMaximumWidth(120)

        def _toggle_config() -> None:
            vis = not config_group.isVisible()
            config_group.setVisible(vis)
            config_ready_hint.setVisible(not vis)
        toggle_config_btn.clicked.connect(_toggle_config)

        layout.addWidget(config_group)
        layout.addWidget(config_ready_hint)
        layout.addWidget(task_group)

        # 根据当前配置决定是否默认隐藏配置区域，放大分析区域
        if self._ai_config_ready():
            config_group.setVisible(False)
            config_ready_hint.setVisible(True)
        layout.addWidget(toggle_config_btn)

        layout.setStretchFactor(task_group, 1)
        return widget

    def _ai_config_ready(self) -> bool:
        provider = self.ai_config.provider
        cfg = self.ai_config.providers.get(provider)
        return bool(cfg and cfg.api_key)

    def _build_settings_tab(self) -> QtWidgets.QWidget:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout(widget)

        self.setting_auto = QtWidgets.QCheckBox("拖入自动分析")
        self.setting_auto.setChecked(self.settings.get("auto_analyze", True))

        self.setting_history = QtWidgets.QCheckBox("记录操作历史")
        self.setting_history.setChecked(self.settings.get("history", True))

        self.setting_sky_model = QtWidgets.QLineEdit(self.settings.get("sky_model", ""))
        self.setting_sky_model.setPlaceholderText("sky 模型名称（可选）")

        self.setting_text_auto = QtWidgets.QCheckBox("文本页自动识别编码")
        self.setting_text_auto.setChecked(self.settings.get("text_auto_detect", True))
        self.setting_text_multi = QtWidgets.QCheckBox("允许多次递归解码")
        self.setting_text_multi.setChecked(self.settings.get("text_multi_decode", True))
        self.setting_text_depth = QtWidgets.QSpinBox()
        self.setting_text_depth.setRange(1, 5)
        self.setting_text_depth.setValue(int(self.settings.get("text_decode_depth", 3)))

        ai_group = QtWidgets.QGroupBox("AI API 配置")
        ai_form = QtWidgets.QFormLayout(ai_group)
        self.ai_provider_combo = QtWidgets.QComboBox()
        self.ai_provider_combo.addItems(SUPPORTED_PROVIDERS)
        self.ai_provider_combo.setCurrentText(self.ai_config.provider)
        self.ai_api_key = QtWidgets.QLineEdit()
        self.ai_api_key.setEchoMode(QtWidgets.QLineEdit.Password)
        self.ai_api_key.setPlaceholderText("API Key（可留空使用环境变量）")
        self.ai_base_url = QtWidgets.QLineEdit()
        self.ai_base_url.setPlaceholderText("自定义 base_url（可选）")
        self.ai_endpoint = QtWidgets.QLineEdit()
        self.ai_endpoint.setPlaceholderText("自定义 endpoint/path（可选）")
        self.ai_model = QtWidgets.QLineEdit()
        self.ai_model.setPlaceholderText("模型名称，如 gpt-4o / claude-3-sonnet")
        self.ai_status = QtWidgets.QLabel("")
        self.ai_provider_combo.currentTextChanged.connect(self._load_ai_provider_fields)
        self._load_ai_provider_fields(self.ai_provider_combo.currentText())

        ai_form.addRow(QtWidgets.QLabel("服务商"), self.ai_provider_combo)
        ai_form.addRow(QtWidgets.QLabel("API Key"), self.ai_api_key)
        ai_form.addRow(QtWidgets.QLabel("base_url"), self.ai_base_url)
        ai_form.addRow(QtWidgets.QLabel("endpoint"), self.ai_endpoint)
        ai_form.addRow(QtWidgets.QLabel("模型名称"), self.ai_model)
        ai_form.addRow(QtWidgets.QLabel("状态"), self.ai_status)

        save_btn = QtWidgets.QPushButton("保存设置")
        save_btn.clicked.connect(self._save_settings)

        layout.addRow(self.setting_auto)
        layout.addRow(self.setting_history)
        layout.addRow(QtWidgets.QLabel("sky 模型"), self.setting_sky_model)
        layout.addRow(self.setting_text_auto)
        layout.addRow(self.setting_text_multi)
        layout.addRow(QtWidgets.QLabel("递归解码深度"), self.setting_text_depth)
        layout.addRow(QtWidgets.QLabel("AI 配置"), ai_group)
        layout.addRow(save_btn)
        return widget

    def _build_text_tab(self) -> QtWidgets.QWidget:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)

        self.input_edit = QtWidgets.QTextEdit()
        self.input_edit.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        self.output_edit = QtWidgets.QTextEdit()
        self.output_edit.setReadOnly(True)
        self.output_edit.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)

        op_layout = QtWidgets.QHBoxLayout()
        self.op_combo = QtWidgets.QComboBox()
        self.op_combo.addItems(
            [
                "base64 encode",
                "base64 decode",
                "base64url encode",
                "base64url decode",
                "base32 encode",
                "base32 decode",
                "base16 encode",
                "base16 decode",
                "base58 encode",
                "base58 decode",
                "base85 encode",
                "base85 decode",
                "url encode",
                "url decode",
                "html encode",
                "html decode",
                "rot13",
                "atbash",
                "caesar +3",
                "caesar -3",
                "morse encode",
                "morse decode",
                "railfence encrypt",
                "railfence decrypt",
                "reverse",
                "upper",
                "lower",
                "swapcase",
                "bacon encode",
                "bacon decode",
                "pigpen encode",
                "pigpen decode",
                "corevalues encode",
                "corevalues decode",
                "buddha encode",
                "buddha decode",
                "quoted-printable encode",
                "quoted-printable decode",
                "unicode encode",
                "unicode decode",
                "hex -> ascii",
                "bin -> ascii",
                "base convert",
            ]
        )

        self.baseconv_from = QtWidgets.QComboBox()
        self.baseconv_from.addItems(["2", "8", "10", "16"])
        self.baseconv_to = QtWidgets.QComboBox()
        self.baseconv_to.addItems(["2", "8", "10", "16"])

        run_btn = QtWidgets.QPushButton("执行")
        run_btn.clicked.connect(self._run_text_op)

        load_btn = QtWidgets.QPushButton("打开文件")
        load_btn.clicked.connect(self._load_file_into_input)

        auto_detect_btn = QtWidgets.QPushButton("自动识别解码")
        auto_detect_btn.clicked.connect(self._run_text_auto_detect)

        self.base_variant = QtWidgets.QComboBox()
        base_types = sorted(set(base_registry().keys()))
        self.base_variant.addItems(base_types)
        base_encode_btn = QtWidgets.QPushButton("Base 编码")
        base_decode_btn = QtWidgets.QPushButton("Base 解码")
        base_encode_btn.clicked.connect(lambda: self._run_base_section("encode"))
        base_decode_btn.clicked.connect(lambda: self._run_base_section("decode"))

        op_layout.addWidget(QtWidgets.QLabel("操作:"))
        op_layout.addWidget(self.op_combo, 1)
        op_layout.addWidget(QtWidgets.QLabel("进制 From/To"))
        op_layout.addWidget(self.baseconv_from)
        op_layout.addWidget(self.baseconv_to)
        op_layout.addWidget(run_btn)
        op_layout.addWidget(load_btn)
        op_layout.addWidget(auto_detect_btn)
        op_layout.addWidget(QtWidgets.QLabel("Base类型"))
        op_layout.addWidget(self.base_variant)
        op_layout.addWidget(base_encode_btn)
        op_layout.addWidget(base_decode_btn)

        layout.addLayout(op_layout)
        io_split = QtWidgets.QHBoxLayout()
        io_left = QtWidgets.QVBoxLayout()
        io_left.addWidget(QtWidgets.QLabel("输入"))
        io_left.addWidget(self.input_edit, 3)
        io_left.addWidget(QtWidgets.QLabel("输出"))
        io_left.addWidget(self.output_edit, 3)
        io_split.addLayout(io_left, 3)

        auto_layout = QtWidgets.QVBoxLayout()
        self.auto_detect_output = QtWidgets.QTextEdit()
        self.auto_detect_output.setReadOnly(True)
        self.auto_detect_output.setSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        auto_layout.addWidget(QtWidgets.QLabel("自动识别结果"))
        auto_layout.addWidget(self.auto_detect_output, 1)
        io_split.addLayout(auto_layout, 2)

        layout.addLayout(io_split)
        return widget

    def _build_crypto_tab(self) -> QtWidgets.QWidget:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QGridLayout(widget)

        self.crypto_input = QtWidgets.QTextEdit()
        self.crypto_output = QtWidgets.QTextEdit()
        self.crypto_output.setReadOnly(True)

        self.crypto_cipher = QtWidgets.QComboBox()
        self.crypto_cipher.addItems(["aes", "des"])
        self.crypto_mode = QtWidgets.QComboBox()
        self.crypto_mode.addItems(["encrypt", "decrypt"])
        self.crypto_key = QtWidgets.QLineEdit()
        self.crypto_key.setPlaceholderText("Key (hex/utf8/base64)")
        self.crypto_input_format = QtWidgets.QComboBox()
        self.crypto_input_format.addItems(["utf8", "hex", "base64"])
        self.crypto_output_format = QtWidgets.QComboBox()
        self.crypto_output_format.addItems(["hex", "utf8", "base64"])
        self.crypto_key_format = QtWidgets.QComboBox()
        self.crypto_key_format.addItems(["utf8", "hex", "base64"])

        run_btn = QtWidgets.QPushButton("执行")
        run_btn.clicked.connect(self._run_crypto_op)

        layout.addWidget(QtWidgets.QLabel("Cipher"), 0, 0)
        layout.addWidget(self.crypto_cipher, 0, 1)
        layout.addWidget(QtWidgets.QLabel("Mode"), 0, 2)
        layout.addWidget(self.crypto_mode, 0, 3)
        layout.addWidget(QtWidgets.QLabel("Key"), 1, 0)
        layout.addWidget(self.crypto_key, 1, 1, 1, 3)
        layout.addWidget(QtWidgets.QLabel("Input fmt"), 2, 0)
        layout.addWidget(self.crypto_input_format, 2, 1)
        layout.addWidget(QtWidgets.QLabel("Output fmt"), 2, 2)
        layout.addWidget(self.crypto_output_format, 2, 3)
        layout.addWidget(QtWidgets.QLabel("Key fmt"), 3, 0)
        layout.addWidget(self.crypto_key_format, 3, 1)
        layout.addWidget(run_btn, 3, 3)
        layout.addWidget(QtWidgets.QLabel("输入"), 4, 0, 1, 4)
        layout.addWidget(self.crypto_input, 5, 0, 1, 4)
        layout.addWidget(QtWidgets.QLabel("输出"), 6, 0, 1, 4)
        layout.addWidget(self.crypto_output, 7, 0, 1, 4)

        return widget

    def _build_file_tab(self) -> QtWidgets.QWidget:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)

        # 文件选择
        file_group = QtWidgets.QGroupBox("文件选择")
        file_form = QtWidgets.QGridLayout(file_group)
        self.file_path_edit = FileDropLineEdit()
        self.file_path_edit.setToolTip("支持拖拽，或粘贴/输入路径")
        self.file_path_edit.fileDropped.connect(self._load_file_preview)
        choose_btn = QtWidgets.QPushButton("选择文件")
        choose_btn.clicked.connect(self._choose_file_for_file_tab)
        file_hint = QtWidgets.QLabel("支持 ZIP/7Z/RAR/GIF/PNG 等，拖入后自动预览前 2KB。")
        file_hint.setStyleSheet("color: gray;")
        file_form.addWidget(QtWidgets.QLabel("路径"), 0, 0)
        file_form.addWidget(self.file_path_edit, 0, 1, 1, 3)
        file_form.addWidget(choose_btn, 0, 4)
        file_form.addWidget(file_hint, 1, 1, 1, 3)

        # 快捷操作
        action_group = QtWidgets.QGroupBox("快捷操作")
        action_layout = QtWidgets.QHBoxLayout(action_group)
        zip_btn = QtWidgets.QPushButton("检测ZIP伪加密")
        zip_btn.clicked.connect(self._run_zip_check)
        binwalk_btn = QtWidgets.QPushButton("Binwalk提取")
        binwalk_btn.clicked.connect(self._run_binwalk)
        ai_stego_btn = QtWidgets.QPushButton("AI 隐写建议")
        ai_stego_btn.clicked.connect(self._run_ai_stego_assist)
        for btn in [zip_btn, binwalk_btn, ai_stego_btn]:
            btn.setMinimumWidth(110)
        action_layout.addWidget(zip_btn)
        action_layout.addWidget(binwalk_btn)
        action_layout.addWidget(ai_stego_btn)
        action_layout.addStretch(1)

        # 预览与结果
        self.file_preview = QtWidgets.QTextEdit()
        self.file_preview.setReadOnly(True)
        self.stego_result = QtWidgets.QTextEdit()
        self.stego_result.setReadOnly(True)
        preview_group = QtWidgets.QGroupBox("文件预览")
        preview_layout = QtWidgets.QVBoxLayout(preview_group)
        preview_layout.addWidget(self.file_preview)
        result_group = QtWidgets.QGroupBox("结果输出")
        result_layout = QtWidgets.QVBoxLayout(result_group)
        result_layout.addWidget(self.stego_result)

        pane = QtWidgets.QHBoxLayout()
        pane.addWidget(preview_group, 1)
        pane.addWidget(result_group, 1)

        layout.addWidget(file_group)
        layout.addWidget(action_group)
        layout.addLayout(pane)

        return widget

    def _run_text_op(self) -> None:
        op = self.op_combo.currentText()
        text = self.input_edit.toPlainText()
        try:
            output = self._dispatch_text_op(op, text)
        except Exception as exc:  # pragma: no cover - GUI feedback
            output = f"错误: {exc}"
        self.output_edit.setPlainText(output)
        if self.settings.get("text_auto_detect", True):
            self._run_text_auto_detect()

    def _dispatch_text_op(self, op: str, text: str) -> str:
        mapping: Dict[str, Callable[[str], str]] = {
            "base64 encode": base64_encode,
            "base64 decode": base64_decode,
            "base64url encode": base64url_encode,
            "base64url decode": base64url_decode,
            "base32 encode": base32_encode,
            "base32 decode": base32_decode,
            "base16 encode": base16_encode,
            "base16 decode": base16_decode,
            "base58 encode": base58_encode,
            "base58 decode": base58_decode,
            "base85 encode": base85_encode,
            "base85 decode": base85_decode,
            "url encode": url_encode,
            "url decode": url_decode,
            "html encode": html_entity_encode,
            "html decode": html_entity_decode,
            "rot13": rot13,
            "atbash": atbash,
            "caesar +3": lambda t: caesar_shift(t, 3),
            "caesar -3": lambda t: caesar_shift(t, -3),
            "morse encode": morse_encode,
            "morse decode": morse_decode,
            "railfence encrypt": lambda t: rail_fence_encrypt(t, 3),
            "railfence decrypt": lambda t: rail_fence_decrypt(t, 3),
            "reverse": reverse_string,
            "upper": to_upper,
            "lower": to_lower,
            "swapcase": swap_case,
            "bacon encode": bacon_encode,
            "bacon decode": bacon_decode,
            "pigpen encode": pigpen_encode,
            "pigpen decode": pigpen_decode,
            "corevalues encode": core_values_encode,
            "corevalues decode": core_values_decode,
            "buddha encode": buddha_encode,
            "buddha decode": buddha_decode,
            "quoted-printable encode": quoted_printable_encode,
            "quoted-printable decode": quoted_printable_decode,
            "unicode encode": unicode_escape_encode,
            "unicode decode": unicode_escape_decode,
            "hex -> ascii": hex_to_ascii,
            "bin -> ascii": bin_to_ascii,
        }
        if op in mapping:
            return mapping[op](text)
        # base conversion separately
        from_base = int(self.baseconv_from.currentText())
        to_base = int(self.baseconv_to.currentText())
        return convert_base(text.strip(), from_base, to_base)

    def _run_crypto_op(self) -> None:
        text = self.crypto_input.toPlainText()
        key = self.crypto_key.text()
        cipher = self.crypto_cipher.currentText()
        mode = self.crypto_mode.currentText()
        input_fmt = self.crypto_input_format.currentText()
        output_fmt = self.crypto_output_format.currentText()
        key_fmt = self.crypto_key_format.currentText()
        try:
            if mode == "encrypt":
                result = encrypt_ecb(cipher, text, key, input_format=input_fmt, key_format=key_fmt, output_format=output_fmt)
            else:
                result = decrypt_ecb(cipher, text, key, input_format=input_fmt, key_format=key_fmt, output_format=output_fmt)
        except Exception as exc:  # pragma: no cover - GUI feedback
            result = f"错误: {exc}"
        self.crypto_output.setPlainText(result)

    def _run_zip_check(self) -> None:
        path = self.file_path_edit.text()
        if not path:
            self.stego_result.setPlainText("请选择文件")
            return
        try:
            findings = detect_zip_pseudo_encryption(path)
            lines = []
            for f in findings:
                lines.append(f"{f['filename']}: {f['status']} ({f['detail']})")
            self.stego_result.setPlainText("\n".join(lines))
        except Exception as exc:  # pragma: no cover - GUI feedback
            self.stego_result.setPlainText(f"错误: {exc}")

    def _run_binwalk(self) -> None:
        path = self.file_path_edit.text()
        if not path:
            self.stego_result.setPlainText("请选择文件")
            return
        try:
            out_dir = binwalk_extract(path)
            self.stego_result.setPlainText(f"提取完成: {out_dir}")
        except Exception as exc:  # pragma: no cover - GUI feedback
            self.stego_result.setPlainText(f"错误: {exc}")

    def _load_file_into_input(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择文件")
        if path:
            data = Path(path).read_bytes()
            guess = detect_encoding_via_file(Path(path))
            content = decode_bytes_best_effort(data, preferred_encoding=guess)
            self.input_edit.setPlainText(content)

    def _load_file_preview(self, path: str) -> None:
        try:
            content = Path(path).read_bytes()
            guess = detect_encoding_via_file(Path(path))
            self.file_preview.setPlainText(
                decode_bytes_best_effort(
                    content[:2048],
                    preferred_encoding=guess,
                    encodings=["utf-8", "gb18030", "big5", "shift_jis", "cp1252", "latin-1"],
                )
            )
        except Exception as exc:  # pragma: no cover - GUI feedback
            self.file_preview.setPlainText(f"无法读取文件: {exc}")

    def _choose_file_for_file_tab(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择文件")
        if path:
            self.file_path_edit.setText(path)
            self._load_file_preview(path)

    # -------- Auto solve --------
    def _auto_handle_file_drop(self, path: str) -> None:
        if not self.auto_toggle.isChecked():
            return
        self._auto_analyze_file(path)

    def _auto_analyze_input(self) -> None:
        text = self.auto_input.toPlainText()
        if text.strip():
            self._auto_analyze_text(text.strip())
        file_path = self.auto_file_drop.text().strip()
        if file_path:
            self._auto_analyze_file(file_path)

    # -------- Archive brute-force --------
    def _auto_analyze_text(self, text: str) -> None:
        lines = []
        lines.append("[文本探测]")
        lines.append(f"长度: {len(text)}")
        # Auto decode candidates
        candidates = auto_decode(text)
        if candidates:
            for method, result in candidates:
                lines.append(f"{method}: {result}")
        else:
            lines.append("未识别常见编码")
        # Hash brute force guesses
        for algo, hex_len in [("md5", 32), ("sha1", 40), ("sha256", 64)]:
            if len(text) == hex_len:
                guess = brute_force_hash(text, algo=algo)
                if guess:
                    lines.append(f"{algo} 弱口令: {guess}")
                    break
        self.auto_output.setPlainText("\n".join(lines))

    def _auto_analyze_file(self, path: str) -> None:
        lines = [f"[文件探测] {path}"]
        p = Path(path)
        suffix = p.suffix.lower()
        try:
            if suffix == ".zip":
                findings = detect_zip_pseudo_encryption(path)
                for f in findings:
                    lines.append(f"ZIP: {f['filename']} {f['status']} ({f['detail']})")
            if suffix == ".gif":
                frames = split_gif_frames(path)
                lines.append(f"GIF 帧分离: {len(frames)} 帧 -> {frames[:3]}{'...' if len(frames) > 3 else ''}")
            if suffix in [".png", ".bmp", ".jpg", ".jpeg", ".gif"]:
                if suffix == ".png":
                    try:
                        chunks = list_png_chunks(path)
                        lines.append(f"PNG Chunks: {chunks[:6]}{'...' if len(chunks) > 6 else ''}")
                    except Exception:
                        pass
                try:
                    exif = extract_exif(path)
                    if exif:
                        lines.append(f"EXIF 发现 {len(exif)} 项")
                except Exception:
                    pass
                try:
                    qr = decode_qr(path)
                    if qr:
                        lines.append(f"QR 解码: {qr}")
                except Exception:
                    pass
                try:
                    data = lsb_extract(path, bits=1, channels="R", max_bytes=8)
                    if data:
                        lines.append(f"LSB 提取(8字节 hex): {data.hex()}")
                except Exception:
                    pass
        except Exception as exc:  # pragma: no cover - GUI feedback
            lines.append(f"错误: {exc}")
        self.auto_output.setPlainText("\n".join(lines))

    def _run_ai_cipher_assist(self) -> None:
        text = self.auto_input.toPlainText().strip()
        if not text:
            self.auto_output.setPlainText("请输入文本后再调用 AI 辅助。")
            return
        try:
            data = ai_assist_cipher(text)
            self.auto_output.setPlainText(render_ai_result(data))
        except AIError as exc:  # pragma: no cover - GUI feedback
            self.auto_output.setPlainText(f"AI 调用失败: {exc}")

    def _run_ai_stego_assist(self) -> None:
        path = self.file_path_edit.text().strip()
        if not path:
            self.stego_result.setPlainText("请选择文件后再调用 AI 辅助。")
            return
        hint = self.file_preview.toPlainText()[:512]
        try:
            data = ai_assist_stego(path, extra=hint)
            self.stego_result.setPlainText(render_ai_result(data))
        except AIError as exc:  # pragma: no cover - GUI feedback
            self.stego_result.setPlainText(f"AI 调用失败: {exc}")

    # -------- Text auto-detect helpers --------
    def _run_text_auto_detect(self) -> None:
        text = self.input_edit.toPlainText().strip()
        if not text:
            self.auto_detect_output.setPlainText("请输入内容以识别编码")
            return
        lines: List[str] = ["[自动识别]"]
        depth = int(self.settings.get("text_decode_depth", 3))
        allow_recursive = self.settings.get("text_multi_decode", True)
        seen = {text}
        queue: List[Tuple[str, int]] = [(text, 0)]
        found_any = False
        while queue:
            current, level = queue.pop(0)
            if level >= depth:
                continue
            candidates = auto_decode(current)
            if candidates:
                for method, result in candidates:
                    prefix = "  " * level
                    lines.append(f"{prefix}{method}: {result}")
                    found_any = True
                    if allow_recursive and result not in seen:
                        seen.add(result)
                        queue.append((result, level + 1))
            elif level == 0 and not allow_recursive:
                break
            if not allow_recursive:
                break
        if not found_any:
            lines.append("未识别常见编码")
        self.auto_detect_output.setPlainText("\n".join(lines))

    def _run_base_section(self, mode: str) -> None:
        variant = self.base_variant.currentText()
        text = self.input_edit.toPlainText()
        try:
            if variant == "base58":
                output = base58_encode(text) if mode == "encode" else base58_decode(text)
            else:
                codecs = base_registry()
                enc, dec = codecs[variant]
                if mode == "encode":
                    output = enc(text.encode("utf-8", errors="replace"))
                else:
                    output = decode_bytes_best_effort(dec(text))
            self.output_edit.setPlainText(str(output))
        except Exception as exc:  # pragma: no cover - GUI feedback
            self.output_edit.setPlainText(f"错误: {exc}")

    def _ensure_setting_defaults(self) -> None:
        defaults = {
            "auto_analyze": True,
            "history": True,
            "sky_model": "",
            "text_auto_detect": True,
            "text_multi_decode": True,
            "text_decode_depth": 3,
        }
        for key, value in defaults.items():
            self.settings.setdefault(key, value)

    def _load_settings(self) -> Dict[str, object]:
        if SETTINGS_PATH.exists():
            try:
                return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_settings(self) -> None:
        self.settings["auto_analyze"] = self.setting_auto.isChecked()
        self.settings["history"] = self.setting_history.isChecked()
        self.settings["sky_model"] = self.setting_sky_model.text().strip()
        self.settings["text_auto_detect"] = self.setting_text_auto.isChecked()
        self.settings["text_multi_decode"] = self.setting_text_multi.isChecked()
        self.settings["text_decode_depth"] = self.setting_text_depth.value()
        try:
            SETTINGS_PATH.write_text(json.dumps(self.settings, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        self._save_ai_config()
        # sync toggles
        self.auto_toggle.setChecked(self.settings["auto_analyze"])

    def _load_ai_provider_fields(self, provider: str) -> None:
        cfg: ProviderConfig = self.ai_config.providers.get(provider, ProviderConfig())
        self.ai_api_key.setText(cfg.api_key)
        self.ai_base_url.setText(cfg.base_url)
        self.ai_endpoint.setText(cfg.endpoint)
        self.ai_model.setText(cfg.model)

    def _save_ai_config(self) -> None:
        provider = self.ai_provider_combo.currentText()
        cfg = self.ai_config.providers.get(provider, ProviderConfig())
        cfg.api_key = self.ai_api_key.text().strip()
        cfg.base_url = self.ai_base_url.text().strip()
        cfg.endpoint = self.ai_endpoint.text().strip()
        cfg.model = self.ai_model.text().strip()
        self.ai_config.providers[provider] = cfg
        self.ai_config.provider = provider
        try:
            save_ai_config(self.ai_config)
            self.ai_status.setText("AI 配置已保存")
        except Exception as exc:  # pragma: no cover - GUI feedback
            self.ai_status.setText(f"保存失败: {exc}")

    # -------- AI Tab helpers --------
    def _refresh_ai_models(self, provider: str) -> None:
        presets = {
            "openai": ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"],
            "anthropic": ["claude-3-5-sonnet", "claude-3-opus", "claude-3-sonnet-20240229"],
            "qianfan": ["ERNIE-Speed-128K", "ERNIE-Bot-4", "ERNIE-Lite-8K"],
            "qwen": ["qwen-turbo", "qwen-plus", "qwen-max"],
            "deepseek": ["deepseek-chat", "deepseek-coder"],
            "ollama": ["llama3", "qwen2", "mistral"],
        }
        self.ai_tab_model.blockSignals(True)
        self.ai_tab_model.clear()
        for model in presets.get(provider, []):
            self.ai_tab_model.addItem(model)
        self.ai_tab_model.setCurrentIndex(0 if self.ai_tab_model.count() else -1)
        self.ai_tab_model.blockSignals(False)

    def _handle_ai_provider_change(self, provider: str) -> None:
        self._refresh_ai_models(provider)
        self._load_ai_tab_fields(provider)
        # Keep settings tab provider in sync
        self.ai_provider_combo.setCurrentText(provider)

    def _load_ai_tab_fields(self, provider: str) -> None:
        cfg: ProviderConfig = self.ai_config.providers.get(provider, ProviderConfig())
        self.ai_tab_api_key.setText(cfg.api_key)
        self.ai_tab_base_url.setText(cfg.base_url)
        self.ai_tab_endpoint.setText(cfg.endpoint)
        if cfg.model:
            if self.ai_tab_model.findText(cfg.model) == -1:
                self.ai_tab_model.addItem(cfg.model)
            self.ai_tab_model.setCurrentText(cfg.model)

    def _save_ai_tab_config(self) -> None:
        provider = self.ai_tab_provider.currentText()
        cfg = self.ai_config.providers.get(provider, ProviderConfig())
        cfg.api_key = self.ai_tab_api_key.text().strip()
        cfg.base_url = self.ai_tab_base_url.text().strip()
        cfg.endpoint = self.ai_tab_endpoint.text().strip()
        cfg.model = self.ai_tab_model.currentText().strip()
        self.ai_config.providers[provider] = cfg
        self.ai_config.provider = provider
        # sync settings tab widgets
        self.ai_provider_combo.setCurrentText(provider)
        self.ai_api_key.setText(cfg.api_key)
        self.ai_base_url.setText(cfg.base_url)
        self.ai_endpoint.setText(cfg.endpoint)
        self.ai_model.setText(cfg.model)
        try:
            save_ai_config(self.ai_config)
            QtWidgets.QMessageBox.information(self, "AI 配置", "保存成功")
        except Exception as exc:  # pragma: no cover - GUI feedback
            QtWidgets.QMessageBox.warning(self, "AI 配置", f"保存失败: {exc}")

    def _clear_ai_key(self) -> None:
        self.ai_tab_api_key.clear()
        self._save_ai_tab_config()

    def _test_ai_connection(self) -> None:
        self._save_ai_tab_config()
        provider = self.ai_tab_provider.currentText()
        try:
            resp = call_ai_chat(
                [{"role": "user", "content": "ping"}],
                provider=provider,
                model=self.ai_tab_model.currentText().strip() or None,
                max_tokens=8,
                temperature=0,
            )
            QtWidgets.QMessageBox.information(self, "连通性测试", f"调用成功，返回: {resp[:200]}")
        except AIError as exc:  # pragma: no cover - GUI feedback
            QtWidgets.QMessageBox.warning(self, "连通性测试", str(exc))

    def _choose_ai_file(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择文件")
        if path:
            self.ai_file_input.setText(path)

    def _handle_ai_file_drop(self, path: str) -> None:
        self.ai_file_input.setText(path)
        if self.ai_task_combo.currentText() == "隐写建议":
            self._run_ai_tab_analysis()

    def _run_ai_tab_analysis(self) -> None:
        task = self.ai_task_combo.currentText()
        text = self.ai_text_input.toPlainText().strip()
        hint = self.ai_hint_input.text().strip()
        file_path = self.ai_file_input.text().strip()
        try:
            if task == "密文识别/解码":
                if not text:
                    raise ValueError("请先输入文本")
                data = ai_assist_cipher(text)
                action = "cipher"
            elif task == "哈希分析":
                if not text:
                    raise ValueError("请先输入文本")
                data = ai_assist_crypto(text, hint=hint)
                action = "crypto"
            else:
                if not file_path:
                    raise ValueError("请选择文件")
                # 传递文件预览作为补充上下文
                preview = self.file_preview.toPlainText()[:512] if hasattr(self, "file_preview") else ""
                extra = hint or preview
                data = ai_assist_stego(file_path, extra=extra)
                action = "stego"
            rendered = render_ai_result(data)
            self.ai_output.setPlainText(rendered)
            log_event(
                action="ai_assist",
                payload={"task": task, "provider": self.ai_tab_provider.currentText(), "file": file_path or None},
            )
        except AIError as exc:  # pragma: no cover - GUI feedback
            QtWidgets.QMessageBox.warning(self, "AI 调用失败", str(exc))
        except Exception as exc:  # pragma: no cover - GUI feedback
            QtWidgets.QMessageBox.warning(self, "输入错误", str(exc))


def run_gui() -> None:
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    run_gui()
