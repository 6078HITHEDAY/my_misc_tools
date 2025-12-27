# my_masic_tools · CTF Tools / CTF 工具箱

轻量级、模块化的 CTF 工具集，涵盖常见编码/经典密码、对称加密、隐写与弱口令爆破，提供 PyQt5 图形界面与 argparse 命令行两种入口。

## 快速开始
- 环境要求：Python 3.8+，`pip`；GUI 需要可用的图形环境。部分功能依赖系统工具：QR 解码需安装 zbar，Binwalk 提取需 `binwalk`。
- 安装
```bash
git clone <repo-url> my_masic_tools
cd my_masic_tools
python3 -m pip install -r requirements.txt
```
- 运行
```bash
# 启动 GUI
PYTHONPATH=src python3 -m ctf_tools.gui

# CLI 最简示例：Base64 解码
PYTHONPATH=src python3 -m ctf_tools base decode "ZmxhZw=="
```
- 更多用法：在 CLI 前缀 `PYTHONPATH=src`, 通过 `-m ctf_tools <command>` 调用；测试可运行 `PYTHONPATH=src python3 -m unittest discover -v -s tests`。

## 功能特性
- 编码与经典密码：Base16/32/58/64/85/91/92/100、Base45/62、URL、HTML 实体、Unicode escape、Caesar/ROT5/13/18/47/8000、Atbash、Vigenere、Morse、Rail Fence、Quoted-Printable、UUencode、Bacon、Pigpen、社会主义核心价值观 / 与佛论禅、自定义 Base 编解码。
- 加解密与哈希：AES/DES ECB/CBC（可配置密钥格式和 IV）、通用进制转换、MD5/SHA* 计算、弱口令哈希爆破、压缩包密码爆破（ZIP/7Z/RAR，支持字典/生成组合、进度回调、自动解压）。
- 隐写与文件工具：ZIP 伪加密检测、Binwalk 提取、图片 LSB 提取、GIF 帧分离、QR 解码、EXIF 信息、PNG Chunk 列表。
- 自动化与体验：自动识别常见编码，文本递归解码开关，拖拽文件自动分析，历史记录（可关闭），GUI 与 CLI 双入口。

## AI API 配置与辅助（OpenAI / Anthropic / 百度千帆 / Qwen / DeepSeek / Ollama）
- 配置文件：默认 `~/.ctf_tools_ai.json`，缺失字段会自动回落到环境变量（`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `QIANFAN_API_KEY` / `DASHSCOPE_API_KEY` / `DEEPSEEK_API_KEY` / `OLLAMA_BASE_URL` 等）。
- CLI 配置示例：`PYTHONPATH=src python3 -m ctf_tools ai-config --provider openai --api-key sk-*** --base-url https://api.openai.com/v1 --model gpt-4o --set-active`
- CLI AI 任务：`ai identify/decrypt/analyze`，如 `PYTHONPATH=src python3 -m ctf_tools ai identify --cipher "dGVzdA==" --provider deepseek --output result.txt`（支持 `--file` / `--hint` / `--api-key` 覆盖）。
- 兼容旧命令：`ai-assist cipher|crypto|stego` 仍可用。
- GUI：新增「AI 辅助解码」页可视化填写服务商、API Key、base_url/endpoint、模型名称（预置常用模型），提供保存/连通性测试/清空密钥按钮；文本/文件任务一键调用 AI；文件页也有“AI 隐写建议”。
