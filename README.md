# my_masic_tools · CTF Tools / CTF 工具箱

轻量级、模块化的 CTF 工具集，涵盖常见编码/经典密码、对称加密、隐写与弱口令爆破，提供 PyQt5 图形界面与 argparse 命令行两种入口。
## 正在完整中────
## 快速开始
- 环境要求：Python 3.8+，`pip`；GUI 需要可用的图形环境。部分功能依赖系统工具：QR 解码需安装 zbar，Binwalk 提取需 `binwalk`。
- 安装（推荐先建虚拟环境）
```bash
git clone <repo-url> my_masic_tools
cd my_masic_tools
# 可选：创建虚拟环境
python3 -m venv venv && source venv/bin/activate
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
- 加解密与哈希：AES/DES ECB/CBC（可配置密钥格式和 IV）、通用进制转换、MD5/SHA* 计算、弱口令哈希爆破。
- 隐写与文件工具：ZIP 伪加密检测、Binwalk 提取、图片 LSB 提取、GIF 帧分离、QR 解码、EXIF 信息、PNG Chunk 列表。
- 自动化与体验：自动识别常见编码（覆盖 Base16/32/45/58/62/85/91/URL/HTML/Unicode/ROT/Atbash/社会主义核心价值观/与佛论禅 等），文本递归解码开关，拖拽文件自动分析，历史记录（可关闭），GUI 与 CLI 双入口；文件/文本读取自动尝试 UTF-8/GB18030/Big5/Shift_JIS/CP1252/Latin-1，支持 `--encoding` 指定；GUI 文件工具页分组布局清晰。
- 反编译辅助：新增 CLI `pyi-unpack` 可解包 PyInstaller 可执行（提取 CArchive 与 PYZ），方便后续反编译。

## AI API 配置与辅助（OpenAI / Anthropic / 百度千帆 / Qwen / DeepSeek / Ollama）
- 配置文件：默认 `~/.ctf_tools_ai.json`，缺失字段会自动回落到环境变量（`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `QIANFAN_API_KEY` / `DASHSCOPE_API_KEY` / `DEEPSEEK_API_KEY` / `OLLAMA_BASE_URL` 等）。
- CLI 配置示例：`PYTHONPATH=src python3 -m ctf_tools ai-config --provider openai --api-key sk-*** --base-url https://api.openai.com/v1 --model gpt-4o --set-active`
- CLI AI 任务：`ai identify/decrypt/analyze`，如 `PYTHONPATH=src python3 -m ctf_tools ai identify --cipher "dGVzdA==" --provider deepseek --output result.txt`（支持 `--file` / `--hint` / `--api-key` 覆盖）。
- 兼容旧命令：`ai-assist cipher|crypto|stego` 仍可用。
- GUI：新增「AI 辅助解码」页可视化填写服务商、API Key、base_url/endpoint、模型名称（预置常用模型），提供保存/连通性测试/清空密钥按钮；文本/文件任务一键调用 AI；文件页也有“AI 隐写建议”。

## 开发进度
- 核心功能：编码/经典密码、AES/DES、哈希爆破、压缩包爆破（ZIP/7Z/RAR）、隐写工具已就绪，CLI 与 PyQt5 GUI 均可用。
- AI 功能：支持 OpenAI / Anthropic / 千帆 / Qwen / DeepSeek / Ollama，提供 CLI 与 GUI 配置入口。
- 自动化：`PYTHONPATH=src python3 -m unittest discover -v -s tests`（当前全部通过）。

## 开发计划
- 增补隐写与文件分析：扩展常见文件格式探测，增加图片/音频简单探针。
- AI 联动：补充不同 provider 的示例调用与容错提示。
- 交互优化：GUI 主题/布局微调，CLI 子命令示例与错误提示更友好。
- 打包发布：GitHub Actions 自动构建 deb / Flatpak / AppImage / Windows exe（见 `.github/workflows/package.yml`）。

## 再开发指南
1) 环境：Python 3.8+，`python3 -m venv venv && source venv/bin/activate`，再执行 `python3 -m pip install -r requirements.txt`。
2) 运行：`PYTHONPATH=src python3 -m ctf_tools.gui` 打开 GUI；CLI 示例 `PYTHONPATH=src python3 -m ctf_tools base decode "ZmxhZw=="`。
3) 测试：修改后跑 `PYTHONPATH=src python3 -m unittest discover -v -s tests` 确认通过。
4) 代码风格：保持现有模块化/函数式风格，新增功能请加少量注释便于快速理解；避免引入非必要依赖。
