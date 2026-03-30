# TrafficAnalyzer

面向 PCAP 的三阶段流量分析框架（Demo -> 可扩展骨架）。

## 架构

1. 包解析 (Packet Parsing)  
`TrafficAnalyzer/parsers/packet_parser.py`  
读取 pcap/pcapng，统一转为 `PacketRecord`。

2. 协议解析 (Protocol Parsing)  
`TrafficAnalyzer/protocols/*`  
按插件匹配并提取协议事件，当前内置: HTTP / DNS / TLS / Modbus。

3. 攻击分析 (Attack Detection)  
`TrafficAnalyzer/attacks/*`  
按规则引擎分析协议事件与包行为，当前内置: 端口扫描 / SQL注入 / 冰蝎(启发式)。

4. Web 任务执行模型 (Chunk + Local DB + Parallel Module Workers)  
`TrafficAnalyzer/web/job_manager.py`  
上传文件分块落盘，解析阶段按批写入本地 SQLite，模块阶段按模块并行执行；移除模块时会立即终止对应执行进程。
大文件会自动先切分成多个 PCAP 分片，再并行解析后合并结果。

5. Fast Parse 模式  
`TrafficAnalyzer/parsers/packet_parser.py`  
默认走 `tshark -T fields` 轻量字段流，只按协议需求补拉字段；需要时可显式切换到 `PacketParser(mode="pyshark")` 做全量解析。

6. Demo Benchmark 已接入 CLI  
`TrafficAnalyzer/benchmarks/lazy_parse.py`  
可直接通过 `benchmark` 子命令跑全量解析 vs 懒加载解析对比，脚本版 `scripts/demo_lazy_parse_benchmark.py` 仍可单独执行。

## 快速启动

```bash
python3.10 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### 系统依赖

项目的 fast path 和大文件切分依赖 Wireshark CLI 工具。至少需要以下命令在 `PATH` 中可用：

- `tshark`
- `editcap`
- `capinfos`

如果系统里没有这些命令，`PacketParser` 会退回到 `pyshark`，但大文件切分与部分性能优化不会生效。

建议后续统一使用虚拟环境内解释器（即 Python 3.10）执行：

```bash
.venv/bin/python -m TrafficAnalyzer.main --help
```

### CLI 分析

```bash
.venv/bin/python -m TrafficAnalyzer.main doctor
.venv/bin/python -m TrafficAnalyzer.main analyze tests/file.pcapng
.venv/bin/python -m TrafficAnalyzer.main analyze tests/file.pcapng --json
.venv/bin/python -m TrafficAnalyzer.main benchmark tests/Modbus.pcap tests/file.pcapng
```

建议先运行一次 `doctor`，确认 `tshark / editcap / capinfos / pyshark` 等依赖是否齐全。

### Web UI

```bash
.venv/bin/python -m TrafficAnalyzer.main web --host 0.0.0.0 --port 8000
```

浏览器访问 `http://127.0.0.1:8000` 上传 pcap 文件进行分析。

## 扩展方式

- 新增协议解析器: 继承 `BaseProtocolParser`
- 新增攻击检测器: 继承 `BaseAttackDetector`
- 在 `build_protocol_parsers()` / `build_attack_detectors()` 中注册
