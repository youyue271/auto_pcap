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

## 快速启动

```bash
python3 -m pip install -r requirements.txt
```

### CLI 分析

```bash
python3 -m TrafficAnalyzer.main analyze tests/file.pcapng
python3 -m TrafficAnalyzer.main analyze tests/file.pcapng --json
```

### Web UI

```bash
python3 -m TrafficAnalyzer.main web --host 0.0.0.0 --port 8000
```

浏览器访问 `http://127.0.0.1:8000` 上传 pcap 文件进行分析。

## 扩展方式

- 新增协议解析器: 继承 `BaseProtocolParser`
- 新增攻击检测器: 继承 `BaseAttackDetector`
- 在 `build_protocol_parsers()` / `build_attack_detectors()` 中注册
