# Threshold for switching to SQLite storage (in bytes)
# Default: 100MB. If pcap size > this, use SQLite.
LARGE_PCAP_THRESHOLD = 100 * 1024 * 1024

WIRESHARK_FAST_PATH_COMMAND = "tshark"
WIRESHARK_SPLIT_COMMANDS = ("editcap", "capinfos")

PROTOCOL_PARSER_PATHS = (
    "TrafficAnalyzer.protocols.http_parser.HTTPProtocolParser",
    "TrafficAnalyzer.protocols.dns_parser.DNSProtocolParser",
    "TrafficAnalyzer.protocols.tls_parser.TLSProtocolParser",
    "TrafficAnalyzer.protocols.modbus_parser.ModbusProtocolParser",
)

ATTACK_DETECTOR_PATHS = (
    "TrafficAnalyzer.attacks.port_scan_detector.PortScanDetector",
    "TrafficAnalyzer.attacks.sql_injection_detector.SQLInjectionDetector",
    "TrafficAnalyzer.attacks.behinder_detector.BehinderDetector",
)

# Detector configurations keyed by current detector class name.
DETECTOR_CONFIGS = {
    "PortScanDetector": {
        "threshold": 10,
        "time_window": 5.0,
    },
    "SQLInjectionDetector": {},
    "BehinderDetector": {},
}

# Backward-compatible alias for earlier naming in the project.
ANALYZER_CONFIGS = DETECTOR_CONFIGS
