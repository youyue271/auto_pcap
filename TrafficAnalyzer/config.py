# Threshold for switching to SQLite storage (in bytes)
# Default: 100MB. If pcap size > this, use SQLite.
LARGE_PCAP_THRESHOLD = 100 * 1024 * 1024
PARALLEL_PARSE_MAX_WORKERS = 8

WIRESHARK_FAST_PATH_COMMAND = "tshark"
WIRESHARK_SPLIT_COMMANDS = ("editcap", "capinfos")

PROTOCOL_PARSER_PATHS = (
    "TrafficAnalyzer.protocols.http_parser.HTTPProtocolParser",
    "TrafficAnalyzer.protocols.dns_parser.DNSProtocolParser",
    "TrafficAnalyzer.protocols.tls_parser.TLSProtocolParser",
    "TrafficAnalyzer.protocols.modbus_parser.ModbusProtocolParser",
    "TrafficAnalyzer.protocols.usb_parser.USBProtocolParser",
)

ATTACK_DETECTOR_PATHS = (
    "TrafficAnalyzer.attacks.webshell_detector.WebShellDetector",
    "TrafficAnalyzer.attacks.sql_injection_detector.SQLInjectionDetector",
)

# Detector configurations keyed by current detector class name.
DETECTOR_CONFIGS = {
    "WebShellDetector": {},
    "SQLInjectionDetector": {},
}

# Backward-compatible alias for earlier naming in the project.
ANALYZER_CONFIGS = DETECTOR_CONFIGS
