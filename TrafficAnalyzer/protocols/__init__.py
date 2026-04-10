from TrafficAnalyzer.config import PROTOCOL_PARSER_PATHS
from TrafficAnalyzer.core.factory import build_instances
from TrafficAnalyzer.protocols.base import BaseProtocolParser
from TrafficAnalyzer.protocols.dns_parser import DNSProtocolParser
from TrafficAnalyzer.protocols.ftp_parser import FTPProtocolParser
from TrafficAnalyzer.protocols.http_parser import HTTPProtocolParser
from TrafficAnalyzer.protocols.modbus_parser import ModbusProtocolParser
from TrafficAnalyzer.protocols.tls_parser import TLSProtocolParser
from TrafficAnalyzer.protocols.usb_parser import USBProtocolParser


def build_protocol_parsers() -> list[BaseProtocolParser]:
    return build_instances(PROTOCOL_PARSER_PATHS)


__all__ = [
    "BaseProtocolParser",
    "FTPProtocolParser",
    "HTTPProtocolParser",
    "DNSProtocolParser",
    "TLSProtocolParser",
    "ModbusProtocolParser",
    "USBProtocolParser",
    "build_protocol_parsers",
]
