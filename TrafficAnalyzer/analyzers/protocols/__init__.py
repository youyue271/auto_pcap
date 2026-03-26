from TrafficAnalyzer.protocols.base import BaseProtocolParser
from TrafficAnalyzer.protocols.dns_parser import DNSProtocolParser
from TrafficAnalyzer.protocols.http_parser import HTTPProtocolParser
from TrafficAnalyzer.protocols.modbus_parser import ModbusProtocolParser
from TrafficAnalyzer.protocols.tls_parser import TLSProtocolParser


def build_protocol_parsers() -> list[BaseProtocolParser]:
    return [
        HTTPProtocolParser(),
        DNSProtocolParser(),
        TLSProtocolParser(),
        ModbusProtocolParser(),
    ]
