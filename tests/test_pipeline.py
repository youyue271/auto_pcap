import os
import sys
import unittest

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from TrafficAnalyzer.core.models import PacketRecord
from TrafficAnalyzer.benchmarks.lazy_parse import build_parser as build_benchmark_parser
from TrafficAnalyzer.parsers.packet_parser import PacketParser
from TrafficAnalyzer.pipeline.service import build_default_pipeline_service


class TestPipelineService(unittest.TestCase):
    def test_sqli_and_port_scan_detection(self):
        service = build_default_pipeline_service()

        packets = []
        base_ts = 100.0
        for idx, port in enumerate(range(1000, 1012)):
            packets.append(
                PacketRecord(
                    index=idx,
                    timestamp=base_ts + (idx * 0.1),
                    flow_id=f"10.0.0.5:{port}-192.168.1.10:80-6",
                    src_ip="10.0.0.5",
                    dst_ip="192.168.1.10",
                    src_port=50000 + idx,
                    dst_port=port,
                    proto="6",
                    layers=["ip", "tcp"],
                )
            )

        packets.append(
            PacketRecord(
                index=99,
                timestamp=120.0,
                flow_id="10.0.0.8:51111-192.168.1.20:80-6",
                src_ip="10.0.0.8",
                dst_ip="192.168.1.20",
                src_port=51111,
                dst_port=80,
                proto="6",
                layers=["ip", "tcp", "http"],
                raw={
                    "http": {
                        "request_method": "GET",
                        "request_uri": "/login.php?id=1%27+or+1%3D1+union+select+1,2--",
                        "host": "example.com",
                    }
                },
            )
        )

        report = service.analyze_packets(packets, source="unit-test")
        rule_ids = {alert.rule_id for alert in report.alerts}

        self.assertEqual(report.packet_count, len(packets))
        self.assertIn("ATTACK.PORT_SCAN", rule_ids)
        self.assertIn("ATTACK.SQL_INJECTION", rule_ids)
        self.assertGreaterEqual(report.stats["protocol_event_count"], 1)
        self.assertIn("debug", report.stats)
        self.assertIn("stage_ms", report.stats["debug"])
        self.assertIn("packet_read", report.stats["debug"]["stage_ms"])

    def test_module_selection_and_http_details(self):
        service = build_default_pipeline_service()

        packets = [
            PacketRecord(
                index=1,
                timestamp=1.0,
                flow_id="1",
                src_ip="10.1.1.1",
                dst_ip="10.1.1.2",
                src_port=50000,
                dst_port=80,
                proto="6",
                layers=["ip", "tcp", "http"],
                raw={
                    "http": {
                        "request_method": "GET",
                        "host": "example.org",
                        "request_uri": "/index.php?id=1",
                        "user_agent": "ua-test",
                        "content_type": "text/html",
                    }
                },
            ),
            PacketRecord(
                index=2,
                timestamp=2.0,
                flow_id="2",
                src_ip="10.2.2.1",
                dst_ip="10.2.2.2",
                src_port=55555,
                dst_port=502,
                proto="6",
                layers=["ip", "tcp", "mbtcp"],
                raw={"mbtcp": {"func_code": "03"}},
            ),
        ]

        report = service.analyze_packets(
            packets,
            source="unit-test",
            enabled_protocols=["HTTP"],
            enabled_attacks=[],
        )

        stats = report.stats
        self.assertEqual(stats["selected_modules"]["protocols"], ["HTTP"])
        self.assertEqual(stats["selected_modules"]["attacks"], [])
        self.assertEqual(stats["protocol_distribution"], {"HTTP": 1})
        self.assertIn("HTTP", stats["detailed_views"])
        self.assertNotIn("Modbus", stats["detailed_views"])

    def test_fast_packet_parser_smoke(self):
        parser = PacketParser(mode="fast")
        packets = list(parser.parse_file("tests/file.pcapng"))

        self.assertGreater(len(packets), 0)
        self.assertIsNotNone(packets[0].timestamp)
        self.assertTrue(any(packet.layers for packet in packets))
        self.assertTrue(any(packet.proto is not None for packet in packets))

    def test_benchmark_cli_parser_exists(self):
        parser = build_benchmark_parser()
        args = parser.parse_args(["tests/file.pcapng"])
        self.assertEqual(args.pcaps, ["tests/file.pcapng"])
        self.assertIsNotNone(args.workers)


if __name__ == "__main__":
    unittest.main()
