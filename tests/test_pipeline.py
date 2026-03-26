import os
import sys
import unittest

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from TrafficAnalyzer.core.models import PacketRecord
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


if __name__ == "__main__":
    unittest.main()
