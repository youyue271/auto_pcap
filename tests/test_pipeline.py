import base64
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
    def test_default_attack_registry_only_runs_remaining_attack_modules(self):
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

        self.assertEqual(report.packet_count, len(packets))
        self.assertEqual(report.alerts, [])
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

    def test_webshell_detector_collects_generic_metadata_from_sample(self):
        service = build_default_pipeline_service()
        report = service.analyze_file(
            "tests/buuctf/atta.pcapng",
            enabled_protocols=[],
            enabled_attacks=["WebShellDetector"],
        )

        self.assertNotIn("WebShell", report.stats["protocol_distribution"])
        evidences = [alert.evidence for alert in report.alerts]

        self.assertTrue(any(item.get("family_hint") == "assert_loader" for item in evidences if item.get("stage") == "request"))
        self.assertTrue(
            any("pass:base64/php" in str(item.get("encoded_artifact_summary")) for item in evidences if item.get("stage") == "request")
        )
        self.assertTrue(any(item.get("response_marker") == "x_at_y" for item in evidences if item.get("stage") == "response"))

    def test_webshell_detector_extracts_encoded_artifacts_from_eval_loader_request(self):
        service = build_default_pipeline_service()
        action_payload = base64.b64encode(b"@eval($_POST[aa]);").decode("ascii")
        path_payload = base64.b64encode(b"D:\\wamp64\\www\\upload\\").decode("ascii")
        jpeg_hex = "FFD8FFE000104A46494600010101000000000000" + ("AA" * 40)
        packet = PacketRecord(
            index=1,
            timestamp=1.0,
            flow_id="flow-1",
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=50000,
            dst_port=80,
            proto="6",
            layers=["ip", "tcp", "http"],
            raw={
                "http": {
                    "request_method": "POST",
                    "host": "example.test",
                    "request_uri": "/upload/1.php",
                    "content_type": "application/x-www-form-urlencoded",
                    "file_data": (
                        "aa=@eval(base64_decode($_POST[action]));"
                        f"&action={action_payload}"
                        f"&z1={path_payload}"
                        f"&z2={jpeg_hex}"
                    ),
                }
            },
        )

        report = service.analyze_packets(
            [packet],
            source="unit-test",
            enabled_protocols=[],
            enabled_attacks=["WebShellDetector"],
        )
        detail = report.stats["attack_detailed_views"]["WebShellDetector"]
        records = detail["records"]
        evidence = report.alerts[0].evidence

        self.assertEqual(len(records), 1)
        self.assertEqual(evidence["family_hint"], "eval_loader")
        self.assertEqual(records[0]["family_variant"], "china_chopper_like")
        self.assertEqual(records[0]["possible_webshell"], "可能是中国菜刀类 PHP WebShell")
        self.assertIn("@eval($_POST[aa]);", records[0]["php_script"])
        self.assertIn("packet=1", records[0]["log_output"])
        self.assertIn("可能是中国菜刀类 PHP WebShell", detail["detected_webshells"])
        self.assertTrue(any("@eval($_POST[aa]);" in item for item in detail["php_scripts"]))
        self.assertIn("action:base64/php", evidence["encoded_artifact_summary"])
        self.assertIn("z1:base64/text", evidence["encoded_artifact_summary"])
        self.assertIn("z2:hex/jpeg", evidence["encoded_artifact_summary"])

    def test_http_detail_links_requests_and_exposes_top_lists_from_ljrhg_sample(self):
        service = build_default_pipeline_service()
        report = service.analyze_file(
            "tests/陇剑rhg/1.pcapng",
            enabled_protocols=["HTTP"],
            enabled_attacks=[],
        )

        detail = report.stats["detailed_views"]["HTTP"]
        requests = detail["requests"]

        self.assertGreater(detail["request_count"], 20000)
        self.assertGreater(len(requests), 50)
        self.assertNotIn("json_records", detail)
        self.assertIn("top_hosts", detail)
        self.assertIn("top_paths", detail)
        self.assertGreater(detail.get("top_hosts_total", 0), 0)
        self.assertGreater(detail.get("top_paths_total", 0), 0)
        self.assertLessEqual(len(detail["top_hosts"]), 200)
        self.assertLessEqual(len(detail["top_paths"]), 200)

        request_row = next(item for item in requests if item.get("direction") == "request" and item.get("uri") == "/api/v1/user/1")
        response_row = next(item for item in requests if item.get("direction") == "response" and item.get("uri") == "/api/v1/user/1")
        heartbeat_row = next(item for item in requests if item.get("direction") == "response" and item.get("uri") == "/ECAgent/?op=__check_alive__")

        self.assertEqual(request_row["linked_packet_index"], response_row["packet_index"])
        self.assertEqual(response_row["linked_packet_index"], request_row["packet_index"])
        self.assertEqual(response_row["request_packet_index"], request_row["packet_index"])
        self.assertEqual(request_row["response_packet_index"], response_row["packet_index"])
        self.assertEqual(response_row["status_code"], "200")
        self.assertIn("request_id", str(response_row.get("payload_preview") or ""))
        self.assertIn("__check_alive__", str(heartbeat_row.get("payload_preview") or ""))

    def test_http_details_expose_status_codes_and_site_pages(self):
        service = build_default_pipeline_service()
        packets = [
            PacketRecord(
                index=0,
                timestamp=1.0,
                flow_id="flow-http-1",
                src_ip="10.10.10.20",
                dst_ip="192.168.0.10",
                src_port=50000,
                dst_port=80,
                proto="6",
                layers=["ip", "tcp", "http"],
                raw={
                    "http": {
                        "request_method": "GET",
                        "host": "demo.local",
                        "request_uri": "/admin",
                        "response_in": "2",
                    }
                },
            ),
            PacketRecord(
                index=1,
                timestamp=1.1,
                flow_id="flow-http-1",
                src_ip="192.168.0.10",
                dst_ip="10.10.10.20",
                src_port=80,
                dst_port=50000,
                proto="6",
                layers=["ip", "tcp", "http"],
                raw={
                    "http": {
                        "response_code": "200",
                        "content_type": "text/html; charset=UTF-8",
                        "file_data": "<html><body>admin</body></html>",
                        "request_in": "1",
                    }
                },
            ),
            PacketRecord(
                index=2,
                timestamp=2.0,
                flow_id="flow-http-1",
                src_ip="10.10.10.20",
                dst_ip="192.168.0.10",
                src_port=50000,
                dst_port=80,
                proto="6",
                layers=["ip", "tcp", "http"],
                raw={
                    "http": {
                        "request_method": "GET",
                        "host": "demo.local",
                        "request_uri": "/missing",
                        "response_in": "4",
                    }
                },
            ),
            PacketRecord(
                index=3,
                timestamp=2.1,
                flow_id="flow-http-1",
                src_ip="192.168.0.10",
                dst_ip="10.10.10.20",
                src_port=80,
                dst_port=50000,
                proto="6",
                layers=["ip", "tcp", "http"],
                raw={
                    "http": {
                        "response_code": "404",
                        "content_type": "text/html",
                        "file_data": "<html><body>missing</body></html>",
                        "request_in": "3",
                    }
                },
            ),
        ]

        report = service.analyze_packets(
            packets,
            source="unit-test",
            enabled_protocols=["HTTP"],
            enabled_attacks=[],
        )

        detail = report.stats["detailed_views"]["HTTP"]
        status_codes = dict(detail.get("top_status_codes") or [])
        site_pages = detail.get("site_pages") or []

        self.assertEqual(status_codes.get("200"), 1)
        self.assertEqual(status_codes.get("404"), 1)
        self.assertEqual(detail.get("top_status_codes_total"), 2)
        self.assertEqual(detail.get("site_pages_total"), 1)
        self.assertEqual(detail.get("site_pages_exported"), 0)
        self.assertEqual(detail.get("site_hosts_total"), 1)
        self.assertEqual(len(site_pages), 1)
        self.assertEqual(site_pages[0]["server_ip"], "192.168.0.10")
        self.assertEqual(site_pages[0]["host"], "demo.local")
        self.assertEqual(site_pages[0]["uri_path"], "/admin")
        self.assertEqual(site_pages[0]["response_packet_index"], 1)
        self.assertIsNone(site_pages[0].get("url"))

    def test_webshell_detector_identifies_atta1_as_china_chopper_like_http_traffic(self):
        service = build_default_pipeline_service()
        report = service.analyze_file(
            "tests/buuctf/atta1.pcapng",
            enabled_protocols=[],
            enabled_attacks=["WebShellDetector"],
        )

        detail = report.stats["attack_detailed_views"]["WebShellDetector"]
        records = detail["records"]
        rule_ids = {alert.rule_id for alert in report.alerts}
        top_operations = dict(detail.get("top_operations") or [])
        commands = [str(item.get("interaction_command") or "") for item in records]
        logs = [str(item.get("log_output") or "") for item in records]
        php_scripts = [str(item.get("php_script") or "") for item in records]
        response_evidences = [alert.evidence for alert in report.alerts if alert.evidence.get("stage") == "response"]
        command_section = detail.get("interaction_commands") or []
        log_section = detail.get("log_entries") or []
        script_section = detail.get("php_scripts") or []

        self.assertIn("ATTACK.WEBSHELL.CHINA_CHOPPER_LIKE", rule_ids)
        self.assertTrue(all(item.get("possible_webshell") == "可能是中国菜刀类 PHP WebShell" for item in records))
        self.assertTrue(any("> pwd" in item for item in commands))
        self.assertTrue(any("> ls " in item or item.startswith("> ls") for item in commands))
        self.assertTrue(any("> upload " in item for item in commands))
        self.assertTrue(any("> cat " in item for item in commands))
        self.assertTrue(any(item.get("response_marker") == "arrow_pipe" for item in response_evidences))
        self.assertGreater(top_operations.get("probe_environment", 0), 0)
        self.assertGreater(top_operations.get("list_directory", 0), 0)
        self.assertGreater(top_operations.get("write_file", 0), 0)
        self.assertGreater(top_operations.get("read_file", 0), 0)
        self.assertTrue(any("D:/wamp64/www/upload" in item for item in commands))
        self.assertTrue(any("flag.txt" in item for item in commands))
        self.assertTrue(any("1.php" in item and "@eval($_POST[aa]);" in item for item in commands))
        self.assertTrue(any("export_url=/artifacts/" in item for item in logs))
        self.assertTrue(any("6666.jpg" in item for item in logs))
        self.assertTrue(any("hello.zip" in item for item in logs))
        self.assertTrue(any("archive_members=flag.txt [encrypted]" in item for item in logs))
        self.assertTrue(any("@ini_set" in item for item in php_scripts))
        self.assertTrue(any("> pwd" in item for item in command_section))
        self.assertTrue(any("> ls " in item or item.startswith("> ls") for item in command_section))
        self.assertTrue(any("> upload " in item for item in command_section))
        self.assertTrue(any("> cat " in item for item in command_section))
        self.assertTrue(any("export_url=/artifacts/" in item for item in log_section))
        self.assertTrue(any("archive_members=flag.txt [encrypted]" in item for item in log_section))
        self.assertTrue(any("@ini_set" in item for item in script_section))

    def test_webshell_detector_identifies_flag_pcap_as_godzilla_like_http_traffic(self):
        if not os.path.exists("tests/陇剑rhg/flag.pcapng"):
            self.skipTest("缺少 tests/陇剑rhg/flag.pcapng 样本")
        service = build_default_pipeline_service()
        report = service.analyze_file(
            "tests/陇剑rhg/flag.pcapng",
            enabled_protocols=[],
            enabled_attacks=["WebShellDetector"],
        )

        detail = report.stats["attack_detailed_views"]["WebShellDetector"]
        records = detail["records"]
        rule_ids = {alert.rule_id for alert in report.alerts}
        commands = [str(item.get("interaction_command") or "") for item in records]
        logs = [str(item.get("log_output") or "") for item in records]
        scripts = [str(item.get("php_script") or "") for item in records]
        supported = detail.get("supported_webshell_types") or []

        self.assertIn("ATTACK.WEBSHELL.GODZILLA_LIKE", rule_ids)
        self.assertIn("中国菜刀类 PHP WebShell", supported)
        self.assertIn("哥斯拉类 PHP WebShell", supported)
        self.assertTrue(any(item.get("possible_webshell") == "可能是哥斯拉类 PHP WebShell" for item in records))
        self.assertGreaterEqual(len(records), 8)
        self.assertTrue(any("> pwd" in item and "/app" in item for item in commands))
        self.assertTrue(any("> cd /app" in item and "> ls" in item and "seCr3t.php" in item for item in commands))
        self.assertTrue(any("> echo \"part2!@#\"" in item and "part2!@#" in item for item in commands))
        self.assertTrue(any("> cat something" in item and "The_Last_Part_U_Fin3" in item for item in commands))
        self.assertTrue(any('crypto=raw-body marker + base64 + XOR(key=e10adc39) + zlib' in item for item in logs))
        self.assertTrue(any("marker_p=vkzJl2VQbzhPhLHS" in item for item in logs))
        self.assertTrue(any("@eval(@gzuncompress(@x(@base64_decode($m[1]),$k)))" in item for item in scripts))

    def test_webshell_detector_identifies_cookie_exec_shell_in_ljrhg_2_sample(self):
        if not os.path.exists("tests/陇剑rhg/2.pcapng"):
            self.skipTest("缺少 tests/陇剑rhg/2.pcapng 样本")
        service = build_default_pipeline_service()
        report = service.analyze_file(
            "tests/陇剑rhg/2.pcapng",
            enabled_protocols=[],
            enabled_attacks=["WebShellDetector"],
        )

        detail = report.stats["attack_detailed_views"]["WebShellDetector"]
        records = detail["records"]
        commands = [str(item.get("interaction_command") or "") for item in records]
        logs = [str(item.get("log_output") or "") for item in records]
        scripts = [str(item.get("php_script") or "") for item in records]
        supported = detail.get("supported_webshell_types") or []
        labels = [str(item.get("possible_webshell") or "") for item in records]

        self.assertIn("Cookie 命令执行类 PHP WebShell", supported)
        self.assertTrue(any(label == "可能是Cookie 命令执行类 PHP WebShell" for label in labels))
        self.assertTrue(any("> id" in item and ("uid=" in item or "不是内部或外部命令" in item) for item in commands))
        self.assertTrue(any("> dir" in item and "shell.php" in item and "key.zip" in item for item in commands))
        self.assertTrue(any("> systeminfo" in item for item in commands))
        self.assertTrue(any("> tasklist /SVC" in item for item in commands))
        self.assertTrue(any("request_cookie=cm" in item for item in logs))
        self.assertTrue(any("response_cookie=M-cookie" in item for item in logs))
        self.assertTrue(any("base64_decode($_COOKIE['cm'])" in item for item in scripts))
        self.assertTrue(any(label.startswith("可能是哥斯拉类 PHP WebShell") for label in labels))


if __name__ == "__main__":
    unittest.main()
