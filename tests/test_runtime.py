import unittest
from unittest.mock import patch

from TrafficAnalyzer.attacks import build_attack_detectors
from TrafficAnalyzer.core.loader import PcapLoader, _parse_capinfos_packet_count
from TrafficAnalyzer.core.models import PacketRecord
from TrafficAnalyzer.main import build_parser
from TrafficAnalyzer.protocols import build_protocol_parsers
from TrafficAnalyzer.runtime import format_runtime_report, runtime_report_dict, validate_runtime
from TrafficAnalyzer.web.job_manager import AnalysisJob, JobManager, _parse_packet_chunk


class TestRegistryAndRuntime(unittest.TestCase):
    def test_parse_capinfos_packet_count(self):
        self.assertEqual(_parse_capinfos_packet_count("tests/file.pcapng\t7106"), 7106)
        self.assertEqual(_parse_capinfos_packet_count("7106"), 7106)

    @patch("TrafficAnalyzer.core.loader.subprocess.check_output")
    def test_pcap_loader_packet_count(self, mock_check_output):
        mock_check_output.return_value = "tests/file.pcapng\t2048\n"
        count, estimated = PcapLoader("tests/file.pcapng").get_packet_count()
        self.assertEqual(count, 2048)
        self.assertFalse(estimated)

    @patch("TrafficAnalyzer.web.job_manager.PacketParser")
    def test_parse_packet_chunk_reports_progress_incrementally(self, mock_parser_cls):
        parser = mock_parser_cls.return_value
        parser.parse_file.return_value = iter(
            [
                PacketRecord(index=i, timestamp=float(i), flow_id=str(i))
                for i in range(5)
            ]
        )

        progress_deltas: list[int] = []
        result = _parse_packet_chunk(
            "sample.pcap",
            progress_callback=progress_deltas.append,
            progress_interval=2,
        )

        self.assertEqual(result["packet_count"], 5)
        self.assertEqual(progress_deltas, [2, 2, 1])

    def test_protocol_registry_build_order(self):
        parsers = build_protocol_parsers()
        self.assertEqual([parser.name for parser in parsers], ["HTTP", "DNS", "TLS", "Modbus"])

    def test_attack_registry_uses_detector_config(self):
        detectors = build_attack_detectors()
        port_scan = next(detector for detector in detectors if detector.name == "PortScanDetector")
        self.assertEqual(port_scan.threshold, 10)
        self.assertEqual(port_scan.time_window, 5.0)

    def test_doctor_command_exists(self):
        parser = build_parser()
        args = parser.parse_args(["doctor", "--json"])
        self.assertTrue(args.json)
        self.assertIsNotNone(args.func)

    def test_validate_runtime_warns_when_only_fast_path_is_missing(self):
        snapshot = {
            "commands": {"tshark": False, "editcap": False, "capinfos": False},
            "modules": {
                "pyshark": True,
                "uvicorn": True,
                "fastapi": True,
                "jinja2": True,
                "multipart": True,
            },
        }
        result = validate_runtime("analyze", snapshot=snapshot)
        self.assertTrue(result.ok)
        self.assertEqual(result.errors, [])
        self.assertTrue(any("tshark" in message for message in result.warnings))

    def test_validate_runtime_rejects_benchmark_without_required_dependencies(self):
        snapshot = {
            "commands": {"tshark": False, "editcap": True, "capinfos": True},
            "modules": {
                "pyshark": False,
                "uvicorn": True,
                "fastapi": True,
                "jinja2": True,
                "multipart": True,
            },
        }
        result = validate_runtime("benchmark", snapshot=snapshot)
        self.assertFalse(result.ok)
        self.assertEqual(len(result.errors), 2)

    @patch("TrafficAnalyzer.runtime.collect_runtime_snapshot")
    def test_runtime_report_and_formatting(self, mock_snapshot):
        mock_snapshot.return_value = {
            "commands": {"tshark": True, "editcap": True, "capinfos": True},
            "modules": {
                "pyshark": True,
                "uvicorn": True,
                "fastapi": True,
                "jinja2": True,
                "multipart": True,
            },
        }
        report = runtime_report_dict()
        rendered = format_runtime_report(report)
        self.assertTrue(report["healthy"])
        self.assertIn("TrafficAnalyzer Runtime Doctor", rendered)
        self.assertIn("analyze: OK", rendered)

    def test_job_status_includes_parse_progress(self):
        manager = JobManager()
        job = AnalysisJob(
            job_id="job-1",
            filename="sample.pcap",
            temp_path="sample.pcap",
            db_path="job-1.sqlite3",
            max_packets=None,
            status="parsing",
            packet_count=200,
            source_packet_count=1000,
            target_packet_count=1000,
            progress_updated_at="2026-03-29T12:00:00+00:00",
        )
        manager.jobs[job.job_id] = job
        payload = manager.job_status(job.job_id)

        progress = payload["job"]["progress"]
        self.assertEqual(payload["job"]["source_packet_count"], 1000)
        self.assertEqual(payload["job"]["target_packet_count"], 1000)
        self.assertEqual(progress["parsed"], 200)
        self.assertEqual(progress["total"], 1000)
        self.assertEqual(progress["percent"], 20.0)


if __name__ == "__main__":
    unittest.main()
