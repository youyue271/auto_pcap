import io
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from TrafficAnalyzer.attacks import build_attack_detectors
from TrafficAnalyzer.core.loader import PcapLoader, _parse_capinfos_packet_count
from TrafficAnalyzer.core.models import PacketRecord
from TrafficAnalyzer.main import build_parser
from TrafficAnalyzer.parsers.packet_parser import PacketParser
from TrafficAnalyzer.protocols import build_protocol_parsers
from TrafficAnalyzer.runtime import format_runtime_report, runtime_report_dict, validate_runtime
from TrafficAnalyzer.utils.artifact_utils import artifact_raw_url, artifact_viewer_url, normalize_artifact_relative_path
from TrafficAnalyzer.web.job_manager import AnalysisJob, JobManager, ModuleExecution, _init_packet_db, _parse_packet_chunk


class TestRegistryAndRuntime(unittest.TestCase):
    def test_artifact_url_helpers_normalize_and_escape_paths(self):
        self.assertEqual(normalize_artifact_relative_path(r" http_rebuild\demo path\index.php "), "http_rebuild/demo path/index.php")
        self.assertEqual(artifact_raw_url("http_rebuild/demo path/index.php"), "/artifacts/http_rebuild/demo%20path/index.php")
        self.assertEqual(
            artifact_viewer_url("http_rebuild/demo path/index.php"),
            "/artifact-view?path=http_rebuild/demo%20path/index.php",
        )
        with self.assertRaises(ValueError):
            normalize_artifact_relative_path("../etc/passwd")

    def test_godzilla_key_candidates_expand_dictionary_words_to_md5_variants(self):
        manager = JobManager()
        try:
            candidates, meta = manager._resolve_godzilla_key_candidates(
                key_text=r"E:\STEVE\project\auto-pcap\tests\陇剑rhg\key.txt",
                key_file_name=None,
                key_file_bytes=None,
            )
            values = {str(item.get("value") or ""): item for item in candidates}

            self.assertEqual(meta["mode"], "path_file")
            self.assertEqual(meta["input_count"], 100)
            self.assertIn("1p79u0ztp", values)
            self.assertIn("0ca63845f8997771", values)
            self.assertEqual(values["0ca63845f8997771"]["source"], "1p79u0ztp")
            self.assertEqual(values["0ca63845f8997771"]["strategy"], "md5_first16")
        finally:
            manager.jobs.clear()
            manager.shutdown()

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

    @patch("TrafficAnalyzer.web.job_manager.PacketParser")
    def test_parse_packet_chunk_can_stream_records_to_output_file(self, mock_parser_cls):
        parser = mock_parser_cls.return_value
        parser.parse_file.return_value = iter(
            [
                PacketRecord(index=i, timestamp=float(i), flow_id=str(i), src_ip=f"10.0.0.{i}")
                for i in range(3)
            ]
        )

        with TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "chunk.jsonl"
            result = _parse_packet_chunk("sample.pcap", output_path=str(output_path))

            self.assertEqual(result["packet_count"], 3)
            self.assertEqual(result["output_path"], str(output_path))
            self.assertNotIn("records", result)

            rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([row["index"] for row in rows], [0, 1, 2])
            self.assertEqual(rows[2]["src_ip"], "10.0.0.2")

    @patch("TrafficAnalyzer.parsers.packet_parser.shutil.which", return_value="/usr/bin/tshark")
    @patch("TrafficAnalyzer.parsers.packet_parser.PacketParser._parse_file_pyshark")
    @patch("TrafficAnalyzer.parsers.packet_parser.subprocess.Popen")
    def test_fast_parser_fallback_discards_partial_tshark_output(self, mock_popen, mock_pyshark, _mock_which):
        class FakeProcess:
            def __init__(self, stdout_text: str, stderr_text: str, retcode: int):
                self.stdout = io.StringIO(stdout_text)
                self.stderr = io.StringIO(stderr_text)
                self._retcode = retcode

            def wait(self, timeout=None):
                return self._retcode

        partial_rows = "\n".join(
            [
                "\t".join(
                    [
                        "1",
                        "1.0",
                        "60",
                        "eth:ip:tcp",
                        "10.0.0.1",
                        "10.0.0.2",
                        "6",
                        "",
                        "",
                        "",
                        "12345",
                        "80",
                        "0x00000002",
                        "",
                        "",
                    ]
                ),
                "\t".join(
                    [
                        "2",
                        "1.1",
                        "60",
                        "eth:ip:tcp",
                        "10.0.0.2",
                        "10.0.0.1",
                        "6",
                        "",
                        "",
                        "",
                        "80",
                        "12345",
                        "0x00000012",
                        "",
                        "",
                    ]
                ),
            ]
        )
        mock_popen.return_value = FakeProcess(partial_rows, "simulated tshark failure", 2)
        fallback_packets = [
            PacketRecord(
                index=2,
                timestamp=2.0,
                flow_id="fallback-flow",
                src_ip="192.168.0.10",
                dst_ip="192.168.0.20",
            )
        ]

        def fake_pyshark(pcap_path, start_index=0, stop_index=None):
            self.assertEqual(pcap_path, "sample.pcap")
            self.assertEqual(start_index, 2)
            self.assertIsNone(stop_index)
            return iter(fallback_packets)

        mock_pyshark.side_effect = fake_pyshark

        parser = PacketParser(mode="fast")
        packets = list(parser.parse_file("sample.pcap", protocol_parsers=[]))

        self.assertEqual(len(packets), 3)
        self.assertEqual([packet.index for packet in packets], [0, 1, 2])
        self.assertEqual(packets[-1].flow_id, "fallback-flow")
        mock_pyshark.assert_called_once()

    @patch("TrafficAnalyzer.parsers.packet_parser.shutil.which", return_value="/usr/bin/tshark")
    @patch("TrafficAnalyzer.parsers.packet_parser.PacketParser._parse_file_pyshark")
    @patch("TrafficAnalyzer.parsers.packet_parser.subprocess.Popen")
    def test_fast_parser_handles_large_http_field_without_fallback(self, mock_popen, mock_pyshark, _mock_which):
        class FakeProcess:
            def __init__(self, stdout_text: str, stderr_text: str, retcode: int):
                self.stdout = io.StringIO(stdout_text)
                self.stderr = io.StringIO(stderr_text)
                self._retcode = retcode

            def wait(self, timeout=None):
                return self._retcode

        large_payload = "A" * 200000
        row = "\t".join(
            [
                "1",
                "1.0",
                "60",
                "eth:ip:tcp:http",
                "10.0.0.1",
                "10.0.0.2",
                "6",
                "",
                "",
                "",
                "12345",
                "80",
                "0x00000018",
                "",
                "",
                "POST",
                "example.test",
                "/upload/1.php",
                "",
                "ua",
                "application/x-www-form-urlencoded",
                "",
                large_payload,
            ]
        )
        mock_popen.return_value = FakeProcess(row, "", 0)
        parser = PacketParser(mode="fast")

        class FakeHTTPParser:
            def required_fields(self):
                return [
                    "http.request.method",
                    "http.host",
                    "http.request.uri",
                    "http.request.full_uri",
                    "http.user_agent",
                    "http.content_type",
                    "http.response.code",
                    "http.file_data",
                ]

        packets = list(parser.parse_file("sample.pcap", protocol_parsers=[FakeHTTPParser()]))

        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].raw["http"]["file_data"], large_payload)
        mock_pyshark.assert_not_called()

    @patch("TrafficAnalyzer.parsers.packet_parser.shutil.which", return_value="/usr/bin/tshark")
    @patch("TrafficAnalyzer.parsers.packet_parser.PacketParser._parse_file_pyshark")
    @patch("TrafficAnalyzer.parsers.packet_parser.subprocess.Popen")
    def test_fast_parser_fills_missing_frame_gap_with_pyshark_range(self, mock_popen, mock_pyshark, _mock_which):
        class FakeProcess:
            def __init__(self, stdout_text: str, stderr_text: str, retcode: int):
                self.stdout = io.StringIO(stdout_text)
                self.stderr = io.StringIO(stderr_text)
                self._retcode = retcode

            def wait(self, timeout=None):
                return self._retcode

        rows = "\n".join(
            [
                "\t".join(
                    [
                        "1",
                        "1.0",
                        "60",
                        "eth:ip:tcp",
                        "10.0.0.1",
                        "10.0.0.2",
                        "6",
                        "",
                        "",
                        "",
                        "12345",
                        "80",
                        "0x00000002",
                        "",
                        "",
                    ]
                ),
                "\t".join(
                    [
                        "3",
                        "1.2",
                        "60",
                        "eth:ip:tcp",
                        "10.0.0.2",
                        "10.0.0.1",
                        "6",
                        "",
                        "",
                        "",
                        "80",
                        "12345",
                        "0x00000012",
                        "",
                        "",
                    ]
                ),
            ]
        )
        mock_popen.return_value = FakeProcess(rows, "", 0)

        def fake_pyshark(pcap_path, start_index=0, stop_index=None):
            self.assertEqual(pcap_path, "sample.pcap")
            self.assertEqual(start_index, 1)
            self.assertEqual(stop_index, 2)
            return iter(
                [
                    PacketRecord(
                        index=1,
                        timestamp=1.1,
                        flow_id="gap-fill",
                        src_ip="10.0.0.9",
                        dst_ip="10.0.0.10",
                    )
                ]
            )

        mock_pyshark.side_effect = fake_pyshark
        parser = PacketParser(mode="fast")
        packets = list(parser.parse_file("sample.pcap", protocol_parsers=[]))

        self.assertEqual([packet.index for packet in packets], [0, 1, 2])
        self.assertEqual(packets[1].flow_id, "gap-fill")
        mock_pyshark.assert_called_once()

    def test_protocol_registry_build_order(self):
        parsers = build_protocol_parsers()
        self.assertEqual([parser.name for parser in parsers], ["HTTP", "DNS", "TLS", "Modbus"])

    def test_attack_registry_uses_detector_config(self):
        detectors = build_attack_detectors()
        self.assertEqual([detector.name for detector in detectors], ["WebShellDetector"])

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
        with TemporaryDirectory() as tmpdir:
            manager = JobManager(storage_root=tmpdir)
            try:
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
                self.assertEqual(payload["job"]["project_id"], "job-1")
                self.assertEqual(payload["job"]["source_packet_count"], 1000)
                self.assertEqual(payload["job"]["target_packet_count"], 1000)
                self.assertEqual(progress["parsed"], 200)
                self.assertEqual(progress["total"], 1000)
                self.assertEqual(progress["percent"], 20.0)
            finally:
                manager.jobs.clear()
                manager.shutdown()

    def test_job_status_includes_running_module_progress(self):
        with TemporaryDirectory() as tmpdir:
            manager = JobManager(storage_root=tmpdir)
            try:
                progress_path = Path(tmpdir) / "module.progress.json"
                progress_path.write_text(
                    json.dumps(
                        {
                            "processed": 400,
                            "total": 1000,
                            "percent": 40.0,
                            "updated_at": "2026-03-30T12:34:56+00:00",
                        }
                    ),
                    encoding="utf-8",
                )

                job = AnalysisJob(
                    job_id="job-1",
                    filename="sample.pcap",
                    temp_path="sample.pcap",
                    db_path="job-1.sqlite3",
                    max_packets=None,
                    status="parsed",
                    packet_count=1000,
                )
                module = ModuleExecution(
                    module_type="protocol",
                    module_name="HTTP",
                    status="running",
                    progress_path=str(progress_path),
                )
                job.modules[module.key] = module
                manager.jobs[job.job_id] = job

                payload = manager.job_status(job.job_id)
                modules = payload["job"]["modules"]
                self.assertEqual(len(modules), 1)
                self.assertEqual(modules[0]["progress"]["processed"], 400)
                self.assertEqual(modules[0]["progress"]["total"], 1000)
                self.assertEqual(modules[0]["progress"]["percent"], 40.0)

                module.status = "completed"
                module.progress_path = None
                payload = manager.job_status(job.job_id)
                self.assertIsNone(payload["job"]["modules"][0]["progress"])
            finally:
                manager.jobs.clear()
                manager.shutdown()

    def test_project_persistence_supports_recover_and_delete_by_project_id(self):
        with TemporaryDirectory() as tmpdir:
            storage_root = Path(tmpdir)
            project_dir = storage_root / "project-1"
            project_dir.mkdir(parents=True, exist_ok=True)
            db_path = project_dir / "packets.sqlite3"
            _init_packet_db(str(db_path))

            manager = JobManager(storage_root=tmpdir)
            recovered_manager = None
            try:
                job = AnalysisJob(
                    job_id="job-1",
                    project_id="project-1",
                    filename="sample.pcap",
                    temp_path="sample.pcap",
                    db_path=str(db_path),
                    max_packets=None,
                    project_dir=str(project_dir),
                    metadata_path=str(project_dir / "meta.json"),
                    status="parsed",
                    packet_count=321,
                    source_packet_count=500,
                    target_packet_count=500,
                )
                module = ModuleExecution(
                    module_type="protocol",
                    module_name="HTTP",
                    status="completed",
                    result={
                        "module": {"type": "protocol", "name": "HTTP"},
                        "summary": {"packet_count": 321, "protocol_event_count": 12, "alert_count": 0},
                        "detail": {"request_count": 12},
                        "debug": {"stage_ms": {"total": 1.2}, "error_count": 0},
                    },
                )
                job.modules[module.key] = module
                manager.jobs[job.job_id] = job
                manager._persist_job(job)

                recovered_manager = JobManager(storage_root=tmpdir)
                projects = recovered_manager.list_projects()
                self.assertEqual(len(projects), 1)
                self.assertEqual(projects[0]["project_id"], "project-1")
                self.assertEqual(projects[0]["job_id"], "job-1")
                self.assertEqual(projects[0]["completed_module_count"], 1)

                payload = recovered_manager.load_project("project-1")
                self.assertEqual(payload["job"]["project_id"], "project-1")
                self.assertEqual(payload["job"]["job_id"], "job-1")
                self.assertEqual(payload["results"]["modules"][0]["result"]["detail"]["request_count"], 12)

                result = recovered_manager.delete_project("project-1")
                self.assertTrue(result["deleted"])
                self.assertFalse(project_dir.exists())
            finally:
                manager.jobs.clear()
                manager.shutdown()
                if recovered_manager is not None:
                    recovered_manager.jobs.clear()
                    recovered_manager.shutdown()

    def test_project_snapshot_reports_rich_state_and_delete_hints(self):
        with TemporaryDirectory() as tmpdir:
            storage_root = Path(tmpdir)
            project_dir = storage_root / "project-1"
            project_dir.mkdir(parents=True, exist_ok=True)
            db_path = project_dir / "packets.sqlite3"
            _init_packet_db(str(db_path))

            manager = JobManager(storage_root=tmpdir)
            try:
                job = AnalysisJob(
                    job_id="job-1",
                    project_id="project-1",
                    filename="sample.pcap",
                    temp_path="sample.pcap",
                    db_path=str(db_path),
                    max_packets=None,
                    project_dir=str(project_dir),
                    metadata_path=str(project_dir / "meta.json"),
                    status="parsed",
                    parse_mode="parallel",
                    parse_error="base parse warning",
                )
                job.modules["protocol:HTTP"] = ModuleExecution(
                    module_type="protocol",
                    module_name="HTTP",
                    status="completed",
                    finished_at="2026-03-30T02:00:00+00:00",
                )
                job.modules["protocol:DNS"] = ModuleExecution(
                    module_type="protocol",
                    module_name="DNS",
                    status="running",
                    started_at="2026-03-30T03:00:00+00:00",
                )
                job.modules["attack:WebShellDetector"] = ModuleExecution(
                    module_type="attack",
                    module_name="WebShellDetector",
                    status="error",
                    error="detector failed",
                    finished_at="2026-03-30T04:00:00+00:00",
                )
                manager.jobs[job.job_id] = job

                snapshot = manager.list_projects()[0]
                self.assertEqual(snapshot["running_module_count"], 1)
                self.assertEqual(snapshot["completed_module_count"], 1)
                self.assertEqual(snapshot["error_module_count"], 1)
                self.assertEqual(snapshot["latest_completed_modules"][0]["name"], "HTTP")
                self.assertFalse(snapshot["can_delete"])
                self.assertIn("运行中", snapshot["delete_block_reason"])
                self.assertEqual(snapshot["recent_errors"][0]["scope"], "parse")
                self.assertEqual(snapshot["recent_errors"][1]["name"], "WebShellDetector")
            finally:
                manager.jobs.clear()
                manager.shutdown()

    def test_restart_module_requeues_existing_module(self):
        with TemporaryDirectory() as tmpdir:
            storage_root = Path(tmpdir)
            project_dir = storage_root / "project-1"
            project_dir.mkdir(parents=True, exist_ok=True)
            db_path = project_dir / "packets.sqlite3"
            _init_packet_db(str(db_path))

            manager = JobManager(storage_root=tmpdir)
            try:
                job = AnalysisJob(
                    job_id="job-1",
                    project_id="project-1",
                    filename="sample.pcap",
                    temp_path="sample.pcap",
                    db_path=str(db_path),
                    max_packets=None,
                    project_dir=str(project_dir),
                    metadata_path=str(project_dir / "meta.json"),
                    status="parsed",
                )
                module = ModuleExecution(
                    module_type="protocol",
                    module_name="HTTP",
                    status="completed",
                    started_at="2026-03-30T01:00:00+00:00",
                    finished_at="2026-03-30T01:05:00+00:00",
                    result={"summary": {"packet_count": 10}},
                )
                job.modules[module.key] = module
                manager.jobs[job.job_id] = job

                with patch.object(manager, "_submit_module") as mock_submit:
                    payload = manager.restart_module("project-1", "protocol", "HTTP")

                self.assertEqual(payload["status"], "pending")
                self.assertEqual(module.status, "pending")
                self.assertIsNone(module.result)
                self.assertIsNone(module.finished_at)
                mock_submit.assert_called_once_with("job-1", "protocol:HTTP")
            finally:
                manager.jobs.clear()
                manager.shutdown()

    def test_cleanup_projects_keeps_recent_and_skips_busy(self):
        with TemporaryDirectory() as tmpdir:
            storage_root = Path(tmpdir)
            manager = JobManager(storage_root=tmpdir)
            try:
                for project_id, updated_at, status in [
                    ("project-new", "2026-03-30T05:00:00+00:00", "parsed"),
                    ("project-old", "2026-03-30T03:00:00+00:00", "parsed"),
                    ("project-busy", "2026-03-30T01:00:00+00:00", "parsing"),
                ]:
                    project_dir = storage_root / project_id
                    project_dir.mkdir(parents=True, exist_ok=True)
                    db_path = project_dir / "packets.sqlite3"
                    _init_packet_db(str(db_path))
                    job = AnalysisJob(
                        job_id=f"job-{project_id}",
                        project_id=project_id,
                        filename=f"{project_id}.pcap",
                        temp_path=f"{project_id}.pcap",
                        db_path=str(db_path),
                        max_packets=None,
                        project_dir=str(project_dir),
                        metadata_path=str(project_dir / "meta.json"),
                        status=status,
                        progress_updated_at=updated_at,
                    )
                    manager.jobs[job.job_id] = job
                    manager._persist_job(job)

                result = manager.cleanup_projects(keep_recent=1)
                deleted_ids = {item["project_id"] for item in result["deleted"]}
                skipped_ids = {item["project_id"] for item in result["skipped"]}

                self.assertEqual(result["requested_count"], 2)
                self.assertIn("project-old", deleted_ids)
                self.assertIn("project-busy", skipped_ids)
                self.assertTrue((storage_root / "project-new").exists())
                self.assertFalse((storage_root / "project-old").exists())
                self.assertTrue((storage_root / "project-busy").exists())
            finally:
                manager.jobs.clear()
                manager.shutdown()

    @patch("TrafficAnalyzer.web.job_manager.PcapLoader")
    @patch("TrafficAnalyzer.web.job_manager._parse_packet_chunk")
    def test_parallel_base_parse_merges_chunks_in_split_order(self, mock_parse_chunk, mock_loader_cls):
        with TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "packets.sqlite3"
            _init_packet_db(str(db_path))

            split_files = ["chunk-a.pcap", "chunk-b.pcap"]
            mock_loader_cls.return_value.split_pcap.return_value = split_files

            def fake_parse_chunk(pcap_path, progress_callback=None, progress_interval=1000, output_path=None):
                assert output_path is not None
                payloads = {
                    "chunk-a.pcap": [
                        {"timestamp": 1.0, "flow_id": "a-0", "src_ip": "10.0.0.1"},
                        {"timestamp": 2.0, "flow_id": "a-1", "src_ip": "10.0.0.2"},
                    ],
                    "chunk-b.pcap": [
                        {"timestamp": 3.0, "flow_id": "b-0", "src_ip": "10.0.1.1"},
                    ],
                }[pcap_path]

                if pcap_path == "chunk-a.pcap":
                    time.sleep(0.05)

                with open(output_path, "w", encoding="utf-8") as fp:
                    for local_index, payload in enumerate(payloads):
                        row = {
                            "index": local_index,
                            "layers": [],
                            "payload_text": "",
                            "raw": {},
                            **payload,
                        }
                        fp.write(json.dumps(row, ensure_ascii=False))
                        fp.write("\n")

                if progress_callback:
                    progress_callback(len(payloads))
                return {
                    "pcap_path": pcap_path,
                    "packet_count": len(payloads),
                    "output_path": output_path,
                }

            mock_parse_chunk.side_effect = fake_parse_chunk

            manager = JobManager(storage_root=tmpdir, db_flush_size=2)
            conn = sqlite3.connect(str(db_path))
            try:
                job = AnalysisJob(
                    job_id="job-1",
                    filename="sample.pcap",
                    temp_path="sample.pcap",
                    db_path=str(db_path),
                    max_packets=None,
                )

                parsed_count, returned_split_files, split_dir = manager._run_parallel_base_parse(
                    job=job,
                    conn=conn,
                    batch=[],
                )

                self.assertEqual(parsed_count, 3)
                self.assertEqual(returned_split_files, split_files)
                self.assertEqual(split_dir, "")

                rows = conn.execute("SELECT idx, packet_json FROM packets ORDER BY idx").fetchall()
                packets = [json.loads(packet_json) for _, packet_json in rows]

                self.assertEqual([idx for idx, _ in rows], [0, 1, 2])
                self.assertEqual([packet["flow_id"] for packet in packets], ["a-0", "a-1", "b-0"])
                self.assertEqual(job.packet_count, 3)
            finally:
                conn.close()
                manager.jobs.clear()
                manager.shutdown()

    @patch("TrafficAnalyzer.web.job_manager.Thread")
    def test_job_manager_moves_uploaded_capture_into_project_dir(self, mock_thread_cls):
        class FakeThread:
            def __init__(self, *args, **kwargs):
                self._alive = False

            def start(self):
                return None

            def is_alive(self):
                return self._alive

            def join(self, timeout=None):
                return None

        mock_thread_cls.side_effect = lambda *args, **kwargs: FakeThread(*args, **kwargs)

        with TemporaryDirectory() as tmpdir:
            storage_root = Path(tmpdir) / "projects"
            upload_path = Path(tmpdir) / "incoming.pcapng"
            upload_path.write_bytes(b"pcap-data")

            manager = JobManager(storage_root=str(storage_root))
            job_id = manager.create_job(
                filename="atta1.pcapng",
                temp_path=str(upload_path),
                max_packets=None,
                source_size_bytes=upload_path.stat().st_size,
            )

            job = manager.jobs[job_id]
            stored_path = Path(job.temp_path)
            meta = json.loads(Path(job.metadata_path).read_text(encoding="utf-8"))

            self.assertFalse(upload_path.exists())
            self.assertTrue(stored_path.exists())
            self.assertEqual(stored_path.read_bytes(), b"pcap-data")
            self.assertEqual(stored_path.parent, Path(job.project_dir))
            self.assertTrue(stored_path.name.startswith("source"))
            self.assertEqual(meta["temp_path"], str(stored_path))
            self.assertEqual(meta["capture_path"], str(stored_path))
            manager.jobs.clear()
            manager.shutdown()


if __name__ == "__main__":
    unittest.main()
