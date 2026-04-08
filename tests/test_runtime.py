from dataclasses import asdict
import io
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from TrafficAnalyzer.attacks import build_attack_detectors
from TrafficAnalyzer.core.loader import PcapLoader, _parse_capinfos_packet_count
from TrafficAnalyzer.core.models import PacketRecord
from TrafficAnalyzer.main import build_parser
from TrafficAnalyzer.parsers.packet_parser import PacketParser
from TrafficAnalyzer.pipeline.service import build_default_pipeline_service
from TrafficAnalyzer.protocols import build_protocol_parsers
from TrafficAnalyzer.protocols.http_parser import HTTPProtocolParser
from TrafficAnalyzer.runtime import format_runtime_report, runtime_report_dict, validate_runtime
from TrafficAnalyzer.utils.artifact_utils import artifact_raw_url, artifact_viewer_url, normalize_artifact_relative_path
from TrafficAnalyzer.utils.tls_keylog import normalize_tls_keylog_text
from TrafficAnalyzer.web.job_manager import AnalysisJob, JobManager, ModuleExecution, _init_packet_db, _module_worker, _parse_packet_chunk


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

    def test_job_manager_parse_godzilla_key_uses_detected_session_key_when_input_empty(self):
        if not os.path.exists("tests/buuctf/Godzilla.pcap"):
            self.skipTest("缺少 tests/buuctf/Godzilla.pcap 样本")

        parser = PacketParser(mode="fast")
        packets = list(parser.parse_file("tests/buuctf/Godzilla.pcap"))

        service = build_default_pipeline_service()
        report = service.analyze_packets(
            packets,
            source="unit-test",
            enabled_protocols=[],
            enabled_attacks=["WebShellDetector"],
        )

        with TemporaryDirectory() as tmpdir:
            manager = JobManager(storage_root=tmpdir)
            try:
                project_dir = Path(tmpdir) / "project-1"
                project_dir.mkdir(parents=True, exist_ok=True)
                db_path = project_dir / "packets.sqlite3"
                _init_packet_db(str(db_path))
                conn = sqlite3.connect(str(db_path))
                try:
                    conn.executemany(
                        "INSERT INTO packets (idx, packet_json) VALUES (?, ?)",
                        [
                            (
                                packet.index,
                                json.dumps(packet.__dict__, ensure_ascii=False, separators=(",", ":")),
                            )
                            for packet in packets
                        ],
                    )
                    conn.commit()
                finally:
                    conn.close()

                job = AnalysisJob(
                    job_id="job-1",
                    filename="Godzilla.pcap",
                    temp_path="tests/buuctf/Godzilla.pcap",
                    db_path=str(db_path),
                    max_packets=None,
                    project_dir=str(project_dir),
                    metadata_path=str(project_dir / "meta.json"),
                    status="parsed",
                )
                job.modules["attack:WebShellDetector"] = ModuleExecution(
                    module_type="attack",
                    module_name="WebShellDetector",
                    status="completed",
                    result={"alerts": [asdict(alert) for alert in report.alerts]},
                )
                manager.jobs[job.job_id] = job

                result = manager.parse_webshell_godzilla_key(job.job_id)

                self.assertTrue(result["matched"])
                self.assertTrue(result["exact_match"])
                self.assertEqual(result["candidate_source"]["mode"], "traffic_detected")
                self.assertEqual(result["used_key"], "421eb7f1b8e4b3cf")
                self.assertEqual(result["detected_key"], "421eb7f1b8e4b3cf")
                self.assertIn("421eb7f1b8e4b3cf", result["detected_keys"])
                self.assertEqual(result["matched_derivation"], "流量中检测到")
                self.assertEqual(result["matched_context"]["pass_param"], "babyshell")
                self.assertTrue(
                    any(
                        "Godzilla1sS000Int3rEstIng" in str(
                            (entry.get("response") or {}).get("text")
                            or (entry.get("response") or {}).get("preview")
                            or ""
                        )
                        for context in result["contexts"]
                        for entry in (context.get("entries") or [])
                    )
                )
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

    @patch("TrafficAnalyzer.web.job_manager._stream_packets_from_db", return_value=iter([]))
    @patch("TrafficAnalyzer.web.job_manager.build_default_pipeline_service")
    @patch("TrafficAnalyzer.web.job_manager._run_mapreduce_worker")
    @patch("TrafficAnalyzer.web.job_manager._write_json_atomic")
    def test_module_worker_runs_usb_sequentially_not_mapreduce(
        self,
        mock_write_json,
        mock_mapreduce,
        mock_build_service,
        _mock_stream_packets,
    ):
        mock_mapreduce.return_value = {"module": {"type": "protocol", "name": "USB"}}
        mock_service = mock_build_service.return_value
        mock_service.analyze_packets.return_value = SimpleNamespace(
            packet_count=0,
            stats={
                "protocol_event_count": 0,
                "alert_count": 0,
                "detailed_views": {
                    "USB": {
                        "record_count": 0,
                        "mouse": {
                            "draw_segment_count": 7,
                        },
                    }
                },
                "debug": {},
            },
        )

        _module_worker(
            db_path="ignored.sqlite3",
            module_type="protocol",
            module_name="USB",
            source="unit-test",
            result_path="ignored-result.json",
            fetch_size=100,
        )

        mock_mapreduce.assert_not_called()
        mock_service.analyze_packets.assert_called_once()
        mock_write_json.assert_called_once()
        payload = mock_write_json.call_args.args[1]
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["module"]["name"], "USB")
        self.assertEqual(payload["result"]["detail"]["mouse"]["draw_segment_count"], 7)

    def test_normalize_tls_keylog_text_repairs_escaped_lines_and_discards_noise(self):
        raw_text = (
            "------boundary\\r\\n"
            "Content-Disposition: form-data; name=\"file\"; filename=\"sslkey.log\"\\r\\n\\r\\n"
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET 00112233445566778899aabbccddeeff aabbccddeeff00112233445566778899\\n"
            "SERVER_TRAFFIC_SECRET_0 11223344556677889900aabbccddeeff 99887766554433221100ffeeddccbbaa\\r\\n"
            "------boundary--"
        )

        normalized = normalize_tls_keylog_text(raw_text)

        self.assertEqual(
            normalized.splitlines(),
            [
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET 00112233445566778899aabbccddeeff aabbccddeeff00112233445566778899",
                "SERVER_TRAFFIC_SECRET_0 11223344556677889900aabbccddeeff 99887766554433221100ffeeddccbbaa",
            ],
        )

    def test_job_manager_parse_tls_keylog_returns_decrypted_flag_hits(self):
        if not os.path.exists("tests/buuctf/tls.pcapng"):
            self.skipTest("缺少 tests/buuctf/tls.pcapng 样本")

        extractor = PacketParser(mode="fast")
        upload_packets = list(
            extractor.parse_file(
                "tests/buuctf/tls.pcapng",
                protocol_parsers=[HTTPProtocolParser()],
            )
        )
        uploaded_keylog = next(
            str((packet.raw.get("http") or {}).get("file_data") or "")
            for packet in upload_packets
            if "CLIENT_HANDSHAKE_TRAFFIC_SECRET" in str((packet.raw.get("http") or {}).get("file_data") or "")
        )

        with TemporaryDirectory() as tmpdir:
            manager = JobManager(storage_root=tmpdir)
            try:
                project_dir = Path(tmpdir) / "project-1"
                project_dir.mkdir(parents=True, exist_ok=True)
                db_path = project_dir / "packets.sqlite3"
                _init_packet_db(str(db_path))
                job = AnalysisJob(
                    job_id="job-1",
                    filename="tls.pcapng",
                    temp_path="tests/buuctf/tls.pcapng",
                    db_path=str(db_path),
                    max_packets=None,
                    project_dir=str(project_dir),
                    metadata_path=str(project_dir / "meta.json"),
                    status="parsed",
                )
                manager.jobs[job.job_id] = job

                result = manager.parse_tls_keylog(job.job_id, key_text=uploaded_keylog)

                self.assertGreater(result["summary"]["http_request_count"], 0)
                self.assertGreater(result["summary"]["tls_session_count"], 0)
                self.assertIn("flag{e3364403651e775bfb9b3ffa06b69994}", result["flag_hits"])
            finally:
                manager.jobs.clear()
                manager.shutdown()

    def test_job_manager_start_tls_decrypt_task_reports_progress_and_result(self):
        with TemporaryDirectory() as tmpdir:
            manager = JobManager(storage_root=tmpdir)
            try:
                project_dir = Path(tmpdir) / "project-1"
                project_dir.mkdir(parents=True, exist_ok=True)
                db_path = project_dir / "packets.sqlite3"
                _init_packet_db(str(db_path))
                job = AnalysisJob(
                    job_id="job-1",
                    filename="tls.pcapng",
                    temp_path="tests/buuctf/tls.pcapng",
                    db_path=str(db_path),
                    max_packets=None,
                    project_dir=str(project_dir),
                    metadata_path=str(project_dir / "meta.json"),
                    status="parsed",
                    packet_count=205,
                )
                manager.jobs[job.job_id] = job

                def fake_parse_tls_keylog_report(*, job, normalized_keylog, source_meta, progress_callback):
                    self.assertEqual(job.job_id, "job-1")
                    self.assertIn("CLIENT_RANDOM", normalized_keylog)
                    if progress_callback is not None:
                        progress_callback("packet_read", 51, 205, "正在使用 TLS keylog 重新读取 pcap")
                    time.sleep(0.05)
                    if progress_callback is not None:
                        progress_callback("finalizing", 205, 205, "正在提取 TLS / HTTP 结果并整理命中信息")
                    return {
                        "keylog_source": source_meta,
                        "summary": {
                            "packet_count": 205,
                            "protocol_event_count": 53,
                            "tls_session_count": 43,
                            "http_request_count": 10,
                            "http_upload_count": 1,
                            "flag_hit_count": 1,
                        },
                        "tls_detail": {},
                        "http_detail": {},
                        "flag_hits": ["flag{demo}"],
                    }

                with patch.object(manager, "_parse_tls_keylog_report", side_effect=fake_parse_tls_keylog_report):
                    started = manager.start_tls_decrypt_task(
                        job.job_id,
                        key_text="CLIENT_RANDOM 00112233445566778899aabbccddeeff aabbccddeeff00112233445566778899",
                    )
                    self.assertEqual(started["task"]["status"], "running")
                    self.assertIn(started["task"]["stage"], {"initializing", "packet_read", "finalizing"})

                    task_payload = None
                    deadline = time.time() + 2.0
                    while time.time() < deadline:
                        status = manager.tls_decrypt_status(job.job_id)
                        task_payload = status["task"]
                        if task_payload and task_payload["status"] != "running":
                            break
                        time.sleep(0.02)

                    self.assertIsNotNone(task_payload)
                    self.assertEqual(task_payload["status"], "completed")
                    self.assertEqual(task_payload["stage"], "completed")
                    self.assertEqual(task_payload["progress"]["processed"], 205)
                    self.assertEqual(task_payload["progress"]["total"], 205)
                    self.assertEqual(task_payload["result"]["summary"]["http_request_count"], 10)
                    self.assertEqual(task_payload["result"]["flag_hits"], ["flag{demo}"])

                    cached = manager.start_tls_decrypt_task(
                        job.job_id,
                        key_text="CLIENT_RANDOM 00112233445566778899aabbccddeeff aabbccddeeff00112233445566778899",
                    )
                    self.assertEqual(cached["task"]["status"], "completed")
                    self.assertEqual(cached["task"]["result"]["summary"]["tls_session_count"], 43)
            finally:
                manager.jobs.clear()
                manager.shutdown()

    def test_job_manager_tls_decrypt_publishes_http_result_into_job_results(self):
        with TemporaryDirectory() as tmpdir:
            manager = JobManager(storage_root=tmpdir)
            try:
                project_dir = Path(tmpdir) / "project-1"
                project_dir.mkdir(parents=True, exist_ok=True)
                db_path = project_dir / "packets.sqlite3"
                _init_packet_db(str(db_path))
                job = AnalysisJob(
                    job_id="job-1",
                    filename="tls.pcapng",
                    temp_path="tests/buuctf/tls.pcapng",
                    db_path=str(db_path),
                    max_packets=None,
                    project_dir=str(project_dir),
                    metadata_path=str(project_dir / "meta.json"),
                    status="parsed",
                    packet_count=205,
                )
                manager.jobs[job.job_id] = job

                with patch.object(
                    manager,
                    "_parse_tls_keylog_report",
                    return_value={
                        "keylog_source": {"mode": "text", "label": "inline", "line_count": 1},
                        "summary": {
                            "packet_count": 205,
                            "protocol_event_count": 53,
                            "tls_session_count": 7,
                            "http_request_count": 3,
                            "http_upload_count": 1,
                            "flag_hit_count": 1,
                        },
                        "tls_detail": {},
                        "http_detail": {
                            "request_count": 3,
                            "upload_count": 1,
                            "requests": [
                                {"packet_index": 8, "direction": "request", "method": "POST", "host": "demo.local", "uri": "/upload"},
                                {"packet_index": 9, "direction": "response", "status_code": "200", "uri": "/upload"},
                            ],
                            "uploads": [
                                {"packet_index": 8, "filename": "flag.txt", "url": "/artifacts/http_uploads/flag.txt"},
                            ],
                            "upload_points": [
                                {
                                    "server_ip": "10.0.0.2",
                                    "host": "demo.local",
                                    "method": "POST",
                                    "uri": "/upload",
                                    "uri_path": "/upload",
                                    "request_count": 1,
                                    "upload_count": 1,
                                    "files": [
                                        {"filename": "flag.txt", "url": "/artifacts/http_uploads/flag.txt"},
                                    ],
                                }
                            ],
                        },
                        "flag_hits": ["flag{demo}"],
                    },
                ):
                    started_revision = job.revision
                    started = manager.start_tls_decrypt_task(
                        job.job_id,
                        key_text="CLIENT_RANDOM 00112233445566778899aabbccddeeff aabbccddeeff00112233445566778899",
                    )
                    self.assertIn(started["task"]["status"], {"running", "completed"})

                    deadline = time.time() + 2.0
                    while time.time() < deadline:
                        task = manager.tls_decrypt_status(job.job_id)["task"]
                        result_file = project_dir / "module_results" / "protocol__HTTP.json"
                        if task and task["status"] == "completed" and result_file.exists():
                            break
                        time.sleep(0.02)
                    else:
                        self.fail("TLS decrypt task did not finish in time")

                self.assertGreater(job.revision, started_revision)
                http_module = job.modules.get("protocol:HTTP")
                self.assertIsNotNone(http_module)
                self.assertEqual(http_module.status, "completed")
                self.assertEqual(http_module.result["meta"]["source"], "tls_decrypt")
                self.assertEqual(http_module.result["detail"]["request_count"], 3)
                self.assertEqual(http_module.result["detail"]["upload_count"], 1)
                self.assertEqual(http_module.result["summary"]["protocol_event_count"], 3)

                results = manager.job_results(job.job_id)
                result_map = {
                    f'{item["module_type"]}:{item["module_name"]}': item
                    for item in results["modules"]
                }
                self.assertIn("protocol:HTTP", result_map)
                self.assertEqual(result_map["protocol:HTTP"]["result"]["detail"]["request_count"], 3)
                self.assertEqual(result_map["protocol:HTTP"]["result"]["meta"]["source"], "tls_decrypt")
                self.assertTrue((project_dir / "module_results" / "protocol__HTTP.json").exists())
            finally:
                manager.jobs.clear()
                manager.shutdown()

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

        def fake_pyshark(pcap_path, start_index=0, stop_index=None, tls_keylog_path=None):
            self.assertEqual(pcap_path, "sample.pcap")
            self.assertEqual(start_index, 2)
            self.assertIsNone(stop_index)
            self.assertIsNone(tls_keylog_path)
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
    @patch("TrafficAnalyzer.parsers.packet_parser.tempfile.NamedTemporaryFile")
    @patch("TrafficAnalyzer.parsers.packet_parser.os.remove")
    def test_fast_parser_passes_tls_keylog_to_tshark(
        self,
        mock_remove,
        mock_named_tempfile,
        mock_popen,
        mock_pyshark,
        _mock_which,
    ):
        class FakeProcess:
            def __init__(self, stdout_text: str, stderr_text: str, retcode: int):
                self.stdout = io.StringIO(stdout_text)
                self.stderr = io.StringIO(stderr_text)
                self._retcode = retcode

            def wait(self, timeout=None):
                return self._retcode

        class FakeTempFile:
            def __init__(self):
                self.name = "/tmp/mock-tls.keys"

            def write(self, _value):
                return None

            def close(self):
                return None

        row = "\t".join(
            [
                "1",
                "1.0",
                "60",
                "eth:ip:tcp:tls",
                "10.0.0.1",
                "10.0.0.2",
                "6",
                "",
                "",
                "",
                "44321",
                "443",
                "0x00000018",
                "",
                "",
            ]
        )
        mock_popen.return_value = FakeProcess(row, "", 0)
        mock_named_tempfile.return_value = FakeTempFile()

        parser = PacketParser(mode="fast")
        packets = list(
            parser.parse_file(
                "sample.pcap",
                protocol_parsers=[],
                tls_keylog_text="CLIENT_RANDOM 00112233445566778899aabbccddeeff aabbccddeeff00112233445566778899",
            )
        )

        self.assertEqual(len(packets), 1)
        cmd = mock_popen.call_args.args[0]
        self.assertIn("-o", cmd)
        self.assertTrue(any(str(item).startswith("tls.keylog_file:") for item in cmd))
        mock_pyshark.assert_not_called()
        mock_remove.assert_called_once_with("/tmp/mock-tls.keys")

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

        def fake_pyshark(pcap_path, start_index=0, stop_index=None, tls_keylog_path=None):
            self.assertEqual(pcap_path, "sample.pcap")
            self.assertEqual(start_index, 1)
            self.assertEqual(stop_index, 2)
            self.assertIsNone(tls_keylog_path)
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
        self.assertEqual([parser.name for parser in parsers], ["HTTP", "DNS", "TLS", "Modbus", "USB"])

    def test_attack_registry_uses_detector_config(self):
        detectors = build_attack_detectors()
        self.assertEqual([detector.name for detector in detectors], ["WebShellDetector", "SQLInjectionDetector"])

    def test_job_manager_parse_sqli_bool_reconstructs_flag(self):
        if not os.path.exists("tests/buuctf/sqli.pcap"):
            self.skipTest("缺少 tests/buuctf/sqli.pcap 样本")

        parser = PacketParser(mode="fast")
        packets = list(parser.parse_file("tests/buuctf/sqli.pcap"))

        service = build_default_pipeline_service()
        report = service.analyze_packets(
            packets,
            source="unit-test",
            enabled_protocols=[],
            enabled_attacks=["SQLInjectionDetector"],
        )

        with TemporaryDirectory() as tmpdir:
            manager = JobManager(storage_root=tmpdir)
            try:
                project_dir = Path(tmpdir) / "project-1"
                project_dir.mkdir(parents=True, exist_ok=True)
                db_path = project_dir / "packets.sqlite3"
                _init_packet_db(str(db_path))
                conn = sqlite3.connect(str(db_path))
                try:
                    conn.executemany(
                        "INSERT INTO packets (idx, packet_json) VALUES (?, ?)",
                        [
                            (
                                packet.index,
                                json.dumps(packet.__dict__, ensure_ascii=False, separators=(",", ":")),
                            )
                            for packet in packets
                        ],
                    )
                    conn.commit()
                finally:
                    conn.close()

                job = AnalysisJob(
                    job_id="job-1",
                    filename="sqli.pcap",
                    temp_path="tests/buuctf/sqli.pcap",
                    db_path=str(db_path),
                    max_packets=None,
                    project_dir=str(project_dir),
                    metadata_path=str(project_dir / "meta.json"),
                    status="parsed",
                )
                job.modules["attack:SQLInjectionDetector"] = ModuleExecution(
                    module_type="attack",
                    module_name="SQLInjectionDetector",
                    status="completed",
                    result={"alerts": [asdict(alert) for alert in report.alerts]},
                )
                manager.jobs[job.job_id] = job

                result = manager.parse_sql_injection_bool(job.job_id)
                marker_result = manager.parse_sql_injection_bool(job.job_id, true_marker="好耶")

                self.assertTrue(result["matched"])
                self.assertEqual(result["analysis_mode"], "response_length")
                self.assertEqual(result["best_text"], "flag{c84bb04a-8663-4ee2-9449-349f1ee83e11}")
                self.assertTrue(any(context.get("restored_text") == result["best_text"] for context in result["contexts"]))
                self.assertTrue(any(context.get("true_length_values") for context in result["contexts"]))

                self.assertTrue(marker_result["matched"])
                self.assertEqual(marker_result["analysis_mode"], "marker_text")
                self.assertEqual(marker_result["best_text"], "flag{c84bb04a-8663-4ee2-9449-349f1ee83e11}")
            finally:
                manager.jobs.clear()
                manager.shutdown()

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

    def test_remove_module_does_not_reappear_in_status_or_recovered_project(self):
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
                )
                module = ModuleExecution(
                    module_type="protocol",
                    module_name="HTTP",
                    status="completed",
                    result={
                        "module": {"type": "protocol", "name": "HTTP"},
                        "summary": {"packet_count": 1, "protocol_event_count": 1, "alert_count": 0},
                        "detail": {"request_count": 1},
                    },
                )
                job.modules[module.key] = module
                manager.jobs[job.job_id] = job
                manager._persist_job(job)

                removed = manager.remove_module(job.job_id, "protocol", "HTTP")
                self.assertTrue(removed["removed"])

                status_payload = manager.job_status(job.job_id)
                self.assertEqual(status_payload["job"]["modules"], [])

                recovered_manager = JobManager(storage_root=tmpdir)
                payload = recovered_manager.load_project("project-1")
                self.assertEqual(payload["job"]["modules"], [])
                self.assertEqual(payload["results"]["modules"], [])
            finally:
                manager.jobs.clear()
                manager.shutdown()
                if recovered_manager is not None:
                    recovered_manager.jobs.clear()
                    recovered_manager.shutdown()

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

            def fake_parse_chunk(
                pcap_path,
                progress_callback=None,
                progress_interval=1000,
                output_path=None,
                tls_keylog_text=None,
            ):
                assert output_path is not None
                self.assertIsNone(tls_keylog_text)
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

                parsed_count, returned_split_files, split_dir, basic_protocol_counter = manager._run_parallel_base_parse(
                    job=job,
                    conn=conn,
                    batch=[],
                )

                self.assertEqual(parsed_count, 3)
                self.assertEqual(returned_split_files, split_files)
                self.assertEqual(split_dir, "")
                self.assertEqual(dict(basic_protocol_counter), {})

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
