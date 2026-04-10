from __future__ import annotations

from collections import defaultdict
from collections import deque
import base64
import hashlib
import io
import os
import posixpath
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Deque, Dict, List, Optional
from urllib.parse import parse_qs
from urllib.parse import urlsplit
import zipfile

from TrafficAnalyzer.attacks.base import BaseAttackDetector
from TrafficAnalyzer.attacks.webshell_parsers import CookieExecParser, ChinaChopperParser, GodzillaParser
from TrafficAnalyzer.core.models import AttackAlert, PacketRecord, ProtocolEvent
from TrafficAnalyzer.utils.artifact_utils import artifact_raw_url, artifact_viewer_url


class WebShellDetector(BaseAttackDetector):
    name = "WebShellDetector"
    description = "检测 HTTP WebShell 管理流量，提取条目、编码信息与家族指纹"

    _WEBSHELL_PATH = re.compile(r"/[^?\s]+\.(?:php|jsp|jspx|asp|aspx)(?:\?|$)", re.IGNORECASE)
    _BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")
    _HEX_BLOB = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64,})(?![0-9A-Fa-f])")
    _RESPONSE_XY = re.compile(r"X@Y(?P<body>.*?)(?:\[S\](?P<cwd>.*?)\[E\])?X@Y", re.DOTALL)
    _RESPONSE_ARROW = re.compile(r"->\|(?P<body>.*?)\|<-", re.DOTALL)
    _PHP_SOURCE = re.compile(r"@?eval\s*\(\s*\$_POST\[", re.IGNORECASE)
    _COOKIE_EXEC_UPLOAD = re.compile(
        r"base64_decode\s*\(\s*\$_COOKIE\[['\"]cm['\"]\]\s*\).*?setcookie\s*\(\s*\$_COOKIE\[['\"]cn['\"]\]",
        re.IGNORECASE | re.DOTALL,
    )
    _SUSPICIOUS_PARAM_NAMES = {
        "aa",
        "action",
        "assert",
        "cmd",
        "code",
        "data",
        "pass",
        "payload",
        "shell",
        "z0",
        "z1",
        "z2",
    }
    _TEXT_SIGNATURES = (
        ("array_map_assert", "array_map(assert"),
        ("eval_post", "eval($_post["),
        ("base64_post", "base64_decode($_post["),
        ("proc_open", "proc_open("),
        ("command_exec", "system("),
        ("command_exec", "shell_exec("),
        ("command_exec", "passthru("),
        ("command_exec", "exec("),
        ("opendir", "opendir("),
        ("file_read", "fopen($f,r)"),
        ("file_write", "fopen($f,w)"),
    )

    def __init__(self, request_threshold: int = 4, response_threshold: int = 2):
        self.request_threshold = request_threshold
        self.response_threshold = response_threshold
        self.cookie_exec_parser = CookieExecParser()
        self.china_chopper_parser = ChinaChopperParser()
        self.godzilla_parser = GodzillaParser()
        self.pending_cookie_exec: Dict[str, Deque[dict[str, Any]]] = defaultdict(deque)
        self.pending_china_chopper: Dict[str, Deque[dict[str, Any]]] = defaultdict(deque)
        self.pending_godzilla: Dict[str, Deque[dict[str, Any]]] = defaultdict(deque)
        self.source = "in-memory"
        self.export_root = Path.cwd() / "data" / "webshell_exports"
        self.current_export_dir: Path | None = None
        self.stream_recovery_candidates: list[AttackAlert] = []
        self.stream_transaction_cache: dict[str, list[dict[str, Any]]] = {}

    def required_protocols(self) -> list[str]:
        return ["HTTP"]

    def set_context(self, source: str = "in-memory") -> None:
        self.source = source or "in-memory"
        self.current_export_dir = None
        if not source or source in {"in-memory", "unit-test"}:
            return
        source_path = Path(source)
        if not source_path.exists():
            return

        safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "_", source_path.stem) or "capture"
        source_hash = hashlib.sha1(str(source_path.resolve()).encode("utf-8", errors="ignore")).hexdigest()[:8]
        export_dir = self.export_root / f"{safe_stem}_{source_hash}"
        export_dir.mkdir(parents=True, exist_ok=True)
        self.current_export_dir = export_dir

    def analyze(self, packet: PacketRecord, protocol_events: List[ProtocolEvent]) -> List[AttackAlert]:
        alerts: list[AttackAlert] = []
        for event in protocol_events:
            if event.protocol != "HTTP":
                continue

            details = event.details or {}
            tcp_stream = str(details.get("tcp_stream") or self._packet_tcp_stream(packet) or "").strip() or None
            flow_key = tcp_stream or packet.flow_id
            method = str(details.get("method") or "").upper()
            payload = str(details.get("payload") or "")
            uri = str(details.get("uri") or "")
            content_type = str(details.get("content_type") or "")
            request_cookie = str(details.get("cookie") or "")
            set_cookie = str(details.get("set_cookie") or "")

            if method:
                evidence = self._build_request_details(
                    method=method,
                    uri=uri,
                    payload=payload,
                    request_cookie=request_cookie,
                    content_type=content_type,
                )
            else:
                evidence = self._build_response_details(payload=payload, set_cookie=set_cookie)

            if evidence is None:
                continue

            if method:
                self._apply_request_family_parsers(
                    packet_index=packet.index,
                    evidence=evidence,
                    raw_payload=payload,
                )
            else:
                self._apply_response_family_parsers(
                    flow_id=flow_key,
                    packet_index=packet.index,
                    evidence=evidence,
                    payload=payload,
                )

            evidence.update(
                {
                    "method": method or None,
                    "host": details.get("host"),
                    "uri": uri or None,
                    "status_code": details.get("status_code"),
                    "content_type": content_type or None,
                    "request_cookie": request_cookie or None,
                    "set_cookie": set_cookie or None,
                    "protocol": "HTTP",
                    "detector": self.name,
                    "tcp_stream": tcp_stream,
                }
            )
            alert = self._build_alert(packet, evidence)
            alerts.append(alert)
            self._queue_request_for_response(flow_key, alert)
            self._schedule_stream_recovery(alert)

        return alerts

    def reset(self) -> None:
        self.pending_cookie_exec.clear()
        self.pending_china_chopper.clear()
        self.pending_godzilla.clear()
        self.stream_recovery_candidates.clear()
        self.stream_transaction_cache.clear()

    def finalize(self) -> List[AttackAlert]:
        self._recover_stream_read_artifacts()
        return []

    def _build_request_details(
        self,
        *,
        method: str,
        uri: str,
        payload: str,
        request_cookie: str,
        content_type: str,
    ) -> dict | None:
        params = parse_qs(payload, keep_blank_values=True) if payload and "=" in payload else {}
        param_names = list(params.keys())
        suspicious_params = [name for name in param_names if self._is_suspicious_param_name(name)]
        path_flags = self._path_flags(uri)
        signature_hits = self._signature_hits(payload)
        artifacts = self._collect_artifacts(params)
        embedded_php_source = self._extract_embedded_php_source(payload)
        family_hint = self._family_hint(signature_hits, artifacts, content_type)
        fingerprint_hits = self._request_fingerprint_hits(
            method=method,
            path_flags=path_flags,
            params=params,
            signature_hits=signature_hits,
            artifacts=artifacts,
            request_cookie=request_cookie,
            content_type=content_type,
            raw_payload=payload,
        )
        family_variant = self._family_variant(fingerprint_hits, family_hint)
        score = self._request_score(
            method=method,
            path_flags=path_flags,
            suspicious_params=suspicious_params,
            signature_hits=signature_hits,
            artifacts=artifacts,
            fingerprint_hits=fingerprint_hits,
        )
        if score < self.request_threshold:
            return None

        return {
            "stage": "request",
            "score": score,
            "request_cookie": request_cookie or None,
            "path_flags": path_flags,
            "primary_param": param_names[0] if param_names else None,
            "webshell_param": param_names[0] if param_names else None,
            "param_names": param_names,
            "suspicious_params": suspicious_params,
            "signature_hits": signature_hits,
            "fingerprint_hits": fingerprint_hits,
            "family_hint": family_hint,
            "family_variant": family_variant,
            "encoded_artifacts": artifacts,
            "encoded_artifact_summary": self._artifact_summary(artifacts),
            "payload_preview": self._trim_text(payload, 240),
            "php_script_source": embedded_php_source,
            "suspicious_reasons": self._request_reasons(
                method=method,
                path_flags=path_flags,
                suspicious_params=suspicious_params,
                signature_hits=signature_hits,
                artifacts=artifacts,
                fingerprint_hits=fingerprint_hits,
            ),
        }

    def _build_response_details(self, *, payload: str, set_cookie: str) -> dict | None:
        response_marker = None
        response_preview = None
        marker_hits: list[str] = []
        for marker_name, matcher in (("x_at_y", self._RESPONSE_XY), ("arrow_pipe", self._RESPONSE_ARROW)):
            match = matcher.search(payload)
            if not match:
                continue
            response_marker = marker_name
            marker_hits.append(f"{marker_name}_marker")
            response_preview = self._normalize_text((match.group("body") or "").strip()) or None
            break

        signature_hits = self._signature_hits(payload)
        if self._PHP_SOURCE.search(payload):
            signature_hits.append("php_source")
        signature_hits = sorted(set(signature_hits + marker_hits))
        artifacts = self._collect_inline_artifacts("response", payload)
        fingerprint_hits = self._response_fingerprint_hits(
            response_marker=response_marker,
            signature_hits=signature_hits,
            artifacts=artifacts,
            set_cookie=set_cookie,
            payload=payload,
        )
        family_hint = self._family_hint(signature_hits, artifacts, "")
        family_variant = self._family_variant(fingerprint_hits, family_hint)
        score = self._response_score(
            response_marker=response_marker,
            signature_hits=signature_hits,
            artifacts=artifacts,
            fingerprint_hits=fingerprint_hits,
        )
        if score < self.response_threshold:
            return None

        return {
            "stage": "response",
            "score": score,
            "set_cookie": set_cookie or None,
            "response_marker": response_marker,
            "response_preview": self._trim_text(response_preview, 240),
            "signature_hits": signature_hits,
            "fingerprint_hits": fingerprint_hits,
            "family_hint": family_hint,
            "family_variant": family_variant,
            "encoded_artifacts": artifacts,
            "encoded_artifact_summary": self._artifact_summary(artifacts),
            "payload_preview": self._trim_text(payload, 240),
            "suspicious_reasons": list(dict.fromkeys(list(signature_hits) + list(fingerprint_hits))),
        }

    def _build_alert(self, packet: PacketRecord, evidence: dict[str, Any]) -> AttackAlert:
        score = int(evidence.get("score") or 0)
        fingerprint_hits = [str(item) for item in (evidence.get("fingerprint_hits") or []) if item]
        family_variant = str(evidence.get("family_variant") or "")
        stage = str(evidence.get("stage") or "")

        rule_id = "ATTACK.WEBSHELL"
        name = "疑似 WebShell 管理流量"
        severity = "medium"
        description = "HTTP 流量命中 WebShell 管理请求/响应特征"

        if family_variant == "china_chopper_like":
            rule_id = "ATTACK.WEBSHELL.CHINA_CHOPPER_LIKE"
            name = "疑似中国菜刀类 PHP WebShell 流量"
            severity = "high"
            description = "HTTP 流量命中中国菜刀类 PHP eval-loader 指纹"
        elif family_variant == "cookie_exec_like":
            rule_id = "ATTACK.WEBSHELL.COOKIE_EXEC_LIKE"
            name = "疑似 Cookie 命令执行类 PHP WebShell 流量"
            severity = "high"
            description = "HTTP 流量命中 Cookie 命令执行类 PHP WebShell 指纹"
        elif family_variant == "godzilla_like":
            rule_id = "ATTACK.WEBSHELL.GODZILLA_LIKE"
            name = "疑似哥斯拉类 PHP WebShell 流量"
            severity = "high"
            description = "HTTP 流量命中 Godzilla 类 PHP XOR/zlib 加密信道指纹"
        elif family_variant == "assert_loader_like":
            rule_id = "ATTACK.WEBSHELL.ASSERT_LOADER"
            name = "疑似 Assert Loader WebShell 流量"
            severity = "high"
            description = "HTTP 流量命中 assert/array_map 型 WebShell 指纹"
        elif family_variant == "php_eval_loader":
            rule_id = "ATTACK.WEBSHELL.PHP_EVAL_LOADER"
            name = "疑似 PHP Eval Loader WebShell 流量"
            severity = "high"
            description = "HTTP 流量命中 PHP eval/base64 loader 指纹"
        elif family_variant == "encrypted_http_loader":
            rule_id = "ATTACK.WEBSHELL.ENCRYPTED_HTTP"
            name = "疑似加密型 HTTP WebShell 流量"
            severity = "high"
            description = "HTTP 流量命中加密载荷型 WebShell 指纹"
        elif stage == "response":
            severity = "high" if fingerprint_hits else "medium"

        confidence = min(0.56 + (score * 0.06) + (len(fingerprint_hits) * 0.08), 0.99)
        return AttackAlert(
            rule_id=rule_id,
            name=name,
            severity=severity,
            confidence=round(confidence, 2),
            description=description,
            detector=self.name,
            packet_indexes=[packet.index],
            flow_id=packet.flow_id,
            evidence={
                "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip,
                **evidence,
            },
        )

    def _apply_request_family_parsers(
        self,
        *,
        packet_index: int,
        evidence: dict[str, Any],
        raw_payload: str,
    ) -> None:
        cookie_header = str(evidence.get("request_cookie") or "")

        parsed = self.godzilla_parser.parse_request(raw_payload)
        if parsed:
            evidence.update(parsed)
            evidence["godzilla_variant_id"] = parsed.get("godzilla_variant_id") or "godzilla_php_xor_zlib_v1"
            self._refresh_terminal_transcript(evidence)
            evidence["fingerprint_hits"] = list(
                dict.fromkeys(list(evidence.get("fingerprint_hits") or []) + ["godzilla_request_parser"])
            )
            evidence["family_variant"] = "godzilla_like"
            reasons = list(evidence.get("suspicious_reasons") or [])
            reasons.extend(
                [
                    "family_parser:godzilla",
                    f"operation:{parsed.get('parsed_operation') or 'execute_php'}",
                ]
            )
            evidence["suspicious_reasons"] = list(dict.fromkeys(reasons))
            return

        parsed = self.cookie_exec_parser.parse_request(cookie_header=cookie_header)
        if parsed:
            evidence.update(parsed)
            self._refresh_terminal_transcript(evidence)
            evidence["fingerprint_hits"] = list(
                dict.fromkeys(list(evidence.get("fingerprint_hits") or []) + ["cookie_exec_request_parser"])
            )
            evidence["family_variant"] = "cookie_exec_like"
            reasons = list(evidence.get("suspicious_reasons") or [])
            reasons.extend(
                [
                    "family_parser:cookie_exec",
                    f"operation:{parsed.get('parsed_operation') or 'execute_command'}",
                ]
            )
            evidence["suspicious_reasons"] = list(dict.fromkeys(reasons))
            return

        if not self.china_chopper_parser.match_request(evidence):
            return
        parsed = self.china_chopper_parser.parse_request(evidence)
        if not parsed:
            return
        evidence.update(parsed)
        params = parse_qs(raw_payload, keep_blank_values=True) if raw_payload and "=" in raw_payload else {}
        export_info = self._maybe_export_request_artifact(packet_index=packet_index, evidence=evidence, params=params)
        if export_info:
            self._append_exported_artifact(evidence, export_info)
        self._refresh_terminal_transcript(evidence)
        fingerprint_hits = list(dict.fromkeys(list(evidence.get("fingerprint_hits") or []) + ["china_chopper_request_script"]))
        evidence["fingerprint_hits"] = fingerprint_hits
        evidence["family_variant"] = "china_chopper_like"

        reasons = list(evidence.get("suspicious_reasons") or [])
        reasons.append("family_parser:china_chopper")
        operation = str(parsed.get("parsed_operation") or "")
        if operation:
            reasons.append(f"operation:{operation}")
        evidence["suspicious_reasons"] = list(dict.fromkeys(reasons))

    def _apply_response_family_parsers(
        self,
        *,
        flow_id: str,
        packet_index: int,
        evidence: dict[str, Any],
        payload: str,
    ) -> None:
        set_cookie_header = str(evidence.get("set_cookie") or "")

        pending_cookie_exec = self._peek_pending_request(self.pending_cookie_exec, flow_id)
        if pending_cookie_exec is not None:
            request_alert = pending_cookie_exec["alert"]
            request_parse = pending_cookie_exec["details"]
            parsed_output = self.cookie_exec_parser.parse_response(
                set_cookie_header=set_cookie_header,
                request_parse=request_parse,
            )
            if parsed_output:
                self._pop_pending_request(self.pending_cookie_exec, flow_id)
                self._attach_cookie_exec_output(
                    request_alert=request_alert,
                    request_details=request_parse,
                    response_details=evidence,
                    response_packet_index=packet_index,
                    parsed_output=parsed_output,
                )
                evidence["linked_request_packet_index"] = request_alert.packet_indexes[0] if request_alert.packet_indexes else None
                return

        parsed_cookie_exec = self.cookie_exec_parser.parse_response(set_cookie_header=set_cookie_header, request_parse=None)
        if parsed_cookie_exec:
            self._merge_parsed_output_fields(evidence, parsed_cookie_exec)
            evidence["family_parser"] = self.cookie_exec_parser.name
            evidence["family_variant"] = "cookie_exec_like"
            evidence["fingerprint_hits"] = list(
                dict.fromkeys(list(evidence.get("fingerprint_hits") or []) + ["cookie_exec_response_parser"])
            )
            self._refresh_terminal_transcript(evidence)
            return

        pending_godzilla = self._peek_pending_request(self.pending_godzilla, flow_id)
        if pending_godzilla is not None:
            request_alert = pending_godzilla["alert"]
            request_parse = pending_godzilla["details"]
            parsed_output = self.godzilla_parser.parse_response(body=payload, request_parse=request_parse)
            if parsed_output:
                self._pop_pending_request(self.pending_godzilla, flow_id)
                self._attach_godzilla_output(
                    request_alert=request_alert,
                    request_details=request_parse,
                    response_details=evidence,
                    response_packet_index=packet_index,
                    parsed_output=parsed_output,
                )
                evidence["linked_request_packet_index"] = request_alert.packet_indexes[0] if request_alert.packet_indexes else None
                return

        parsed_godzilla = self.godzilla_parser.parse_response(body=payload, request_parse=None)
        if parsed_godzilla:
            self._merge_parsed_output_fields(evidence, parsed_godzilla)
            evidence["family_parser"] = self.godzilla_parser.name
            evidence["family_variant"] = "godzilla_like"
            evidence["fingerprint_hits"] = list(
                dict.fromkeys(list(evidence.get("fingerprint_hits") or []) + ["godzilla_response_parser"])
            )
            self._refresh_terminal_transcript(evidence)
            return

        if str(evidence.get("response_marker") or "") != "arrow_pipe":
            return

        response_body = self._extract_response_body(payload, marker="arrow_pipe")
        if response_body is None:
            return

        pending = self._pop_pending_request(self.pending_china_chopper, flow_id)
        if pending is not None:
            request_alert = pending["alert"]
            request_parse = pending["details"]
            parsed_output = self.china_chopper_parser.parse_response(body=response_body, request_parse=request_parse)
            export_info = self._maybe_export_response_artifact(
                packet_index=packet_index,
                request_details=request_alert.evidence,
                response_body=response_body,
            )
            if export_info:
                self._append_exported_artifact(request_alert.evidence, export_info)
                self._append_exported_artifact(parsed_output, export_info)
            self._attach_china_chopper_output(
                request_alert=request_alert,
                request_details=request_parse,
                response_details=evidence,
                response_packet_index=packet_index,
                parsed_output=parsed_output,
            )
            evidence["linked_request_packet_index"] = request_alert.packet_indexes[0] if request_alert.packet_indexes else None
            return

        parsed_output = self.china_chopper_parser.parse_response(body=response_body, request_parse=None)
        self._merge_parsed_output_fields(evidence, parsed_output)
        evidence["family_parser"] = self.china_chopper_parser.name
        evidence["family_variant"] = "china_chopper_like"
        self._refresh_terminal_transcript(evidence)
        evidence["fingerprint_hits"] = list(
            dict.fromkeys(list(evidence.get("fingerprint_hits") or []) + ["china_chopper_arrow_response"])
        )

    def _queue_request_for_response(self, flow_id: str, alert: AttackAlert) -> None:
        evidence = alert.evidence or {}
        if alert.detector != self.name:
            return
        if str(evidence.get("stage") or "") != "request":
            return
        family_parser = str(evidence.get("family_parser") or "")
        if family_parser == self.cookie_exec_parser.name:
            self._append_pending_request(self.pending_cookie_exec, flow_id, alert)
        elif family_parser == self.china_chopper_parser.name:
            self._append_pending_request(self.pending_china_chopper, flow_id, alert)
        elif family_parser == self.godzilla_parser.name:
            self._append_pending_request(self.pending_godzilla, flow_id, alert)

    def _append_pending_request(
        self,
        queue_map: Dict[str, Deque[dict[str, Any]]],
        flow_id: str,
        alert: AttackAlert,
    ) -> None:
        queue_map[flow_id].append(
            {
                "alert": alert,
                "details": dict(alert.evidence or {}),
            }
        )

    def _peek_pending_request(
        self,
        queue_map: Dict[str, Deque[dict[str, Any]]],
        flow_id: str,
    ) -> dict[str, Any] | None:
        queue = queue_map.get(flow_id)
        if not queue:
            return None
        return queue[0]

    def _pop_pending_request(
        self,
        queue_map: Dict[str, Deque[dict[str, Any]]],
        flow_id: str,
    ) -> dict[str, Any] | None:
        queue = queue_map.get(flow_id)
        if not queue:
            return None
        item = queue.popleft()
        if not queue:
            queue_map.pop(flow_id, None)
        return item

    def _attach_china_chopper_output(
        self,
        *,
        request_alert: AttackAlert,
        request_details: dict[str, Any],
        response_details: dict[str, Any],
        response_packet_index: int | None,
        parsed_output: dict[str, Any],
    ) -> None:
        self._merge_parsed_output_fields(response_details, parsed_output)
        response_details["family_parser"] = self.china_chopper_parser.name
        response_details["family_variant"] = "china_chopper_like"
        response_details["parsed_operation"] = request_details.get("parsed_operation")
        response_details["parsed_operation_label"] = request_details.get("parsed_operation_label")
        response_details["target_path"] = request_details.get("target_path")
        response_details["request_summary"] = request_details.get("request_summary")
        response_details["terminal_command"] = request_details.get("terminal_command")
        self._refresh_terminal_transcript(response_details)
        response_details["fingerprint_hits"] = list(
            dict.fromkeys(list(response_details.get("fingerprint_hits") or []) + ["china_chopper_arrow_response"])
        )

        request_evidence = request_alert.evidence
        request_evidence["linked_response_packet_index"] = response_packet_index
        self._merge_parsed_output_fields(request_evidence, parsed_output)
        request_evidence["php_script_source"] = request_details.get("php_script_source")
        request_evidence["crypto_summary"] = request_details.get("crypto_summary")
        request_evidence["loader_param"] = request_details.get("loader_param")
        request_evidence["payload_name"] = request_details.get("payload_name")
        request_evidence["session_key"] = request_details.get("session_key")
        request_evidence["loader_wrapper"] = request_details.get("loader_wrapper")
        self._refresh_terminal_transcript(request_evidence)

    def _attach_cookie_exec_output(
        self,
        *,
        request_alert: AttackAlert,
        request_details: dict[str, Any],
        response_details: dict[str, Any],
        response_packet_index: int | None,
        parsed_output: dict[str, Any],
    ) -> None:
        self._merge_parsed_output_fields(response_details, parsed_output)
        response_details["family_parser"] = self.cookie_exec_parser.name
        response_details["family_variant"] = "cookie_exec_like"
        response_details["parsed_operation"] = request_details.get("parsed_operation")
        response_details["target_path"] = request_details.get("target_path")
        response_details["request_summary"] = request_details.get("request_summary")
        response_details["terminal_command"] = request_details.get("terminal_command")
        response_details["php_script_source"] = request_details.get("php_script_source")
        response_details["crypto_summary"] = request_details.get("crypto_summary")
        response_details["request_cookie_name"] = request_details.get("request_cookie_name")
        response_details["response_cookie_name"] = request_details.get("response_cookie_name")
        response_details["response_delimiter"] = request_details.get("response_delimiter")
        self._refresh_terminal_transcript(response_details)
        response_details["fingerprint_hits"] = list(
            dict.fromkeys(list(response_details.get("fingerprint_hits") or []) + ["cookie_exec_response_parser"])
        )

        request_evidence = request_alert.evidence
        request_evidence["linked_response_packet_index"] = response_packet_index
        self._merge_parsed_output_fields(request_evidence, parsed_output)
        request_evidence["php_script_source"] = request_details.get("php_script_source")
        request_evidence["crypto_summary"] = request_details.get("crypto_summary")
        request_evidence["loader_param"] = request_details.get("loader_param")
        request_evidence["payload_name"] = request_details.get("payload_name")
        request_evidence["session_key"] = request_details.get("session_key")
        request_evidence["loader_wrapper"] = request_details.get("loader_wrapper")
        self._refresh_terminal_transcript(request_evidence)

    def _attach_godzilla_output(
        self,
        *,
        request_alert: AttackAlert,
        request_details: dict[str, Any],
        response_details: dict[str, Any],
        response_packet_index: int | None,
        parsed_output: dict[str, Any],
    ) -> None:
        self._merge_parsed_output_fields(response_details, parsed_output)
        response_details["family_parser"] = self.godzilla_parser.name
        response_details["family_variant"] = "godzilla_like"
        response_details["parsed_operation"] = request_details.get("parsed_operation")
        response_details["target_path"] = request_details.get("target_path")
        response_details["request_summary"] = request_details.get("request_summary")
        response_details["terminal_command"] = request_details.get("terminal_command")
        response_details["php_script_source"] = request_details.get("php_script_source")
        response_details["crypto_summary"] = request_details.get("crypto_summary")
        response_details["session_markers"] = request_details.get("session_markers")
        response_details["godzilla_variant_id"] = request_details.get("godzilla_variant_id")
        response_details["loader_param"] = request_details.get("loader_param")
        response_details["payload_name"] = request_details.get("payload_name")
        response_details["session_key"] = request_details.get("session_key")
        response_details["loader_wrapper"] = request_details.get("loader_wrapper")
        self._refresh_terminal_transcript(response_details)
        response_details["fingerprint_hits"] = list(
            dict.fromkeys(list(response_details.get("fingerprint_hits") or []) + ["godzilla_response_parser"])
        )

        request_evidence = request_alert.evidence
        request_evidence["linked_response_packet_index"] = response_packet_index
        self._merge_parsed_output_fields(request_evidence, parsed_output)
        request_evidence["php_script_source"] = request_details.get("php_script_source")
        request_evidence["crypto_summary"] = request_details.get("crypto_summary")
        request_evidence["loader_param"] = request_details.get("loader_param")
        request_evidence["payload_name"] = request_details.get("payload_name")
        request_evidence["session_key"] = request_details.get("session_key")
        request_evidence["loader_wrapper"] = request_details.get("loader_wrapper")
        self._refresh_terminal_transcript(request_evidence)

    def _merge_parsed_output_fields(self, target: dict[str, Any], parsed_output: dict[str, Any]) -> None:
        target["output_type"] = parsed_output.get("output_type")
        target["output_summary"] = parsed_output.get("output_summary")
        target["output_preview"] = parsed_output.get("output_preview")
        target["output"] = parsed_output.get("output")
        target["terminal_output"] = parsed_output.get("terminal_output")
        target["parsed_output"] = parsed_output.get("parsed_output")
        for key in (
            "family_parser",
            "family_variant",
            "godzilla_variant_id",
            "webshell_label",
            "crypto_summary",
            "session_markers",
            "parsed_operation",
            "parsed_operation_label",
            "target_path",
            "request_summary",
            "terminal_command",
            "php_script_source",
            "loader_param",
            "payload_name",
            "session_key",
            "loader_wrapper",
            "decoded_request",
            "request_cookie_name",
            "response_cookie_name",
            "response_delimiter",
        ):
            value = parsed_output.get(key)
            if value is not None:
                target[key] = value
        if parsed_output.get("exported_artifacts"):
            for item in parsed_output.get("exported_artifacts") or []:
                self._append_exported_artifact(target, item)

    def _extract_response_body(self, payload: str, marker: str) -> str | None:
        if marker == "arrow_pipe":
            match = self._RESPONSE_ARROW.search(payload)
            return (match.group("body") or "") if match else None
        if marker == "x_at_y":
            match = self._RESPONSE_XY.search(payload)
            return (match.group("body") or "") if match else None
        return None

    def _refresh_terminal_transcript(self, evidence: dict[str, Any]) -> None:
        command = str(evidence.get("terminal_command") or "").strip()
        output = str(evidence.get("terminal_output") or evidence.get("output") or "").strip()
        lines: list[str] = []
        if command:
            for line in command.splitlines():
                line = line.strip()
                if line:
                    lines.append(f"> {line}")
        if output:
            lines.append(output)
        evidence["terminal_transcript"] = "\n".join(lines).strip() or None

    def _packet_tcp_stream(self, packet: PacketRecord) -> str | None:
        tcp = packet.raw.get("tcp", {})
        stream = tcp.get("stream") if isinstance(tcp, dict) else None
        text = str(stream or "").strip()
        return text or None

    def _schedule_stream_recovery(self, alert: AttackAlert) -> None:
        detail = alert.evidence or {}
        if str(detail.get("stage") or "") != "request":
            return
        if str(detail.get("family_parser") or "") != self.china_chopper_parser.name:
            return
        if str(detail.get("parsed_operation") or "") != "read_file":
            return
        if not str(detail.get("tcp_stream") or "").strip():
            return
        self.stream_recovery_candidates.append(alert)

    def _recover_stream_read_artifacts(self) -> None:
        if not self.stream_recovery_candidates:
            return
        if shutil.which("tshark") is None:
            return
        source_path = Path(self.source)
        if not source_path.exists():
            return

        for alert in self.stream_recovery_candidates:
            detail = alert.evidence or {}
            request_packet_index = alert.packet_indexes[0] if alert.packet_indexes else None
            stream_id = str(detail.get("tcp_stream") or "").strip()
            if request_packet_index is None or not stream_id:
                continue

            transaction = self._stream_transaction_for_request(stream_id, request_packet_index + 1)
            if not transaction:
                continue

            response_body = transaction.get("response_body") or b""
            if not response_body:
                continue

            payload = self._extract_arrow_body_bytes(response_body)
            if not payload:
                continue

            parsed_output = self._build_recovered_file_output(payload, detail)
            self._merge_parsed_output_fields(detail, parsed_output)

            response_packet_index = transaction.get("response_packet_index")
            if response_packet_index is not None:
                detail["linked_response_packet_index"] = response_packet_index
            response_content_length = transaction.get("response_content_length")
            if response_content_length is not None:
                detail["response_content_length"] = response_content_length

            export_packet_index = response_packet_index if response_packet_index is not None else request_packet_index
            export_info = self._export_bytes(
                packet_index=export_packet_index,
                category="download",
                target_path=str(detail.get("target_path") or "") or None,
                data=payload,
            )
            if export_info:
                self._append_exported_artifact(detail, export_info)
            self._refresh_terminal_transcript(detail)

    def _stream_transaction_for_request(self, stream_id: str, request_frame_number: int) -> dict[str, Any] | None:
        transactions = self.stream_transaction_cache.get(stream_id)
        if transactions is None:
            transactions = self._load_stream_transactions(stream_id)
            self.stream_transaction_cache[stream_id] = transactions
        for item in transactions:
            if item.get("request_frame_number") == request_frame_number:
                return item
        return None

    def _load_stream_transactions(self, stream_id: str) -> list[dict[str, Any]]:
        client_bytes, server_bytes = self._follow_tcp_stream_raw(stream_id)
        if client_bytes is None or server_bytes is None:
            return []

        request_messages = self._parse_http_messages(client_bytes)
        response_messages = self._parse_http_messages(server_bytes)
        request_frames = self._http_frame_numbers(stream_id, request=True)
        response_frames = self._http_frame_numbers(stream_id, request=False)
        message_count = min(len(request_messages), len(response_messages), len(request_frames), len(response_frames))

        transactions: list[dict[str, Any]] = []
        for idx in range(message_count):
            response_headers = response_messages[idx].get("headers", {})
            response_frame_number = response_frames[idx]
            transactions.append(
                {
                    "request_frame_number": request_frames[idx],
                    "response_frame_number": response_frame_number,
                    "response_packet_index": response_frame_number - 1 if response_frame_number is not None else None,
                    "request_body": request_messages[idx].get("body") or b"",
                    "response_body": response_messages[idx].get("body") or b"",
                    "response_content_length": self._int_or_none(response_headers.get("content-length")),
                }
            )
        return transactions

    def _follow_tcp_stream_raw(self, stream_id: str) -> tuple[bytes | None, bytes | None]:
        cmd = ["tshark", "-r", self.source, "-q", "-z", f"follow,tcp,raw,{stream_id}"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        if proc.returncode != 0:
            return None, None

        client_chunks: list[str] = []
        server_chunks: list[str] = []
        started = False
        for raw_line in proc.stdout.splitlines():
            line = raw_line.rstrip("\n")
            if line.startswith("Node 1:"):
                started = True
                continue
            if not started:
                continue
            if line.startswith("==="):
                break
            if not line.strip():
                continue
            direction_chunks = server_chunks if line.startswith("\t") else client_chunks
            chunk = re.sub(r"[^0-9A-Fa-f]", "", line)
            if chunk:
                direction_chunks.append(chunk)

        try:
            client_bytes = bytes.fromhex("".join(client_chunks))
            server_bytes = bytes.fromhex("".join(server_chunks))
        except ValueError:
            return None, None
        return client_bytes, server_bytes

    def _parse_http_messages(self, data: bytes) -> list[dict[str, Any]]:
        messages: list[dict[str, Any]] = []
        cursor = 0
        total = len(data)
        while cursor < total:
            header_end = data.find(b"\r\n\r\n", cursor)
            if header_end < 0:
                break
            header_block = data[cursor:header_end]
            header_text = header_block.decode("latin1", errors="ignore")
            lines = header_text.split("\r\n")
            if not lines or not lines[0]:
                break

            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" not in line:
                    continue
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()

            content_length = self._int_or_none(headers.get("content-length")) or 0
            body_start = header_end + 4
            body_end = body_start + max(content_length, 0)
            if body_end > total:
                break

            messages.append(
                {
                    "start_line": lines[0],
                    "headers": headers,
                    "body": data[body_start:body_end],
                }
            )
            cursor = body_end
        return messages

    def _http_frame_numbers(self, stream_id: str, *, request: bool) -> list[int]:
        display_filter = f"tcp.stream=={stream_id} && {'http.request' if request else 'http.response'}"
        cmd = ["tshark", "-r", self.source, "-Y", display_filter, "-T", "fields", "-e", "frame.number"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        if proc.returncode != 0:
            return []
        frames: list[int] = []
        for line in proc.stdout.splitlines():
            value = self._int_or_none(line.strip())
            if value is not None:
                frames.append(value)
        return frames

    def _extract_arrow_body_bytes(self, body: bytes) -> bytes | None:
        start = body.find(b"->|")
        if start < 0:
            return None
        start += 3
        end = body.rfind(b"|<-")
        if end < start:
            return None
        return body[start:end]

    def _build_recovered_file_output(self, payload: bytes, request_details: dict[str, Any]) -> dict[str, Any]:
        target_path = str(request_details.get("target_path") or "") or None
        decoded_kind, _ = self._classify_decoded(payload)
        if decoded_kind in {"php", "text"}:
            body_text = payload.decode("utf-8", errors="replace")
            return self.china_chopper_parser.parse_response(body=body_text, request_parse=request_details)
        if decoded_kind == "zip":
            return self._build_zip_output(payload, target_path)
        return self._build_binary_file_output(payload, target_path, decoded_kind)

    def _build_zip_output(self, payload: bytes, target_path: str | None) -> dict[str, Any]:
        members: list[str] = []
        encrypted = False
        comment = ""
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                for info in archive.infolist()[:50]:
                    is_encrypted = bool(info.flag_bits & 0x1)
                    encrypted = encrypted or is_encrypted
                    label = info.filename
                    if is_encrypted:
                        label = f"{label} [encrypted]"
                    members.append(label)
                comment = archive.comment.decode("utf-8", errors="replace").strip("\x00\r\n\t ")
        except zipfile.BadZipFile:
            return self._build_binary_file_output(payload, target_path, "zip")

        lines = list(members) if members else [f"[zip {len(payload)}B]"]
        if comment:
            lines.append(comment)
        preview = "\n".join(lines)
        summary = f"读取文件 {target_path or '?'}，ZIP {len(payload)}B"
        if members:
            summary = f"{summary}，成员 {len(members)} 个"
        return {
            "output_type": "file_content",
            "output_summary": summary,
            "output_preview": self._trim_text(preview, 240),
            "output": self._trim_text(preview, 2000),
            "terminal_output": self._trim_text(preview, 4000),
            "parsed_output": {
                "target_path": target_path,
                "archive_type": "zip",
                "binary_size": len(payload),
                "zip_members": members,
                "archive_encrypted": encrypted,
                "archive_comment": comment or None,
            },
        }

    def _build_binary_file_output(self, payload: bytes, target_path: str | None, decoded_kind: str) -> dict[str, Any]:
        label = decoded_kind if decoded_kind and decoded_kind != "binary" else "binary"
        terminal_output = f"[{label} {len(payload)}B]"
        return {
            "output_type": "file_content",
            "output_summary": f"读取文件 {target_path or '?'}，{label} {len(payload)}B",
            "output_preview": terminal_output,
            "output": terminal_output,
            "terminal_output": terminal_output,
            "parsed_output": {
                "target_path": target_path,
                "binary_type": label,
                "binary_size": len(payload),
            },
        }

    def _int_or_none(self, value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(str(value).strip())
        except Exception:
            return None

    def _maybe_export_request_artifact(
        self,
        *,
        packet_index: int,
        evidence: dict[str, Any],
        params: dict[str, list[str]],
    ) -> dict[str, Any] | None:
        if str(evidence.get("parsed_operation") or "") != "write_file":
            return None
        raw_value = ((params.get("z2") or [""])[0]).strip()
        if not raw_value:
            return None
        decoded = self._decode_best_effort(raw_value)
        if not decoded:
            return None
        target_path = str(evidence.get("target_path") or "") or None
        return self._export_bytes(
            packet_index=packet_index,
            category="upload",
            target_path=target_path,
            data=decoded,
        )

    def _maybe_export_response_artifact(
        self,
        *,
        packet_index: int,
        request_details: dict[str, Any],
        response_body: str,
    ) -> dict[str, Any] | None:
        operation = str(request_details.get("parsed_operation") or "")
        if operation not in {"read_file", "write_file"}:
            return None
        if operation == "write_file":
            return None

        data = self._string_to_bytes_best_effort(response_body)
        if not data:
            return None
        target_path = str(request_details.get("target_path") or "") or None
        return self._export_bytes(
            packet_index=packet_index,
            category="download",
            target_path=target_path,
            data=data,
        )

    def _append_exported_artifact(self, target: dict[str, Any], artifact: dict[str, Any]) -> None:
        items = list(target.get("exported_artifacts") or [])
        key = str(artifact.get("path") or artifact.get("url") or "")
        if key and any(str(item.get("path") or item.get("url") or "") == key for item in items):
            target["exported_artifacts"] = items
            return
        items.append(artifact)
        target["exported_artifacts"] = items

    def _export_bytes(
        self,
        *,
        packet_index: int,
        category: str,
        target_path: str | None,
        data: bytes,
    ) -> dict[str, Any] | None:
        if self.current_export_dir is None or not data:
            return None

        filename = self._safe_export_filename(packet_index=packet_index, category=category, target_path=target_path)
        export_path = self.current_export_dir / filename
        export_path.write_bytes(data)
        relative = export_path.relative_to(self.export_root).as_posix()
        return {
            "category": category,
            "name": export_path.name,
            "path": str(export_path),
            "url": artifact_raw_url(relative),
            "viewer_url": artifact_viewer_url(relative),
            "size": len(data),
        }

    def _safe_export_filename(self, *, packet_index: int, category: str, target_path: str | None) -> str:
        basename = self._target_basename(target_path) or f"{category}.bin"
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", basename).strip("._") or f"{category}.bin"
        return f"packet_{packet_index:06d}_{category}_{safe_name}"

    def _target_basename(self, target_path: str | None) -> str | None:
        if not target_path:
            return None
        parts = re.split(r"[\\\\/]+", str(target_path))
        return parts[-1] if parts else None

    def _decode_best_effort(self, value: str) -> bytes | None:
        compact = re.sub(r"\s+", "", value)
        if self._looks_like_hex(compact):
            try:
                return bytes.fromhex(compact)
            except ValueError:
                return None
        if self._looks_like_base64(compact):
            try:
                padding = (-len(compact)) % 4
                return base64.b64decode(compact + ("=" * padding), validate=False)
            except Exception:
                return None
        return self._string_to_bytes_best_effort(value)

    def _string_to_bytes_best_effort(self, value: str) -> bytes | None:
        if not value:
            return None
        if any(ord(ch) > 255 for ch in value):
            return value.encode("utf-8", errors="ignore")
        return value.encode("latin1", errors="ignore")

    def _request_score(
        self,
        *,
        method: str,
        path_flags: list[str],
        suspicious_params: list[str],
        signature_hits: list[str],
        artifacts: list[dict],
        fingerprint_hits: list[str],
    ) -> int:
        score = 0
        if method == "POST":
            score += 1
        score += min(len(path_flags), 2)
        if suspicious_params:
            score += 1
        if signature_hits:
            score += 2
        if artifacts:
            score += 1
        if any(item.get("decoded_kind") == "php" for item in artifacts):
            score += 1
        score += min(len(fingerprint_hits), 3)
        return score

    def _response_score(
        self,
        *,
        response_marker: str | None,
        signature_hits: list[str],
        artifacts: list[dict],
        fingerprint_hits: list[str],
    ) -> int:
        score = 0
        if response_marker:
            score += 2
        if signature_hits:
            score += 1
        if artifacts:
            score += 1
        score += min(len(fingerprint_hits), 3)
        return score

    def _request_reasons(
        self,
        *,
        method: str,
        path_flags: list[str],
        suspicious_params: list[str],
        signature_hits: list[str],
        artifacts: list[dict],
        fingerprint_hits: list[str],
    ) -> list[str]:
        reasons = []
        if method:
            reasons.append(f"method:{method}")
        reasons.extend(f"path:{flag}" for flag in path_flags)
        if suspicious_params:
            reasons.append(f"params:{','.join(suspicious_params[:6])}")
        reasons.extend(f"signature:{item}" for item in signature_hits[:8])
        reasons.extend(f"fingerprint:{item}" for item in fingerprint_hits[:8])
        if artifacts:
            reasons.append(f"artifacts:{len(artifacts)}")
        return reasons

    def _request_fingerprint_hits(
        self,
        *,
        method: str,
        path_flags: list[str],
        params: dict[str, list[str]],
        signature_hits: list[str],
        artifacts: list[dict],
        request_cookie: str,
        content_type: str,
        raw_payload: str,
    ) -> list[str]:
        hits: list[str] = []
        param_names = {name.lower() for name in params}
        artifact_map = {item.get("field"): item for item in artifacts}
        signature_set = set(signature_hits)

        if method == "POST" and "script_suffix" in path_flags and (
            "eval_post" in signature_set or "base64_post" in signature_set
        ):
            hits.append("php_eval_loader_stub")

        if "array_map_assert" in signature_set:
            hits.append("php_assert_loader_stub")

        if {"aa", "action", "z1", "z2"}.issubset(param_names):
            action_artifact = artifact_map.get("action")
            z1_artifact = artifact_map.get("z1")
            if (
                action_artifact
                and action_artifact.get("encoding") == "base64"
                and action_artifact.get("decoded_kind") == "php"
                and z1_artifact
                and z1_artifact.get("encoding") == "base64"
            ):
                hits.append("china_chopper_param_layout")

        if any(item.get("field") == "z2" and item.get("encoding") == "hex" for item in artifacts):
            hits.append("file_transfer_blob")

        if content_type.lower().startswith("application/x-www-form-urlencoded") and artifacts:
            hits.append("form_encoded_loader")

        if "upload_path" in path_flags and "short_script_name" in path_flags:
            hits.append("dropper_path")

        if content_type.lower() == "application/octet-stream":
            hits.append("binary_encrypted_post")

        if self.cookie_exec_parser.identify_request_variant(request_cookie):
            hits.extend(["cookie_exec_cookie_layout", "cookie_exec_known_variant"])

        if self._COOKIE_EXEC_UPLOAD.search(raw_payload or ""):
            hits.append("cookie_exec_upload_stub")

        if self.godzilla_parser.identify_request_variant(raw_payload):
            hits.extend(["godzilla_request_marker", "godzilla_known_variant"])

        return sorted(set(hits))

    def _response_fingerprint_hits(
        self,
        *,
        response_marker: str | None,
        signature_hits: list[str],
        artifacts: list[dict],
        set_cookie: str,
        payload: str,
    ) -> list[str]:
        hits: list[str] = []
        signature_set = set(signature_hits)

        if response_marker == "arrow_pipe":
            hits.append("china_chopper_arrow_response")
        if response_marker == "x_at_y":
            hits.append("assert_loader_x_at_y_response")
        if "php_source" in signature_set:
            hits.append("php_source_echo")
        if any(item.get("decoded_kind") in {"jpeg", "zip"} for item in artifacts):
            hits.append("file_transfer_response")
        if self.cookie_exec_parser.identify_response_variant(set_cookie_header=set_cookie, request_parse=None):
            hits.extend(["cookie_exec_set_cookie", "cookie_exec_known_variant"])
        if self.godzilla_parser.identify_response_variant(payload):
            hits.extend(["godzilla_response_marker", "godzilla_known_variant"])

        return sorted(set(hits))

    def _family_variant(self, fingerprint_hits: list[str], family_hint: str | None) -> str | None:
        hit_set = set(fingerprint_hits)
        if "china_chopper_param_layout" in hit_set or "china_chopper_arrow_response" in hit_set:
            return "china_chopper_like"
        if "cookie_exec_cookie_layout" in hit_set or "cookie_exec_set_cookie" in hit_set or "cookie_exec_upload_stub" in hit_set:
            return "cookie_exec_like"
        if "godzilla_request_marker" in hit_set or "godzilla_response_marker" in hit_set:
            return "godzilla_like"
        if "php_assert_loader_stub" in hit_set or "assert_loader_x_at_y_response" in hit_set:
            return "assert_loader_like"
        if "php_eval_loader_stub" in hit_set or family_hint == "eval_loader":
            return "php_eval_loader"
        if "binary_encrypted_post" in hit_set or family_hint == "encrypted_post":
            return "encrypted_http_loader"
        return None

    def _path_flags(self, uri: str) -> list[str]:
        if not uri:
            return []
        path = urlsplit(uri).path or uri
        flags = []
        if self._WEBSHELL_PATH.search(path):
            flags.append("script_suffix")

        basename = posixpath.basename(path).lower()
        dirname = posixpath.dirname(path).lower()
        if any(token in basename for token in ("shell", "cmd", "backdoor", "assert", "eval")):
            flags.append("suspicious_basename")
        elif re.fullmatch(r"[a-z]?\d{1,3}\.(php|jsp|jspx|asp|aspx)", basename):
            flags.append("short_script_name")
        if "/upload" in dirname or path.lower().startswith("/upload/"):
            flags.append("upload_path")
        return flags

    def _signature_hits(self, text: str) -> list[str]:
        if not text:
            return []
        normalized = self._normalize_signature_text(text)
        hits = []
        for name, needle in self._TEXT_SIGNATURES:
            if needle in normalized:
                hits.append(name)
        return sorted(set(hits))

    def _collect_artifacts(self, params: dict[str, list[str]]) -> list[dict]:
        artifacts: list[dict] = []
        for field_name, values in params.items():
            if not values:
                continue
            artifacts.extend(self._collect_inline_artifacts(field_name, values[0]))
        return artifacts

    def _collect_inline_artifacts(self, field_name: str, value: str) -> list[dict]:
        if not value:
            return []

        artifacts: list[dict] = []
        seen: set[tuple[str, str, int]] = set()
        candidates: list[tuple[str, str]] = []
        stripped = value.strip()
        if self._looks_like_hex(stripped):
            candidates.append(("hex", stripped))
        elif self._looks_like_base64(stripped):
            candidates.append(("base64", stripped))
        candidates.extend(("base64", match) for match in self._BASE64_BLOB.findall(value))
        candidates.extend(("hex", match) for match in self._HEX_BLOB.findall(value))

        for encoding, candidate in candidates:
            if encoding == "base64" and self._looks_like_hex(candidate):
                continue
            try:
                decoded = self._decode_candidate(candidate, encoding)
            except Exception:
                continue
            if not decoded:
                continue

            key = (encoding, field_name, len(decoded))
            if key in seen:
                continue
            seen.add(key)

            decoded_kind, decoded_preview = self._classify_decoded(decoded)
            artifacts.append(
                {
                    "field": field_name,
                    "encoding": encoding,
                    "encoded_length": len(candidate),
                    "decoded_length": len(decoded),
                    "decoded_kind": decoded_kind,
                    "decoded_preview": decoded_preview,
                }
            )

            if len(artifacts) >= 6:
                break
        return artifacts

    def _decode_candidate(self, candidate: str, encoding: str) -> bytes:
        if encoding == "base64":
            compact = re.sub(r"\s+", "", candidate)
            padding = (-len(compact)) % 4
            return base64.b64decode(compact + ("=" * padding), validate=False)
        return bytes.fromhex(candidate)

    def _classify_decoded(self, decoded: bytes) -> tuple[str, str | None]:
        if decoded.startswith(b"\xff\xd8\xff"):
            return "jpeg", self._trim_text(decoded[:24].hex().upper(), 240)
        if decoded.startswith(b"PK\x03\x04"):
            return "zip", self._trim_text(decoded[:24].hex().upper(), 240)

        text = decoded.decode("utf-8", errors="replace")
        if self._looks_like_text(text):
            normalized = self._normalize_signature_text(text)
            if any(
                token in normalized
                for token in (
                    "eval($_post[",
                    "base64_decode($_post[",
                    "array_map(assert",
                    "$_server[",
                    "proc_open(",
                    "function_exists(",
                    "ini_set(",
                    "die();",
                )
            ):
                return "php", self._trim_text(self._normalize_text(text), 4000)
            return "text", self._trim_text(self._normalize_text(text), 1000)

        return "binary", self._trim_text(decoded[:24].hex().upper(), 240)

    def _family_hint(self, signature_hits: list[str], artifacts: list[dict], content_type: str) -> str | None:
        hits = set(signature_hits)
        if "array_map_assert" in hits:
            return "assert_loader"
        if "eval_post" in hits or "base64_post" in hits:
            return "eval_loader"
        if "php_source" in hits:
            return "one_liner_source"
        if content_type.lower() == "application/octet-stream":
            return "encrypted_post"
        if any(item.get("decoded_kind") == "php" for item in artifacts):
            return "embedded_php"
        return None

    def _artifact_summary(self, artifacts: list[dict]) -> str | None:
        if not artifacts:
            return None
        return "; ".join(
            f"{item['field']}:{item['encoding']}/{item['decoded_kind']}({item['decoded_length']}B)"
            for item in artifacts[:6]
        )

    def _is_suspicious_param_name(self, name: str) -> bool:
        lower_name = name.lower()
        return lower_name in self._SUSPICIOUS_PARAM_NAMES or re.fullmatch(r"z\d+", lower_name) is not None

    def _looks_like_base64(self, value: str) -> bool:
        compact = re.sub(r"\s+", "", value)
        if len(compact) < 24:
            return False
        if len(compact) % 4 != 0:
            return False
        return re.fullmatch(r"[A-Za-z0-9+/=]+", compact) is not None

    def _looks_like_hex(self, value: str) -> bool:
        compact = re.sub(r"\s+", "", value)
        if len(compact) < 64 or len(compact) % 2 != 0:
            return False
        return re.fullmatch(r"[0-9A-Fa-f]+", compact) is not None

    def _looks_like_text(self, value: str) -> bool:
        if not value:
            return False
        printable = sum(1 for char in value if char.isprintable() or char in "\r\n\t")
        return printable / max(len(value), 1) >= 0.85

    def _normalize_signature_text(self, value: str) -> str:
        return re.sub(r"[\s\"'`\\\.]+", "", value).lower()

    def _extract_embedded_php_source(self, value: str) -> str | None:
        match = re.search(r"(<\?php.*?\?>)", str(value or ""), re.IGNORECASE | re.DOTALL)
        if not match:
            return None
        return self._trim_text(self._normalize_text(match.group(1).strip()), 4000)

    def _trim_text(self, value: Any, limit: int) -> str | None:
        if value is None:
            return None
        text = str(value)
        if len(text) <= limit:
            return text
        return f"{text[: limit - 3]}..."

    def _normalize_text(self, value: str) -> str:
        return value.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", "\t")
