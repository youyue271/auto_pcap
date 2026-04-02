from __future__ import annotations

import re
from typing import Any


class ChinaChopperParser:
    name = "china_chopper"

    _DIR_ENTRY = re.compile(
        r"(?P<name>.+?)t(?P<mtime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})t(?P<size>\d+)t(?P<mode>\d{4})n"
    )

    def match_request(self, details: dict[str, Any]) -> bool:
        action_source = self._artifact_text(details, "action")
        if not action_source:
            return False
        normalized = self._normalize_php(action_source)
        return 'echo("->|")' in normalized or 'echo(\'->|\')' in normalized

    def parse_request(self, details: dict[str, Any]) -> dict[str, Any] | None:
        action_source = self._artifact_text(details, "action")
        if not action_source:
            return None

        normalized = self._normalize_php(action_source)
        z1_value = self._artifact_text(details, "z1")
        z2_artifact = self._artifact(details, "z2")
        output_type = "text"

        operation = "generic"
        operation_label = "通用菜刀动作"
        target_path = z1_value
        request_summary = "识别到中国菜刀类 PHP 管理脚本"

        if '$_server["script_filename"]' in normalized or '$_server["path_translated"]' in normalized:
            operation = "probe_environment"
            operation_label = "环境探测"
            request_summary = "探测脚本目录、盘符和系统信息"
            output_type = "environment_info"
        elif "opendir(" in normalized:
            operation = "list_directory"
            operation_label = "目录遍历"
            request_summary = f"列目录 {target_path or '(未解析路径)'}"
            output_type = "directory_listing"
        elif 'fopen($f,"w")' in normalized or "fwrite(" in normalized or "str_replace(" in normalized:
            operation = "write_file"
            operation_label = "文件写入"
            request_summary = f"写入文件 {target_path or '(未解析路径)'}"
            output_type = "write_result"
        elif 'fopen($f,"r")' in normalized or 'fopen($p,"r")' in normalized or "fread(" in normalized or "filesize(" in normalized:
            operation = "read_file"
            operation_label = "文件读取"
            request_summary = f"读取文件 {target_path or '(未解析路径)'}"
            output_type = "file_content"
        elif any(token in normalized for token in ("system(", "shell_exec(", "passthru(", "exec(", "proc_open(")):
            operation = "execute_command"
            operation_label = "命令执行"
            request_summary = "执行系统命令或进程控制"
            output_type = "command_output"

        if operation == "write_file" and z2_artifact:
            blob_kind = str(z2_artifact.get("decoded_kind") or "binary")
            blob_len = int(z2_artifact.get("decoded_length") or 0)
            request_summary = f"{request_summary}，载荷 {blob_kind} {blob_len}B"

        return {
            "family_parser": self.name,
            "family_variant": "china_chopper_like",
            "parsed_operation": operation,
            "parsed_operation_label": operation_label,
            "target_path": target_path,
            "request_summary": request_summary,
            "terminal_command": self._terminal_command(operation, target_path),
            "output_type": output_type,
            "request_args": {
                "z1": z1_value,
                "z2_kind": z2_artifact.get("decoded_kind") if z2_artifact else None,
                "z2_size": z2_artifact.get("decoded_length") if z2_artifact else None,
            },
        }

    def parse_response(
        self,
        *,
        body: str,
        request_parse: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        operation = str((request_parse or {}).get("parsed_operation") or "")
        target_path = str((request_parse or {}).get("target_path") or "") or None

        if operation == "probe_environment":
            return self._parse_environment_output(body)
        if operation == "list_directory":
            return self._parse_directory_output(body, target_path)
        if operation == "write_file":
            return self._parse_write_output(body, target_path, request_parse or {})
        if operation == "read_file":
            return self._parse_file_content_output(body, target_path)
        if operation == "execute_command":
            return self._parse_command_output(body)

        guessed = self._guess_response_output(body)
        if guessed is not None:
            return guessed
        return self._generic_output(body)

    def _parse_environment_output(self, body: str) -> dict[str, Any]:
        raw = body.strip()
        parts = raw.split("t", 2)
        script_dir = parts[0] if len(parts) > 0 else ""
        drives = re.findall(r"[A-Z]:", parts[1]) if len(parts) > 1 else []
        system_info = parts[2] if len(parts) > 2 else ""
        summary = f"脚本目录 {script_dir or '?'}；盘符 {', '.join(drives) or '?'}；系统 {system_info or '?'}"
        terminal_output = "\n".join(part for part in [script_dir, " ".join(drives), system_info] if part)
        return {
            "output_type": "environment_info",
            "output_summary": summary,
            "output_preview": self._trim(summary, 240),
            "output": self._trim(terminal_output or summary, 1200),
            "terminal_output": self._trim(terminal_output or summary, 2000),
            "parsed_output": {
                "script_dir": script_dir or None,
                "drives": drives,
                "system_info": system_info or None,
            },
        }

    def _parse_directory_output(self, body: str, target_path: str | None) -> dict[str, Any]:
        entries = []
        for match in self._DIR_ENTRY.finditer(body):
            entries.append(
                {
                    "name": match.group("name"),
                    "mtime": match.group("mtime"),
                    "size": int(match.group("size")),
                    "mode": match.group("mode"),
                }
            )
        names = [entry["name"] for entry in entries[:12]]
        summary = f"目录 {target_path or '?'} 共 {len(entries)} 个条目"
        if names:
            summary = f"{summary}: {', '.join(names)}"
        terminal_output = "\n".join(entry["name"] for entry in entries) or body.strip()
        return {
            "output_type": "directory_listing",
            "output_summary": summary,
            "output_preview": self._trim(summary, 240),
            "output": self._trim(terminal_output, 1200),
            "terminal_output": self._trim(terminal_output, 4000),
            "parsed_output": {
                "target_path": target_path,
                "entry_count": len(entries),
                "entries": entries[:50],
            },
        }

    def _parse_write_output(self, body: str, target_path: str | None, request_parse: dict[str, Any]) -> dict[str, Any]:
        cleaned = body.strip()
        success = cleaned == "1"
        size_hint = request_parse.get("request_args", {}).get("z2_size")
        summary = f"写入文件 {target_path or '?'} {'成功' if success else '失败'}"
        if size_hint:
            summary = f"{summary}，载荷 {size_hint}B"
        return {
            "output_type": "write_result",
            "output_summary": summary,
            "output_preview": self._trim(summary, 240),
            "output": self._trim(cleaned or summary, 1200),
            "terminal_output": self._trim(cleaned or summary, 2000),
            "parsed_output": {
                "target_path": target_path,
                "success": success,
                "raw": cleaned,
            },
        }

    def _parse_file_content_output(self, body: str, target_path: str | None) -> dict[str, Any]:
        normalized = self._normalize_file_text(body)
        summary = f"读取文件 {target_path or '?'}，返回 {len(normalized)} 字符"
        return {
            "output_type": "file_content",
            "output_summary": summary,
            "output_preview": self._trim(normalized, 240),
            "output": self._trim(normalized, 2000),
            "terminal_output": self._trim(normalized, 4000),
            "parsed_output": {
                "target_path": target_path,
                "content": self._trim(normalized, 4000),
                "length": len(normalized),
            },
        }

    def _parse_command_output(self, body: str) -> dict[str, Any]:
        cleaned = self._normalize_file_text(body)
        summary = f"命令返回 {len(cleaned)} 字符"
        return {
            "output_type": "command_output",
            "output_summary": summary,
            "output_preview": self._trim(cleaned, 240),
            "output": self._trim(cleaned, 2000),
            "terminal_output": self._trim(cleaned, 4000),
            "parsed_output": {
                "content": self._trim(cleaned, 4000),
                "length": len(cleaned),
            },
        }

    def _guess_response_output(self, body: str) -> dict[str, Any] | None:
        if self._DIR_ENTRY.search(body):
            return self._parse_directory_output(body, None)
        if re.match(r".+?t[A-Z](?::[A-Z])*:t", body):
            return self._parse_environment_output(body)
        if body.lstrip().startswith("<?php"):
            return self._parse_file_content_output(body, None)
        return None

    def _generic_output(self, body: str) -> dict[str, Any]:
        cleaned = self._normalize_file_text(body)
        return {
            "output_type": "text",
            "output_summary": f"返回 {len(cleaned)} 字符",
            "output_preview": self._trim(cleaned, 240),
            "output": self._trim(cleaned, 2000),
            "terminal_output": self._trim(cleaned, 4000),
            "parsed_output": {
                "content": self._trim(cleaned, 4000),
                "length": len(cleaned),
            },
        }

    def _artifact(self, details: dict[str, Any], field: str) -> dict[str, Any] | None:
        for item in details.get("encoded_artifacts") or []:
            if str(item.get("field") or "") == field:
                return item
        return None

    def _artifact_text(self, details: dict[str, Any], field: str) -> str | None:
        artifact = self._artifact(details, field)
        if artifact is None:
            return None
        preview = artifact.get("decoded_preview")
        if preview is None:
            return None
        return str(preview)

    def _normalize_php(self, text: str) -> str:
        return re.sub(r"[\s'`\\\\]+", "", text.lower())

    def _normalize_file_text(self, text: str) -> str:
        normalized = str(text or "")
        if "\n" not in normalized and "\r" not in normalized and "rnrn" in normalized.lower():
            normalized = normalized.replace("rnrn", "\n\n").replace("rn", "\n")
        return normalized

    def _terminal_command(self, operation: str, target_path: str | None) -> str:
        target = target_path or ""
        if operation == "probe_environment":
            return "pwd\ndrives\nsysteminfo"
        if operation == "list_directory":
            return f"ls {target}".strip()
        if operation == "write_file":
            return f"upload {target}".strip()
        if operation == "read_file":
            return f"cat {target}".strip()
        if operation == "execute_command":
            return "exec"
        return "webshell"

    def _trim(self, value: str, limit: int) -> str:
        if len(value) <= limit:
            return value
        return f"{value[: limit - 3]}..."
