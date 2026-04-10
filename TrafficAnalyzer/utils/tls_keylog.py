from __future__ import annotations

from pathlib import Path
import re

TLS_KEYLOG_LINE_RE = re.compile(r"^[A-Z0-9_]+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+$")
TLS_KEYLOG_RECORD_RE = re.compile(
    r"(?:CLIENT_[A-Z0-9_]+|SERVER_[A-Z0-9_]+|EXPORTER_[A-Z0-9_]+|EARLY_EXPORTER_SECRET|ECH_SECRET)"
    r"\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+"
)


def decode_text_payload(payload: bytes) -> str:
    for encoding in ("utf-8", "gb18030", "latin1"):
        try:
            return payload.decode(encoding)
        except UnicodeDecodeError:
            continue
    return payload.decode("latin1", errors="replace")


def normalize_local_input_path(raw_path: str) -> Path | None:
    text = str(raw_path or "").strip().strip('"').strip("'")
    if not text:
        return None
    if len(text) >= 3 and text[1:3] in {":\\", ":/"} and text[0].isalpha():
        drive = text[0].lower()
        suffix = text[3:].replace("\\", "/")
        return Path(f"/mnt/{drive}/{suffix}")
    return Path(text).expanduser()


def normalize_tls_keylog_text(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""

    repaired = (
        text.replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\\r", "\n")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )

    rows: list[str] = []
    seen: set[str] = set()
    for match in TLS_KEYLOG_RECORD_RE.finditer(repaired):
        line = " ".join(str(match.group(0) or "").strip().strip("\ufeff").split())
        if not line or not TLS_KEYLOG_LINE_RE.match(line) or line in seen:
            continue
        seen.add(line)
        rows.append(line)
    return "\n".join(rows)


def resolve_tls_keylog_text(
    *,
    key_text: str | None = None,
    key_file_name: str | None = None,
    key_file_bytes: bytes | None = None,
) -> tuple[str | None, dict]:
    if key_file_bytes:
        raw_text = decode_text_payload(key_file_bytes)
        label = key_file_name or "uploaded"
        mode = "upload_file"
    else:
        text = str(key_text or "").strip()
        if not text:
            return None, {"mode": "empty", "label": "", "line_count": 0}

        file_path = None
        if "\n" not in text and "\r" not in text and len(text) < 4096:
            file_path = normalize_local_input_path(text)

        is_file = False
        if file_path is not None:
            try:
                is_file = file_path.is_file()
            except OSError:
                is_file = False

        if is_file and file_path is not None:
            raw_text = decode_text_payload(file_path.read_bytes())
            label = str(file_path)
            mode = "path_file"
        else:
            raw_text = text
            label = "inline"
            mode = "inline_text"

    normalized = normalize_tls_keylog_text(raw_text)
    line_count = len(normalized.splitlines()) if normalized else 0
    return normalized or None, {
        "mode": mode if normalized else "empty",
        "label": label if normalized else "",
        "line_count": line_count,
    }
