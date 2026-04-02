from __future__ import annotations

from urllib.parse import quote


def normalize_artifact_relative_path(raw_path: str) -> str:
    text = str(raw_path or "").replace("\\", "/").strip()
    if not text:
        raise ValueError("artifact path is empty")

    parts: list[str] = []
    for part in text.split("/"):
        part = part.strip()
        if not part or part == ".":
            continue
        if part == "..":
            raise ValueError("artifact path traversal is not allowed")
        parts.append(part)

    if not parts:
        raise ValueError("artifact path is empty")
    return "/".join(parts)


def artifact_raw_url(relative_path: str) -> str:
    normalized = normalize_artifact_relative_path(relative_path)
    return "/artifacts/" + "/".join(quote(part, safe="") for part in normalized.split("/"))


def artifact_viewer_url(relative_path: str) -> str:
    normalized = normalize_artifact_relative_path(relative_path)
    return "/artifact-view?path=" + quote(normalized, safe="/")
