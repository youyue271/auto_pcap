from __future__ import annotations

import os
import tempfile
from dataclasses import asdict
from pathlib import Path
import traceback

from fastapi.concurrency import run_in_threadpool
from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from TrafficAnalyzer.pipeline import build_default_pipeline_service
from TrafficAnalyzer.utils.artifact_utils import artifact_raw_url, artifact_viewer_url, normalize_artifact_relative_path
from TrafficAnalyzer.web.job_manager import HTTPError, JobManager

BASE_DIR = Path(__file__).resolve().parent
ARTIFACTS_DIR = BASE_DIR.parent.parent / "data" / "webshell_exports"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
CYBERCHEF_STATIC_DIR = Path("/mnt/e/STEVE/software/CRYPTO/CyberChef_v9.21.0")
CYBERCHEF_ENTRY_NAME = "CyberChef_v10.5.2.html"
CYBERCHEF_FALLBACK_URL = f"file:///E:/STEVE/software/CRYPTO/CyberChef_v9.21.0/{CYBERCHEF_ENTRY_NAME}"
CYBERCHEF_LOCAL_URL = (
    f"/cyberchef-static/{CYBERCHEF_ENTRY_NAME}"
    if (CYBERCHEF_STATIC_DIR / CYBERCHEF_ENTRY_NAME).exists()
    else CYBERCHEF_FALLBACK_URL
)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app = FastAPI(title="TrafficAnalyzer Web UI", version="0.1.0")
app.mount("/artifacts", StaticFiles(directory=str(ARTIFACTS_DIR)), name="artifacts")
if CYBERCHEF_STATIC_DIR.exists():
    app.mount("/cyberchef-static", StaticFiles(directory=str(CYBERCHEF_STATIC_DIR)), name="cyberchef-static")
job_manager = JobManager()
UPLOAD_CHUNK_SIZE = 1024 * 1024


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "report": None,
            "cyberchef_url": CYBERCHEF_LOCAL_URL,
        },
    )


def _resolve_artifact_file(raw_path: str) -> tuple[str, Path]:
    try:
        relative_path = normalize_artifact_relative_path(raw_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"无效的导出文件路径: {exc}") from exc

    artifact_path = (ARTIFACTS_DIR / relative_path).resolve()
    artifacts_root = ARTIFACTS_DIR.resolve()
    try:
        artifact_path.relative_to(artifacts_root)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="导出文件路径越界") from exc
    if not artifact_path.exists() or not artifact_path.is_file():
        raise HTTPException(status_code=404, detail="导出文件不存在")
    return relative_path, artifact_path


@app.get("/artifact-view", response_class=HTMLResponse)
async def artifact_view(request: Request, path: str):
    relative_path, artifact_path = _resolve_artifact_file(path)
    return templates.TemplateResponse(
        request=request,
        name="artifact_viewer.html",
        context={
            "relative_path": relative_path,
            "artifact_name": artifact_path.name,
            "artifact_suffix": artifact_path.suffix.lower(),
            "artifact_size": artifact_path.stat().st_size,
            "raw_url": artifact_raw_url(relative_path),
            "viewer_url": artifact_viewer_url(relative_path),
            "cyberchef_url": CYBERCHEF_LOCAL_URL,
        },
    )


async def _save_upload_temp(pcap_file: UploadFile) -> tuple[str, str, int]:
    if not pcap_file.filename:
        raise HTTPException(status_code=400, detail="文件名为空")

    filename = pcap_file.filename.lower()
    if not filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="仅支持 pcap/pcapng/cap 文件")

    suffix = os.path.splitext(filename)[1] or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        total = 0
        while True:
            chunk = await pcap_file.read(UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            tmp.write(chunk)
            total += len(chunk)
        temp_path = tmp.name
    if total == 0:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(status_code=400, detail="上传文件为空")
    return pcap_file.filename, temp_path, total


def _normalize_module_selection(values: list[str] | None) -> list[str] | None:
    if values is None:
        return None
    cleaned = [v for v in values if v and v != "__none__"]
    if "__none__" in values and not cleaned:
        return []
    return cleaned


async def _analyze_upload(
    pcap_file: UploadFile,
    protocols: list[str] | None = None,
    attacks: list[str] | None = None,
    max_packets: int | None = None,
) -> tuple[str, dict]:
    _, temp_path, _ = await _save_upload_temp(pcap_file)

    try:
        protocols = _normalize_module_selection(protocols)
        attacks = _normalize_module_selection(attacks)
        service = build_default_pipeline_service()
        # pyshark 是阻塞型 + 内部 asyncio 逻辑，放在线程池避免和 ASGI 事件循环冲突
        report = await run_in_threadpool(
            service.analyze_file,
            temp_path,
            max_packets,
            protocols,
            attacks,
        )
        report_dict = asdict(report)
        return pcap_file.filename, report_dict
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "message": f"分析失败: {exc}",
                "traceback": traceback.format_exc(limit=10),
            },
        ) from exc
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.post("/api/analyze")
async def analyze_api(
    pcap_file: UploadFile = File(...),
    protocols: list[str] | None = Form(default=None),
    attacks: list[str] | None = Form(default=None),
    max_packets: int | None = Form(default=None),
):
    filename, report = await _analyze_upload(
        pcap_file=pcap_file,
        protocols=protocols,
        attacks=attacks,
        max_packets=max_packets,
    )
    return {
        "ok": True,
        "filename": filename,
        "report": report,
    }


@app.get("/api/modules")
async def list_modules():
    return {
        "ok": True,
        "modules": job_manager.list_modules(),
    }


@app.get("/api/projects")
async def list_projects():
    return {
        "ok": True,
        "projects": job_manager.list_projects(),
    }


@app.post("/api/projects/{project_id}/load")
async def load_project(project_id: str):
    try:
        return job_manager.load_project(project_id)
    except HTTPError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: str):
    try:
        result = job_manager.delete_project(project_id)
        return {"ok": True, **result}
    except HTTPError as exc:
        message = str(exc)
        code = 404 if "任务不存在" in message else 400
        raise HTTPException(status_code=code, detail=message) from exc


@app.post("/api/projects/cleanup")
async def cleanup_projects(payload: dict | None = Body(default=None)):
    try:
        payload = payload or {}
        result = job_manager.cleanup_projects(
            project_ids=payload.get("project_ids"),
            keep_recent=payload.get("keep_recent"),
        )
        return {"ok": True, **result}
    except HTTPError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/jobs/start")
async def start_job(
    pcap_file: UploadFile = File(...),
    max_packets: int | None = Form(default=None),
    tls_key_text: str | None = Form(default=None),
    tls_key_file: UploadFile | None = File(default=None),
):
    filename, temp_path, source_size_bytes = await _save_upload_temp(pcap_file)
    tls_key_file_name = tls_key_file.filename if tls_key_file and tls_key_file.filename else None
    tls_key_file_bytes = await tls_key_file.read() if tls_key_file is not None else None
    try:
        job_id = job_manager.create_job(
            filename=filename,
            temp_path=temp_path,
            max_packets=max_packets,
            source_size_bytes=source_size_bytes,
            tls_keylog_text=tls_key_text,
            tls_keylog_file_name=tls_key_file_name,
            tls_keylog_file_bytes=tls_key_file_bytes,
        )
        return {
            "ok": True,
            "job_id": job_id,
            "project_id": job_id,
            "filename": filename,
        }
    except HTTPError as exc:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/jobs/{job_id}/status")
async def job_status(job_id: str):
    try:
        return job_manager.job_status(job_id)
    except HTTPError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/jobs/{job_id}/results")
async def job_results(job_id: str):
    try:
        return job_manager.job_results(job_id)
    except HTTPError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/jobs/{job_id}/webshell/godzilla/parse")
async def parse_godzilla_webshell_key(
    job_id: str,
    key_text: str | None = Form(default=None),
    key_file: UploadFile | None = File(default=None),
):
    key_file_name = key_file.filename if key_file and key_file.filename else None
    key_file_bytes = await key_file.read() if key_file is not None else None
    try:
        result = await run_in_threadpool(
            job_manager.parse_webshell_godzilla_key,
            job_id,
            key_text=key_text,
            key_file_name=key_file_name,
            key_file_bytes=key_file_bytes,
        )
        return {"ok": True, "result": result}
    except HTTPError as exc:
        message = str(exc)
        code = 404 if "任务不存在" in message else 400
        raise HTTPException(status_code=code, detail=message) from exc


@app.post("/api/jobs/{job_id}/sqli/bool/parse")
async def parse_sqli_bool(
    job_id: str,
    true_marker: str | None = Form(default=None),
):
    try:
        result = await run_in_threadpool(
            job_manager.parse_sql_injection_bool,
            job_id,
            true_marker=true_marker,
        )
        return {"ok": True, "result": result}
    except HTTPError as exc:
        message = str(exc)
        code = 404 if "任务不存在" in message else 400
        raise HTTPException(status_code=code, detail=message) from exc


@app.post("/api/jobs/{job_id}/tls/decrypt")
async def parse_tls_keylog(
    job_id: str,
    key_text: str | None = Form(default=None),
    key_file: UploadFile | None = File(default=None),
):
    key_file_name = key_file.filename if key_file and key_file.filename else None
    key_file_bytes = await key_file.read() if key_file is not None else None
    try:
        result = await run_in_threadpool(
            job_manager.start_tls_decrypt_task,
            job_id,
            key_text=key_text,
            key_file_name=key_file_name,
            key_file_bytes=key_file_bytes,
        )
        return result
    except HTTPError as exc:
        message = str(exc)
        code = 404 if "任务不存在" in message else 400
        raise HTTPException(status_code=code, detail=message) from exc


@app.get("/api/jobs/{job_id}/tls/decrypt/status")
async def tls_decrypt_status(job_id: str):
    try:
        return job_manager.tls_decrypt_status(job_id)
    except HTTPError as exc:
        message = str(exc)
        code = 404 if "任务不存在" in message else 400
        raise HTTPException(status_code=code, detail=message) from exc


@app.post("/api/jobs/{job_id}/modules/add")
async def add_job_module(
    job_id: str,
    module_type: str = Form(...),
    module_name: str = Form(...),
):
    try:
        module = job_manager.add_module(job_id=job_id, module_type=module_type, module_name=module_name)
        return {"ok": True, "module": module}
    except HTTPError as exc:
        message = str(exc)
        code = 404 if "任务不存在" in message else 400
        raise HTTPException(status_code=code, detail=message) from exc


@app.post("/api/jobs/{job_id}/modules/remove")
async def remove_job_module(
    job_id: str,
    module_type: str = Form(...),
    module_name: str = Form(...),
):
    try:
        result = job_manager.remove_module(job_id=job_id, module_type=module_type, module_name=module_name)
        return {"ok": True, **result}
    except HTTPError as exc:
        message = str(exc)
        code = 404 if "任务不存在" in message else 400
        raise HTTPException(status_code=code, detail=message) from exc


@app.post("/api/jobs/{job_id}/modules/restart")
async def restart_job_module(
    job_id: str,
    module_type: str = Form(...),
    module_name: str = Form(...),
):
    try:
        module = job_manager.restart_module(job_id=job_id, module_type=module_type, module_name=module_name)
        return {"ok": True, "module": module}
    except HTTPError as exc:
        message = str(exc)
        code = 404 if "任务不存在" in message or "模块不存在" in message else 400
        raise HTTPException(status_code=code, detail=message) from exc


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(request: Request, pcap_file: UploadFile = File(...)):
    filename, report_dict = await _analyze_upload(pcap_file)

    return templates.TemplateResponse(
        request=request,
        name="result.html",
        context={
            "filename": filename,
            "report": report_dict,
        },
    )


@app.on_event("shutdown")
def on_shutdown() -> None:
    job_manager.shutdown()
