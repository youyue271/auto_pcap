from __future__ import annotations

import os
import tempfile
from dataclasses import asdict
from pathlib import Path
import traceback

from fastapi.concurrency import run_in_threadpool
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from TrafficAnalyzer.pipeline import build_default_pipeline_service
from TrafficAnalyzer.web.job_manager import HTTPError, JobManager

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app = FastAPI(title="TrafficAnalyzer Web UI", version="0.1.0")
job_manager = JobManager()
UPLOAD_CHUNK_SIZE = 1024 * 1024


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"report": None},
    )


async def _save_upload_temp(pcap_file: UploadFile) -> tuple[str, str]:
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
    return pcap_file.filename, temp_path


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
    _, temp_path = await _save_upload_temp(pcap_file)

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


@app.post("/api/jobs/start")
async def start_job(
    pcap_file: UploadFile = File(...),
    max_packets: int | None = Form(default=None),
):
    filename, temp_path = await _save_upload_temp(pcap_file)
    job_id = job_manager.create_job(filename=filename, temp_path=temp_path, max_packets=max_packets)
    return {
        "ok": True,
        "job_id": job_id,
        "filename": filename,
    }


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
