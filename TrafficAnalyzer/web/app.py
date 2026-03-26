from __future__ import annotations

import os
import tempfile
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from TrafficAnalyzer.pipeline import build_default_pipeline_service

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app = FastAPI(title="TrafficAnalyzer Web UI", version="0.1.0")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"report": None},
    )


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(request: Request, pcap_file: UploadFile = File(...)):
    if not pcap_file.filename:
        raise HTTPException(status_code=400, detail="文件名为空")

    filename = pcap_file.filename.lower()
    if not filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="仅支持 pcap/pcapng/cap 文件")

    suffix = os.path.splitext(filename)[1] or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await pcap_file.read()
        tmp.write(content)
        temp_path = tmp.name

    try:
        service = build_default_pipeline_service()
        report = service.analyze_file(temp_path)
        report_dict = asdict(report)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"分析失败: {exc}") from exc
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    return templates.TemplateResponse(
        request=request,
        name="result.html",
        context={
            "filename": pcap_file.filename,
            "report": report_dict,
        },
    )

