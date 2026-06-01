#!/usr/bin/env python3
"""
BLOODHOUND — server.py  (FastAPI + SSE)
Streams the hunt to the browser as Server-Sent Events.

Run:
    pip install fastapi uvicorn
    py -m uvicorn server:app --reload --port 8000
Then open  http://localhost:8000  in your browser.

Endpoints:
  GET /            -> the detective-board UI (index.html)
  GET /api/health  -> {ok, es} so the UI can show the cluster is real
  GET /api/hunt    -> SSE stream of hunt events (text/event-stream)

Query params on /api/hunt:
  mode = mock | gemini   (brain)
  data = offline | live  (executor)
  pause = seconds to hold the raw-JSON beat (default 1.5; demo breathing room)
"""
import json, os
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from agent import ALERT
from agent_stream import hunt_stream

app = FastAPI(title="BLOODHOUND")

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")


def _make_llm(mode):
    if mode == "gemini":
        from agent_brains import GeminiLLM
        return GeminiLLM()
    from agent_brains import MockLLM
    return MockLLM()


def _make_executor(data):
    if data == "live":
        from agent_brains import LiveExecutor
        return LiveExecutor()
    from agent_brains import OfflineExecutor
    return OfflineExecutor(os.path.join(HERE, "logs.ndjson"))


@app.get("/api/health")
def health():
    es_ok = False
    try:
        from elasticsearch import Elasticsearch
        es_ok = Elasticsearch("http://localhost:9200", request_timeout=2).ping()
    except Exception:
        es_ok = False
    return {"ok": True, "es": es_ok}


@app.get("/api/hunt")
async def hunt(request: Request, mode: str = "mock", data: str = "offline",
               pause: float = 1.5):
    llm = _make_llm(mode)
    executor = _make_executor(data)

    def gen():
        # SSE format: each message is "data: <json>\n\n"
        for ev in hunt_stream(llm, executor, ALERT, pause=pause):
            yield f"data: {json.dumps(ev)}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/")
def index():
    # index.html may live in static/ or at the project root
    for idx in (os.path.join(STATIC, "index.html"), os.path.join(HERE, "index.html")):
        if os.path.exists(idx):
            return FileResponse(idx)
    return JSONResponse({"error": "index.html not found (looked in static/ and project root)"},
                        status_code=404)


# serve any other static assets (none needed if index.html is self-contained)
if os.path.isdir(STATIC):
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
