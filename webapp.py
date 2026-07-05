"""FastAPI web UI for the DICOM Network Monitor.

Server-rendered page plus two small JSON endpoints the page polls:
/api/status for the top bar, /api/events for new timeline entries.
"""

import ctypes
import sys
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

import capture
import config
from timeline import Monitor

app = FastAPI(title="DICOM Network Monitor")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

monitor = Monitor()
manager = capture.CaptureManager(monitor)

TSHARK = capture.find_tshark()
TSHARK_VERSION = capture.tshark_version(TSHARK) if TSHARK else ""


def is_admin():
    """True/False on Windows, None elsewhere (not applicable)."""
    if sys.platform != "win32":
        return None
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


def gather_status():
    interfaces, iface_error = ([], "tshark not found")
    if TSHARK:
        interfaces, iface_error = capture.list_interfaces(TSHARK)
    return {
        "tshark": TSHARK,
        "tshark_version": TSHARK_VERSION,
        "tshark_configured": config.TSHARK_PATH,
        "is_admin": is_admin(),
        "interfaces": interfaces,
        "interface_error": iface_error,
        "loopback_present": capture.has_loopback(interfaces),
        "capturing": manager.running,
        "capture_interface": manager.interface["name"] if manager.interface
        else None,
        "filter": manager.filter_text,
        "packets": manager.packets,
        "raw_lines": manager.raw_lines,
        "capture_error": manager.last_error,
        "ports": config.DICOM_PORTS,
        "focus_hosts": config.FOCUS_HOSTS,
        "log_path": str(Path(config.LOG_PATH).resolve()),
    }


@app.get("/")
def index(request: Request):
    return templates.TemplateResponse(
        request, "monitor.html", {"status": gather_status()})


@app.get("/api/status")
def api_status():
    return gather_status()


@app.post("/api/capture/start")
async def api_start(request: Request):
    body = await request.json()
    if not TSHARK:
        return JSONResponse({"error": "tshark not found; check TSHARK_PATH "
                             "in config.py"}, status_code=400)

    # Development/replay hook: {"file": "path.pcap"} replays a capture file.
    read_file = body.get("file")
    if read_file:
        if not Path(read_file).is_file():
            return JSONResponse({"error": f"no such file: {read_file}"},
                                status_code=400)
        error = manager.start(TSHARK, None, read_file=read_file)
        if error:
            return JSONResponse({"error": error}, status_code=500)
        return {"ok": True}

    # The browser sends the device token (\Device\NPF_{...}); the numeric
    # index is accepted only as a fallback since it can shift across reboots.
    wanted = str(body.get("interface", ""))
    interfaces, iface_error = capture.list_interfaces(TSHARK)
    chosen = next((i for i in interfaces if i["device"] == wanted), None) \
        or next((i for i in interfaces if i["index"] == wanted), None)
    if chosen is None:
        return JSONResponse(
            {"error": iface_error or f"unknown interface: {wanted}"},
            status_code=400)
    error = manager.start(TSHARK, chosen)
    if error:
        return JSONResponse({"error": error}, status_code=500)
    return {"ok": True}


@app.post("/api/capture/stop")
def api_stop():
    manager.stop()
    return {"ok": True}


@app.get("/api/events")
def api_events(after: int = 0):
    data = monitor.snapshot_since(after)
    data["capturing"] = manager.running
    data["packets"] = manager.packets
    return data


@app.get("/download")
def download():
    text = "\n".join(monitor.session_lines) + "\n"
    return PlainTextResponse(text, headers={
        "Content-Disposition":
            'attachment; filename="dicom-monitor-session.log"'})
