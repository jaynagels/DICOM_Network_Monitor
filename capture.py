"""tshark integration: find it, list interfaces, run the live capture.

tshark is Wireshark's command-line engine. It does the packet capture, TCP
reassembly and DICOM dissection; we consume its newline-delimited JSON
(-T ek) and feed each packet to the timeline builder. Nothing in this
project re-implements reassembly or PDU parsing.
"""

import logging
import os
import re
import shutil
import subprocess
import sys
import threading

import config
import ekparse

logger = logging.getLogger("monitor.capture")

_COMMON_TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/opt/homebrew/bin/tshark",            # macOS dev box
    "/usr/local/bin/tshark",
    "/usr/bin/tshark",
]


def find_tshark():
    """Return the tshark path to use, or None when not found anywhere."""
    candidates = [config.TSHARK_PATH] + _COMMON_TSHARK_PATHS
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return shutil.which("tshark")


def tshark_version(tshark):
    try:
        out = subprocess.run([tshark, "--version"], capture_output=True,
                             text=True, timeout=15).stdout
        return out.splitlines()[0] if out else ""
    except Exception:
        return ""


def _interface_hint(name, desc):
    """One-line guidance for the interface picker."""
    label = f"{name} {desc}".lower()
    if "loopback" in label:
        return ("watches localhost-only traffic: pick this when two DICOM "
                "apps on THIS box talk to each other over 127.0.0.1")
    if "ethernet" in label or label.startswith("en") or "eth" in label:
        return ("your wired network adapter: pick this to watch traffic "
                "between this box and the Linux server")
    if "wi-fi" in label or "wireless" in label or "wlan" in label:
        return "wireless adapter: watches traffic to other machines over Wi-Fi"
    if "bluetooth" in label or "vpn" in label or "npcap" in label:
        return "rarely the right choice for the lab scenarios"
    return "watches traffic passing through this adapter"


def list_interfaces(tshark):
    """Run tshark -D. Returns (interfaces, error_text).

    interfaces: [{"index": "1", "id": r"\\Device\\NPF_{...}", "name": "Ethernet",
                  "hint": "..."}]
    An empty list with error text usually means: not running as Administrator
    (Npcap only shows adapters to elevated processes by default).
    """
    try:
        proc = subprocess.run([tshark, "-D"], capture_output=True, text=True,
                              timeout=30)
    except Exception as exc:
        return [], f"could not run tshark -D: {exc}"
    interfaces = []
    for line in proc.stdout.splitlines():
        m = re.match(r"^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$", line.strip())
        if not m:
            continue
        index, dev_id, desc = m.group(1), m.group(2), m.group(3) or ""
        display = desc or dev_id
        interfaces.append({
            "index": index,
            "id": dev_id,
            "name": display,
            "hint": _interface_hint(dev_id, desc),
        })
    error = ""
    if not interfaces:
        error = (proc.stderr.strip()
                 or "tshark found no capture interfaces")
    return interfaces, error


def has_loopback(interfaces):
    return any("loopback" in f"{i['id']} {i['name']}".lower()
               for i in interfaces)


def build_bpf():
    """Capture filter from the configured ports and optional focus hosts."""
    ports = " or ".join(f"tcp port {p}" for p in config.DICOM_PORTS)
    bpf = f"({ports})" if config.FOCUS_HOSTS else ports
    if config.FOCUS_HOSTS:
        hosts = " or ".join(f"host {h}" for h in config.FOCUS_HOSTS)
        bpf += f" and ({hosts})"
    return bpf


# Besides DICOM packets we also want the TCP connection open/close story.
_DISPLAY_FILTER = ("dicom || (tcp.flags.syn==1 && tcp.flags.ack==0) "
                   "|| tcp.flags.fin==1 || tcp.flags.reset==1")


def build_command(tshark, interface_id=None, read_file=None):
    cmd = [tshark]
    if read_file:
        cmd += ["-r", read_file]
    else:
        # -p: no promiscuous mode; we only watch this box's own conversations
        cmd += ["-i", interface_id, "-p", "-f", build_bpf()]
    for port in config.DICOM_PORTS:
        cmd += ["-d", f"tcp.port=={port},dicom"]
    cmd += [
        "-Y", _DISPLAY_FILTER,
        "-T", "ek",
        "-J", "frame ip ipv6 tcp dicom",
        "-l",           # line-buffered: events reach the browser live
        "-Q",           # keep stderr quiet unless something is wrong
    ]
    return cmd


class CaptureManager:
    """Owns the tshark subprocess and pumps its output into the Monitor."""

    def __init__(self, monitor):
        self.monitor = monitor
        self._proc = None
        self._lock = threading.Lock()
        self.interface = None      # dict from list_interfaces
        self.filter_text = build_bpf()
        self.packets = 0
        self.last_error = ""

    @property
    def running(self):
        return self._proc is not None and self._proc.poll() is None

    def start(self, tshark, interface, read_file=None):
        """Start capturing. Returns error text ('' on success)."""
        with self._lock:
            if self.running:
                return "capture already running"
            cmd = build_command(tshark, interface and interface["id"],
                                read_file)
            logger.info("starting: %s", " ".join(cmd))
            creationflags = 0
            if sys.platform == "win32":
                creationflags = subprocess.CREATE_NO_WINDOW
            try:
                self._proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, encoding="utf-8", errors="replace",
                    bufsize=1, creationflags=creationflags)
            except OSError as exc:
                self.last_error = f"could not start tshark: {exc}"
                self._proc = None
                return self.last_error
            self.interface = interface
            self.packets = 0
            self.last_error = ""
            threading.Thread(target=self._pump_stdout, daemon=True).start()
            threading.Thread(target=self._pump_stderr, daemon=True).start()

        # Give tshark a moment to fail fast (bad interface, no permission).
        try:
            self._proc.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            pass    # still running: good
        if not self.running and self.packets == 0:
            error = self.last_error or "tshark exited immediately"
            self._proc = None
            return error

        where = interface["name"] if interface else read_file
        self.monitor.session_event(
            f"Capture started on '{where}' with filter: {self.filter_text}")
        return ""

    def stop(self):
        with self._lock:
            proc = self._proc
            self._proc = None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if proc:
            self.monitor.session_event("Capture stopped")

    def _pump_stdout(self):
        proc = self._proc
        if not proc or not proc.stdout:
            return
        for line in proc.stdout:
            pkt = ekparse.parse_ek_line(line)
            if pkt is None:
                continue
            self.packets += 1
            try:
                self.monitor.process(pkt)
            except Exception:
                logger.exception("error building timeline for a packet")

    def _pump_stderr(self):
        proc = self._proc
        if not proc or not proc.stderr:
            return
        lines = []
        for line in proc.stderr:
            line = line.strip()
            if line:
                lines.append(line)
                logger.warning("tshark: %s", line)
        if lines:
            self.last_error = lines[-1]
            # Surface capture-permission problems in the timeline itself.
            joined = " ".join(lines).lower()
            if "permission" in joined or "denied" in joined:
                self.monitor.session_event(
                    "tshark could not open the interface (permission denied)."
                    " Close the app and run start-monitor.bat as "
                    "Administrator.", kind="fail")
