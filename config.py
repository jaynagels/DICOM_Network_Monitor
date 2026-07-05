"""Central configuration for the DICOM Learning Lab Network Monitor.

Every tunable value lives here. Edit this file, restart the app, done.
Nothing elsewhere in the project hard-codes ports or paths.
"""

# ---------------------------------------------------------------------------
# Web UI (local browser only)
# ---------------------------------------------------------------------------
WEB_HOST = "127.0.0.1"
WEB_PORT = 8090          # avoid clashing with the modality emulator's 8080 if both run

# ---------------------------------------------------------------------------
# tshark (Wireshark's command-line engine, does the capture and dissection)
# ---------------------------------------------------------------------------
# Path to tshark.exe. If this exact path does not exist the app also tries
# the PATH and the common Wireshark install locations before giving up.
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# ---------------------------------------------------------------------------
# What to watch
# ---------------------------------------------------------------------------
# Ports to treat as DICOM. Used both for the capture filter (only traffic on
# these ports is captured) and for tshark decode-as rules (so non-standard
# ports still dissect as DICOM). Adjust to your lab nodes:
#   104   default DICOM port
#   11112 DCM4CHEE archive
#   4242  Order Entry System (MWL/MPPS) - also Orthanc's default DICOM port
#   2762  DICOM over TLS (dissects as TLS, shown so you can see it exists)
DICOM_PORTS = [104, 11112, 4242, 2762]

# Optional endpoint focus. Blank = watch all DICOM on the chosen interface.
# When set, the capture filter narrows to traffic involving these hosts.
FOCUS_HOSTS = []           # e.g. ["172.31.32.107"] for the Linux archive

# How many timeline events to keep in the server buffer (the browser shows
# the same set; older events are still in the session log file).
EVENT_BUFFER = 2000

# Where to write the session log (full plain-language timeline, appended).
LOG_PATH = "dicom-monitor.log"
