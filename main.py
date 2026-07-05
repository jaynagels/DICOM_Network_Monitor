"""Entrypoint for the DICOM Network Monitor.

Passive tool: it never opens a DICOM association itself, it only watches.
tshark does the capture and dissection; uvicorn serves the local web UI on
127.0.0.1. The start-monitor.bat launcher and the optional NSSM service
both run exactly this file.

Packet capture on Windows needs Administrator rights (Npcap only shows
adapters to elevated processes by default), so run the launcher elevated.
The app still starts without them and shows exactly what is missing.
"""

import logging
import sys

import uvicorn

import config
from webapp import app, monitor, gather_status

logger = logging.getLogger("monitor")


def main():
    logging.basicConfig(
        level=logging.INFO, stream=sys.stdout,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    monitor.open_log()
    status = gather_status()
    if not status["tshark"]:
        logger.error(
            "tshark not found. Install Wireshark (it includes tshark) or "
            "fix TSHARK_PATH in config.py (currently %r). The web UI will "
            "explain the same thing.", config.TSHARK_PATH)
    else:
        logger.info("using %s (%s)", status["tshark"],
                    status["tshark_version"])
        if not status["interfaces"]:
            logger.error(
                "no capture interfaces visible: %s. On Windows this almost "
                "always means the app is not running as Administrator.",
                status["interface_error"])
        elif not status["loopback_present"]:
            logger.warning(
                "no Npcap Loopback Adapter found: localhost-to-localhost "
                "capture will not be possible until Npcap is reinstalled "
                "with 'Support loopback traffic' ticked.")
    logger.info("watching DICOM ports %s%s", config.DICOM_PORTS,
                f" (focus hosts: {config.FOCUS_HOSTS})"
                if config.FOCUS_HOSTS else "")
    logger.info("session log: %s", status["log_path"])
    logger.info("Web UI on http://%s:%s", config.WEB_HOST, config.WEB_PORT)
    uvicorn.run(app, host=config.WEB_HOST, port=config.WEB_PORT,
                log_level="warning")


if __name__ == "__main__":
    main()
