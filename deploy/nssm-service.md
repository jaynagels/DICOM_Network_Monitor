# Running the DICOM Network Monitor as a Windows service (optional)

For the baked AMI you can register the monitor as an auto-starting Windows
service with NSSM (the Non-Sucking Service Manager), so it is already
running when the student logs in. For a normal lab session, right-clicking
`start-monitor.bat` and choosing "Run as administrator" is enough and this
page can be ignored.

## The capture-rights catch

A service session has no desktop, which is fine here because the UI is a
browser page. But packet capture still needs privileges:

- By default Npcap is installed with "Restrict Npcap driver's access to
  Administrators only" ticked. A service then needs to run as an account
  with administrator rights (LocalSystem works) to see any interfaces.
- Alternatively, reinstall Npcap with that restriction unticked; then any
  account can capture. For a shared teaching image, running the service as
  LocalSystem is the simpler and more contained choice.

## One-time setup

1. Run `start-monitor.bat` once (elevated) so the `.venv` folder exists
   and the dependencies are installed.
2. Download NSSM from https://nssm.cc and put `nssm.exe` somewhere on the
   PATH (for example `C:\Windows\System32`).
3. In an elevated (Administrator) command prompt, with `C:\DicomMonitor`
   standing in for wherever this folder lives:

```
nssm install DicomMonitor "C:\DicomMonitor\.venv\Scripts\python.exe" "C:\DicomMonitor\main.py"
nssm set DicomMonitor AppDirectory "C:\DicomMonitor"
nssm set DicomMonitor DisplayName "DICOM Lab Network Monitor"
nssm set DicomMonitor Description "Passive DICOM traffic timeline (tshark) for the DICOM teaching lab"
nssm set DicomMonitor Start SERVICE_AUTO_START
nssm set DicomMonitor AppStdout "C:\DicomMonitor\monitor-service.log"
nssm set DicomMonitor AppStderr "C:\DicomMonitor\monitor-service.log"
nssm start DicomMonitor
```

NSSM services run as LocalSystem by default, which has capture rights, so
no extra account setup is needed.

## Everyday commands

```
nssm status  DicomMonitor
nssm restart DicomMonitor     (after editing config.py)
nssm stop    DicomMonitor
nssm remove  DicomMonitor confirm
```

## Notes

- The plain-language session timeline is in `dicom-monitor.log` next to
  `main.py` (that is `LOG_PATH` in config.py); `monitor-service.log` above
  only holds the server's own startup and error output.
- The web server binds 127.0.0.1 only, so the service is reachable just
  from a browser on this workstation; no inbound firewall rule is needed.
- The monitor is purely passive: it opens no DICOM listener and no
  outbound DICOM connections.
