# DICOM Network Monitor

A passive traffic monitor for the DICOM teaching lab. It watches the DICOM
conversations between two endpoints and tells their story as a clean,
plain-language timeline in the browser: did the association form, was it
accepted or rejected and why, which DIMSE messages were exchanged, and what
every status code means. Think "Wireshark's DICOM story without Wireshark's
cockpit".

It never sends a single DICOM message itself. Wireshark's command-line
engine `tshark` does the capture, TCP reassembly and DICOM dissection; this
app turns that into a timeline a student can actually read.

## Requirements

- Windows workstation with **Wireshark installed** (tshark comes with it)
  and **Npcap** (Wireshark's capture driver, installed alongside it).
- **Administrator rights.** Packet capture on Windows needs elevation:
  Npcap only shows network adapters to elevated processes by default.
  Right-click `start-monitor.bat` and choose "Run as administrator".
  If you forget, nothing breaks: the app starts anyway and shows a banner
  explaining exactly what to do.
- Python 3.9+ (the launcher creates its own virtual environment on first
  run).

Then browse to <http://127.0.0.1:8090>. The web server binds 127.0.0.1
only, so no inbound firewall rule is needed.

## Picking the right capture interface

The interface picker lists everything tshark can see, with a hint next to
each. The two lab scenarios:

1. **Windows app to the Linux archive** (MicroDICOM or the modality
   emulator on this box talking to DCM4CHEE or the Order Entry System at
   the Linux IP): pick your **Ethernet adapter**. Works with a standard
   Npcap install.

2. **Localhost to localhost** (two DICOM apps on this same Windows box
   talking over 127.0.0.1): pick the **Npcap Loopback Adapter**. This
   adapter only exists if Npcap was installed with **"Support loopback
   traffic"** ticked. If it is missing, the app shows a banner saying so;
   the fix is to reinstall Npcap (or Wireshark, which bundles it) with
   that option enabled. Without it a localhost capture silently sees
   nothing, which is why the app refuses to let you find that out the
   hard way.

## What gets captured

Only TCP traffic on the ports listed in `config.py` (`DICOM_PORTS`), and
only on the interface you choose. The active filter is always shown
read-only in the top bar. Traffic on those ports is force-dissected as
DICOM, so non-standard ports still decode; Wireshark's DICOM heuristic
also recognizes associations on ports that are not listed at all.

Set `FOCUS_HOSTS` in `config.py` to narrow the capture to traffic
involving specific machines, e.g. just the Linux archive.

## Reading the timeline

Each box is one association (one TCP conversation). Inside, in order:

- the TCP connect,
- A-ASSOCIATE-RQ with calling and called AE titles and every proposed
  presentation context (SOP classes and transfer syntaxes, by name),
- A-ASSOCIATE-AC with what was accepted, or A-ASSOCIATE-RJ / A-ABORT with
  the result, source and reason decoded to plain English,
- every DIMSE message (C-ECHO, C-STORE, C-FIND, C-MOVE, C-GET, MPPS
  N-CREATE/N-SET) with message IDs, SOP classes by name, and every status
  code shown as hex plus its meaning,
- the release or the reset that ended it.

### C-MOVE, the interesting one

A C-MOVE involves two associations, and most retrieve problems hide in
the second one. The monitor correlates them:

- The C-MOVE-RQ card records the move destination AE title.
- When the archive opens its return association to that AE, the new card
  is tagged "return assoc for C-MOVE #n" and both cards link to each
  other. The C-STORE sub-operations happen there.
- Each C-MOVE-RSP updates a live tally: remaining, completed, failed,
  warning sub-operations.
- If things go wrong, the diagnosis is spelled out on the final response:
  destination AE not configured on the archive (status 0xA801), no return
  association ever seen (destination not listening, or wrong host/port
  registered), or a failed sub-operation count.

## Session log

Everything shown on screen is also appended, timestamped, to
`dicom-monitor.log` (path configurable via `LOG_PATH`). The "download
session log" link in the UI saves the current session as a text file,
ready to attach to a bug report.

## Configuration

All tunables are at the top of `config.py`: web port, tshark path, DICOM
ports, focus hosts, event buffer size, log path. Edit, restart, done.

## Troubleshooting: capture runs but 0 packets appear

"0 packets" only tells you the end of the pipeline was empty; the cause
can be in capture, dissection, ek output, or parsing. Two tools pinpoint
the layer instead of guessing:

- While a capture is running, open <http://127.0.0.1:8090/api/status>:
  `raw_lines` counts every line tshark emitted, `packets` counts the ones
  the parser accepted. `raw_lines` stuck at 0 means tshark saw nothing
  (capture/dissection side); `raw_lines` climbing while `packets` stays 0
  means the parser is rejecting output (parse side). The session log also
  records the exact tshark argv at every capture start.
- `python tools\diagnose_capture.py --interface <n>` (elevated) runs one
  gate per pipeline layer, from a minimal capture up to the app's exact
  command, and names the first layer that fails plus the minimal fix.
  See the docstring in that file for the gate-by-gate meaning.

## Running as a Windows service

See `deploy/nssm-service.md`. Short version: fine for the web UI, but the
service account still needs capture rights, so it must run as an
administrator account (or Npcap must be installed in unrestricted mode).

## Acceptance tests

1. Launched elevated: the app lists capture interfaces and loads at
   127.0.0.1:8090. Launched non-elevated: a clear "run as Administrator"
   banner appears instead of a silent failure.
2. Capture on the Ethernet adapter, C-ECHO from a Windows DICOM app to
   the Linux archive: one card with the association (calling/called AE),
   C-ECHO-RQ/RSP, and status 0x0000 Success.
3. C-FIND to the archive: the query association, the C-FIND-RQ with its
   identifier, pending responses per match, and a final status with a
   match count.
4. C-MOVE retrieve: the C-MOVE-RQ with its destination, the linked return
   association, the C-STORE sub-operations on it, and the live
   remaining/completed/failed/warning tally. A deliberately broken
   retrieve (destination not listening, or wrong port registered on the
   archive) shows the plain-language diagnosis instead of a blank result.
5. An A-ASSOCIATE-RJ or A-ABORT is decoded to a readable reason.
6. On the Npcap Loopback Adapter, a localhost-to-localhost exchange is
   captured; if the adapter is absent, the app says so and explains the
   Npcap reinstall.
7. The session log matches the on-screen timeline.
