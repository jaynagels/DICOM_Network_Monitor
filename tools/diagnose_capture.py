"""Layered capture diagnosis: find WHERE the pipeline loses packets.

The monitor's pipeline has four layers that can each fail independently:

  capture     does tshark receive frames from Npcap at all?
  dissection  do the decode-as rules and display filter keep DICOM frames?
  ek output   does -T ek (with -J, -l, -Q) emit JSON lines, live?
  parse       does ekparse.py accept those lines?

"0 packets" in the UI only says the LAST layer produced nothing. This
script runs one gate per layer, each adding only the flags that layer
introduces, and reports the first gate that fails. Every command is built
from the app's own capture.py so what is tested is what the app runs.

Usage (elevated, on the workstation):

    python tools\\diagnose_capture.py --list
    python tools\\diagnose_capture.py --interface 4
    python tools\\diagnose_capture.py --interface "\\Device\\NPF_{...}"

Then perform a C-ECHO (or any DICOM exchange) while each gate is
capturing; the script tells you when. Each gate runs for --seconds
(default 20) and prints its verdict. Use --gate to re-run a single gate.

Gates:

  A  tshark -i <device> -f <bpf>                    capture, default output
  B  gate A plus -p                                 the app's promiscuous-off flag
  C  gate B plus -d ... -Y ...                      dissection + display filter
  D  the app's exact argv (-T ek -J ... -l -Q)      ek output, raw dump
  E  gate D piped through ekparse, same Popen       what the app actually does
     configuration as capture.py (text mode, utf-8, bufsize=1,
     CREATE_NO_WINDOW on Windows)

Reading the verdicts:

  A fails                the device token or the BPF filter is wrong for
                         this box; retry with --interface <number> and, if
                         that passes, the device-name form is the problem
  A passes, B fails      -p suppresses capture on this adapter; the fix is
                         to drop -p from build_command
  B passes, C fails      display filter or decode-as (dissection layer)
  C passes, D fails      ek serialization (-T ek / -J / -l / -Q)
  D passes, E fails      Python side: subprocess plumbing or ekparse
                         rejecting lines (the gate prints samples of what
                         was rejected and why)

--file <pcap> replays a capture file through gates D and E instead of
capturing live (development smoke test; gates A-C need live traffic).
"""

import argparse
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import capture      # noqa: E402
import config       # noqa: E402
import ekparse      # noqa: E402


def app_popen_kwargs():
    """Exactly how capture.py's CaptureManager starts tshark."""
    kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                  text=True, encoding="utf-8", errors="replace", bufsize=1)
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    return kwargs


def print_argv(argv):
    print("  argv:")
    for a in argv:
        print(f"    {a!r}")
    # copy-paste form for a manual re-run
    quoted = " ".join(f'"{a}"' if " " in a or "|" in a else a for a in argv)
    print(f"  shell: {quoted}")


def run_command(argv, seconds, line_sink, announce=True):
    """Run one tshark command, stream stdout lines into line_sink(line).

    Returns (line_count, stderr_text, exit_code).
    """
    print_argv(argv)
    proc = subprocess.Popen(argv, **app_popen_kwargs())
    count = 0
    first_line_at = [None]
    start = time.time()

    def pump():
        nonlocal count
        for line in proc.stdout:
            if line.strip():
                count += 1
                if first_line_at[0] is None:
                    first_line_at[0] = time.time() - start
                line_sink(line.rstrip("\n"))

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    if announce:
        print(f"  >>> capturing for ~{seconds}s: DO THE C-ECHO / C-FIND NOW <<<")
    try:
        proc.wait(timeout=seconds + 30)
    except subprocess.TimeoutExpired:
        proc.kill()
        print("  note: tshark did not stop by itself, killed it")
    reader.join(timeout=5)
    stderr = proc.stderr.read().strip()
    if first_line_at[0] is not None:
        print(f"  first output line arrived after {first_line_at[0]:.1f}s "
              f"(large values mean buffering, not absence)")
    if stderr:
        print("  stderr from tshark:")
        for line in stderr.splitlines():
            print(f"    | {line}")
    return count, stderr, proc.returncode


def show_sample(lines, limit=10):
    for line in lines[:limit]:
        print(f"    | {line[:200]}")
    if len(lines) > limit:
        print(f"    | ... and {len(lines) - limit} more lines")


def gate_header(letter, title):
    print()
    print(f"=== GATE {letter}: {title} " + "=" * max(0, 50 - len(title)))


def live_argv_base(tshark, device, seconds):
    return [tshark, "-i", device, "-f", capture.build_bpf(),
            "-a", f"duration:{seconds}"]


def gate_a(tshark, device, seconds):
    gate_header("A", "capture layer, default output, no -p")
    argv = live_argv_base(tshark, device, seconds)
    lines = []
    count, _, _ = run_command(argv, seconds, lines.append)
    show_sample(lines)
    print(f"  GATE A: {count} packet lines -> "
          f"{'PASS' if count else 'FAIL'}")
    if not count:
        print("  verdict: tshark received nothing even with the minimal "
              "flags. Re-run with --interface <number from --list>; if the "
              "number works, the device-name form of -i is the problem. If "
              "neither works, the BPF filter is dropping everything: check "
              "the ports in config.DICOM_PORTS against the traffic.")
    return count > 0


def gate_b(tshark, device, seconds):
    gate_header("B", "capture layer with -p (the app disables promiscuous)")
    argv = live_argv_base(tshark, device, seconds)
    argv.insert(3, "-p")
    lines = []
    count, _, _ = run_command(argv, seconds, lines.append)
    show_sample(lines)
    print(f"  GATE B: {count} packet lines -> "
          f"{'PASS' if count else 'FAIL'}")
    if not count:
        print("  verdict: -p suppresses capture on this adapter/driver. "
              "Minimal fix: remove -p from build_command in capture.py.")
    return count > 0


def gate_c(tshark, device, seconds):
    gate_header("C", "dissection: decode-as rules + display filter")
    argv = live_argv_base(tshark, device, seconds)
    argv.insert(3, "-p")
    for port in config.DICOM_PORTS:
        argv += ["-d", f"tcp.port=={port},dicom"]
    argv += ["-Y", capture._DISPLAY_FILTER]
    lines = []
    count, _, _ = run_command(argv, seconds, lines.append)
    show_sample(lines)
    dicom_lines = sum(1 for l in lines if "DICOM" in l)
    print(f"  GATE C: {count} lines pass the display filter, "
          f"{dicom_lines} dissected as DICOM -> "
          f"{'PASS' if count else 'FAIL'}")
    if not count:
        print("  verdict: frames are captured (gate B) but the display "
              "filter drops everything: dissection layer. Inspect -d rules "
              "and the -Y expression.")
    return count > 0


def full_argv(tshark, device, seconds=None, read_file=None):
    argv = capture.build_command(tshark, device, read_file=read_file)
    if seconds and not read_file:
        argv += ["-a", f"duration:{seconds}"]
    return argv


def gate_d(tshark, device, seconds, read_file=None):
    gate_header("D", "ek output: the app's EXACT argv, raw dump")
    argv = full_argv(tshark, device, seconds, read_file)
    lines = []
    count, _, _ = run_command(argv, seconds, lines.append,
                              announce=read_file is None)
    show_sample(lines, limit=6)
    json_lines = sum(1 for l in lines if '"layers"' in l)
    print(f"  GATE D: {count} stdout lines, {json_lines} with \"layers\" -> "
          f"{'PASS' if json_lines else 'FAIL'}")
    if count and not json_lines:
        print("  verdict: tshark emits output but no packet JSON: the ek "
              "serialization (-T ek / -J) is producing nothing usable.")
    elif not count:
        print("  verdict: the exact argv emits nothing although gate C "
              "captured: one of -T ek, -J, -l, -Q changes behavior. Re-run "
              "gate D dropping one of those flags at a time.")
    return json_lines > 0


def gate_e(tshark, device, seconds, read_file=None):
    gate_header("E", "parse: exact argv piped through ekparse, app-style")
    argv = full_argv(tshark, device, seconds, read_file)
    raw = []
    parsed = []
    rejected = []

    def sink(line):
        raw.append(line)
        pkt = ekparse.parse_ek_line(line)
        if pkt is not None:
            parsed.append(pkt)
        elif '"layers"' in line:
            rejected.append(line)

    run_command(argv, seconds, sink, announce=read_file is None)
    print(f"  GATE E: {len(raw)} raw lines, {len(parsed)} parsed packets, "
          f"{len(rejected)} packet lines REJECTED by ekparse -> "
          f"{'PASS' if parsed else 'FAIL'}")
    if parsed:
        streams = sorted({p.stream for p in parsed if p.stream is not None})
        dicom = sum(1 for p in parsed if p.has_dicom)
        print(f"  parsed detail: {dicom} packets with a DICOM layer, "
              f"TCP streams {streams}")
    if rejected:
        print("  sample of rejected packet lines (parse layer bug):")
        show_sample(rejected, limit=4)
    if raw and not parsed and not rejected:
        print("  verdict: stdout lines arrive but none contain \"layers\": "
              "same as a gate D failure; the parse layer never had a chance.")
    return len(parsed) > 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", action="store_true",
                    help="list capture interfaces and exit")
    ap.add_argument("--interface",
                    help="device token or index number from --list")
    ap.add_argument("--seconds", type=int, default=20,
                    help="capture window per gate (default 20)")
    ap.add_argument("--gate", choices=list("abcde"),
                    help="run a single gate instead of all in order")
    ap.add_argument("--file", help="replay a pcap through gates D+E only")
    args = ap.parse_args()

    tshark = capture.find_tshark()
    if not tshark:
        print("tshark not found; fix TSHARK_PATH in config.py")
        return 2
    print(f"tshark: {tshark}")
    print(f"BPF from config: {capture.build_bpf()}")

    interfaces, err = capture.list_interfaces(tshark)
    if args.list:
        for i in interfaces:
            print(f"{i['index']:>3}. device={i['device']}  label={i['name']}")
        if err:
            print(f"error: {err}")
        return 0

    if args.file:
        ok_d = gate_d(tshark, None, args.seconds, read_file=args.file)
        ok_e = gate_e(tshark, None, args.seconds, read_file=args.file)
        return 0 if (ok_d and ok_e) else 1

    if not args.interface:
        print("need --interface (see --list) or --file")
        return 2
    chosen = next((i for i in interfaces
                   if args.interface in (i["device"], i["index"])), None)
    if chosen is None:
        print(f"interface {args.interface!r} not in tshark -D output; "
              f"testing it verbatim anyway")
        device = args.interface
    else:
        device = chosen["device"]
        print(f"interface: {chosen['index']}. {chosen['name']} -> {device}")

    gates = {
        "a": lambda: gate_a(tshark, device, args.seconds),
        "b": lambda: gate_b(tshark, device, args.seconds),
        "c": lambda: gate_c(tshark, device, args.seconds),
        "d": lambda: gate_d(tshark, device, args.seconds),
        "e": lambda: gate_e(tshark, device, args.seconds),
    }
    if args.gate:
        return 0 if gates[args.gate]() else 1

    for letter in "abcde":
        if not gates[letter]():
            print()
            print(f"STOPPED at gate {letter.upper()}: that is the failing "
                  f"layer. See the verdict above for the minimal fix.")
            return 1
    print()
    print("All gates pass. If the app still shows 0 packets, compare "
          "http://127.0.0.1:8090/api/status raw_lines vs packets: "
          "raw_lines > 0 with packets == 0 points back at parsing inside "
          "the app process.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
