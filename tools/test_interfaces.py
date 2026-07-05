"""Regression test for tshark -D parsing and the -i capture argument.

The fixture below is real tshark -D output from the lab's Windows
workstation. The bug this guards against: passing the friendly label
("Ethernet 3") to tshark -i, which silently captures zero packets on
Windows. tshark must receive the device token instead.

Run from the project root:  python tools/test_interfaces.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import capture

FIXTURE = r"""1. \Device\NPF_{FF716D9F-6EF9-4123-A2EF-EB9A23C5B76B} (Local Area Connection* 9)
2. \Device\NPF_{20FBCCFD-9B9B-466B-91D5-27CF097317C7} (Local Area Connection* 8)
3. \Device\NPF_{922271DF-D27D-4C84-93CA-AB07762A76EF} (Local Area Connection* 7)
4. \Device\NPF_{EFDCC438-1368-4889-B23E-1841C6D0BDB5} (Ethernet 3)
5. \Device\NPF_Loopback (Adapter for loopback traffic capture)
6. etwdump (Event Tracing for Windows (ETW) reader)
"""


def main():
    interfaces = capture.parse_interface_lines(FIXTURE)
    assert len(interfaces) == 6, f"expected 6 interfaces, got {len(interfaces)}"

    eth = interfaces[3]
    assert eth["index"] == "4"
    assert eth["device"] == r"\Device\NPF_{EFDCC438-1368-4889-B23E-1841C6D0BDB5}"
    assert eth["name"] == "Ethernet 3"

    loop = interfaces[4]
    assert loop["device"] == r"\Device\NPF_Loopback"
    assert loop["name"] == "Adapter for loopback traffic capture"
    assert "localhost" in loop["hint"]
    assert capture.has_loopback(interfaces)

    etw = interfaces[5]
    assert etw["device"] == "etwdump"
    assert etw["name"] == "Event Tracing for Windows (ETW) reader"

    # The friendly label must never appear anywhere in the tshark argv;
    # -i must receive the device token.
    cmd = capture.build_command("tshark", eth["device"])
    i_arg = cmd[cmd.index("-i") + 1]
    assert i_arg == r"\Device\NPF_{EFDCC438-1368-4889-B23E-1841C6D0BDB5}", i_arg
    assert "Ethernet 3" not in cmd

    cmd = capture.build_command("tshark", loop["device"])
    assert cmd[cmd.index("-i") + 1] == r"\Device\NPF_Loopback"

    print("PASS: 6 interfaces parsed; -i gets the device token, "
          "never the friendly label")


if __name__ == "__main__":
    main()
