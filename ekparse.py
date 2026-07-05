"""Turn one line of tshark -T ek output into a structured packet record.

tshark does all the hard work (TCP reassembly, PDU dissection, UID and
element decoding); this module only reshapes its JSON into something the
timeline builder can consume. Two sources of truth per packet:

  - structured fields (dicom_dicom_pdu_type, dicom_dicom_assoc_ae_calling,
    reject/abort codes, ...) for association-level facts, and
  - the dissector's "text" tree for DIMSE command/data elements, which
    tshark prints fully decoded, e.g.
        (0000,0100)  2 Command Field         C-MOVE-RQ
        (0000,0900)  2 Status                Refused: Move Destination unknown (0xa801)

The text lines are grouped per PDV ("PDV, C-ECHO-RQ ID=1" starts a group)
and each element line is parsed into (tag, name, value).
"""

import json
import re

# element line: (gggg,eeee) <len> <name padded with 2+ spaces> <value>
_ELEM_RE = re.compile(r"^\((\w{4}),(\w{4})\)\s+-?\d+\s+(\S.*)$")
# trailing "(0xff00)" style status code inside a decoded value
_HEX_RE = re.compile(r"\(0x([0-9a-fA-F]+)\)\s*$")

PDU_NAMES = {
    1: "A-ASSOCIATE-RQ",
    2: "A-ASSOCIATE-AC",
    3: "A-ASSOCIATE-RJ",
    4: "P-DATA",
    5: "A-RELEASE-RQ",
    6: "A-RELEASE-RP",
    7: "A-ABORT",
}


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first_int(value, default=None):
    for item in _as_list(value):
        try:
            return int(item)
        except (TypeError, ValueError):
            continue
    return default


def _truthy_flag(value):
    return str(value).lower() in ("1", "true")


def split_name_value(rest):
    """Split 'Command Field       C-MOVE-RQ' into (name, value).

    The dissector pads the element name with spaces; element names contain
    only single spaces, so the first run of 2+ spaces is the divider.
    """
    parts = re.split(r"\s{2,}", rest, maxsplit=1)
    name = parts[0].strip()
    value = parts[1].strip() if len(parts) > 1 else ""
    return name, value


def value_status_code(value):
    """Extract the numeric status from a decoded value like 'Success (0x00)'."""
    m = _HEX_RE.search(value)
    return int(m.group(1), 16) if m else None


class Pdv:
    """One PDV worth of dissected elements from the text tree."""

    def __init__(self, summary):
        self.summary = summary                    # "C-ECHO-RQ ID=1" (PDV, stripped)
        self.is_command = "-DATA" not in summary and re.match(
            r"[CN]-[A-Z-]+-(RQ|RSP)\b", summary) is not None
        self.elements = {}                        # (group, elem) -> (name, value)

    def add(self, group, elem, name, value):
        self.elements[(group, elem)] = (name, value)

    def get(self, group, elem, default=""):
        return self.elements.get((group, elem), ("", default))[1]

    @property
    def command(self):
        """'C-ECHO-RQ' etc. from the Command Field element, if present."""
        return self.get(0x0000, 0x0100) or None


class Packet:
    """Everything the timeline needs from one captured frame."""

    def __init__(self):
        self.ts = 0.0
        self.stream = None       # tshark TCP stream index: our association key
        self.src = self.dst = ""
        self.sport = self.dport = 0
        self.syn = self.fin = self.rst = self.ack = False
        self.has_dicom = False
        self.pdu_types = []      # ints, in frame order
        self.assoc = {}          # calling/called AE, contexts (for RQ/AC)
        self.reject = None       # (result, source, reason)
        self.abort = None        # (source, reason)
        self.pdvs = []           # list of Pdv

    @property
    def src_label(self):
        return f"{self.src}:{self.sport}"

    @property
    def dst_label(self):
        return f"{self.dst}:{self.dport}"


def _parse_assoc(dic):
    """Association-level structured fields plus contexts from the text tree."""
    assoc = {}
    calling = _as_list(dic.get("dicom_dicom_assoc_ae_calling"))
    called = _as_list(dic.get("dicom_dicom_assoc_ae_called"))
    if calling:
        assoc["calling"] = calling[0].strip()
    if called:
        assoc["called"] = called[0].strip()

    # Presentation contexts, from the ordered text tree:
    # RQ:  "Presentation Context: <name> (<uid>)" then Abstract/Transfer lines
    # AC:  "Presentation Context: ID 0x01, Accept, <xfer>, <abstract>"
    contexts = []
    for line in _as_list(dic.get("text")):
        if line.startswith("Presentation Context:"):
            contexts.append({"head": line[len("Presentation Context:"):].strip(),
                             "transfer": []})
        elif line.startswith("Abstract Syntax:") and contexts:
            contexts[-1]["abstract"] = line[len("Abstract Syntax:"):].strip()
        elif line.startswith("Transfer Syntax:") and contexts:
            contexts[-1]["transfer"].append(line[len("Transfer Syntax:"):].strip())
    assoc["contexts"] = contexts
    return assoc


def _parse_pdvs(dic):
    pdvs = []
    current = None
    for line in _as_list(dic.get("text")):
        if line.startswith("PDV,"):
            current = Pdv(line[4:].strip())
            pdvs.append(current)
            continue
        m = _ELEM_RE.match(line)
        if m and current is not None:
            name, value = split_name_value(m.group(3))
            current.add(int(m.group(1), 16), int(m.group(2), 16), name, value)
    return pdvs


def parse_ek_line(line):
    """Parse one ek JSON line; return a Packet or None for non-packet lines."""
    line = line.strip()
    if not line or '"layers"' not in line:
        return None    # ek index lines and blanks
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    layers = rec.get("layers")
    if not layers:
        return None

    pkt = Packet()
    try:
        pkt.ts = int(rec.get("timestamp", 0)) / 1000.0   # epoch milliseconds
    except (TypeError, ValueError):
        pkt.ts = 0.0

    ip = layers.get("ip") or {}
    ip6 = layers.get("ipv6") or {}
    pkt.src = _as_list(ip.get("ip_ip_src") or ip6.get("ipv6_ipv6_src"))[0] \
        if (ip or ip6) else ""
    pkt.dst = _as_list(ip.get("ip_ip_dst") or ip6.get("ipv6_ipv6_dst"))[0] \
        if (ip or ip6) else ""

    tcp = layers.get("tcp")
    if not tcp:
        return None
    pkt.stream = _first_int(tcp.get("tcp_tcp_stream"))
    pkt.sport = _first_int(tcp.get("tcp_tcp_srcport"), 0)
    pkt.dport = _first_int(tcp.get("tcp_tcp_dstport"), 0)
    flags = tcp.get("tcp_tcp_flags_tree") or tcp
    pkt.syn = _truthy_flag(_as_list(flags.get("tcp_tcp_flags_syn"))[0]
                           if _as_list(flags.get("tcp_tcp_flags_syn")) else "")
    pkt.ack = _truthy_flag(_as_list(flags.get("tcp_tcp_flags_ack"))[0]
                           if _as_list(flags.get("tcp_tcp_flags_ack")) else "")
    pkt.fin = _truthy_flag(_as_list(flags.get("tcp_tcp_flags_fin"))[0]
                           if _as_list(flags.get("tcp_tcp_flags_fin")) else "")
    pkt.rst = _truthy_flag(_as_list(flags.get("tcp_tcp_flags_reset"))[0]
                           if _as_list(flags.get("tcp_tcp_flags_reset")) else "")

    # A frame with several DICOM PDUs comes through as a list of layer dicts.
    for dic in _as_list(layers.get("dicom")):
        if not isinstance(dic, dict):
            continue
        pkt.has_dicom = True
        types = [int(t) for t in _as_list(dic.get("dicom_dicom_pdu_type"))]
        pkt.pdu_types += types
        if any(t in (1, 2) for t in types):
            pkt.assoc = _parse_assoc(dic)
        if 3 in types:
            pkt.reject = (
                _first_int(dic.get("dicom_dicom_assoc_reject_result"), 0),
                _first_int(dic.get("dicom_dicom_assoc_reject_source"), 0),
                _first_int(dic.get("dicom_dicom_assoc_reject_reason"), 0),
            )
        if 7 in types:
            pkt.abort = (
                _first_int(dic.get("dicom_dicom_assoc_abort_source"), 0),
                _first_int(dic.get("dicom_dicom_assoc_abort_reason"), 0),
            )
        if 4 in types:
            pkt.pdvs += _parse_pdvs(dic)
    return pkt
