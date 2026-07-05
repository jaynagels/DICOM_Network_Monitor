"""Plain-English dictionaries for DICOM UIDs, status codes and PDU reasons.

tshark already decodes most UIDs to names inside its output; these tables
cover the pieces it leaves numeric (status codes, reject and abort reasons)
plus a UID fallback for anything shown bare. Never show a bare hex status
without its meaning: always go through decode_status().
"""

# ---------------------------------------------------------------------------
# DIMSE status codes -> (meaning, kind)
# kind is one of: ok, pending, warn, fail  (drives the color in the UI)
# ---------------------------------------------------------------------------
_STATUS_EXACT = {
    0x0000: ("Success", "ok"),
    0xFF00: ("Pending: match/sub-operation supplied, more to come", "pending"),
    0xFF01: ("Pending: match supplied, but some optional keys were not "
             "supported", "pending"),
    0xFE00: ("Cancelled: sub-operations terminated by a C-CANCEL", "warn"),
    0x0001: ("Warning: requested optional attributes are not supported", "warn"),
    0x0105: ("Failed: no such attribute", "fail"),
    0x0106: ("Failed: invalid attribute value", "fail"),
    0x0107: ("Warning: attribute list error", "warn"),
    0x0110: ("Failed: processing failure", "fail"),
    0x0111: ("Failed: duplicate SOP Instance", "fail"),
    0x0112: ("Failed: no such SOP Instance", "fail"),
    0x0116: ("Warning: attribute value out of range", "warn"),
    0x0117: ("Failed: invalid object instance", "fail"),
    0x0118: ("Failed: no such SOP Class", "fail"),
    0x0119: ("Failed: class/instance conflict", "fail"),
    0x0122: ("Failed: SOP Class not supported", "fail"),
    0x0124: ("Refused: not authorized", "fail"),
    0x0210: ("Failed: duplicate invocation", "fail"),
    0x0211: ("Failed: unrecognized operation", "fail"),
    0x0212: ("Failed: mistyped argument", "fail"),
    0xA700: ("Refused: out of resources", "fail"),
    0xA701: ("Refused: out of resources, unable to calculate number of "
             "matches", "fail"),
    0xA702: ("Refused: out of resources, unable to perform sub-operations",
             "fail"),
    0xA801: ("Refused: move destination unknown", "fail"),
    0xA900: ("Failed: identifier does not match SOP Class", "fail"),
    0xB000: ("Warning: sub-operations complete, one or more failures", "warn"),
    0xB006: ("Warning: elements discarded", "warn"),
    0xB007: ("Warning: data set does not match SOP Class", "warn"),
}


def decode_status(code):
    """Return (meaning, kind) for a DIMSE status code."""
    if code in _STATUS_EXACT:
        return _STATUS_EXACT[code]
    if 0xC000 <= code <= 0xCFFF:
        return ("Failed: unable to process", "fail")
    if 0xA000 <= code <= 0xAFFF:
        return ("Refused/failed", "fail")
    if 0xB000 <= code <= 0xBFFF:
        return ("Warning", "warn")
    return ("Unknown status", "warn")


def status_text(code):
    """'0xA801 Refused: move destination unknown' style string."""
    meaning, _ = decode_status(code)
    return f"0x{code:04X} {meaning}"


# ---------------------------------------------------------------------------
# A-ASSOCIATE-RJ result / source / reason (PS3.8 section 9.3.4)
# ---------------------------------------------------------------------------
REJECT_RESULT = {
    1: "rejected permanently (retrying will not help)",
    2: "rejected transiently (the peer may accept later)",
}

REJECT_SOURCE = {
    1: "the called application itself",
    2: "the DICOM association layer (ACSE)",
    3: "the presentation layer",
}

# reason tables keyed by source
REJECT_REASON = {
    1: {
        1: "no reason given",
        2: "application context name not supported",
        3: "calling AE title not recognized: the peer does not know this "
           "client's AE title",
        7: "called AE title not recognized: this server does not answer to "
           "the AE title the client asked for",
    },
    2: {
        1: "no reason given",
        2: "protocol version not supported",
    },
    3: {
        1: "temporary congestion, try again later",
        2: "local limit exceeded (too many simultaneous associations)",
    },
}


def decode_reject(result, source, reason):
    res = REJECT_RESULT.get(result, f"result {result}")
    src = REJECT_SOURCE.get(source, f"source {source}")
    rsn = REJECT_REASON.get(source, {}).get(reason, f"reason code {reason}")
    return f"{res}, by {src}: {rsn}"


# ---------------------------------------------------------------------------
# A-ABORT source / reason (PS3.8 section 9.3.8)
# ---------------------------------------------------------------------------
ABORT_SOURCE = {
    0: "the application that started the abort (usually the SCU giving up)",
    2: "the DICOM protocol layer itself (it saw something invalid)",
}

ABORT_REASON = {
    0: "not specified",
    1: "unrecognized PDU",
    2: "unexpected PDU",
    4: "unrecognized PDU parameter",
    5: "unexpected PDU parameter",
    6: "invalid PDU parameter value",
}


def decode_abort(source, reason):
    src = ABORT_SOURCE.get(source, f"source {source}")
    text = f"aborted by {src}"
    if source == 2:
        text += f", reason: {ABORT_REASON.get(reason, f'code {reason}')}"
    return text


# ---------------------------------------------------------------------------
# Presentation context negotiation result (in A-ASSOCIATE-AC)
# ---------------------------------------------------------------------------
PCTX_RESULT = {
    0: "accepted",
    1: "rejected by the user",
    2: "rejected (no reason)",
    3: "rejected: abstract syntax (SOP class) not supported",
    4: "rejected: none of the proposed transfer syntaxes supported",
}


# ---------------------------------------------------------------------------
# UID -> human name fallback (tshark usually names these already; this table
# covers UIDs it prints bare, and lets us name UIDs found in element values)
# ---------------------------------------------------------------------------
UID_NAMES = {
    "1.2.840.10008.1.1": "Verification (C-ECHO)",
    "1.2.840.10008.1.20.1": "Storage Commitment Push Model",
    "1.2.840.10008.3.1.2.3.3": "Modality Performed Procedure Step (MPPS)",
    "1.2.840.10008.5.1.4.31": "Modality Worklist (MWL) FIND",
    "1.2.840.10008.5.1.4.1.2.1.1": "Patient Root Query/Retrieve - FIND",
    "1.2.840.10008.5.1.4.1.2.1.2": "Patient Root Query/Retrieve - MOVE",
    "1.2.840.10008.5.1.4.1.2.1.3": "Patient Root Query/Retrieve - GET",
    "1.2.840.10008.5.1.4.1.2.2.1": "Study Root Query/Retrieve - FIND",
    "1.2.840.10008.5.1.4.1.2.2.2": "Study Root Query/Retrieve - MOVE",
    "1.2.840.10008.5.1.4.1.2.2.3": "Study Root Query/Retrieve - GET",
    "1.2.840.10008.5.1.4.1.1.1": "CR Image Storage",
    "1.2.840.10008.5.1.4.1.1.1.1": "Digital X-Ray Image Storage",
    "1.2.840.10008.5.1.4.1.1.1.2": "Digital Mammography X-Ray Image Storage",
    "1.2.840.10008.5.1.4.1.1.2": "CT Image Storage",
    "1.2.840.10008.5.1.4.1.1.2.1": "Enhanced CT Image Storage",
    "1.2.840.10008.5.1.4.1.1.4": "MR Image Storage",
    "1.2.840.10008.5.1.4.1.1.4.1": "Enhanced MR Image Storage",
    "1.2.840.10008.5.1.4.1.1.6.1": "Ultrasound Image Storage",
    "1.2.840.10008.5.1.4.1.1.7": "Secondary Capture Image Storage",
    "1.2.840.10008.5.1.4.1.1.12.1": "X-Ray Angiographic Image Storage",
    "1.2.840.10008.5.1.4.1.1.20": "NM Image Storage",
    "1.2.840.10008.5.1.4.1.1.128": "PET Image Storage",
    "1.2.840.10008.5.1.4.1.1.88.11": "Basic Text SR Storage",
    "1.2.840.10008.5.1.4.1.1.88.22": "Enhanced SR Storage",
    "1.2.840.10008.5.1.4.1.1.88.33": "Comprehensive SR Storage",
    "1.2.840.10008.1.2": "Implicit VR Little Endian",
    "1.2.840.10008.1.2.1": "Explicit VR Little Endian",
    "1.2.840.10008.1.2.1.99": "Deflated Explicit VR Little Endian",
    "1.2.840.10008.1.2.2": "Explicit VR Big Endian",
    "1.2.840.10008.1.2.4.50": "JPEG Baseline",
    "1.2.840.10008.1.2.4.51": "JPEG Extended",
    "1.2.840.10008.1.2.4.57": "JPEG Lossless",
    "1.2.840.10008.1.2.4.70": "JPEG Lossless SV1",
    "1.2.840.10008.1.2.4.80": "JPEG-LS Lossless",
    "1.2.840.10008.1.2.4.90": "JPEG 2000 Lossless",
    "1.2.840.10008.1.2.4.91": "JPEG 2000",
    "1.2.840.10008.1.2.5": "RLE Lossless",
}


def uid_name(uid):
    """Human name for a UID, or the UID itself when unknown."""
    return UID_NAMES.get(uid, uid)


# ---------------------------------------------------------------------------
# What each DIMSE command means, one plain-language phrase
# ---------------------------------------------------------------------------
COMMAND_MEANING = {
    "C-ECHO-RQ": "connectivity test (DICOM ping)",
    "C-ECHO-RSP": "reply to the connectivity test",
    "C-STORE-RQ": "request to store an object",
    "C-STORE-RSP": "result of the store",
    "C-FIND-RQ": "query",
    "C-FIND-RSP": "query response",
    "C-MOVE-RQ": "retrieve request: send objects to a third AE",
    "C-MOVE-RSP": "retrieve progress/result",
    "C-GET-RQ": "retrieve request: send objects back on this association",
    "C-GET-RSP": "retrieve progress/result",
    "C-CANCEL-RQ": "cancel the running operation",
    "N-CREATE-RQ": "create a managed object (MPPS: procedure step started)",
    "N-CREATE-RSP": "result of the create",
    "N-SET-RQ": "update a managed object (MPPS: procedure step progress)",
    "N-SET-RSP": "result of the update",
    "N-EVENT-REPORT-RQ": "event notification",
    "N-EVENT-REPORT-RSP": "event notification reply",
    "N-GET-RQ": "read a managed object",
    "N-GET-RSP": "result of the read",
    "N-ACTION-RQ": "action request (e.g. storage commitment)",
    "N-ACTION-RSP": "action result",
    "N-DELETE-RQ": "delete a managed object",
    "N-DELETE-RSP": "result of the delete",
}
