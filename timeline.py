"""Build the plain-language DIMSE timeline from parsed packets.

Packets (from ekparse) are grouped into associations by tshark's TCP stream
index. Each association collects ordered events; C-MOVE requests are
correlated with the return association the archive opens to the move
destination, and with the sub-operation tallies in the C-MOVE-RSP messages.
"""

import re
import threading
import time
from collections import deque

import config
import dicom_names as dn
from ekparse import PDU_NAMES

_KIND_RANK = {"info": 0, "ok": 1, "pending": 2, "warn": 3, "fail": 4}

# element values worth surfacing from data (identifier / object) PDVs
_INTERESTING_TAGS = [
    ((0x0008, 0x0052), "Level"),
    ((0x0010, 0x0010), "PatientName"),
    ((0x0010, 0x0020), "PatientID"),
    ((0x0008, 0x0060), "Modality"),
    ((0x0008, 0x0050), "AccessionNumber"),
    ((0x0020, 0x000D), "StudyInstanceUID"),
    ((0x0040, 0x0252), "MPPS status"),
]


def _sop_display(value):
    """tshark prints 'uid (Name)'; prefer the name, fall back to our table."""
    m = re.match(r"^([0-9.]+)\s*\((.+)\)$", value)
    if m:
        return m.group(2)
    return dn.uid_name(value) if value else "unknown SOP class"


def _short_uid(uid):
    return uid if len(uid) <= 40 else uid[:18] + "..." + uid[-18:]


class Association:
    def __init__(self, assoc_id, stream, first_pkt):
        self.id = assoc_id
        self.stream = stream
        self.client = first_pkt.src_label
        self.server = first_pkt.dst_label
        self.calling = ""
        self.called = ""
        self.state = "connecting"
        self.worst = "info"
        self.ops = []              # DIMSE command families, in first-seen order
        self.move_link = None      # move number when this is a return association
        self.closed_noted = False
        self.n_contexts_proposed = 0
        self.last_seq = 0          # seq of the last event, for change polling

    def note_op(self, family):
        if family not in self.ops:
            self.ops.append(family)

    def raise_worst(self, kind):
        if kind == "pending":
            return    # transient, not an outcome
        if _KIND_RANK.get(kind, 0) > _KIND_RANK.get(self.worst, 0):
            self.worst = kind

    def summary(self):
        peers = f"{self.client} -> {self.server}"
        aes = f"{self.calling} -> {self.called}" if self.calling else ""
        return {
            "id": self.id,
            "peers": peers,
            "aes": aes,
            "ops": " ".join(self.ops),
            "state": self.state,
            "worst": self.worst,
            "move_link": self.move_link,
            "last_seq": self.last_seq,
        }


class MoveOp:
    def __init__(self, number, assoc, msg_id, dest, sop_name):
        self.number = number
        self.assoc_id = assoc.id
        self.msg_id = msg_id
        self.dest = dest
        self.sop_name = sop_name
        self.remaining = self.completed = self.failed = self.warning = None
        self.final_status = None
        self.return_assoc_id = None
        self.created = time.time()


class Monitor:
    """Consumes packets, produces the event timeline. Thread-safe."""

    def __init__(self):
        self._lock = threading.Lock()
        self.events = deque(maxlen=config.EVENT_BUFFER)
        self.assocs = {}           # stream index -> Association
        self.assoc_order = []
        self.moves = []
        self.seq = 0
        self._next_assoc_id = 1
        self._find_matches = {}    # (assoc_id, msg_id) -> pending match count
        self._last_command = {}    # (assoc_id, src_label) -> command context
        self._log = None
        self.session_lines = []

    # ------------------------------------------------------------------
    # logging
    # ------------------------------------------------------------------
    def open_log(self):
        if self._log is None:
            self._log = open(config.LOG_PATH, "a", encoding="utf-8")

    def _write_log(self, ts, assoc, kind, text, details):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        stamp += ".%03d" % int((ts % 1) * 1000)
        tag = f"assoc#{assoc.id}" if assoc else "session"
        lines = [f"{stamp} {tag:>9} [{kind.upper():>7}] {text}"]
        lines += [f"{'':32}- {d}" for d in details]
        for line in lines:
            self.session_lines.append(line)
            if self._log:
                self._log.write(line + "\n")
        if self._log:
            self._log.flush()

    # ------------------------------------------------------------------
    # event emission
    # ------------------------------------------------------------------
    def _emit(self, ts, assoc, kind, text, details=None):
        details = details or []
        self.seq += 1
        stamp = time.strftime("%H:%M:%S", time.localtime(ts))
        stamp += ".%03d" % int((ts % 1) * 1000)
        event = {
            "seq": self.seq,
            "ts": stamp,
            "assoc": assoc.id if assoc else None,
            "kind": kind,
            "text": text,
            "details": details,
        }
        self.events.append(event)
        if assoc:
            assoc.last_seq = self.seq
            assoc.raise_worst(kind)
        self._write_log(ts, assoc, kind, text, details)
        return event

    def session_event(self, text, kind="info"):
        with self._lock:
            self._emit(time.time(), None, kind, text)

    # ------------------------------------------------------------------
    # packet intake
    # ------------------------------------------------------------------
    def process(self, pkt):
        if pkt.stream is None:
            return
        with self._lock:
            assoc = self.assocs.get(pkt.stream)
            if assoc is None:
                if pkt.rst or pkt.fin:
                    return    # tail end of a connection we never saw open
                assoc = Association(self._next_assoc_id, pkt.stream, pkt)
                self._next_assoc_id += 1
                self.assocs[pkt.stream] = assoc
                self.assoc_order.append(pkt.stream)
                if pkt.syn and not pkt.ack:
                    self._emit(pkt.ts, assoc, "info",
                               f"TCP connection opened: {pkt.src_label} -> "
                               f"{pkt.dst_label}")
                else:
                    self._emit(pkt.ts, assoc, "info",
                               f"Conversation joined mid-stream: {pkt.src_label}"
                               f" -> {pkt.dst_label} (capture started after the "
                               f"connection opened)")

            for pdu_type in pkt.pdu_types:
                self._handle_pdu(assoc, pkt, pdu_type)
            for pdv in pkt.pdvs:
                if pdv.is_command:
                    self._handle_command(assoc, pkt, pdv)
                else:
                    self._handle_data(assoc, pkt, pdv)

            if (pkt.fin or pkt.rst) and not pkt.has_dicom \
                    and not assoc.closed_noted:
                assoc.closed_noted = True
                if pkt.rst:
                    self._emit(pkt.ts, assoc, "warn",
                               f"TCP connection reset by {pkt.src_label} "
                               f"(hard close, no DICOM goodbye)")
                    if assoc.state not in ("released", "rejected", "aborted"):
                        assoc.state = "reset"
                else:
                    self._emit(pkt.ts, assoc, "info", "TCP connection closed")
                    if assoc.state not in ("released", "rejected", "aborted",
                                           "reset"):
                        assoc.state = "closed"

    # ------------------------------------------------------------------
    # association-level PDUs
    # ------------------------------------------------------------------
    def _handle_pdu(self, assoc, pkt, pdu_type):
        name = PDU_NAMES.get(pdu_type, f"PDU type {pdu_type}")
        if pdu_type == 1:      # A-ASSOCIATE-RQ
            assoc.calling = pkt.assoc.get("calling", "")
            assoc.called = pkt.assoc.get("called", "")
            assoc.state = "negotiating"
            contexts = pkt.assoc.get("contexts", [])
            assoc.n_contexts_proposed = len(contexts)
            details = []
            for ctx in contexts:
                abstract = ctx.get("abstract") or ctx.get("head", "")
                transfers = "; ".join(_strip_uid(t) for t in ctx["transfer"])
                details.append(f"Proposes {_strip_uid(abstract)}"
                               + (f" ({transfers})" if transfers else ""))
            self._emit(pkt.ts, assoc, "info",
                       f"A-ASSOCIATE-RQ: '{assoc.calling}' asks '{assoc.called}'"
                       f" to open a DICOM association "
                       f"({len(contexts)} presentation context"
                       f"{'s' if len(contexts) != 1 else ''} proposed)",
                       details)
            self._maybe_link_move(assoc, pkt.ts)

        elif pdu_type == 2:    # A-ASSOCIATE-AC
            contexts = pkt.assoc.get("contexts", [])
            accepted = sum(1 for c in contexts if ", Accept," in c.get("head", ""))
            rejected = len(contexts) - accepted
            details = [f"Context {_rewrite_ac_head(c['head'])}" for c in contexts]
            kind = "ok" if rejected == 0 else "warn"
            text = (f"A-ASSOCIATE-AC: '{assoc.called or pkt.assoc.get('called', '')}'"
                    f" accepted the association"
                    f" ({accepted} context{'s' if accepted != 1 else ''} accepted"
                    + (f", {rejected} rejected" if rejected else "") + ")")
            assoc.state = "established"
            self._emit(pkt.ts, assoc, kind, text, details)

        elif pdu_type == 3:    # A-ASSOCIATE-RJ
            result, source, reason = pkt.reject
            assoc.state = "rejected"
            self._emit(pkt.ts, assoc, "fail",
                       "A-ASSOCIATE-RJ: association "
                       + dn.decode_reject(result, source, reason),
                       [f"result={result}, source={source}, reason={reason}"])

        elif pdu_type == 5:
            self._emit(pkt.ts, assoc, "info",
                       "A-RELEASE-RQ: graceful close requested")

        elif pdu_type == 6:
            assoc.state = "released"
            self._emit(pkt.ts, assoc, "info",
                       "A-RELEASE-RP: association released cleanly")

        elif pdu_type == 7:
            source, reason = pkt.abort
            assoc.state = "aborted"
            self._emit(pkt.ts, assoc, "fail",
                       "A-ABORT: association " + dn.decode_abort(source, reason),
                       [f"source={source}, reason={reason}"])

    # ------------------------------------------------------------------
    # DIMSE commands
    # ------------------------------------------------------------------
    def _handle_command(self, assoc, pkt, pdv):
        cmd = pdv.command
        if not cmd:
            return
        family = cmd.rsplit("-", 1)[0]      # C-ECHO-RQ -> C-ECHO
        assoc.note_op(family)
        msg_id = pdv.get(0x0000, 0x0110) or pdv.get(0x0000, 0x0120)
        sop_name = _sop_display(pdv.get(0x0000, 0x0002)
                                or pdv.get(0x0000, 0x0003))
        status_val = pdv.get(0x0000, 0x0900)
        status_code = None
        if status_val:
            from ekparse import value_status_code
            status_code = value_status_code(status_val)

        self._last_command[(assoc.id, pkt.src_label)] = \
            {"cmd": cmd, "msg_id": msg_id, "sop": sop_name, "ts": pkt.ts}

        head = f"{cmd} (msg {msg_id})"
        if cmd.endswith("-RQ"):
            self._handle_request(assoc, pkt, pdv, cmd, head, sop_name, msg_id)
        else:
            self._handle_response(assoc, pkt, pdv, cmd, head, sop_name,
                                  msg_id, status_code)

    def _handle_request(self, assoc, pkt, pdv, cmd, head, sop_name, msg_id):
        meaning = dn.COMMAND_MEANING.get(cmd, "request")
        details = []
        kind = "info"
        if cmd == "C-STORE-RQ":
            instance = pdv.get(0x0000, 0x1000)
            text = f"{head}: storing one {sop_name} object"
            if instance:
                details.append(f"SOP Instance {_short_uid(instance)}")
            originator = pdv.get(0x0000, 0x1030)
            if originator:
                orig_msg = pdv.get(0x0000, 0x1031)
                details.append(f"Sub-operation of a C-MOVE started by "
                               f"'{originator.strip()}' (its msg {orig_msg})")
        elif cmd == "C-MOVE-RQ":
            dest = pdv.get(0x0000, 0x0600).strip()
            move = MoveOp(len(self.moves) + 1, assoc, msg_id, dest, sop_name)
            self.moves.append(move)
            text = (f"{head}: C-MOVE #{move.number}: asking "
                    f"'{assoc.called or 'the archive'}' to send matching "
                    f"objects to '{dest}' ({sop_name})")
            details.append(f"Now watch for a NEW association where the archive"
                           f" connects to '{dest}' to deliver the objects")
        elif cmd == "C-FIND-RQ":
            text = f"{head}: {meaning} using {sop_name}"
        elif cmd == "C-ECHO-RQ":
            text = f"{head}: {meaning}"
        elif cmd in ("N-CREATE-RQ", "N-SET-RQ"):
            what = "started" if cmd == "N-CREATE-RQ" else "being updated"
            if "Performed Procedure" in sop_name:
                text = f"{head}: MPPS: a performed procedure step is {what}"
            else:
                text = f"{head}: {meaning} ({sop_name})"
        else:
            text = f"{head}: {meaning} ({sop_name})"
        self._emit(pkt.ts, assoc, kind, text, details)

    def _handle_response(self, assoc, pkt, pdv, cmd, head, sop_name,
                         msg_id, status_code):
        if status_code is None:
            self._emit(pkt.ts, assoc, "info", f"{head}: response")
            return
        meaning, kind = dn.decode_status(status_code)
        status = dn.status_text(status_code)
        details = []

        if cmd == "C-FIND-RSP":
            key = (assoc.id, msg_id)
            if kind == "pending":
                self._find_matches[key] = self._find_matches.get(key, 0) + 1
                self._emit(pkt.ts, assoc, "pending",
                           f"{head}: match #{self._find_matches[key]} received"
                           f" ({status})")
            else:
                count = self._find_matches.pop(key, 0)
                self._emit(pkt.ts, assoc, kind,
                           f"{head}: query finished with {count} match"
                           f"{'es' if count != 1 else ''} ({status})")
            return

        if cmd in ("C-MOVE-RSP", "C-GET-RSP"):
            self._handle_move_response(assoc, pkt, pdv, cmd, head, msg_id,
                                       status_code, status, kind)
            return

        text = f"{head}: {status}"
        if cmd == "C-STORE-RSP" and assoc.move_link:
            text += f" (C-MOVE #{assoc.move_link} sub-operation)"
        self._emit(pkt.ts, assoc, kind, text, details)

    # ------------------------------------------------------------------
    # C-MOVE: the crown feature
    # ------------------------------------------------------------------
    def _find_move(self, assoc_id, msg_id):
        for move in reversed(self.moves):
            if move.assoc_id == assoc_id and move.msg_id == msg_id:
                return move
        return None

    def _handle_move_response(self, assoc, pkt, pdv, cmd, head, msg_id,
                              status_code, status, kind):
        move = self._find_move(assoc.id, msg_id) if cmd == "C-MOVE-RSP" else None
        tally = {}
        for elem, attr in ((0x1020, "remaining"), (0x1021, "completed"),
                           (0x1022, "failed"), (0x1023, "warning")):
            value = pdv.get(0x0000, elem)
            if value != "":
                try:
                    tally[attr] = int(value)
                except ValueError:
                    pass
        if move:
            for attr, value in tally.items():
                setattr(move, attr, value)

        tally_text = ""
        if tally:
            tally_text = (" | sub-operations: "
                          + ", ".join(f"{k} {v}" for k, v in tally.items()))
        label = f"C-MOVE #{move.number}" if move else head
        if kind == "pending":
            self._emit(pkt.ts, assoc, "pending",
                       f"{head}: {label} in progress ({status}){tally_text}")
            return

        # Final response: tell the whole story.
        move_kind = kind
        details = []
        if move:
            move.final_status = status_code
            failed = move.failed or 0
            completed = move.completed or 0
            if status_code == 0xA801:
                move_kind = "fail"
                details.append(
                    f"Move destination '{move.dest}' is not known to the "
                    f"archive: the destination AE title is not configured as "
                    f"a remote node on the archive. Add '{move.dest}' (with "
                    f"this workstation's IP and storage port) to the "
                    f"archive's list of known AEs.")
            elif move.return_assoc_id is None and (failed > 0 or completed == 0):
                move_kind = "fail"
                details.append(
                    f"The archive accepted the C-MOVE request but never "
                    f"opened a connection back to '{move.dest}' to send "
                    f"images (no return association was seen on this capture "
                    f"interface). Check that '{move.dest}' is listening as a "
                    f"Storage SCP and that the archive has the correct host "
                    f"and port registered for it.")
            elif failed > 0:
                move_kind = "warn"
                details.append(
                    f"{failed} sub-operation{'s' if failed != 1 else ''} "
                    f"failed: the archive tried to deliver "
                    f"{'these images' if failed != 1 else 'this image'} to "
                    f"'{move.dest}' but could not. Look at the C-STORE "
                    f"responses on the return association for the reason.")
            if move.return_assoc_id is not None:
                ret = self._assoc_by_id(move.return_assoc_id)
                if ret:
                    details.append(f"Objects were delivered on association "
                                   f"#{ret.id} ({ret.client} -> {ret.server})")
        self._emit(pkt.ts, assoc, move_kind,
                   f"{head}: {label} finished: {status}{tally_text}", details)

    def _assoc_by_id(self, assoc_id):
        for assoc in self.assocs.values():
            if assoc.id == assoc_id:
                return assoc
        return None

    def _maybe_link_move(self, assoc, ts):
        """A new A-ASSOCIATE-RQ: is its called AE a pending move destination?"""
        for move in reversed(self.moves):
            if move.dest and move.dest == assoc.called \
                    and move.return_assoc_id is None \
                    and move.final_status is None \
                    and move.assoc_id != assoc.id:
                move.return_assoc_id = assoc.id
                assoc.move_link = move.number
                origin = self._assoc_by_id(move.assoc_id)
                self._emit(ts, assoc, "ok",
                           f"This is the RETURN ASSOCIATION for C-MOVE "
                           f"#{move.number} (requested on association "
                           f"#{move.assoc_id}): '{assoc.calling}' is "
                           f"connecting back to '{move.dest}' to deliver "
                           f"the objects")
                if origin:
                    self._emit(ts, origin, "ok",
                               f"C-MOVE #{move.number}: the archive opened "
                               f"the return association to '{move.dest}' "
                               f"(association #{assoc.id})")
                return

    # ------------------------------------------------------------------
    # data (identifier / object) PDVs
    # ------------------------------------------------------------------
    def _handle_data(self, assoc, pkt, pdv):
        last = self._last_command.get((assoc.id, pkt.src_label), {})
        cmd = last.get("cmd", "")
        pairs = []
        for tag, label in _INTERESTING_TAGS:
            value = pdv.get(*tag)
            if value:
                pairs.append(f"{label}={value.strip()}")
        if not pairs:
            return
        if cmd == "C-FIND-RQ":
            text = "Query identifier: " + " | ".join(pairs)
        elif cmd == "C-FIND-RSP":
            text = "Match: " + " | ".join(pairs)
        elif cmd in ("N-CREATE-RQ", "N-SET-RQ", "N-CREATE-RSP", "N-SET-RSP"):
            text = "MPPS data: " + " | ".join(pairs)
        elif cmd.startswith("C-MOVE"):
            text = "Move identifier: " + " | ".join(pairs)
        else:
            text = "Object data: " + " | ".join(pairs)
        self._emit(pkt.ts, assoc, "info", text)

    # ------------------------------------------------------------------
    # polling API for the browser
    # ------------------------------------------------------------------
    def snapshot_since(self, after_seq):
        with self._lock:
            events = [e for e in self.events if e["seq"] > after_seq]
            assocs = [self.assocs[s].summary() for s in self.assoc_order
                      if self.assocs[s].last_seq > after_seq]
            return {"events": events, "assocs": assocs, "seq": self.seq}


def _strip_uid(text):
    """'Verification SOP Class (1.2.840.10008.1.1)' -> 'Verification SOP Class'.

    Keeps unknown bare UIDs as-is so nothing is hidden.
    """
    m = re.match(r"^(.+?)\s*\([0-9.]+\)$", text)
    return m.group(1) if m else text


def _rewrite_ac_head(head):
    """Make the accept-line a bit friendlier but keep all facts."""
    return _strip_uid(head)
