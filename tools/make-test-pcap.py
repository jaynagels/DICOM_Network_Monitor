"""Generate a realistic DICOM pcap for parser development and testing.

Development tool only: needs pynetdicom and pydicom installed (they are
NOT in the monitor's requirements.txt on purpose; the monitor itself has
no DICOM dependencies). The bundled dicom-sample.pcap was made with this
script and can be replayed through a running monitor with:

    curl -X POST http://127.0.0.1:8090/api/capture/start ^
         -H "Content-Type: application/json" ^
         -d "{\"file\": \"<absolute path to dicom-sample.pcap>\"}"

Runs real pynetdicom SCP/SCU exchanges over localhost, records the TCP
byte streams through logging proxies, then writes them into a classic
pcap file with fabricated endpoints:
  SCU / workstation : 10.0.0.9   (storage SCP for C-MOVE returns on 11115)
  archive (QR SCP)  : 10.0.0.50:11112

Scenarios: C-ECHO, C-FIND, C-MOVE (good), C-MOVE (unknown dest 0xA801),
C-STORE, MPPS N-CREATE/N-SET, A-ASSOCIATE-RJ, A-ABORT.
"""

import socket
import struct
import threading
import time

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import generate_uid, ImplicitVRLittleEndian
from pynetdicom import AE, evt, build_context
from pynetdicom.sop_class import (
    Verification,
    CTImageStorage,
    StudyRootQueryRetrieveInformationModelFind,
    StudyRootQueryRetrieveInformationModelMove,
    ModalityPerformedProcedureStep,
)

# ---------------------------------------------------------------------------
# Recording proxy: relays bytes and records (conn_id, direction, ts, data)
# ---------------------------------------------------------------------------
RECORDINGS = []   # list of dicts: {"conn": n, "role": "qr"|"store", "chunks": [(dir, ts, bytes)]}
_rec_lock = threading.Lock()


class Proxy(threading.Thread):
    def __init__(self, listen_port, target_port, role):
        super().__init__(daemon=True)
        self.listen_port = listen_port
        self.target_port = target_port
        self.role = role
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", listen_port))
        self.sock.listen(8)

    def run(self):
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            with _rec_lock:
                rec = {"conn": len(RECORDINGS), "role": self.role, "chunks": []}
                RECORDINGS.append(rec)
            upstream = socket.create_connection(("127.0.0.1", self.target_port))
            threading.Thread(target=self._pump, args=(client, upstream, rec, "c2s"),
                             daemon=True).start()
            threading.Thread(target=self._pump, args=(upstream, client, rec, "s2c"),
                             daemon=True).start()

    def _pump(self, src, dst, rec, direction):
        while True:
            try:
                data = src.recv(65536)
            except OSError:
                data = b""
            if not data:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            with _rec_lock:
                rec["chunks"].append((direction, time.time(), data))
            try:
                dst.sendall(data)
            except OSError:
                return


# ---------------------------------------------------------------------------
# DICOM endpoints
# ---------------------------------------------------------------------------
def make_ct_instance(i):
    ds = Dataset()
    ds.SOPClassUID = CTImageStorage
    ds.SOPInstanceUID = generate_uid()
    ds.PatientName = "LAB^PATIENT"
    ds.PatientID = "LAB001"
    ds.StudyInstanceUID = "1.2.826.0.1.3680043.10.9999.1.1"
    ds.SeriesInstanceUID = "1.2.826.0.1.3680043.10.9999.1.2"
    ds.Modality = "CT"
    ds.InstanceNumber = str(i)
    ds.file_meta = FileMetaDataset()
    ds.file_meta.TransferSyntaxUID = ImplicitVRLittleEndian
    ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
    ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    return ds


MOVE_DESTS = {
    "WORKSTATION": ("127.0.0.1", 11120),   # via recording proxy P2
    "OFFLINE": ("127.0.0.1", 11190),       # known AE but nothing listening
}


def handle_find(event):
    for i in range(2):
        ds = Dataset()
        ds.QueryRetrieveLevel = "STUDY"
        ds.PatientName = "LAB^PATIENT"
        ds.PatientID = "LAB001"
        ds.StudyInstanceUID = f"1.2.826.0.1.3680043.10.9999.1.{i+1}"
        yield 0xFF00, ds


def handle_move(event):
    dest = event.move_destination
    if dest not in MOVE_DESTS:
        yield None, None
        return
    addr, port = MOVE_DESTS[dest]
    yield addr, port, {"ae_title": "WORKSTATION",
                       "contexts": [build_context(CTImageStorage)]}
    yield 2
    yield 0xFF00, make_ct_instance(1)
    yield 0xFF00, make_ct_instance(2)


def handle_store(event):
    return 0x0000


def handle_n_create(event):
    ds = Dataset()
    ds.PerformedProcedureStepStatus = "IN PROGRESS"
    return 0x0000, ds


def handle_n_set(event):
    ds = Dataset()
    ds.PerformedProcedureStepStatus = "COMPLETED"
    return 0x0000, ds


def start_qr_scp():
    ae = AE(ae_title="DCM4CHEE")
    ae.add_supported_context(Verification)
    ae.add_supported_context(StudyRootQueryRetrieveInformationModelFind)
    ae.add_supported_context(StudyRootQueryRetrieveInformationModelMove)
    ae.add_supported_context(CTImageStorage)
    ae.add_supported_context(ModalityPerformedProcedureStep)
    ae.require_called_aet = True
    handlers = [
        (evt.EVT_C_FIND, handle_find),
        (evt.EVT_C_MOVE, handle_move),
        (evt.EVT_C_STORE, handle_store),
        (evt.EVT_N_CREATE, handle_n_create),
        (evt.EVT_N_SET, handle_n_set),
    ]
    return ae.start_server(("127.0.0.1", 11113), block=False, evt_handlers=handlers)


def start_store_scp():
    ae = AE(ae_title="WORKSTATION")
    ae.add_supported_context(CTImageStorage)
    return ae.start_server(("127.0.0.1", 11119), block=False,
                           evt_handlers=[(evt.EVT_C_STORE, handle_store)])


def run_scu():
    QR = ("127.0.0.1", 11114)   # proxy P1 -> QR SCP

    # 1. C-ECHO
    ae = AE(ae_title="MICRODICOM")
    ae.add_requested_context(Verification)
    assoc = ae.associate(*QR, ae_title="DCM4CHEE")
    assert assoc.is_established, "echo assoc failed"
    assoc.send_c_echo()
    assoc.release()

    # 2. C-FIND
    ae = AE(ae_title="MICRODICOM")
    ae.add_requested_context(StudyRootQueryRetrieveInformationModelFind)
    assoc = ae.associate(*QR, ae_title="DCM4CHEE")
    query = Dataset()
    query.QueryRetrieveLevel = "STUDY"
    query.PatientName = "LAB*"
    query.PatientID = ""
    query.StudyInstanceUID = ""
    for status, ident in assoc.send_c_find(query, StudyRootQueryRetrieveInformationModelFind):
        pass
    assoc.release()

    # 3. C-MOVE, good destination
    ae = AE(ae_title="MICRODICOM")
    ae.add_requested_context(StudyRootQueryRetrieveInformationModelMove)
    assoc = ae.associate(*QR, ae_title="DCM4CHEE")
    query = Dataset()
    query.QueryRetrieveLevel = "STUDY"
    query.StudyInstanceUID = "1.2.826.0.1.3680043.10.9999.1.1"
    for status, ident in assoc.send_c_move(query, "WORKSTATION",
                                           StudyRootQueryRetrieveInformationModelMove):
        pass
    assoc.release()
    time.sleep(0.5)

    # 4. C-MOVE, unknown destination -> 0xA801
    ae = AE(ae_title="MICRODICOM")
    ae.add_requested_context(StudyRootQueryRetrieveInformationModelMove)
    assoc = ae.associate(*QR, ae_title="DCM4CHEE")
    for status, ident in assoc.send_c_move(query, "NOWHERE",
                                           StudyRootQueryRetrieveInformationModelMove):
        pass
    assoc.release()

    # 4b. C-MOVE, destination known to archive but not listening
    ae = AE(ae_title="MICRODICOM")
    ae.add_requested_context(StudyRootQueryRetrieveInformationModelMove)
    assoc = ae.associate(*QR, ae_title="DCM4CHEE")
    for status, ident in assoc.send_c_move(query, "OFFLINE",
                                           StudyRootQueryRetrieveInformationModelMove):
        pass
    assoc.release()

    # 5. C-STORE direct to archive
    ae = AE(ae_title="MICRODICOM")
    ae.add_requested_context(CTImageStorage)
    assoc = ae.associate(*QR, ae_title="DCM4CHEE")
    assoc.send_c_store(make_ct_instance(99))
    assoc.release()

    # 6. MPPS N-CREATE + N-SET
    ae = AE(ae_title="MICRODICOM")
    ae.add_requested_context(ModalityPerformedProcedureStep)
    assoc = ae.associate(*QR, ae_title="DCM4CHEE")
    mpps_uid = generate_uid()
    ds = Dataset()
    ds.PerformedProcedureStepStatus = "IN PROGRESS"
    ds.PerformedStationAETitle = "MICRODICOM"
    assoc.send_n_create(ds, ModalityPerformedProcedureStep, mpps_uid)
    ds2 = Dataset()
    ds2.PerformedProcedureStepStatus = "COMPLETED"
    assoc.send_n_set(ds2, ModalityPerformedProcedureStep, mpps_uid)
    assoc.release()

    # 7. wrong called AE -> A-ASSOCIATE-RJ
    ae = AE(ae_title="MICRODICOM")
    ae.add_requested_context(Verification)
    assoc = ae.associate(*QR, ae_title="WRONG_AE")
    assert not assoc.is_established

    # 8. A-ABORT mid-association
    ae = AE(ae_title="MICRODICOM")
    ae.add_requested_context(Verification)
    assoc = ae.associate(*QR, ae_title="DCM4CHEE")
    assoc.abort()
    time.sleep(0.3)


# ---------------------------------------------------------------------------
# pcap writer: fabricate Ethernet/IPv4/TCP frames from recorded streams
# ---------------------------------------------------------------------------
SCU_IP, ARCHIVE_IP = "10.0.0.9", "10.0.0.50"
QR_PORT, STORE_PORT = 11112, 11115


def ip2b(ip):
    return bytes(int(x) for x in ip.split("."))


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


class PcapWriter:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def frame(self, ts, data):
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self.f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
        self.f.write(data)

    def close(self):
        self.f.close()


class TcpFlow:
    """Builds both directions of one fabricated TCP connection."""

    def __init__(self, writer, ts, c_ip, c_port, s_ip, s_port):
        self.w = writer
        self.c = (c_ip, c_port)
        self.s = (s_ip, s_port)
        self.seq = {self.c: 1000, self.s: 5000}
        self.macs = {self.c: b"\x02\x00\x00\x00\x00\x09", self.s: b"\x02\x00\x00\x00\x00\x50"}
        # handshake
        self._pkt(ts, self.c, self.s, flags=0x02)           # SYN
        self.seq[self.c] += 1
        self._pkt(ts, self.s, self.c, flags=0x12)           # SYN-ACK
        self.seq[self.s] += 1
        self._pkt(ts, self.c, self.s, flags=0x10)           # ACK

    def _pkt(self, ts, src, dst, payload=b"", flags=0x10):
        seq = self.seq[src]
        ack = self.seq[dst]
        tcp_hdr = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack,
                              5 << 4, flags, 65535, 0, 0)
        pseudo = ip2b(src[0]) + ip2b(dst[0]) + struct.pack("!BBH", 0, 6, len(tcp_hdr) + len(payload))
        csum = checksum(pseudo + tcp_hdr + payload)
        tcp_hdr = tcp_hdr[:16] + struct.pack("!H", csum) + tcp_hdr[18:]
        total = 20 + len(tcp_hdr) + len(payload)
        ip_hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, 6, 0) \
            + ip2b(src[0]) + ip2b(dst[0])
        ip_hdr = ip_hdr[:10] + struct.pack("!H", checksum(ip_hdr)) + ip_hdr[12:]
        eth = self.macs[dst] + self.macs[src] + b"\x08\x00"
        self.w.frame(ts, eth + ip_hdr + tcp_hdr + payload)
        self.seq[src] += len(payload)

    def data(self, ts, direction, payload):
        src, dst = (self.c, self.s) if direction == "c2s" else (self.s, self.c)
        for i in range(0, len(payload), 1400):
            self._pkt(ts, src, dst, payload[i:i + 1400], flags=0x18)  # PSH|ACK

    def close(self, ts):
        self._pkt(ts, self.c, self.s, flags=0x11)  # FIN|ACK
        self.seq[self.c] += 1
        self._pkt(ts, self.s, self.c, flags=0x11)
        self.seq[self.s] += 1
        self._pkt(ts, self.c, self.s, flags=0x10)


def write_pcap(path):
    w = PcapWriter(path)
    # interleave all chunks globally by timestamp, but pcap frames per
    # connection must be seq-consistent; emit per connection in time order
    # (tshark sorts nothing; frames just need to be roughly ordered).
    events = []   # (ts, conn_index, kind, payload/direction)
    for idx, rec in enumerate(RECORDINGS):
        if not rec["chunks"]:
            continue
        t0 = rec["chunks"][0][1] - 0.001
        events.append((t0, idx, "open", None))
        for direction, ts, data in rec["chunks"]:
            events.append((ts, idx, "data", (direction, data)))
        t1 = rec["chunks"][-1][1] + 0.001
        events.append((t1, idx, "close", None))
    events.sort(key=lambda e: (e[0], e[1]))
    flows = {}
    eph = 50000
    for ts, idx, kind, arg in events:
        rec = RECORDINGS[idx]
        if kind == "open":
            if rec["role"] == "qr":
                flows[idx] = TcpFlow(w, ts, SCU_IP, eph, ARCHIVE_IP, QR_PORT)
            else:  # return association: archive -> workstation
                flows[idx] = TcpFlow(w, ts, ARCHIVE_IP, eph, SCU_IP, STORE_PORT)
            eph += 1
        elif kind == "data":
            flows[idx].data(ts, *arg)
        else:
            flows[idx].close(ts)
    w.close()
    print(f"wrote {path}: {len(RECORDINGS)} connections")


if __name__ == "__main__":
    qr = start_qr_scp()
    store = start_store_scp()
    Proxy(11114, 11113, "qr").start()      # SCU -> archive
    Proxy(11120, 11119, "store").start()   # archive -> workstation (C-MOVE return)
    time.sleep(0.3)
    run_scu()
    time.sleep(0.5)
    qr.shutdown()
    store.shutdown()
    write_pcap("dicom-sample.pcap")
    for rec in RECORDINGS:
        total = sum(len(d) for _, _, d in rec["chunks"])
        print(f"  conn {rec['conn']} role={rec['role']} bytes={total}")
