#!/usr/bin/env python3
"""BRIDGE_PLAN Phase 4 gate: USB + TCP simultaneously.

Exercises what the ad-hoc bench check covered, as a permanent test:
  - KISS detect answered on USB and on TWO concurrent TCP sessions
  - a 3rd TCP client is politely rejected (EOF) and the survivors
    stay responsive
  - host fan-out: USB data reaches both TCP clients, TCP data
    reaches USB and the other TCP client, payloads byte-exact
  - radio RX fans out to ALL sessions: one RNode pong arrives on
    USB and on both TCP clients

Usage: dual_link_acceptance.py [c6l_ip] [freq_hz]
  C6L USB console on /dev/ttyACM1, RNode on /dev/ttyUSB1.
"""
import serial, socket, time, threading, sys

FEND, FESC, TFEND, TFESC = 0xC0, 0xDB, 0xDC, 0xDD

def frame(cmd, payload=b''):
    out = bytearray([FEND, cmd])
    for b in payload:
        if b == FEND: out += bytes([FESC, TFEND])
        elif b == FESC: out += bytes([FESC, TFESC])
        else: out.append(b)
    out.append(FEND)
    return bytes(out)

def unescape(data):
    out = bytearray(); esc = False
    for b in data:
        if esc:
            out.append(FEND if b == TFEND else FESC if b == TFESC else b); esc = False
        elif b == FESC: esc = True
        else: out.append(b)
    return bytes(out)

HOST = sys.argv[1] if len(sys.argv) > 1 else '192.168.1.233'
FREQ = int(sys.argv[2]) if len(sys.argv) > 2 else 867500000
PORT = 7633
PASS = 0; FAIL = 0

def check(name, ok):
    global PASS, FAIL
    print(('PASS' if ok else 'FAIL') + f'  {name}', flush=True)
    if ok: PASS += 1
    else: FAIL += 1

def extract_frames(buf):
    """Split buf into complete KISS frames, returning (frames, remainder)."""
    out = []
    while FEND in buf[1:]:
        idx = buf.index(FEND, 1)
        f = bytes(buf[:idx+1]); del buf[:idx+1]
        inner = unescape(f[1:-1])
        if inner: out.append(inner)
    return out

# ---------- RNode side: configure, answer one air ping with one pong ----------
rnode_frames = []
rnode_ponged = threading.Event()
def rnode_side():
    h = serial.Serial('/dev/ttyUSB1', 115200, timeout=0.5)
    h.reset_input_buffer(); h.reset_output_buffer(); time.sleep(0.5); h.reset_input_buffer()
    for _ in range(3):
        h.write(frame(0x08, bytes([0x73]))); h.write(frame(0x50, b'\x00')); h.flush(); time.sleep(0.2)
    h.write(frame(0x01, FREQ.to_bytes(4, 'big'))); h.flush(); time.sleep(0.2)
    h.write(frame(0x02, (125000).to_bytes(4, 'big'))); h.flush(); time.sleep(0.2)
    h.write(frame(0x03, bytes([14]))); h.flush(); time.sleep(0.2)
    h.write(frame(0x04, bytes([9]))); h.flush(); time.sleep(0.2)
    h.write(frame(0x05, bytes([5]))); h.flush(); time.sleep(0.2)
    h.write(frame(0x06, bytes([0x01]))); h.flush(); time.sleep(0.5)
    h.reset_input_buffer()
    print('>>> RNode configured + radio ON, listening', flush=True)
    t0 = time.time(); buf = bytearray()
    while time.time() - t0 < 90:
        try: d = h.read(4096)
        except Exception: return
        if d:
            buf += d
            for inner in extract_frames(buf):
                if len(inner) >= 2 and inner[0] == 0x00:
                    rnode_frames.append(inner[1:])
                    print(f'*** RNode RX: {inner[1]!r}', flush=True)
                    if b'dual ping usb' in inner[1:] and not rnode_ponged.is_set():
                        rnode_ponged.set()
                        time.sleep(1.0)
                        h.write(frame(0x00, b'dual pong rnode')); h.flush()
                        print('>>> RNode TX: dual pong rnode', flush=True)
    h.close()

threading.Thread(target=rnode_side, daemon=True).start()
time.sleep(4)  # let the RNode come up

# ---------- USB side: hardware reset like a real host, probe readiness ----------
c = serial.Serial('/dev/ttyACM1', 115200, timeout=1.0)
c.dtr = False; c.rts = True; time.sleep(0.15); c.rts = False; c.dtr = True
t0 = time.time(); ready = False
while time.time() - t0 < 30 and not ready:
    c.write(frame(0x08, bytes([0x73]))); c.flush()
    d = c.read(4096)
    if b'\x08\x46' in d or b'\xc0\x08\x46' in d: ready = True
    else: time.sleep(0.5)
print(f'>>> C6L boot wait: {time.time()-t0:.1f}s (modem ready: {ready})', flush=True)
c.reset_input_buffer()

usb_frames = []
def usb_watch():
    buf = bytearray()
    while time.time() - t_main_start < 90:
        d = c.read(4096)
        if d:
            buf += d
            usb_frames.extend(extract_frames(buf))
t_main_start = time.time()
threading.Thread(target=usb_watch, daemon=True).start()

def tcp_collect(s, sink):
    buf = bytearray()
    s.settimeout(0.2)
    def watch():
        while True:
            try: d = s.recv(4096)
            except socket.timeout: continue
            except OSError: return
            if not d: return
            buf.extend(d)
            sink.extend(extract_frames(buf))
    t = threading.Thread(target=watch, daemon=True); t.start(); return t

def detect_burst(writer):
    for _ in range(2):
        writer(frame(0x08, bytes([0x73]))); writer(frame(0x50, b'\x00'))
        writer(frame(0x48, b'\x00')); writer(frame(0x49, b'\x00'))

def wait_for(sink, pred, sec):
    t0 = time.time()
    while time.time() - t0 < sec:
        if any(pred(f) for f in sink): return True
        time.sleep(0.2)
    return False

# ---------- radio config over USB (shared radio) ----------
c.write(frame(0x01, FREQ.to_bytes(4, 'big'))); c.flush(); time.sleep(0.3)
c.write(frame(0x02, (125000).to_bytes(4, 'big'))); c.flush(); time.sleep(0.3)
c.write(frame(0x03, bytes([14]))); c.flush(); time.sleep(0.3)
c.write(frame(0x04, bytes([9]))); c.flush(); time.sleep(0.3)
c.write(frame(0x05, bytes([5]))); c.flush(); time.sleep(0.3)
c.write(frame(0x06, bytes([0x01]))); c.flush()
time.sleep(1.0)

# 1-3. Two concurrent TCP sessions + USB all answer detect
a_frames, b_frames = [], []
sa = socket.create_connection((HOST, PORT), timeout=10)
sa.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
tcp_collect(sa, a_frames)
sb = socket.create_connection((HOST, PORT), timeout=10)
sb.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
tcp_collect(sb, b_frames)
detect_burst(lambda f: sa.sendall(f))
detect_burst(lambda f: sb.sendall(f))
detect_burst(lambda f: (c.write(f), c.flush()))
check('tcp A detect 0x46', wait_for(a_frames, lambda f: f[0] == 0x08 and f[1:] == b'\x46', 3))
check('tcp B detect 0x46', wait_for(b_frames, lambda f: f[0] == 0x08 and f[1:] == b'\x46', 3))
check('usb detect 0x46', wait_for(usb_frames, lambda f: f[0] == 0x08 and f[1:] == b'\x46', 3))

# 4. Third TCP client politely rejected (EOF), survivors unaffected
sc = socket.create_connection((HOST, PORT), timeout=10)
sc.settimeout(5)
try:
    d = sc.recv(4096)
    rejected = (d == b'')
except socket.timeout:
    rejected = False
sc.close()
check('3rd tcp client rejected with EOF', rejected)
a_frames.clear()
detect_burst(lambda f: sa.sendall(f))
check('tcp A alive after reject', wait_for(a_frames, lambda f: f[0] == 0x08 and f[1:] == b'\x46', 3))

# 5. Host fan-out, byte-exact, both directions + cross-TCP
c.write(frame(0x00, b'fanout usb->tcp')); c.flush()
check('usb data -> tcp A', wait_for(a_frames, lambda f: f == b'\x00fanout usb->tcp', 3))
check('usb data -> tcp B', wait_for(b_frames, lambda f: f == b'\x00fanout usb->tcp', 3))
sa.sendall(frame(0x00, b'fanout tcp->others'))
check('tcp A data -> usb', wait_for(usb_frames, lambda f: f == b'\x00fanout tcp->others', 3))
check('tcp A data -> tcp B (cross)', wait_for(b_frames, lambda f: f == b'\x00fanout tcp->others', 3))

# 6. Radio leg: USB ping over the air, RNode pong fans out to ALL links
c.write(frame(0x00, b'dual ping usb')); c.flush()
time.sleep(4)  # airtime + CSMA deferral under bench interference
check('rnode got usb air ping', any(b'dual ping usb' in f for f in rnode_frames))
check('radio fan-out -> usb', wait_for(usb_frames, lambda f: f == b'\x00dual pong rnode', 25))
check('radio fan-out -> tcp A', wait_for(a_frames, lambda f: f == b'\x00dual pong rnode', 5))
check('radio fan-out -> tcp B', wait_for(b_frames, lambda f: f == b'\x00dual pong rnode', 5))

sa.close(); sb.close(); c.close()
print(f'\n=== {PASS} passed, {FAIL} failed ===')
sys.exit(1 if FAIL else 0)
