#!/usr/bin/env python3
"""Validate the C6L WiFi-TCP bridge end-to-end: same acceptance flow as
kiss_modem_acceptance.py, but the C6L is reached over TCP instead of USB:
  host <-> TCP:7633 <-> C6L (KISS over WiFi) <-> LoRa <-> RNode (ttyUSB1)

Usage: python3 tests/tcp_kiss_acceptance.py <c6l_ip> [freq_hz]

The RNode side stays on /dev/ttyUSB1 exactly like the USB test (it
configures the Heltec and answers the over-the-air leg); only the C6L
transport changes. USB KISS may run in parallel — the bridge keeps both.
"""
import socket, time, threading, sys

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

if len(sys.argv) < 2:
    print(__doc__); sys.exit(2)
HOST = sys.argv[1]
FREQ = int(sys.argv[2]) if len(sys.argv) > 2 else 867500000
# C6L TCP bridge port. 7633 = the port RNS's RNodeInterface hardcodes
# (TCPConnection.TARGET_PORT; it cannot parse a :port suffix), so the
# bridge listens there for stock-rnsd compatibility.
PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 7633
PASS = 0; FAIL = 0

# >254 B payloads force the RNode split-packet format on the air:
# two LoRa packets sharing a sequence nibble + split flag. Payload
# bytes cover 0xC0/0xDB too, exercising KISS escaping at that size.
BIG_PING = b'bigping-' + bytes(i & 0xFF for i in range(292))  # 300 B
BIG_PONG = b'bigpong-' + bytes(i & 0xFF for i in range(292))  # 300 B

def check(name, ok):
    global PASS, FAIL
    print(('PASS' if ok else 'FAIL') + f'  {name}', flush=True)
    if ok: PASS += 1
    else: FAIL += 1

# ---------- RNode side (receiver first) — identical to kiss_modem_acceptance.py ----------
rnode_frames = []
def rnode_side():
    import serial
    global rnode_frames
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
    while time.time() - t0 < 75:
        try: d = h.read(4096)
        except Exception: return
        if d:
            buf += d
            while FEND in buf[1:]:
                idx = buf.index(FEND, 1)
                f = bytes(buf[:idx+1]); del buf[:idx+1]
                inner = unescape(f[1:-1])
                if len(inner) >= 2 and inner[0] == 0x00:
                    rnode_frames.append(inner[1:])
                    print(f'*** RNode RX: {inner[1]!r}', flush=True)
                    if b'ping from c6l' in inner[1:] and not rnode_frames.count(b'<ponged>'):
                        rnode_frames.append(b'<ponged>')
                        time.sleep(1.0)
                        h.write(frame(0x00, b'pong from rnode')); h.flush()
                        print('>>> RNode TX: pong from rnode', flush=True)
                        # RNode CSMA defers ~1-2s under the rfsight 868MHz
                        # interference; follow up with spaced probes.
                        for extra in range(3):
                            time.sleep(4)
                            h.write(frame(0x00, b'pong-alt-%d' % extra)); h.flush()
                            print(f'>>> RNode TX: pong-alt-{extra}', flush=True)
                    if b'bigping-' in inner[1:] and not rnode_frames.count(b'<bigponged>'):
                        rnode_frames.append(b'<bigponged>')
                        time.sleep(1.0)
                        h.write(frame(0x00, BIG_PONG)); h.flush()
                        print('>>> RNode TX: big pong (300B split)', flush=True)
    h.close()

t_rnode = threading.Thread(target=rnode_side, daemon=True)
t_rnode.start()
time.sleep(4)  # let the RNode come up

# ---------- C6L side (KISS host client over TCP) ----------
s = socket.create_connection((HOST, PORT), timeout=10)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # KISS is tiny frames
print(f'>>> connected to {HOST}:{PORT}', flush=True)
# No DTR/RTS hardware reset over TCP: each connection is a fresh modem
# session (fresh parser state), so only drain any stale bytes.
s.settimeout(0.2)
try: s.recv(4096)
except socket.timeout: pass

def send(data):
    s.sendall(data)  # sendall already blocks until written (the "flush")

def read_frames(sec):
    """Collect KISS frames for N seconds."""
    got = []
    buf = bytearray()
    t0 = time.time()
    s.settimeout(0.1)
    while time.time() - t0 < sec:
        try: d = s.recv(4096)
        except socket.timeout: continue
        except OSError: break
        if not d:  # EOF: bridge closed the session
            print('! connection closed by C6L', flush=True)
            break
        buf += d
        # TCP may split a frame across recvs — keep a persistent buffer
        while FEND in buf[1:]:
            idx = buf.index(FEND, 1)
            f = bytes(buf[:idx+1]); del buf[:idx+1]
            inner = unescape(f[1:-1])
            if inner: got.append(inner)
    return got

# 1. Detect burst
for _ in range(2):
    send(frame(0x08, bytes([0x73]))); send(frame(0x50, b'\x00'))
    send(frame(0x48, b'\x00')); send(frame(0x49, b'\x00'))
frames = read_frames(1.5)
cmds = {f[0]: f[1:] for f in frames if len(f) >= 1}
check(f'detect resp 0x46: {cmds.get(0x08, b"").hex()}', cmds.get(0x08) == b'\x46')
check(f'fw version {cmds.get(0x50, b"").hex()}', len(cmds.get(0x50, b'')) >= 2)
check(f'platform {cmds.get(0x48, b"").hex()} mcu {cmds.get(0x49, b"").hex()}',
      0x48 in cmds and 0x49 in cmds)

# 2. Radio config
send(frame(0x01, FREQ.to_bytes(4, 'big'))); time.sleep(0.3)
send(frame(0x02, (125000).to_bytes(4, 'big'))); time.sleep(0.3)
send(frame(0x03, bytes([14]))); time.sleep(0.3)
send(frame(0x04, bytes([9]))); time.sleep(0.3)
send(frame(0x05, bytes([5]))); time.sleep(0.3)
send(frame(0x06, bytes([0x01])))
frames = read_frames(4.0)
cmds2 = {f[0]: f[1:] for f in frames}
check(f'freq echo {cmds2.get(0x01, b"").hex()}', int.from_bytes(cmds2.get(0x01, b'\x00\x00\x00\x00'), 'big') == FREQ)
check(f'bw echo {cmds2.get(0x02, b"").hex()}', int.from_bytes(cmds2.get(0x02, b'\x00\x00\x00\x00'), 'big') == 125000)
check(f'sf echo {cmds2.get(0x04, b"").hex()}', cmds2.get(0x04) == b'\x09')
check(f'radio state echo {cmds2.get(0x06, b"").hex()}', cmds2.get(0x06) == b'\x01')

# 3. Transmit through the air: C6L -> RNode
send(frame(0x00, b'ping from c6l'))
frames = read_frames(2)
check('CMD_READY flow control', any(f[0] == 0x0F for f in frames))
time.sleep(3)  # airtime + RNode processing
check(f'over-the-air: RNode got {rnode_frames!r}', any(b'ping from c6l' in f for f in rnode_frames))

# 4. Receive through the air: RNode TX -> C6L reports to the TCP client
got_air = []
def air_watch():
    t0 = time.time(); buf = bytearray()
    s.settimeout(0.5)
    while time.time() - t0 < 25:
        try: d = s.recv(4096)
        except socket.timeout: continue
        except OSError: return
        if not d: return
        buf += d
        while FEND in buf[1:]:
            idx = buf.index(FEND, 1)
            f = bytes(buf[:idx+1]); del buf[:idx+1]
            inner = unescape(f[1:-1])
            if len(inner) >= 2 and inner[0] == 0x00:
                got_air.append(inner[1:])
tw = threading.Thread(target=air_watch, daemon=True); tw.start()
time.sleep(1)
print('>>> waiting for RNode auto-pong...', flush=True)
tw.join()
check(f'C6L RX over the air: {got_air!r}',
      any(b'pong from rnode' in g or b'pong-alt-' in g for g in got_air))

# 5. Split TX: C6L -> air -> RNode. 300 B forces the C6L to emit two
#    LoRa packets (header seq + split flag); the RNode firmware
#    reassembles them and must hand back the EXACT payload.
send(frame(0x00, BIG_PING))
read_frames(2)
time.sleep(8)  # two ~1.3 s airtime chunks + RNode reassembly
check(f'split tx: RNode reassembled 300B byte-exact',
      any(f == BIG_PING for f in rnode_frames))

# 6. Split RX: RNode splits the 300 B pong -> C6L must buffer chunk 1
#    and fan the reassembled frame out over TCP (previously each chunk
#    escaped as its own KISS frame and a 255 B chunk was truncated
#    at 240 B — both fixed in poll_rx).
got_big = []
t0 = time.time(); buf = bytearray()
s.settimeout(0.5)
while time.time() - t0 < 25:
    try: d = s.recv(4096)
    except socket.timeout: continue
    except OSError: break
    if not d: break
    buf += d
    while FEND in buf[1:]:
        idx = buf.index(FEND, 1)
        f = bytes(buf[:idx+1]); del buf[:idx+1]
        inner = unescape(f[1:-1])
        if len(inner) >= 2 and inner[0] == 0x00:
            got_big.append(inner[1:])
            if inner[1:] == BIG_PONG: break
    if BIG_PONG in got_big: break
check(f'split rx: C6L reassembled 300B byte-exact',
      any(f == BIG_PONG for f in got_big))

s.close()
print(f'\n=== {PASS} passed, {FAIL} failed ===')
sys.exit(1 if FAIL else 0)
