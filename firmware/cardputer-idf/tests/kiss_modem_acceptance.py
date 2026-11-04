#!/usr/bin/env python3
"""Validate the C6L as an RNode-class KISS modem end-to-end:
  host <-> C6L (KISS over USB) <-> LoRa <-> RNode (ttyUSB1)
"""
import serial, time, threading, sys

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

FREQ = int(sys.argv[1]) if len(sys.argv) > 1 else 867500000
PASS = 0; FAIL = 0

def check(name, ok):
    global PASS, FAIL
    print(('PASS' if ok else 'FAIL') + f'  {name}', flush=True)
    if ok: PASS += 1
    else: FAIL += 1

# ---------- RNode side (receiver first) ----------
rnode_frames = []
def rnode_side():
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
    while time.time() - t0 < 60:
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
    h.close()

t_rnode = threading.Thread(target=rnode_side, daemon=True)
t_rnode.start()
time.sleep(4)  # let the RNode come up

# ---------- C6L side (KISS host client) ----------
c = serial.Serial('/dev/ttyACM1', 115200, timeout=1.0)
# Hardware reset like a real host (DTR/RTS toggle)
c.dtr = False; c.rts = True; time.sleep(0.15); c.rts = False; c.dtr = True
# Boot-settle: wifi::start() blocks the modem up to ~15s for DHCP, so a
# fixed 2.5s settle lands inside that window — early detect writes then
# outlive the reply timeouts (and used to stall in the USB-JTAG FIFO
# entirely). Don't wait on a console line — 'radio up' is empirically
# unreliable (eaten by the USB-JTAG TX path). Probe readiness instead:
# detect bursts until the modem actually answers.
t0 = time.time(); ready = False
while time.time() - t0 < 30 and not ready:
    c.write(frame(0x08, bytes([0x73]))); c.flush()
    d = c.read(4096)
    if b'\x08\x46' in d or b'\xc0\x08\x46' in d: ready = True
    else: time.sleep(0.5)
print(f'>>> C6L boot wait: {time.time()-t0:.1f}s (modem ready: {ready})', flush=True)
c.reset_input_buffer()

def read_frames(sec):
    """Collect KISS frames for N seconds."""
    got = []
    buf = bytearray()
    t0 = time.time()
    while time.time() - t0 < sec:
        d = c.read(4096)
        if d:
            buf += d
            while FEND in buf[1:]:
                idx = buf.index(FEND, 1)
                f = bytes(buf[:idx+1]); del buf[:idx+1]
                inner = unescape(f[1:-1])
                if inner: got.append(inner)
    return got

# 1. Detect burst
for _ in range(2):
    c.write(frame(0x08, bytes([0x73]))); c.write(frame(0x50, b'\x00'))
    c.write(frame(0x48, b'\x00')); c.write(frame(0x49, b'\x00')); c.flush()
frames = read_frames(1.5)
cmds = {f[0]: f[1:] for f in frames if len(f) >= 1}
check(f'detect resp 0x46: {cmds.get(0x08, b"").hex()}', cmds.get(0x08) == b'\x46')
check(f'fw version {cmds.get(0x50, b"").hex()}', len(cmds.get(0x50, b'')) >= 2)
check(f'platform {cmds.get(0x48, b"").hex()} mcu {cmds.get(0x49, b"").hex()}',
      0x48 in cmds and 0x49 in cmds)

# 2. Radio config
c.write(frame(0x01, FREQ.to_bytes(4, 'big'))); c.flush(); time.sleep(0.3)
c.write(frame(0x02, (125000).to_bytes(4, 'big'))); c.flush(); time.sleep(0.3)
c.write(frame(0x03, bytes([14]))); c.flush(); time.sleep(0.3)
c.write(frame(0x04, bytes([9]))); c.flush(); time.sleep(0.3)
c.write(frame(0x05, bytes([5]))); c.flush(); time.sleep(0.3)
c.write(frame(0x06, bytes([0x01]))); c.flush()
frames = read_frames(4.0)
cmds2 = {f[0]: f[1:] for f in frames}
check(f'freq echo {cmds2.get(0x01, b"").hex()}', int.from_bytes(cmds2.get(0x01, b'\x00\x00\x00\x00'), 'big') == FREQ)
check(f'bw echo {cmds2.get(0x02, b"").hex()}', int.from_bytes(cmds2.get(0x02, b'\x00\x00\x00\x00'), 'big') == 125000)
check(f'sf echo {cmds2.get(0x04, b"").hex()}', cmds2.get(0x04) == b'\x09')
check(f'radio state echo {cmds2.get(0x06, b"").hex()}', cmds2.get(0x06) == b'\x01')

# 3. Transmit through the air: C6L -> RNode
c.write(frame(0x00, b'ping from c6l'))
frames = read_frames(2)
check('CMD_READY flow control', any(f[0] == 0x0F for f in frames))
time.sleep(3)  # airtime + RNode processing
check(f'over-the-air: RNode got {rnode_frames!r}', any(b'ping from c6l' in f for f in rnode_frames))

# 4. Receive through the air: RNode TX -> C6L reports to host
got_air = []
def air_watch():
    import serial as ser
    t0 = time.time()
    while time.time() - t0 < 25:
        d = c.read(4096)
        if d:
            buf = bytearray(d)
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

c.close()
print(f'\n=== {PASS} passed, {FAIL} failed ===')
sys.exit(1 if FAIL else 0)
