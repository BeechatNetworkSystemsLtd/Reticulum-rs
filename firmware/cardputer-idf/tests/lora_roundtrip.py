#!/usr/bin/env python3
"""Proper RNode init sequence (mirrors RNS/our Rust iface):
detect burst -> config -> radio ON -> TX, with C6L RX monitoring.
RNode is on /dev/ttyUSB1. C6L on /dev/ttyACM2.
"""
import serial, time, threading, sys

FEND, FESC, TFESC, TFEND = 0xC0, 0xDB, 0xDC, 0xDD

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
            out.append(TFEND if b == 0xDC else TFESC if b == 0xDD else b); esc = False
        elif b == FESC: esc = True
        else: out.append(b)
    return bytes(out)

FREQ = int(sys.argv[1]) if len(sys.argv) > 1 else 867500000

def rnode_side():
    time.sleep(2)
    h = serial.Serial('/dev/ttyUSB1', 115200, timeout=0.5)
    h.reset_input_buffer(); h.reset_output_buffer()
    time.sleep(0.5); h.reset_input_buffer()

    # 1. Detect burst (like RNS: repeat a few times)
    for _ in range(3):
        h.write(frame(0x08, bytes([0x73]))); h.flush()   # CMD_DETECT DETECT_REQ
        h.write(frame(0x50, bytes([0x00]))); h.flush()   # CMD_FW_VERSION
        h.write(frame(0x47, bytes([0x00]))); h.flush()   # CMD_BOARD
        h.write(frame(0x48, bytes([0x00]))); h.flush()   # CMD_PLATFORM
        h.write(frame(0x49, bytes([0x00]))); h.flush()   # CMD_MCU
        time.sleep(0.3)
    d = h.read(4096)
    print(f'>>> Detect responses: {len(d)} bytes', flush=True)
    for f in d.split(b'\xc0'):
        if len(f) >= 2:
            print(f'    cmd=0x{f[0]:02x} data={f[1:20].hex()}', flush=True)

    # 2. Configure radio
    h.write(frame(0x01, FREQ.to_bytes(4, 'big'))); h.flush(); time.sleep(0.2)
    h.write(frame(0x02, (125000).to_bytes(4, 'big'))); h.flush(); time.sleep(0.2)
    h.write(frame(0x03, bytes([14]))); h.flush(); time.sleep(0.2)   # 14 dBm
    h.write(frame(0x04, bytes([9]))); h.flush(); time.sleep(0.2)    # SF9
    h.write(frame(0x05, bytes([5]))); h.flush(); time.sleep(0.2)    # CR 4/5

    # 3. RADIO ON
    h.write(frame(0x06, bytes([0x01]))); h.flush(); time.sleep(0.5)
    d = h.read(4096)
    print(f'>>> Config echo: {d.hex()[:120] if d else "none"}', flush=True)

    # Verify state
    h.write(frame(0x06, bytes([0xFF]))); h.flush(); time.sleep(0.3)
    h.write(frame(0x01, bytes([0xFF]))); h.flush(); time.sleep(0.3)
    d = h.read(4096)
    for f in d.split(b'\xc0'):
        if len(f) >= 2:
            if f[0] == 0x06: print(f'>>> RadioState: 0x{f[1]:02x}', flush=True)
            if f[0] == 0x01 and len(f) >= 5:
                print(f'>>> Frequency: {int.from_bytes(f[1:5], "big")}', flush=True)
    h.reset_input_buffer()

    # 4. Monitor RX while TXing
    def monitor():
        t_start = time.time(); buf = bytearray()
        while time.time() - t_start < 50:
            try: d = h.read(4096)
            except Exception: return
            if d:
                buf += d
                while FEND in buf[1:]:
                    idx = buf.index(FEND, 1)
                    f = bytes(buf[:idx+1]); del buf[:idx+1]
                    inner = unescape(f[1:-1])
                    if len(inner) >= 2 and inner[0] == 0x00:
                        print(f'*** RNODE RX: {inner[1]!r} at {time.time()-t_start:.1f}s', flush=True)
    tm = threading.Thread(target=monitor, daemon=True); tm.start()

    time.sleep(6)
    for i in range(5):
        h.write(frame(0x00, b'hello')); h.flush()
        print(f'>>> RNode TX {i}', flush=True)
        time.sleep(5)
    time.sleep(2)
    h.close()

t = threading.Thread(target=rnode_side); t.start()

s = serial.Serial('/dev/ttyACM2', 115200, timeout=0.5)
s.dtr=False; s.rts=True; time.sleep(0.1); s.rts=False; s.dtr=True
t0=time.time()
while time.time()-t0<46:
    d = s.read(4096)
    if d:
        for line in d.decode(errors='replace').splitlines():
            l = line.strip()
            if not l: continue
            if 'TELEM' in l:
                try:
                    n = int(l.split('#')[1].split(':')[0])
                    if n % 20 == 0: print(f'C6L [{time.time()-t0:5.1f}] {l[:75]}', flush=True)
                except: pass
            elif 'rst:' in l or 'I (' in l or 'heap' in l or 'boot' in l or 'Build' in l or 'ESP-ROM' in l:
                pass
            else:
                print(f'C6L [{time.time()-t0:5.1f}] {l[:110]}', flush=True)
s.close(); t.join()
