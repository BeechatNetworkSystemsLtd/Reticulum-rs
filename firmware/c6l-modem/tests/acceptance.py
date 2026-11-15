#!/usr/bin/env python3
"""c6l-modem protocol acceptance suite.

Run against a flashed c6l-modem device over its USB Serial/JTAG console:
    python3 tests/acceptance.py [--port /dev/ttyACM1]

Mirrors the KISS wire protocol exactly as the Rust host-side
(`reticulum::iface::rnode`) and Python RNS speak it. 16 checks covering
detect, firmware gate, radio configuration with frequency quantization,
airtime locks, telemetry, flow control, leave and post-leave liveness.

Exit code 0 = all pass, 1 = any failure.
"""
import argparse, sys, time

try:
    import serial
except ImportError:
    print("pyserial required: pip3 install pyserial"); sys.exit(1)

FEND, FESC, TFEND, TFESC = 0xC0, 0xDB, 0xDC, 0xDD

def frame(cmd, payload=b""):
    out = bytearray([FEND, cmd])
    for b in payload:
        if b == FEND: out += bytes([FESC, TFEND])
        elif b == FESC: out += bytes([FESC, TFESC])
        else: out.append(b)
    out.append(FEND)
    return bytes(out)

def parse(stream):
    frames, cur, esc = [], None, False
    for b in stream:
        if b == FEND:
            if cur is not None: frames.append(cur)
            cur, esc = None, False
            continue
        if cur is None:
            cur = (b, bytearray()); continue
        cmd, buf = cur
        if esc:
            esc = False
            buf.append({TFEND: FEND, TFESC: FESC}.get(b, b))
        elif b == FESC: esc = True
        else: buf.append(b)
        cur = (cmd, buf)
    if cur is not None: frames.append(cur)
    return [(c, bytes(b)) for c, b in frames]

def recv(s, secs=2.0):
    buf, t0 = b"", time.time()
    while time.time() - t0 < secs: buf += s.read(4096)
    return buf

passed = failed = 0
def ok(name, cond):
    global passed, failed
    print(("PASS " if cond else "FAIL ") + name)
    if cond: passed += 1
    else: failed += 1

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyACM1")
    args = ap.parse_args()
    s = serial.Serial(args.port, 115200, timeout=0.3)
    # Reset-on-open (USB-Serial/JTAG hardware resets on DTR/RTS transitions)
    s.dtr = False; s.rts = True; time.sleep(0.15); s.rts = False; s.dtr = True
    time.sleep(2.5)  # boot + radio init (esp-hal 1.1 stack needs > 1s)

    # 1. detect burst
    s.reset_input_buffer()
    s.write(frame(0x08, [0x73]) + frame(0x50,[0]) + frame(0x48,[0]) + frame(0x49,[0])); s.flush()
    d = {}
    for c, p in parse(recv(s)): d.setdefault(c, p)
    ok("detect response",       d.get(0x08) == b'\x46')
    ok("firmware >= 1.52",      d.get(0x50, b'\x00\x00')[0] == 1 and d.get(0x50, b'')[1] >= 52)
    ok("platform reported",     0x48 in d)
    ok("mcu reported",          0x49 in d)

    # 2. radio config + echo validation (repo hardware-test channel)
    freq, bw, txp, sf, cr = 867_500_017, 125_000, 2, 9, 5
    s.reset_input_buffer()
    s.write(frame(0x01, freq.to_bytes(4,'big')) + frame(0x02, bw.to_bytes(4,'big'))
          + frame(0x03,[txp]) + frame(0x04,[sf]) + frame(0x05,[cr]) + frame(0x06,[1])); s.flush()
    e = {}
    for c, p in parse(recv(s)): e.setdefault(c, p)
    ok("frequency quantized echo", abs(int.from_bytes(e.get(0x01, b'\0'*4),'big') - 867_500_000) <= 32)
    ok("bandwidth echo",          int.from_bytes(e.get(0x02,b''),'big') == bw)
    ok("txpower echo",            e.get(0x03) == bytes([txp]))
    ok("sf echo",                 e.get(0x04) == bytes([sf]))
    ok("cr echo",                 e.get(0x05) == bytes([cr]))
    ok("radio state echo (on)",   e.get(0x06) == b'\x01')

    # 3. airtime lock set/query
    s.reset_input_buffer()
    s.write(frame(0x0B, (1000).to_bytes(2,'big'))); s.flush()
    e = {}
    for c,p in parse(recv(s,1.0)): e.setdefault(c,p)
    ok("st-alock echo", e.get(0x0B) == (1000).to_bytes(2,'big'))

    # 4. telemetry
    s.reset_input_buffer()
    s.write(frame(0x23) + frame(0x24)); s.flush()
    st = {}
    for c,p in parse(recv(s,1.0)): st.setdefault(c,p)
    ok("rssi telemetry reported",  0x23 in st)
    ok("snr telemetry reported",   0x24 in st)

    # 5. flow control: data frame => CMD_READY
    s.reset_input_buffer()
    s.write(frame(0x00, b"\x01\x02\x03")); s.flush()
    ok("flow control CMD_READY after data",
       any(c == 0x0F and p == b'\x01' for c, p in parse(recv(s, 4.0))))

    # 6. leave + liveness
    s.reset_input_buffer()
    s.write(frame(0x0A, [0xFF])); s.flush()
    ok("leave acknowledged", any(c == 0x0A for c, p in parse(recv(s,1.0))))
    time.sleep(0.5)
    s.reset_input_buffer()
    s.write(frame(0x08, [0x73])); s.flush()
    ok("device alive after leave",
       any(c == 0x08 and p == b'\x46' for c, p in parse(recv(s,1.5))))

    s.close()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
