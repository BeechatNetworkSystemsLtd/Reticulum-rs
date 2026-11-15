#!/usr/bin/env python3
"""c6l-modem multi-session stability test.

Opens/closes the USB serial port repeatedly (each close triggers the
USB-Serial/JTAG hardware reset), verifies the device recovers and
answers the detect burst every time.

    python3 tests/stability.py [--port /dev/ttyACM1] [--cycles 5]
"""
import argparse, sys, time
import serial

FEND = 0xC0

def probe(s):
    s.reset_input_buffer()
    s.write(bytes([FEND, 0x08, 0x73, FEND])); s.flush()
    t0 = time.time(); buf = b""
    while time.time() - t0 < 2.0: buf += s.read(512)
    return buf.count(FEND) >= 2

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyACM1")
    ap.add_argument("--cycles", type=int, default=5)
    args = ap.parse_args()
    passed = failed = 0
    for i in range(args.cycles):
        s = serial.Serial(args.port, 115200, timeout=0.3)
        s.dtr = False; s.rts = True; time.sleep(0.15); s.rts = False; s.dtr = True
        time.sleep(2.5)
        ok = probe(s)
        print(f"cycle {i+1}/{args.cycles}: {'OK' if ok else 'FAIL'}")
        if ok: passed += 1
        else: failed += 1
        s.close(); time.sleep(0.5)
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    main()
