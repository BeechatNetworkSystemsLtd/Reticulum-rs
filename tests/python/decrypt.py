#!/usr/bin/env python3
import sys
import RNS

# argv:
# 1: recipient_priv_hex (64 bytes: X25519 priv (32) || Ed25519 priv (32))
# 2: ciphertext_hex
#
# Output: plaintext_hex

recipient_priv = bytes.fromhex(sys.argv[1])
ciphertext = bytes.fromhex(sys.argv[2])
ident = RNS.Identity.from_bytes(recipient_priv)
pt = ident.decrypt(ciphertext)
if pt is None:
    sys.exit(2)

sys.stdout.write(pt.hex())
