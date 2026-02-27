#!/usr/bin/env python3
import sys
import RNS

# argv:
# 1: recipient_pub_hex (64 bytes: X25519 pub (32) || Ed25519 pub (32))
# 2: plaintext_hex
#
# Output: ciphertext_token_hex
# ciphertext_token = eph_pub(32) || token(iv||cbc||hmac)

recipient_pub = bytes.fromhex(sys.argv[1])
plaintext = bytes.fromhex(sys.argv[2])
ident = RNS.Identity(create_keys=False)
ident.load_public_key(recipient_pub)

cipher = ident.encrypt(plaintext)
sys.stdout.write(cipher.hex())
