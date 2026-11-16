"""Block-cipher modes shared by every cipher variant.

Any class providing encrypt_block(int)->int and decrypt_block(int)->int (64-bit
blocks) gets CBC (PKCS#7), CTR, and encrypt-then-MAC seal()/open().
"""
from __future__ import annotations

import hashlib
import hmac
import os

from .bitops import bytes_to_int, int_to_bytes
from .p1_input_ip import BLOCK_BYTES, pkcs7_pad, pkcs7_unpad, to_blocks

MAC_BYTES = 32


class BlockModesMixin:
    # ---- CBC ----------------------------------------------------------------
    def encrypt_cbc(self, data: bytes, iv: bytes | None = None) -> bytes:
        iv = os.urandom(BLOCK_BYTES) if iv is None else iv
        if len(iv) != BLOCK_BYTES:
            raise ValueError("IV must be 8 bytes")
        prev, out = bytes_to_int(iv), [iv]
        for b in to_blocks(pkcs7_pad(data)):
            prev = self.encrypt_block(b ^ prev)
            out.append(int_to_bytes(prev, BLOCK_BYTES))
        return b"".join(out)

    def decrypt_cbc(self, blob: bytes) -> bytes:
        if len(blob) < 2 * BLOCK_BYTES or len(blob) % BLOCK_BYTES:
            raise ValueError("invalid ciphertext length")
        prev, out = bytes_to_int(blob[:BLOCK_BYTES]), []
        for c in to_blocks(blob[BLOCK_BYTES:]):
            out.append(int_to_bytes(self.decrypt_block(c) ^ prev, BLOCK_BYTES))
            prev = c
        try:
            return pkcs7_unpad(b"".join(out))
        except ValueError:
            raise ValueError("invalid padding (wrong key/seed or corrupted data)") from None

    # ---- CTR (no padding; arbitrary lengths) ---------------------------------
    def _ctr(self, data: bytes, nonce: bytes) -> bytes:
        ctr, out = bytes_to_int(nonce), bytearray()
        for i in range(0, len(data), BLOCK_BYTES):
            ks = int_to_bytes(self.encrypt_block(ctr), BLOCK_BYTES)
            out += bytes(a ^ b for a, b in zip(data[i:i + BLOCK_BYTES], ks))
            ctr = (ctr + 1) & ((1 << 64) - 1)
        return bytes(out)

    def encrypt_ctr(self, data: bytes, nonce: bytes | None = None) -> bytes:
        nonce = os.urandom(BLOCK_BYTES) if nonce is None else nonce
        if len(nonce) != BLOCK_BYTES:
            raise ValueError("nonce must be 8 bytes")
        return nonce + self._ctr(data, nonce)

    def decrypt_ctr(self, blob: bytes) -> bytes:
        if len(blob) < BLOCK_BYTES:
            raise ValueError("invalid ciphertext length")
        return self._ctr(blob[BLOCK_BYTES:], blob[:BLOCK_BYTES])

    # ---- unified API + authentication -----------------------------------------
    def encrypt(self, data: bytes, mode: str = "cbc", iv: bytes | None = None) -> bytes:
        if mode == "cbc":
            return self.encrypt_cbc(data, iv)
        if mode == "ctr":
            return self.encrypt_ctr(data, iv)
        raise ValueError("mode must be 'cbc' or 'ctr'")

    def decrypt(self, blob: bytes, mode: str = "cbc") -> bytes:
        if mode == "cbc":
            return self.decrypt_cbc(blob)
        if mode == "ctr":
            return self.decrypt_ctr(blob)
        raise ValueError("mode must be 'cbc' or 'ctr'")

    def seal(self, data: bytes, mac_key: bytes, mode: str = "cbc") -> bytes:
        """Encrypt-then-MAC (HMAC-SHA256 over IV||ciphertext). mac_key must be
        independent of the DES key and the LFSR seed."""
        blob = self.encrypt(data, mode)
        return blob + hmac.new(mac_key, mode.encode() + blob, hashlib.sha256).digest()

    def open(self, sealed: bytes, mac_key: bytes, mode: str = "cbc") -> bytes:
        if len(sealed) < MAC_BYTES:
            raise ValueError("message too short")
        blob, tag = sealed[:-MAC_BYTES], sealed[-MAC_BYTES:]
        good = hmac.new(mac_key, mode.encode() + blob, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, good):
            raise ValueError("authentication failed")
        return self.decrypt(blob, mode)
