"""OAEP padding (RFC 8017 / PKCS#1 v2.2) with SHA-256 and MGF1.

Custom implementation. SHA-256 is taken from `hashlib` (Python stdlib).

Public functions:
- i2osp / os2ip : integer <-> octet string conversions
- mgf1          : Mask Generation Function based on SHA-256
- oaep_encode   : EME-OAEP encoding
- oaep_decode   : EME-OAEP decoding
"""

import hashlib
import secrets


HASH_LEN = 32  # SHA-256 output length in bytes


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def i2osp(x: int, length: int) -> bytes:
    """Integer-to-Octet-String primitive (big-endian, fixed length)."""
    if x < 0 or x >= (1 << (8 * length)):
        raise ValueError("integer too large for given length")
    return x.to_bytes(length, "big")


def os2ip(data: bytes) -> int:
    """Octet-String-to-Integer primitive (big-endian)."""
    return int.from_bytes(data, "big")


def mgf1(seed: bytes, mask_len: int) -> bytes:
    """MGF1 mask generation based on SHA-256."""
    if mask_len > (1 << 32) * HASH_LEN:
        raise ValueError("mask too long")
    out = bytearray()
    counter = 0
    while len(out) < mask_len:
        out.extend(_sha256(seed + i2osp(counter, 4)))
        counter += 1
    return bytes(out[:mask_len])


def oaep_encode(message: bytes, k: int, label: bytes = b"") -> bytes:
    """EME-OAEP encoding.

    `k` is the RSA modulus length in bytes (256 for 2048-bit RSA).
    Maximum message length is k - 2*HASH_LEN - 2 bytes.
    """
    m_len = len(message)
    max_len = k - 2 * HASH_LEN - 2
    if m_len > max_len:
        raise ValueError(f"message too long (max {max_len} bytes for k={k})")

    l_hash = _sha256(label)
    ps = b"\x00" * (k - m_len - 2 * HASH_LEN - 2)
    db = l_hash + ps + b"\x01" + message  # length k - HASH_LEN - 1
    seed = secrets.token_bytes(HASH_LEN)
    db_mask = mgf1(seed, k - HASH_LEN - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = mgf1(masked_db, HASH_LEN)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    em = b"\x00" + masked_seed + masked_db
    return em


def oaep_decode(em: bytes, k: int, label: bytes = b"") -> bytes:
    """EME-OAEP decoding. Raises ValueError on any decoding error."""
    if k < 2 * HASH_LEN + 2:
        raise ValueError("decryption error")
    if len(em) != k:
        raise ValueError("decryption error")

    l_hash = _sha256(label)
    y = em[0]
    masked_seed = em[1:1 + HASH_LEN]
    masked_db = em[1 + HASH_LEN:]
    seed_mask = mgf1(masked_db, HASH_LEN)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, k - HASH_LEN - 1)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    l_hash_prime = db[:HASH_LEN]
    # walk past the zero padding to the 0x01 separator
    i = HASH_LEN
    while i < len(db) and db[i] == 0:
        i += 1

    bad = (y != 0) or (l_hash_prime != l_hash) or (i >= len(db)) or (db[i] != 1)
    if bad:
        raise ValueError("decryption error")
    return db[i + 1:]
