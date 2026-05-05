"""High-level RSA-OAEP-256 file encryption / decryption.

For 2048-bit RSA-OAEP with SHA-256:
  k          = 256 bytes (modulus length)
  max chunk  = k - 2*HASH_LEN - 2 = 190 bytes per plaintext block
  ciphertext = a sequence of 256-byte blocks

Files larger than 190 bytes are encrypted block-by-block; each block is
OAEP-encoded with a fresh random seed and then RSA-encrypted independently.

Key file format (text, hexadecimal):
  line 1: n (modulus) in hex
  line 2: e or d in hex
"""

import os

import oaep
import rsa_core


KEY_BITS = 2048
K = KEY_BITS // 8                       # 256 bytes
MAX_CHUNK = K - 2 * oaep.HASH_LEN - 2   # 190 bytes


# --------------------------- key file I/O ---------------------------

def save_public_key(path: str, pub) -> None:
    n, e = pub
    with open(path, "w", encoding="ascii") as f:
        f.write(f"{n:x}\n{e:x}\n")


def save_private_key(path: str, priv) -> None:
    n, d = priv
    with open(path, "w", encoding="ascii") as f:
        f.write(f"{n:x}\n{d:x}\n")


def load_key(path: str):
    """Load a key file. Returns (n, x) where x is e (public) or d (private)."""
    with open(path, "r", encoding="ascii") as f:
        lines = [ln.strip() for ln in f.readlines() if ln.strip()]
    if len(lines) < 2:
        raise ValueError("invalid key file: expected two hex lines")
    try:
        n = int(lines[0], 16)
        x = int(lines[1], 16)
    except ValueError:
        raise ValueError("invalid key file: lines must be hexadecimal")
    return n, x


# --------------------------- file encryption ---------------------------

def encrypt_file(in_path: str, out_path: str, pub, progress_cb=None) -> None:
    """Encrypt a file with RSA-OAEP-256 (chunked).

    `pub`         : (n, e)
    `progress_cb` : optional callable(done_blocks, total_blocks)
    """
    n, e = pub
    if (n.bit_length() + 7) // 8 != K:
        raise ValueError(f"key size is not {KEY_BITS}-bit")

    file_size = os.path.getsize(in_path)
    total = max(1, (file_size + MAX_CHUNK - 1) // MAX_CHUNK)
    if file_size == 0:
        total = 1  # one block encoding the empty message

    done = 0
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        if file_size == 0:
            em = oaep.oaep_encode(b"", K)
            m = oaep.os2ip(em)
            c = rsa_core.rsaep(n, e, m)
            fout.write(oaep.i2osp(c, K))
            done = 1
            if progress_cb:
                progress_cb(done, total)
            return

        while True:
            chunk = fin.read(MAX_CHUNK)
            if not chunk:
                break
            em = oaep.oaep_encode(chunk, K)
            m = oaep.os2ip(em)
            c = rsa_core.rsaep(n, e, m)
            fout.write(oaep.i2osp(c, K))
            done += 1
            if progress_cb:
                progress_cb(done, total)


# --------------------------- file decryption ---------------------------

def decrypt_file(in_path: str, out_path: str, priv, progress_cb=None) -> None:
    """Decrypt a file produced by `encrypt_file`."""
    n, d = priv
    if (n.bit_length() + 7) // 8 != K:
        raise ValueError(f"key size is not {KEY_BITS}-bit")

    file_size = os.path.getsize(in_path)
    if file_size == 0 or file_size % K != 0:
        raise ValueError(
            f"ciphertext length {file_size} is not a positive multiple of {K}"
        )

    total = file_size // K
    done = 0
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        while True:
            block = fin.read(K)
            if not block:
                break
            if len(block) != K:
                raise ValueError("truncated ciphertext block")
            c = oaep.os2ip(block)
            m = rsa_core.rsadp(n, d, c)
            em = oaep.i2osp(m, K)
            pt = oaep.oaep_decode(em, K)
            fout.write(pt)
            done += 1
            if progress_cb:
                progress_cb(done, total)
