"""End-to-end roundtrip tests: encrypt -> decrypt -> compare bytes.

Run from project root:
    python tests/test_roundtrip.py

Optional: drop sample files into `tests/samples/` (text, image, audio,
video, executable) and they will all be tested.
"""

import os
import sys
import tempfile
import time

# allow running directly: add project root to import path
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from rsa_core import gen_keypair  # noqa: E402
from rsa_oaep import (  # noqa: E402
    decrypt_file,
    encrypt_file,
    load_key,
    save_private_key,
    save_public_key,
)


def _roundtrip(data: bytes, pub, priv, label: str) -> bool:
    with tempfile.TemporaryDirectory() as td:
        in_path = os.path.join(td, "in.bin")
        ct_path = os.path.join(td, "ct.bin")
        out_path = os.path.join(td, "out.bin")
        with open(in_path, "wb") as f:
            f.write(data)
        t0 = time.perf_counter()
        encrypt_file(in_path, ct_path, pub)
        t1 = time.perf_counter()
        decrypt_file(ct_path, out_path, priv)
        t2 = time.perf_counter()
        with open(out_path, "rb") as f:
            result = f.read()
    ok = result == data
    flag = "PASS" if ok else "FAIL"
    print(
        f"  [{flag}] {label:35s} "
        f"size={len(data):>10d} B   "
        f"enc={t1 - t0:6.2f}s  dec={t2 - t1:6.2f}s"
    )
    return ok


def main():
    print("Generating 2048-bit RSA keypair (Miller-Rabin, full custom)...")
    t0 = time.perf_counter()
    pub, priv = gen_keypair(2048)
    print(f"  keygen took {time.perf_counter() - t0:.2f}s, n bits = {pub[0].bit_length()}")

    # also exercise key file save/load
    with tempfile.TemporaryDirectory() as td:
        pp = os.path.join(td, "pub.key")
        sp = os.path.join(td, "priv.key")
        save_public_key(pp, pub)
        save_private_key(sp, priv)
        pub_loaded = load_key(pp)
        priv_loaded = load_key(sp)
        assert pub_loaded == pub, "public key roundtrip failed"
        assert priv_loaded == priv, "private key roundtrip failed"
    print("  key file save/load: OK")

    print()
    print("Roundtrip tests:")
    cases = [
        ("empty",                     b""),
        ("1 byte",                    b"A"),
        ("190 bytes (1 chunk full)",  b"X" * 190),
        ("191 bytes (cross-chunk)",   b"Y" * 191),
        ("380 bytes (exactly 2)",     b"Z" * 380),
        ("text utf-8",                "Halo dunia, RSA-OAEP-256!\n".encode() * 10),
        ("random binary 4 KB",        os.urandom(4096)),
        ("random binary 64 KB",       os.urandom(64 * 1024)),
    ]
    all_ok = True
    for label, data in cases:
        if not _roundtrip(data, pub, priv, label):
            all_ok = False

    # also process any files dropped into tests/samples/
    samples_dir = os.path.join(os.path.dirname(__file__), "samples")
    if os.path.isdir(samples_dir):
        files = sorted(
            f for f in os.listdir(samples_dir)
            if os.path.isfile(os.path.join(samples_dir, f))
        )
        if files:
            print()
            print(f"Sample files from {samples_dir}:")
            for fn in files:
                with open(os.path.join(samples_dir, fn), "rb") as f:
                    data = f.read()
                if not _roundtrip(data, pub, priv, f"sample/{fn}"):
                    all_ok = False

    print()
    print("ALL PASS" if all_ok else "SOME TESTS FAILED")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
