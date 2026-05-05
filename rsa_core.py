"""RSA core primitives — full custom implementation.

No crypto library. Uses only Python standard library:
- secrets : cryptographically secure RNG
- math.gcd : integer gcd

Implements:
- Miller-Rabin primality test
- Random prime generation
- Extended Euclidean algorithm and modular inverse
- 2048-bit keypair generation (e = 65537, Carmichael totient)
- RSA encryption/decryption primitives (RSAEP / RSADP)
"""

from math import gcd
import secrets


_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
    67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
]


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin probabilistic primality test."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # write n - 1 = d * 2^r with d odd
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # a in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def gen_prime(bits: int) -> int:
    """Generate a random probable prime of exactly `bits` bits."""
    if bits < 2:
        raise ValueError("bits must be >= 2")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _egcd(a: int, b: int) -> tuple:
    """Extended Euclidean algorithm. Returns (g, x, y) where a*x + b*y = g."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    """Modular inverse of a modulo m."""
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def gen_keypair(bits: int = 2048):
    """Generate an RSA keypair.

    Returns ((n, e), (n, d)).
    """
    if bits < 512 or bits % 2 != 0:
        raise ValueError("bits must be even and >= 512")
    e = 65537
    half = bits // 2
    while True:
        p = gen_prime(half)
        q = gen_prime(bits - half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        # Carmichael's totient lambda(n) = lcm(p-1, q-1)
        lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
        if gcd(e, lam) != 1:
            continue
        d = modinv(e, lam)
        return (n, e), (n, d)


def rsaep(n: int, e: int, m: int) -> int:
    """RSA encryption primitive: c = m^e mod n."""
    if not 0 <= m < n:
        raise ValueError("message representative out of range")
    return pow(m, e, n)


def rsadp(n: int, d: int, c: int) -> int:
    """RSA decryption primitive: m = c^d mod n."""
    if not 0 <= c < n:
        raise ValueError("ciphertext representative out of range")
    return pow(c, d, n)
