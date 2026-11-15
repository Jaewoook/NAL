#!/usr/bin/env python3
"""Generate a Linux-compatible SHA-512 ($6$) crypt hash from stdin.

macOS LibreSSL `openssl passwd` lacks `-6` and macOS libc `crypt()` silently
falls back to 56-bit DES, so this uses only Python's standard `hashlib`.
"""

import argparse
import hashlib
import secrets
import sys
from typing import Optional

_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

_BLOCK_ORDER = (
    (0, 21, 42), (22, 43, 1), (44, 2, 23),
    (3, 24, 45), (25, 46, 4), (47, 5, 26),
    (6, 27, 48), (28, 49, 7), (50, 8, 29),
    (9, 30, 51), (31, 52, 10), (53, 11, 32),
    (12, 33, 54), (34, 55, 13), (56, 14, 35),
    (15, 36, 57), (37, 58, 16), (59, 17, 38),
    (18, 39, 60), (40, 61, 19), (62, 20, 41),
)


def _to_b64(value: int, count: int) -> str:
    chars = []
    for _ in range(count):
        chars.append(_B64[value & 0x3F])
        value >>= 6
    return "".join(chars)


_DEFAULT_ROUNDS = 5000


def _validate_salt(salt: str) -> str:
    if not salt or any(ch not in _B64 for ch in salt):
        raise ValueError("Salt must be non-empty using only [./0-9A-Za-z].")
    return salt[:16]


def sha512_crypt(password: str, salt: Optional[str] = None, rounds: int = _DEFAULT_ROUNDS) -> str:
    """Return a `$6$salt$hash` string compatible with Linux glibc crypt(3)."""
    if not (1000 <= rounds <= 999999999):
        raise ValueError("Rounds must be between 1000 and 999999999.")
    if salt is None:
        salt = "".join(secrets.choice(_B64) for _ in range(16))
    else:
        salt = _validate_salt(salt)

    pw_b = password.encode("utf-8")
    salt_b = salt.encode("utf-8")
    pw_len = len(pw_b)

    b = hashlib.sha512(pw_b + salt_b + pw_b).digest()

    a_ctx = hashlib.sha512(pw_b + salt_b)
    a_ctx.update((b * (pw_len // 64 + 1))[:pw_len])
    cnt = pw_len
    while cnt > 0:
        a_ctx.update(b if (cnt & 1) else pw_b)
        cnt >>= 1
    a = a_ctx.digest()

    dp_ctx = hashlib.sha512()
    for _ in range(pw_len):
        dp_ctx.update(pw_b)
    dp = dp_ctx.digest()
    p = (dp * (pw_len // 64 + 1))[:pw_len]

    ds_ctx = hashlib.sha512()
    for _ in range(16 + a[0]):
        ds_ctx.update(salt_b)
    ds = ds_ctx.digest()
    s = (ds * (len(salt_b) // 64 + 1))[:len(salt_b)]

    c = a
    for r in range(rounds):
        ctx = hashlib.sha512()
        ctx.update(p if (r & 1) else c)
        if r % 3:
            ctx.update(s)
        if r % 7:
            ctx.update(p)
        ctx.update(c if (r & 1) else p)
        c = ctx.digest()

    encoded = [_to_b64((c[i0] << 16) | (c[i1] << 8) | c[i2], 4) for i0, i1, i2 in _BLOCK_ORDER]
    encoded.append(_to_b64(c[63], 2))
    prefix = f"$6$rounds={rounds}$" if rounds != _DEFAULT_ROUNDS else "$6$"
    return f"{prefix}{salt}${''.join(encoded)}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Hash a password from stdin as SHA-512 crypt ($6$).")
    parser.add_argument("--salt", default=None, help="Optional explicit salt from [./0-9A-Za-z] (max 16 chars used).")
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Do not strip a single trailing newline from stdin.",
    )
    args = parser.parse_args()

    password = sys.stdin.read()
    if not args.raw:
        if password.endswith("\r\n"):
            password = password[:-2]
        elif password.endswith("\n"):
            password = password[:-1]
    if not password:
        print("Error: empty password provided on stdin.", file=sys.stderr)
        return 1

    try:
        print(sha512_crypt(password, salt=args.salt))
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
