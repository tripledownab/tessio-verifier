# What belongs here: the generator for ResponseKeyDerivationTests' vectors, written against Python's
# cryptography package so the C# derivation is checked against an implementation it shares no code with.
#
#   python3 -m pip install cryptography
#   python3 make-response-key-vectors.py
#
# Prints one line per vector: master, salt, d, x and y in hex, then the RFC 7638 thumbprint the
# library uses as the kid.
import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"tessio-verifier response-encryption-key v1"
# SP 800-56A Rev. 3 section 5.6.1.2.1 asks for len(n) + 64 bits, 320 for P-256; 48 bytes is 384.
OKM_LENGTH = 48
# The order of P-256, as the library holds it; its tests compare that with the platform's curve.
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

VECTORS = [
    (bytes(range(32)), bytes(range(0x80, 0x90))),
    (bytes(range(0x20, 0x60)), bytes(range(0xA0, 0xC0))),
    (b"\x00" * 32, b"\xff" * 16),
    # Chosen because its d begins with a zero byte, so the scalar must be written right-aligned.
    (bytes(range(32)), bytes(15) + b"\x51"),
]


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


for master, salt in VECTORS:
    okm = HKDF(algorithm=hashes.SHA256(), length=OKM_LENGTH, salt=salt, info=INFO).derive(master)
    d = int.from_bytes(okm, "big") % (N - 1) + 1
    public = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_numbers()
    x = public.x.to_bytes(32, "big")
    y = public.y.to_bytes(32, "big")
    jwk = '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (b64url(x), b64url(y))
    kid = b64url(hashlib.sha256(jwk.encode()).digest())
    print(master.hex(), salt.hex(), d.to_bytes(32, "big").hex(), x.hex(), y.hex(), kid)
