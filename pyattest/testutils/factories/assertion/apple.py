import struct
from hashlib import sha256

from cbor2 import dumps as cbor_encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def get(
    app_id: str,
    client_data_hash: bytes,
    counter: int = 1,
    private_key: ec.EllipticCurvePrivateKey = None,
):
    """
    Helper to create a fake apple assertion, signed the way the attested key in the Secure Enclave signs one:
    ECDSA P-256 with SHA-256 over nonce = SHA-256(authenticatorData || clientDataHash).
    """
    if private_key is None:
        private_key = ec.generate_private_key(ec.SECP256R1())

    authenticator_data = (
        sha256(app_id.encode()).digest()
        + b"\x00"  # Flag, we'll fill it with zero
        + struct.pack("!I", counter)
    )
    nonce = sha256(authenticator_data + client_data_hash).digest()
    signature = private_key.sign(nonce, ec.ECDSA(hashes.SHA256()))

    data = {"signature": signature, "authenticatorData": authenticator_data}

    return cbor_encode(data), private_key.public_key()
