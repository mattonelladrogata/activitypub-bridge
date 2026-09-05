"""
Keys — RSA keypair generation for ActivityPub actor identity.

Every ActivityPub actor that wants to be followed by Mastodon (or any
real Fediverse server) needs an RSA keypair: the public key goes in
the actor document, the private key signs every outgoing activity via
HTTP Signatures (see signatures.py). Without this, a real server will
simply refuse the delivery — this is not optional plumbing.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_keypair(key_size: int = 2048):
    """Returns (private_key_obj, public_pem_str, private_pem_str)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return private_key, public_pem, private_pem


def load_private_key(pem_str: str):
    return serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)
