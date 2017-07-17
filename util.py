import base64
import os

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class MalformedPublicKey(RuntimeError):
    pass


def random_base64(num_bytes):
    return base64.b64encode(os.urandom(num_bytes)).decode('ascii')


def load_public_key(public_key_pem):
    try:
        public_key = load_pem_public_key(public_key_pem, backend=default_backend())
    except (ValueError, UnsupportedAlgorithm) as e:
        raise MalformedPublicKey('Failed to load PEM public key') from e

    if not isinstance(public_key, RSAPublicKey):
        raise MalformedPublicKey('Expected RSA public key')

    if public_key.key_size != 2048:
        raise MalformedPublicKey('Expected 2048 bit modulus RSA public key')

    return public_key


def verify_challenge(public_key, challenge_str, signature_str):
    message = base64.b64decode(challenge_str)
    signature = bytes(bytearray.fromhex(signature_str))

    public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())


def verify_spkac(public_key, challenge_str, signature_str):
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    message = base64.b64decode(challenge_str)
    signature = bytes(bytearray.fromhex(signature_str))
    spkac = public_key_der + message

    public_key.verify(signature, spkac, padding.PKCS1v15(), hashes.SHA256())
