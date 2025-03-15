import json
import base64
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def RSA_v1_5(kek: bytes):
    public_key = serialization.load_pem_public_key(kek)
    assert isinstance(public_key, rsa.RSAPublicKey)

    aes_key = os.urandom(32)  # AES-256 key
    iv = os.urandom(12)  # IV for AES-GCM
    aad = b"authenticated data"  # Additional authenticated data

    encrypted_key = public_key.encrypt(
        aes_key, padding.PKCS1v15()  # RSAES-PKCS1-v1_5 padding
    )

    return aes_key, encrypted_key, iv, aad
