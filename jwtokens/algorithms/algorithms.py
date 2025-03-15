import typing

from . import ecdsa, hmac
from . import encryption

SigningAlgorithm = typing.Literal["HS256", "HS384", "HS512", "ES256", "ES384", "ES512"]
Signer = typing.Callable[[bytes, typing.Union[str, bytes]], bytes]


signers: typing.Dict[SigningAlgorithm, Signer] = {
    "HS256": hmac.sign256,
    "HS384": hmac.sign384,
    "HS512": hmac.sign512,
    "ES256": ecdsa.sign256,
    "ES384": ecdsa.sign384,
    "ES512": ecdsa.sign512,
}


KeyEncryptAlgorithm = typing.Literal["RSA1_5"]


class KeyEncryptImpl(typing.Protocol):
    def __call__(self, kek: bytes) -> tuple[bytes, bytes, bytes, bytes]: ...


ContentEncryptAlgorithm = typing.Literal["A128CBC-HS256"]


class ContentEncryptImpl(typing.Protocol):
    def __call__(
        self, plaintext: bytes, cek: bytes, iv: bytes, aad: bytes
    ) -> tuple[bytes, bytes]: ...


class Encryptor:
    __key_encryptors: typing.Dict[KeyEncryptAlgorithm, KeyEncryptImpl]
    __content_encryptors: typing.Dict[ContentEncryptAlgorithm, ContentEncryptImpl]

    def __init__(self):
        self.__key_encryptors = {}
        self.__content_encryptors = {}

    def register_alg(self, alg: KeyEncryptAlgorithm, func: KeyEncryptImpl):
        self.__key_encryptors[alg] = func

    def register_enc(self, enc: ContentEncryptAlgorithm, func: ContentEncryptImpl):
        self.__content_encryptors[enc] = func

    def encrypt(
        self,
        alg: KeyEncryptAlgorithm,
        enc: ContentEncryptAlgorithm,
        plaintext: bytes,
        kek: bytes,
    ):
        cek_key, enc_cek_key, iv, aad = self.__key_encryptors[alg](kek)
        ciphertext, tag = self.__content_encryptors[enc](plaintext, cek_key, iv, aad)

        return {}, enc_cek_key, iv, ciphertext, tag


encryptor = Encryptor()
encryptor.register_alg("RSA1_5", encryption.RSA_v1_5)
