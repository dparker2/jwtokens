import typing

from . import HMAC_SHA, ECDSA_SHA

SigningAlgorithm = typing.Literal["HS256", "HS384", "HS512", "ES256", "ES384", "ES512"]
Signer = typing.Callable[[bytes, typing.Union[str, bytes]], bytes]

signers: typing.Dict[SigningAlgorithm, Signer] = {
    "HS256": HMAC_SHA.sign256,
    "HS384": HMAC_SHA.sign384,
    "HS512": HMAC_SHA.sign512,
    "ES256": ECDSA_SHA.sign256,
    "ES384": ECDSA_SHA.sign384,
    "ES512": ECDSA_SHA.sign512,
}


# class Signers(typing.TypedDict):
#     HS256: typing.Callable[[bytes, bytes], bytes]
#     HS384: typing.Callable[[bytes, bytes], bytes]
#     HS512: typing.Callable[[bytes, bytes], bytes]
#     ES256: typing.Callable[[bytes, ec.EllipticCurvePrivateKey], bytes]


# signers: Signers = {
#     "HS256": HMAC_SHA.sign256,
#     "HS384": HMAC_SHA.sign384,
#     "HS512": HMAC_SHA.sign512,
#     "ES256": ECDSA_SHA.sign256,
# }
