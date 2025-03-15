import typing, functools
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization


CURVE_PARAMS = {
    "secp256r1": {"hash_alg": hashes.SHA256, "signature_size": 32},
    "secp384r1": {"hash_alg": hashes.SHA384, "signature_size": 48},
    "secp521r1": {"hash_alg": hashes.SHA512, "signature_size": 66},
}


def _resolve_private_key(key: typing.Union[str, bytes]) -> ec.EllipticCurvePrivateKey:
    if isinstance(key, str):
        private_key = serialization.load_pem_private_key(
            key.encode("utf-8"), password=None
        )
    else:
        private_key = serialization.load_der_private_key(key, password=None)

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        # TODO exception?
        raise TypeError("The private key must be an EC private key")
    return private_key


def _sign(curve_name: str, data: bytes, key: typing.Union[str, bytes]) -> bytes:
    private_key = _resolve_private_key(key)

    if private_key.curve.name != curve_name:
        raise ValueError(f"The private key is not using the {curve_name} curve")

    curve_params = CURVE_PARAMS.get(curve_name)
    if not curve_params:
        raise ValueError(f"Unsupported curve: {curve_name}")

    r, s = decode_dss_signature(
        private_key.sign(
            data, ec.ECDSA(curve_params["hash_alg"](), deterministic_signing=True)
        )
    )

    # Return the concatenated r and s values
    return r.to_bytes(curve_params["signature_size"], "big") + s.to_bytes(
        curve_params["signature_size"], "big"
    )


sign256 = functools.partial(_sign, "secp256r1")
sign384 = functools.partial(_sign, "secp384r1")
sign512 = functools.partial(_sign, "secp521r1")
