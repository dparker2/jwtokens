import typing, functools, hmac, hashlib

from .. import utils


def _sign(digestmod, data: bytes, key: typing.Union[str, bytes]):
    if isinstance(key, str):
        key = utils.nopad_b64decode(key)
    return hmac.new(key, data, digestmod).digest()


sign256 = functools.partial(_sign, hashlib.sha256)
sign384 = functools.partial(_sign, hashlib.sha384)
sign512 = functools.partial(_sign, hashlib.sha512)


def verify():
    pass
