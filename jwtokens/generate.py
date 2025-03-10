import typing, json, time, base64

from . import algorithms
from . import utils


def message(
    claims: typing.Mapping[typing.Any, typing.Any] = {},
    /,
    *,
    issued_timestamp: bool = False,
    expire_secs: typing.Optional[typing.Union[int, float]] = None,
    not_before_secs: typing.Optional[typing.Union[int, float]] = None,
    issuer: typing.Optional[typing.Union[str, bytes]] = None,
    subject: typing.Optional[typing.Union[str, bytes]] = None,
    audience: typing.Optional[typing.Union[str, bytes]] = None,
    jwt_id: typing.Optional[typing.Union[str, bytes]] = None,
):
    now = time.time()
    claimsset = dict(**claims)
    if issued_timestamp:
        claimsset["iat"] = now
    if expire_secs is not None:
        claimsset["exp"] = now + expire_secs
    if not_before_secs is not None:
        claimsset["nbf"] = now + not_before_secs
    if issuer is not None:
        claimsset["iss"] = (
            issuer.decode("utf-8") if isinstance(issuer, bytes) else issuer
        )
    if subject is not None:
        claimsset["sub"] = (
            subject.decode("utf-8") if isinstance(subject, bytes) else subject
        )
    if audience is not None:
        claimsset["aud"] = (
            audience.decode("utf-8") if isinstance(audience, bytes) else audience
        )
    if jwt_id is not None:
        claimsset["jti"] = (
            jwt_id.decode("utf-8") if isinstance(jwt_id, bytes) else jwt_id
        )

    return utils.nopad_b64encode(
        json.dumps(claimsset, separators=(",", ":")).encode("utf-8")
    )


def sign(
    payload: typing.Union[str, bytes],
    algorithm: algorithms.SigningAlgorithm,
    key: typing.Union[str, bytes],
    *,
    add_headers: typing.Mapping[typing.Any, typing.Any] = {},
):
    if isinstance(payload, str):
        payload = utils.nopad_b64decode(payload)

    header = {"alg": algorithm, **add_headers}
    b64header = utils.nopad_b64encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    b64payload = utils.nopad_b64encode(payload)

    sign_input = b64header + "." + b64payload

    signature = utils.nopad_b64encode(
        algorithms.signers[algorithm](sign_input.encode("utf-8"), key)
    )

    return sign_input + "." + signature
