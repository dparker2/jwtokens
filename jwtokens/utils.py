import base64

def nopad_b64decode(data: str):
    missing_padding = len(data) % 4
    if missing_padding:
        data += "=" * (4 - missing_padding)

    return base64.b64decode(data)


def nopad_b64encode(data: bytes):
    return base64.urlsafe_b64encode(data).strip(b"=").decode("ascii")