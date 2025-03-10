import pytest
from jwtokens import sign, message


@pytest.mark.parametrize(
    "algorithm,key,expected_signature_1,expected_signature_2",
    [
        (
            "HS256",
            "9CcYuA7RhsQpQH68ePYJqVSnV2yAhMjOQ4V0AuENwew=",
            "Rk6OQo2xrRJp1M2argLUYdatUKMaRpGZ6PjjLyjd0cU",
            "gKAdgDy0D2u8V8RR3pfdajBQtsHZ6Fnib7cbRka1lvI",
        ),
        (
            "HS384",
            "ahLrbyvMc0IAN3/CUCQQdves1d8mM3mY0cVTNKYLQ/YPIPM8/muQgK8h73YsO0H0",
            "u31i1DsqaVm5nMPsaOEyHEZSngQ6ClSPQ14pnxwXHOH7n5f2r3rbhini5nGxqxq9",
            "Xd2v9ggt3goGFQI61M6Ob_SreRk_31P9GDvSzLEe3zwaksb0TRX31kK1jN8RSUNR",
        ),
        (
            "HS512",
            "u8ay69D7URh6BiXK4FOIl9W0wthyXRxFwg0d+qIuR1uaEtrmz8XWE3V7mYsL7pt93eUQzYvFt0ge62sTfu2/qQ==",
            "yZppTzkJOsLirSHbHh2amcVynSBsngQ9y5crzv2XKMexcYWckwx_RmM_fsU1kj0DNokCBlNXR6LrL72YgATZlg",
            "5sL6azshZ8k69_FavGXe1kK9oE8XyQYNTou2eMBLoAqJ0oeezQRguvli9BOM1R5L9CR-qrjxwwun7GP-hwX4bA",
        ),
        (
            "ES256",
            open("tests/keys/ec/secp256r1.private.pem").read(),
            "tWczrb-lEXv4Hd0fWjJk_pmLf6Y4q5_Nl0tWZIxM3qaJ91N5mNMNz1NiTqI43KFrOljx4obz6zMDr0DSWE4new",
            "8cbMnTBxkR1IgvjjxOAEpZAYXa6uhbqXwHL8t5HhrGaO_zMx0gPITr6mo93EHBlQyMpZdjWVFy8kU8952HwSxg",
        ),
        (
            "ES384",
            open("tests/keys/ec/secp384r1.private.pem").read(),
            "vqTkqQwHGuS6wF0smRH9kemMUgZdzU-rpwycYr8tk-Qz5iwgB1OmIb6mwnWyv20K8OkR0cuQfzxHSpTU1Z2JGi86vftmLPrynmm8NjgA7nwV_peoe61CCjkGvGH7D_wb",
            "V-D8pNrDuiAvZlh8SwLsEBQ0bszREHvytrFHZVPKeOd7-YGQTJ6KmApxZQ7yoKS9l-DOivNMtOTYbSCf8LwrWyRf0PNITRb9ywc0JiAgofOh9kv1y7nG4YbiTAPSt5eY",
        ),
        (
            "ES512",
            open("tests/keys/ec/secp521r1.private.pem").read(),
            "AeErmk4KMSiHHl6fSRoPNEaKrRgKDAYHNB7IOMgHUVBvz-jv0veYJbLEfubbenphgm69VeZtOrtuXafOdoMro7w0AUtaUDIdqzdyLIyLkEs6Hc1VydngFcgsGO4b98mcaEBRNcGzrkBJrMqS5g-XB9mnwn5kFf04wxb4rDRSFHh8QQ8S",
            "AP61N7DInLNTpo_PNEwCihBqQKX-1pdQLLPtzTnoIsS1p32653L3gu69_q3lJ5AH6oH78ljZVYMHFqHFBIkMWwgWAVZvnF_Qq8Qf9VIKO81PUqab-jWYGPySHS4WRkxWU1X_bFyt0ijaAHad2aTgzTyBhePrbgUTRkOBIMyOwWht-cQQ",
        ),
    ],
)
def test_signature(algorithm, key, expected_signature_1, expected_signature_2):
    jws_1 = sign(message(issuer="test-iss"), algorithm, key)
    assert jws_1.endswith("." + expected_signature_1)

    jws_2 = sign("bWVzc2FnZQ==", algorithm, key)
    assert jws_2.endswith("." + expected_signature_2)
