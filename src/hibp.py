import hashlib
import requests


def check_breach(password: str) -> dict:
    """
    Checks a password against the HaveIBeenPwned API using k-anonymity.
    Only the first 5 characters of the SHA-1 hash are sent to the API.
    Full comparison is done locally to avoid sending the full password or hash.
    """
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    exception_val = {"status": "unavailable", "count": None}
    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5
        )
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        return exception_val
    except requests.exceptions.Timeout:
        return exception_val
    except requests.exceptions.RequestException:
        return exception_val
    
    hashes = (line.split(":") for line in response.text.splitlines())
    
    for returned_suffix , count in hashes:
        if returned_suffix == suffix:
            return {"status": "breached", "count": int(count)}
    return {"status": "clean", "count": 0}
