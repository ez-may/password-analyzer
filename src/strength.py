import math
import zxcvbn as zxcvbn_lib
from enum import Enum


class PasswordRating(Enum):
    INVALID = "invalid"
    VERY_WEAK = "very weak"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    VERY_STRONG = "very strong"


class NISTStatus(Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    INCOMPLETE = "incomplete"


def calculate_entropy(password: str) -> dict:
    """
    Calculates two entropy measures for a password: observed Shannon entropy
    based on character frequency distribution, and max entropy assuming full
    printable ASCII pool. Higher values are better.
    """
    if not password:
        return {
            "entropy_bits": 0.0,
            "max_entropy_bits": 0.0,
            "rating": PasswordRating.INVALID.value
        }

    length = len(password)

    # Observed Shannon Entropy: count how many times each unique character
    # appears in the password
    frequency = {}
    for char in password:
        frequency[char] = frequency.get(char, 0) + 1

    # calculate H = sum of weighted surprises across all unique characters
    # for each unique character:
    # - probability p(x) = count / length (how often it appears)
    # - surprise = log2(1/p(x)) (rarer characters are more surprising)
    # - weighted surprise = p(x) * log2(1/p(x)) (weight by how often we
    #   encounter it)
    # summing weighted surprises gives average surprise per character
    # this is equivalent to -sum(p(x) * log2(p(x))) since log2(1/p) = -log2(p)
    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    # H is average surprise per character. Multiply by length for total
    # password entropy
    entropy_bits = entropy * length

    # Max Entropy: theoretical ceiling for observed entropy assuming perfect
    # uniform distribution across all 95 printable ASCII characters. Gap
    # between observed and max entropy indicates room to improve character
    # diversity. Converges to 0 when all 95 characters are used exactly once.
    PRINTABLE_ASCII_POOL = 95
    max_entropy_bits = math.log2(PRINTABLE_ASCII_POOL) * length

    # rating based on observed entropy since it reflects real predictability
    # theoretical entropy always increases with length so is less informative
    # for rating
    if entropy_bits < 28:
        rating = PasswordRating.VERY_WEAK.value
    elif entropy_bits < 36:
        rating = PasswordRating.WEAK.value
    elif entropy_bits < 60:
        rating = PasswordRating.MODERATE.value
    elif entropy_bits < 128:
        rating = PasswordRating.STRONG.value
    else:
        rating = PasswordRating.VERY_STRONG.value

    return {
        "entropy_bits": round(entropy_bits, 2),
        "max_entropy_bits": round(max_entropy_bits, 2),
        "rating": rating
    }


def zxcvbn_score(password: str) -> dict:
    """
    Uses Dropbox's zxcvbn library to estimate password strength.
    Scores range from 0 (very weak) to 4 (very strong)
    """
    if not password:
        return {"score": 0, "rating": PasswordRating.INVALID.value,
                "crack_time": "instant"}

    result = zxcvbn_lib.zxcvbn(password)
    score = result["score"]

    ratings = {
        0: PasswordRating.VERY_WEAK.value,
        1: PasswordRating.WEAK.value,
        2: PasswordRating.MODERATE.value,
        3: PasswordRating.STRONG.value,
        4: PasswordRating.VERY_STRONG.value
    }

    return {
        "score": score,
        "rating": ratings[score],
        "crack_time": result["crack_times_display"][
            "offline_slow_hashing_1e4_per_second"]
    }


def nist_score(password: str, hibp_result: dict, pattern_result: dict) -> dict:
    """
    Checks a password against NIST SP 800-63-4 requirements.
    Source: Section 3.1.1.2 - Password Verifiers
    https://pages.nist.gov/800-63-4/sp800-63b.html

    Compliance is determined by three citable NIST requirements:
    length, breach corpus check, and dictionary word check.
    """
    if not password:
        return {
            "status": NISTStatus.NON_COMPLIANT.value,
            "failures": ["password is empty"],
            "notes": []
        }

    length = len(password)
    breach_status = hibp_result["status"]
    dict_matches = pattern_result["dictionary_check"]["matches"]

    failures = []
    notes = []

    # length checks
    if length < 8:
        failures.append(
            f"must be at least 8 characters (currently {length})"
        )
    elif 8 <= length < 15:
        notes.append(
            f"password is {length} characters - acceptable for MFA only, "
            f"single-factor requires 15 minimum"
        )
    if length > 64:
        notes.append(
            "password exceeds 64 characters - "
            "verify your system accepts this length"
        )

    # breach check
    if breach_status == "breached":
        failures.append(
            f"password appeared in {hibp_result.get('count', 0):,} "
            f"known breaches"
        )
    elif breach_status == "unavailable":
        notes.append(
            "breach check unavailable - "
            "full compliance cannot be determined"
        )

    # dictionary check
    if dict_matches:
        failures.append(
            f"password matches common wordlist: {dict_matches}"
        )

    # determine status
    if breach_status == "unavailable" and not failures:
        status = NISTStatus.INCOMPLETE.value
    elif failures:
        status = NISTStatus.NON_COMPLIANT.value
    else:
        status = NISTStatus.COMPLIANT.value

    return {
        "status": status,
        "failures": failures,
        "notes": notes
    }
