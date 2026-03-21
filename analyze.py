import sys
import argparse
from src.hibp import check_breach
from src.patterns import analyze_patterns
from src.strength import calculate_entropy, zxcvbn_score, nist_score


def analyze_password(password: str) -> dict:
    """
    Executes all password analysis modules in the correct order.
    Returns a unified result dictionary for consumption by the output layer.
    Order: HIBP first, patterns second, NIST third, Shannon and zxcvbn last.
    """
    # HIBP must run first. The result is needed by NIST
    hibp_result = check_breach(password)

    # patterns must run second. The result is needed by NIST
    pattern_result = analyze_patterns(password)

    # NIST runs third
    nist_result = nist_score(password, hibp_result, pattern_result)

    # Shannon and zxcvbn are independent, so they run last
    shannon_result = calculate_entropy(password)
    zxcvbn_result = zxcvbn_score(password)

    if not password:
        return {"failure": "empty password"}
    else:
        return {
            "password": password,
            "hibp": hibp_result,
            "patterns": pattern_result,
            "strength": {
                "shannon": shannon_result,
                "zxcvbn": zxcvbn_result,
                "nist": nist_result
            }
        }
