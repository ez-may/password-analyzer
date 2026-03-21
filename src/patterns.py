import re
from zxcvbn.matching import L33T_TABLE
import os


def _generate_reverse_substitution_table() -> dict:
    """
    Reverses the mapping of character substitutions using zxcvbn's L33T_TABLE.
    L33T_TABLE maps letters to substitutions e.g. {"a": ["@", "4"]}
    Here it is reversed to map substitutions to letters e.g. {"@": ["a"]}
    """
    substitution_table = {}

    for letter, substitutions in L33T_TABLE.items():
        for sub in substitutions:
            if sub not in substitution_table:
                substitution_table[sub] = []
            substitution_table[sub].append(letter)
    return substitution_table


# built once at module load — avoids rebuilding on every function call
SUBSTITUTION_MAP = _generate_reverse_substitution_table()


def _generate_substitution_variants(text: str) -> list:
    """
    Recursively generates all fully normalized variants of text based on a
    substitution mapping. For example, mapping @ to a.
    """

    def recurse(index: int, current: str) -> list:
        # base case. full string built, keep only if entirely alphabetic and
        # if the variant is not the same as original. Handles cases where no
        # substitution takes place
        if index == len(text):
            if current.isalpha() and current != text.lower():
                return [current]
            else:
                return []

        char = text.lower()[index]
        results = []

        if char in SUBSTITUTION_MAP:
            # branch into every possible letter this character could represent
            for letter in SUBSTITUTION_MAP[char]:
                results.extend(recurse(index + 1, current + letter))

        # always also recurse with the original character unchanged
        results.extend(recurse(index + 1, current + char))
        return results

    # deduplicate via set before returning
    return list(set(recurse(0, "")))


def _detect_repeated_characters(password: str) -> dict:
    """
    Uses regex to detect sequences of three or more repeated characters in a
    password.
    """
    pattern = re.compile(r'(.)\1{2,}')
    matches = pattern.findall(password.lower())

    return {
        "found": len(matches) > 0,
        "matches": matches
    }


def _build_walk_set() -> set:
    '''
    Builds a set of all valid keyboard walk substrings of length 3 or more
    from every row in both directions. Called once at module load time.
    '''
    KEYBOARD_WALKS = [
        "1234567890",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1qaz", "2wsx", "3edc", "4rfv",
        "5tgb", "6yhn", "7ujm", "8ik",
        "9ol", "0p"
    ]

    walk_set = set()
    # include both forward and reverse directions for each row
    ALL_WALKS = KEYBOARD_WALKS + [walk[::-1] for walk in KEYBOARD_WALKS]

    for walk in ALL_WALKS:
        for i in range(len(walk) - 2):
            # generate all substrings of length 3 or more starting at i
            for length in range(3, len(walk) - i + 1):
                walk_set.add(walk[i:i + length])

    return walk_set


# built once at module load — avoids rebuilding on every function call
WALK_SET = _build_walk_set()


def _detect_keyboard_walks(password: str) -> dict:
    """
    Detects keyboard walk sequences of 3 or more consecutive characters.
    Normalizes shift characters to their number equivalents before checking
    so that walks are detected regardless of shift key usage.
    Only the longest walk at each position is returned.
    Matches are returned as the original password characters, not normalized.
    """

    SHIFT_TO_NUMBER = {
        "!": "1", "@": "2", "#": "3", "$": "4", "%": "5",
        "^": "6", "&": "7", "*": "8", "(": "9", ")": "0"
    }

    password_lower = password.lower()
    # replace shift characters with number equivalents for walk matching
    normalized = "".join(
        SHIFT_TO_NUMBER.get(char, char)
        for char in password_lower
    )

    matches = []

    # stop 2 positions before end since a walk needs at least 3 characters
    for i in range(len(normalized) - 2):
        # try longest possible match first, break on first hit
        for length in range(len(normalized) - i, 2, -1):
            substring = normalized[i:i + length]
            if substring in WALK_SET:
                # index back into original to preserve shift characters
                original_match = password_lower[i:i + length]
                if original_match not in matches:
                    matches.append(original_match)
                break

    # remove any match that is a substring of a longer match
    longest_matches = [
        match for match in matches
        if not any(
            match in other and match != other
            for other in matches
        )
    ]

    return {
        "found": len(longest_matches) > 0,
        "matches": longest_matches
    }


def _load_wordlist() -> set:
    """
    Loads the wordlist from disk into a set.
    Called once at module load time.
    """
    wordlist_path = os.path.join(os.path.dirname(__file__), "wordlist.txt")
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        print(f"Warning: wordlist not found at {wordlist_path}. "
              f"Dictionary check will be skipped.")
        return set()
    except IOError:
        print("Warning: wordlist could not be read. "
              "Dictionary check will be skipped.")
        return set()


WORDLIST = _load_wordlist()


def _check_dictionary(passwords: str | list) -> dict:
    """
    Checks one or more passwords against the common password wordlist sourced
    from SecLists 10K common passwords.
    """
    if not passwords:
        return {"found": False, "matches": []}

    if isinstance(passwords, str):
        passwords = [passwords]

    matches = [p for p in passwords if p.lower() in WORDLIST]

    return {
        "found": len(matches) > 0,
        "matches": matches
    }


def analyze_patterns(password: str) -> dict:
    """
    Executes all pattern detection checks for a given password.
    Runs substitution variant generation, dictionary check, repeated
    character detection, and keyboard walk detection.
    Returns a single flat dictionary with all results and a top level
    patterns_found boolean.
    """
    if not password:
        return {
            "dictionary_check": {"found": False, "matches": []},
            "repeated_chars_check": {"found": False, "matches": []},
            "keyboard_walks_check": {"found": False, "matches": []},
            "patterns_found": False
        }

    variants = _generate_substitution_variants(password)
    dictionary_result = _check_dictionary([password] + variants)
    repeated_result = _detect_repeated_characters(password)
    walks_result = _detect_keyboard_walks(password)

    patterns_found = any([
        dictionary_result["found"],
        repeated_result["found"],
        walks_result["found"]
    ])

    return {
        "dictionary_check": dictionary_result,
        "repeated_chars_check": repeated_result,
        "keyboard_walks_check": walks_result,
        "patterns_found": patterns_found
    }
