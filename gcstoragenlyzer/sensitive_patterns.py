import re
from typing import Tuple, Dict, Callable

def tc_identity_check(tcno: str) -> Tuple[bool, str]:
    tcno = str(tcno)
    if not re.match(r'^[1-9][0-9]{9}[02468]$', tcno):
        return False, "Invalid format (must be 11 digits, not start with 0, end with even digit)"

    digits = [int(d) for d in tcno]

    odd_sum = sum(digits[0:9:2])
    even_sum = sum(digits[1:8:2])

    tenth_digit = (odd_sum * 7 - even_sum) % 10
    if tenth_digit != digits[9]:
        return False, "Algorithmically invalid (10th digit mismatch)"

    first_ten_sum = sum(digits[0:10])
    eleventh_digit = first_ten_sum % 10
    if eleventh_digit != digits[10]:
        return False, "Algorithmically invalid (11th digit mismatch)"

    return True, "Valid TC Identity"

PATTERNS = {
    'TCIdentity': {
        'name': 'T.C. Identity Number',
        'regex': r'\b[1-9][0-9]{10}\b',
        'validator': 'tc_identity_check'
    },
    "EmailAddress": {
        'name': 'Email Address',
        "regex": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    }
}

VALIDATORS: Dict[str, Callable[[str], Tuple[bool, str]]] = {
    'tc_identity_check': tc_identity_check,
}


def run_validator_by_name(name: str, candidate: str) -> Tuple[bool, str]:
    func = VALIDATORS.get(name)
    if not func:
        return False, f"Validator '{name}' not found"
    try:
        return func(candidate)
    except Exception as e:
        return False, f"Validator error: {e}"
