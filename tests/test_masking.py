from pii_leak_hunter.utils.hashing import HashingService
from pii_leak_hunter.utils.masking import digits_only, extract_mask_candidates, mask_value, masked_preview


def test_masking_preview_and_digits() -> None:
    text = "customer_ssn=123-45-6789"
    start = text.index("123-45-6789")
    end = start + len("123-45-6789")
    preview = masked_preview(text, start, end)
    assert "123-45-6789" not in preview
    assert digits_only("123-45-6789") == "123456789"
    assert mask_value("abcdef", visible=2) == "****ef"


def test_hashing_and_mask_candidates_are_stable_per_run() -> None:
    hashing = HashingService(secret=b"1" * 32)
    assert hashing.hash_value("alice@example.test") == hashing.hash_value("alice@example.test")
    assert extract_mask_candidates("masked=****6789") == {"6789"}
