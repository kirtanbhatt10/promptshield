from promptshield.normalize import fold_leet, is_invisible, normalize, strip_invisible

ZWSP = chr(0x200B)
ZWJ = chr(0x200D)


def test_fullwidth_and_case():
    assert normalize("ＩＧＮＯＲＥ Previous") == "ignore previous"


def test_zero_width_removed():
    assert normalize(f"ig{ZWSP}no{ZWJ}re") == "ignore"


def test_cyrillic_homoglyphs_folded():
    assert normalize("ignоrе") == "ignore"  # Cyrillic о and е


def test_whitespace_collapsed():
    assert normalize("a \n\t  b") == "a b"


def test_leetspeak_folded_inside_words():
    assert fold_leet("1gn0re 4ll") == "ignore all"


def test_plain_numbers_untouched():
    assert normalize("call 2024 at 10") == "call 2024 at 10"


def test_tag_characters_are_invisible():
    assert is_invisible("\U000e0041")
    assert strip_invisible("a\U000e0041b") == "ab"
