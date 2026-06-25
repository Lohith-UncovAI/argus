from argus_img.core.logging import sanitize_log_value


def test_log_sanitizer_escapes_newline_and_bidi_controls():
    value = sanitize_log_value("hello\n\u202eworld")
    assert "\n" not in value
    assert "\u202e" not in value
    assert "\\u202e" in value

