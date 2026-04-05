from src.tp2.utils.lib import get_shellcode_strings, get_capstone_analysis, get_pylibemu_analysis


# --- get_shellcode_strings ---

def test_when_shellcode_has_printable_chars_then_strings_are_extracted():
    # Given
    shellcode = b"hello\x00world"

    # When
    result = get_shellcode_strings(shellcode, min_len=4)

    # Then
    assert "hello" in result
    assert "world" in result


def test_when_shellcode_has_no_printable_chars_then_no_strings_found():
    # Given
    shellcode = b"\x00\x01\x02\x03"

    # When
    result = get_shellcode_strings(shellcode)

    # Then
    assert "No strings found." in result


def test_when_string_shorter_than_min_len_then_not_extracted():
    # Given
    shellcode = b"hi\x00"

    # When
    result = get_shellcode_strings(shellcode, min_len=4)

    # Then
    assert "hi" not in result


def test_when_shellcode_empty_then_no_strings_found():
    # Given
    shellcode = b""

    # When
    result = get_shellcode_strings(shellcode)

    # Then
    assert "No strings found." in result


# --- get_capstone_analysis ---

def test_when_valid_shellcode_then_capstone_returns_instructions():
    # Given - simple xor eax, eax (2 bytes)
    shellcode = b"\x31\xc0"

    # When
    result = get_capstone_analysis(shellcode)

    # Then
    assert "xor" in result


def test_when_capstone_analysis_then_result_contains_address():
    # Given
    shellcode = b"\x31\xc0"

    # When
    result = get_capstone_analysis(shellcode)

    # Then
    assert "0x1000" in result


def test_when_empty_shellcode_then_no_instructions():
    # Given
    shellcode = b""

    # When
    result = get_capstone_analysis(shellcode)

    # Then
    assert "No instructions disassembled." in result


# --- get_pylibemu_analysis ---

def test_when_pylibemu_not_available_then_returns_fallback_message():
    # Given
    from unittest.mock import patch
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "pylibemu":
            raise ImportError
        return real_import(name, *args, **kwargs)

    shellcode = b"\x31\xc0"

    # When
    with patch("builtins.__import__", side_effect=mock_import):
        result = get_pylibemu_analysis(shellcode)

    # Then
    assert "pylibemu not available" in result
