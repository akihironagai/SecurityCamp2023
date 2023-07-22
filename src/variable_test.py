from variable import len_bytes


def test_len_bytes_from_bytes():
    assert len_bytes(b"\x00\x00", 1) == b"\x02\x00\x00"
    assert len_bytes(b"\x00", 2) == b"\x00\x01\x00"


def test_len_bytes_from_sequence_bytes():
    assert len_bytes([b"\x00", b"\x00"], 1) == b"\x02\x00\x00"
    assert len_bytes([b"\x00"], 2) == b"\x00\x01\x00"
