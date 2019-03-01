import typing


def pack_int(length: int, data: bytes) -> bytes:
    return len(data).to_bytes(length, "big") + data


def pack_list(length: int, iterable: typing.Iterable[bytes]) -> bytes:
    return pack_int(length, b"".join(data for data in iterable))


def pack_all(length: int, iterable: typing.Iterable) -> bytes:
    return pack_int(length, b"".join(obj.pack() for obj in iterable))
