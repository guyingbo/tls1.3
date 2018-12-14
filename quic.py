import enum
import struct

MaxPacketSize = 1370


class PublicFlag(enum.IntFlag):
    VERSION = 0x01
    RESET = 0x02
    HAS_DIVERSIFICATION_NONCE = 0x04
    HAS_CONNECCTION_ID = 0x08
    PACKET_NUMBER_6_BYTES = 0x30
    PACKET_NUMBER_4_BYTES = 0x20
    PACKET_NUMBER_2_BYTES = 0x10
    PACKET_NUMBER_1_BYTES = 0x00
    MULTIPATH = 0x40
    RESERVED = 0x80


class RegularFrameType(enum.IntEnum):
    PADDING = 0x00
    RST_STREAM = 0x01
    CONNECTION_CLOSE = 0x02
    GOAWAY = 0x03
    WINDOW_UPDATE = 0x04
    BLOCKED = 0x05
    STOP_WAITING = 0x06
    PING = 0x07

    def pack(self):
        return self.to_bytes(1, "little")


class SpecialFrameType(enum.Enum):
    STREAM = "1fdooossB"
    ACK = "01ntllmmB"
    CONGESTION_FEEDBACK = "001xxxxxB"


class StreamFlag(enum.IntFlag):
    STREAM = 0x80
    STREAM_FINISHED = 0x40
    STREAM_DATA_LENGTH_PRESENT = 0x20
    # STREAM_DATA_OFFSET_LENGTH = 0x1C
    # STREAM_ID_LENGTH = 0x03


class AckFlag(enum.IntFlag):
    ACK = 0x40
    MORE_ACK_RANGE = 0x20
    UNUSED = 0x10


class Version(enum.Enum):
    Q025 = b"Q034"


def make_packet(
    quic_version,
    packet_number,
    version=None,
    reset=False,
    nonce=None,
    connection_id=None,
):
    flag = 0
    if version:
        flag &= PublicFlag.VERSION
    if reset:
        flag &= PublicFlag.RESET
    if nonce:
        flag &= PublicFlag.HAS_DIVERSIFICATION_NONCE
    if packet_number < 1:
        raise Exception(f"invalid packet_number: {packet_number}")
    elif packet_number < 2 ** 8:
        n = 1
    elif packet_number < 2 ** 16:
        n = 2
        flag &= PublicFlag.PACKET_NUMBER_2_BYTES
    elif packet_number < 2 ** 32:
        n = 4
        flag &= PublicFlag.PACKET_NUMBER_4_BYTES
    elif packet_number < 2 ** 64:
        n = 6
        flag &= PublicFlag.PACKET_NUMBER_6_BYTES
    else:
        raise Exception("invalid packet_number: {packet_number}")
    return struct.pack(f"<B8s4s{n}s", flag, connection_id, quic_version, packet_number)


def version_negotiation_packet():
    return make_packet(version=True)


def public_reset_packet():
    return make_packet(reset=True)


def pack_stream_frame(
    payload: bytes,
    stream_id: int,
    *,
    offset: int = 0,
    finish: bool = False,
    fullsize=True,
):
    flag = StreamFlag.STREAM
    if stream_id < 1:
        raise ValueError(f"Stream id {stream_id} < 1")
    else:
        for i in range(4):
            if stream_id < 2 ** (8 * (i + 1)):
                stream_id_flag = i
                stream_id_bytes = stream_id.to_bytes(i + 1, "little")
        else:
            raise ValueError(f"Maxmium stream_id exceeded: {stream_id}")
    if offset < 0:
        raise ValueError(f"Offset {offset} < 0")
    elif offset == 0:
        offset_flag = 0b000_00
        offset_bytes = b""
    else:
        for i in range(8):
            if offset < 2 ** (8 * (i + 1)):
                offset_flag = i << 2
                offset_bytes = offset.to_bytes(i + 1, "little")
                break
        else:
            raise ValueError(f"Maxmium offset exceeded: {offset}")
    flag = StreamFlag.STREAM & stream_id_flag & offset_flag
    if finish:
        flag &= StreamFlag.STREAM_FINISHED
    length = len(payload)
    if fullsize:
        length_bytes = b""
    else:
        flag &= StreamFlag.STREAM_DATA_LENGTH_PRESENT
        length_bytes = length.to_bytes(2, "little")
    return (
        flag.to_bytes(1, "little")
        + stream_id_bytes
        + offset_bytes
        + length_bytes
        + payload
    )


def pack_ack_frame(largest_ack: int, ack_delay, ack_blocks, timestamps):
    if largest_ack < 1:
        raise ValueError(f"Largest acknowledged {largest_ack} < 1")
    for i, nbytes in zip(range(4), (1, 2, 4, 6)):
        if largest_ack < 2 ** ((i + 1) * 8 * nbytes):
            largest_ack_flag = i
            largest_ack_bytes = largest_ack.to_bytes(nbytes, "little")
            break


def stop_waiting_frame(least_unacked_delta: int):
    if least_unacked_delta < 1:
        raise ValueError(
            f"Least unacked delta which is {least_unacked_delta} should not < 1"
        )
    for i, nbytes in zip(range(4), (1, 2, 4, 6)):
        if least_unacked_delta < 2 ** ((i + 1) * 8 * nbytes):
            return i, least_unacked_delta.to_bytes(nbytes, "little")
    else:
        raise ValueError(
            f"Least unacked delta which is {least_unacked_delta} exceed maxmium"
        )


def window_update_frame(stream_id: int = 0, offset: int = 0):
    return struct.pack("<BIQ", RegularFrameType.WINDOW_UPDATE, stream_id, offset)


def blocked_frame(stream_id: int = 0):
    return struct.pack("<BI", RegularFrameType.BLOCKED, stream_id)


def padding_frame(n):
    return struct.pack(f"{n+1}x")


def rst_stream_frame(stream_id, offset, error_code):
    return struct.pack("<BIQI", RegularFrameType.RST_STREAM, offset, error_code)


def ping_frame():
    return RegularFrameType.PING.pack()


def connection_close_frame(error_code, reason):
    length = len(reason)
    return struct.pack(
        f"<BIH{length}s", RegularFrameType.CONNECTION_CLOSE, error_code, length, reason
    )


def goaway_frame(error_code, last_good_stream_id, reason):
    length = len(reason)
    return struct.pack(
        f"<BIIH{length}s",
        RegularFrameType.GOAWAY,
        error_code,
        last_good_stream_id,
        length,
        reason,
    )
