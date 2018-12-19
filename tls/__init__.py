import os
import time
import struct
import random
import iofree
from dataclasses import dataclass
from enum import IntEnum
from types import SimpleNamespace
from nacl.public import PrivateKey
from nacl.bindings import crypto_scalarmult
from . import ciphers
from .key_schedule import PSKWrapper
from .utils import pack_int, pack_list, pack_all

MAX_LIFETIME = 24 * 3600 * 7
AGE_MOD = 2 ** 32


class Alert(Exception):
    def __init__(self, level, description):
        self.level = level
        self.description = description


class MyIntEnum(IntEnum):
    @classmethod
    def from_value(cls, value):
        for e in cls:
            if e == value:
                return e
        raise Exception(f"Known {cls.__name__} type: {value}")


class UInt8Enum(MyIntEnum):
    def pack(self) -> bytes:
        return self.to_bytes(1, "big")


class UInt16Enum(MyIntEnum):
    def pack(self) -> bytes:
        return self.to_bytes(2, "big")


class HandshakeType(UInt8Enum):
    client_hello = 1
    server_hello = 2
    new_session_ticket = 4
    end_of_early_data = 5
    encrypted_extensions = 8
    certificate = 11
    certificate_request = 13
    certificate_verify = 15
    finished = 20
    key_update = 24
    message_hash = 254

    def pack_data(self, data: bytes) -> bytes:
        return self.pack() + pack_int(3, data)

    def tls_inner_plaintext(self, content: bytes) -> bytes:
        return (
            self.pack_data(content)
            + ContentType.handshake.pack()
            + (b"\x00" * random.randint(0, 10))
        )


class ExtensionType(UInt16Enum):
    server_name = 0
    max_fragment_length = 1
    status_request = 5
    supported_groups = 10
    signature_algorithms = 13
    use_srtp = 14
    heartbeat = 15
    application_layer_protocol_negotiation = 16
    signed_certificate_timestamp = 18
    client_certificate_type = 19
    server_certificate_type = 20
    padding = 21
    pre_shared_key = 41
    early_data = 42
    supported_versions = 43
    cookie = 44
    psk_key_exchange_modes = 45
    certificate_authorities = 47
    oid_filters = 48
    post_handshake_auth = 49
    signature_algorithms_cert = 50
    key_share = 51

    def pack_data(self, data: bytes) -> bytes:
        return self.pack() + pack_int(2, data)

    @classmethod
    def server_name_list(cls, host_names: list) -> bytes:
        return cls.server_name.pack_data(
            pack_list(
                2, (NameType.host_name.pack_data(name.encode()) for name in host_names)
            )
        )

    @classmethod
    def supported_versions_list(cls) -> bytes:
        return cls.supported_versions.pack_data(pack_int(1, b"\x03\x04"))

    @classmethod
    def supported_groups_list(cls, named_group, *named_groups) -> bytes:
        return cls.supported_groups.pack_data(
            pack_list(2, (group.pack() for group in (named_group, *named_groups)))
        )

    @classmethod
    def signature_algorithms_list(cls, algo, *algos) -> bytes:
        return cls.signature_algorithms.pack_data(
            pack_list(2, (alg.pack() for alg in (algo, *algos)))
        )

    @classmethod
    def unpack_from(cls, mv):
        extensions = {}
        while mv:
            type_value = int.from_bytes(mv[:2], "big")
            mv = mv[2:]
            if mv:
                extension_data_lenth = int.from_bytes(mv[:2], "big")
                pos = extension_data_lenth + 2
                extension_data = mv[2:pos]
                assert (
                    len(extension_data) == extension_data_lenth
                ), "extension length does not match"
                mv = mv[pos:]
            else:
                extension_data = b""
            et = cls.from_value(type_value)
            extensions[et] = et.unpack(extension_data)
        return extensions

    def unpack(self, data):
        if self == ExtensionType.supported_versions:
            return bytes(data)
        if self == ExtensionType.key_share:
            return NamedGroup.unpack_from(data)
        if self == ExtensionType.server_name:
            return data.decode()
        if self == ExtensionType.pre_shared_key:
            assert len(data) == 2, "invalid length"
            return int.from_bytes(data, "big")
        if self == ExtensionType.early_data:
            if data:
                assert len(data) == 4, "expect uint32 max_early_data_size"
                return int.from_bytes(data, "big")
            return
        raise Exception("not support yet")


class ContentType(UInt8Enum):
    invalid = 0
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23

    def tls_plaintext(self, data: bytes) -> bytes:
        assert len(data) > 0, "need data"
        data = memoryview(data)
        fragments = []
        while True:
            if len(data) > 16384:
                fragments.append(data[:16384])
                data = data[16384:]
            else:
                fragments.append(data)
                break

        return b"".join(
            (
                self.pack()
                + (
                    b"\x03\x01"
                    if i == 0 and self is ContentType.handshake
                    else b"\x03\x03"
                )
                + pack_int(2, fragment)
                for i, fragment in enumerate(fragments)
            )
        )

    def tls_inner_plaintext(self, content: bytes) -> bytes:
        return content + self.pack() + (b"\x00" * random.randint(0, 10))


class AlertLevel(UInt8Enum):
    warning = 1
    fatal = 2


class AlertDescription(UInt8Enum):
    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    record_overflow = 22
    handshake_failure = 40
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    inappropriate_fallback = 86
    user_canceled = 90
    missing_extension = 109
    unsupported_extension = 110
    unrecognized_name = 112
    bad_certificate_status_response = 113
    unknown_psk_identity = 115
    certificate_required = 116
    no_application_protocol = 120


class SignatureScheme(UInt16Enum):
    # RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256 = 0x0401
    rsa_pkcs1_sha384 = 0x0501
    rsa_pkcs1_sha512 = 0x0601
    # ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403
    ecdsa_secp384r1_sha384 = 0x0503
    ecdsa_secp521r1_sha512 = 0x0603
    # RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804
    rsa_pss_rsae_sha384 = 0x0805
    rsa_pss_rsae_sha512 = 0x0806
    # EdDSA algorithms
    ed25519 = 0x0807
    ed448 = 0x0808
    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809
    rsa_pss_pss_sha384 = 0x080a
    rsa_pss_pss_sha512 = 0x080b
    # Legacy algorithms
    rsa_pkcs1_sha1 = 0x0201
    ecdsa_sha1 = 0x0203
    # Reserved Code Points
    # private_use(0xFE00..0xFFFF)


# backend = default_backend()
dh_parameters = {
    # "ffdhe2048": dh.generate_parameters(generator=2, key_size=2048, backend=backend),
    # "ffdhe3072": dh.generate_parameters(generator=2, key_size=3072, backend=backend),
    # "ffdhe4096": dh.generate_parameters(generator=2, key_size=4096, backend=backend),
    # "ffdhe8192": dh.generate_parameters(generator=2, key_size=8192, backend=backend),
}


class NamedGroup(UInt16Enum):
    # Elliptic Curve Groups (ECDHE)
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    x25519 = 0x001D
    x448 = 0x001E
    # Finite Field Groups (DHE)
    ffdhe2048 = 0x0100
    ffdhe3072 = 0x0101
    ffdhe4096 = 0x0102
    ffdhe6144 = 0x0103
    ffdhe8192 = 0x0104
    # Reserved Code Points
    # ffdhe_private_use(0x01FC..0x01FF)
    # ecdhe_private_use(0xFE00..0xFEFF)

    # def dh_key_share_entry(self):
    #     private_key = dh_parameters[self.name].generate_private_key()
    #     peer_public_key = private_key.public_key()
    #     opaque = peer_public_key.public_bytes(
    #         Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    #     )
    #     return private_key, self.pack() + pack_int(2, opaque)

    @classmethod
    def new_x25519(cls):
        private_key = PrivateKey.generate()
        key_exchange = bytes(private_key.public_key)
        return private_key, cls.x25519.pack() + pack_int(2, key_exchange)

    @classmethod
    def unpack_from(cls, data):
        value = int.from_bytes(data[:2], "big")
        group_type = cls.from_value(value)
        length = int.from_bytes(data[2:4], "big")
        assert length == len(data[4:]), "group length does not match"
        key_exchange = bytes(data[4:])
        return KeyShareEntry(group_type, key_exchange)


@dataclass
class KeyShareEntry:
    group: NamedGroup
    key_exchange: bytes
    __slots__ = ("group", "key_exchange")

    def pack(self):
        return self.group.pack() + pack_int(2, self.key_exchange)


class CertificateType(UInt8Enum):
    X509 = 0
    RawPublicKey = 2


@dataclass
class CertificateEntry:
    cert_type: CertificateType
    cert_data: bytes
    extensions: dict
    __slots__ = ("cert_type", "cert_data", "extensions")

    @classmethod
    def unpack_from(cls, data):
        certificate_request_context_len = data[0]
        certificate_request_context = data[1 : 1 + certificate_request_context_len]
        certificate_request_context
        data = data[1 + certificate_request_context_len :]
        certificate_list_len = int.from_bytes(data[:3], "big")
        certificate_list = data[3 : 3 + certificate_list_len]
        assert (
            len(data[3 + certificate_list_len :]) == 0
        ), "Certificate length does not match"
        cert_type = CertificateType.from_value(certificate_list[0])
        cert_data_len = int.from_bytes(certificate_list[1:4], "big")
        cert_data = certificate_list[4 : 4 + cert_data_len]
        extensions_data = certificate_list[4 + cert_data_len :]
        extensions_len = int.from_bytes(extensions_data[:2], "big")
        extensions = ExtensionType.unpack_from(extensions_data[2 : 2 + extensions_len])
        assert (
            len(extensions_data[2 + extensions_len :]) == 0
        ), "extensions length does not match"
        return cls(cert_type, cert_data, extensions)


class KeyUpdateRequest(UInt8Enum):
    update_not_requested = 0
    update_requested = 1


class PskKeyExchangeMode(UInt8Enum):
    psk_ke = 0
    psk_dhe_ke = 1

    def extension(self):
        return ExtensionType.psk_key_exchange_modes.pack_data(pack_int(1, self.pack()))

    @classmethod
    def both_extensions(cls):
        return ExtensionType.psk_key_exchange_modes.pack_data(pack_int(1, b"\x00\x01"))


class CipherSuite(UInt16Enum):
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305

    @classmethod
    def all(cls) -> set:
        if not hasattr(cls, "_all"):
            cls._all = {suite.pack() for suite in cls}
        return cls._all

    @classmethod
    def select(cls, data):
        data = memoryview(data)
        for i in (0, len(data), 2):
            if data[i : i + 2] in cls.all():
                return data[i : i + 2].tobytes()

    @classmethod
    def get_cipher(cls, data):
        value = int.from_bytes(data, "big")
        if value == cls.TLS_AES_128_GCM_SHA256:
            return ciphers.TLS_AES_128_GCM_SHA256
        elif value == cls.TLS_AES_256_GCM_SHA384:
            return ciphers.TLS_AES_256_GCM_SHA384
        elif value == cls.TLS_AES_128_CCM_SHA256:
            return ciphers.TLS_AES_128_CCM_SHA256
        elif value == cls.TLS_AES_128_CCM_8_SHA256:
            return ciphers.TLS_AES_128_CCM_8_SHA256
        elif value == cls.TLS_CHACHA20_POLY1305_SHA256:
            return ciphers.TLS_CHACHA20_POLY1305_SHA256
        else:
            raise Exception("bad cipher suite")

    @classmethod
    def pack_all(cls):
        return pack_all(
            2,
            [
                cls.TLS_CHACHA20_POLY1305_SHA256,
                cls.TLS_AES_128_GCM_SHA256,
                cls.TLS_AES_256_GCM_SHA384,
                cls.TLS_AES_128_CCM_SHA256,
                cls.TLS_AES_128_CCM_8_SHA256,
            ],
        )


class NameType(UInt8Enum):
    host_name = 0

    def pack_data(self, data: bytes) -> bytes:
        return self.pack() + pack_int(2, data)


class Const:
    all_signature_algorithms = ExtensionType.signature_algorithms.pack_data(
        pack_all(2, SignatureScheme)
    )
    all_supported_groups = ExtensionType.supported_groups.pack_data(
        pack_all(2, [NamedGroup.x25519])
    )
    psk_ke_extension = PskKeyExchangeMode.psk_ke.extension()
    psk_dhe_ke_extension = PskKeyExchangeMode.psk_dhe_ke.extension()
    psk_both_extensions = PskKeyExchangeMode.both_extensions()


def server_hello_pack(legacy_session_id_echo, cipher_suite, extensions) -> bytes:
    legacy_version = b"\x03\x03"
    msg = b"".join(
        (
            legacy_version,
            os.urandom(32),
            pack_int(1, legacy_session_id_echo),
            cipher_suite.pack(),
            b"\x00",
        )
    )
    return ContentType.handshake.tls_plaintext(
        HandshakeType.server_hello.pack_data(msg)
    )


def client_hello_key_share_extension(*key_share_entries):
    return ExtensionType.key_share.pack_data(pack_list(2, key_share_entries))


@dataclass
class PskIdentity:
    identity: bytes
    obfuscated_ticket_age: int
    binder_len: int


def client_pre_shared_key_extension(psk_identities):
    binders = pack_psk_binder_entries((i.binder_len * b"\x00" for i in psk_identities))
    return (
        ExtensionType.pre_shared_key.pack_data(
            pack_list(
                2,
                (
                    pack_int(2, i.identity) + i.obfuscated_ticket_age.to_bytes(4, "big")
                    for i in psk_identities
                ),
            )
            + binders
        ),
        len(binders),
    )


def pack_psk_binder_entries(binder_list):
    return pack_list(2, (pack_int(1, binder) for binder in binder_list))


def unpack_certificate_verify(mv):
    algorithm = int.from_bytes(mv[:2], "big")
    scheme = SignatureScheme.from_value(algorithm)
    signature_len = int.from_bytes(mv[2:4], "big")
    signature = mv[4 : 4 + signature_len]
    return SimpleNamespace(algorithm=scheme, signature=signature)


def unpack_new_session_ticket(mv):
    lifetime, age_add, nonce_len = struct.unpack_from("!IIB", mv)
    mv = mv[9:]
    nonce = mv[:nonce_len]
    mv = mv[nonce_len:]
    ticket_len = int.from_bytes(mv[:2], "big")
    mv = mv[2:]
    ticket = bytes(mv[:ticket_len])
    mv = mv[ticket_len:]
    ext_len = int.from_bytes(mv[:2], "big")
    mv = mv[2:]
    assert ext_len == len(mv), "extension length does not match"
    extensions = ExtensionType.unpack_from(mv)
    return NewSessionTicket(
        lifetime=lifetime,
        age_add=age_add,
        nonce=nonce,
        ticket=ticket,
        max_early_data_size=extensions.get(ExtensionType.early_data),
    )


@dataclass
class NewSessionTicket:
    lifetime: int
    age_add: int
    nonce: bytes
    ticket: bytes
    max_early_data_size: int

    def __post_init__(self):
        self.outdated_time = time.time() + min(self.lifetime, MAX_LIFETIME)
        self.obfuscated_ticket_age = ((self.lifetime * 1000) + self.age_add) % AGE_MOD

    def is_outdated(self):
        return time.time() >= self.outdated_time

    def to_psk_identity(self, binder_len):
        return PskIdentity(self.ticket, self.obfuscated_ticket_age, binder_len)


class TLSClientSession:
    def __init__(
        self,
        server_names="",
        psk=None,
        psk_only=False,
        psk_label=b"Client_identity",
        psk_identities=None,
        data_callback=None,
        early_data=None,
    ):
        if type(server_names) == str:
            server_names = [server_names]
        self.server_names = server_names
        self.private_key, key_share_entry = NamedGroup.new_x25519()
        self.early_data = early_data
        self.server_finished = False
        self.data_callback = data_callback or (lambda data: None)
        self.session_tickets = []
        self.psk_only = psk_only or bool(early_data)

        extensions = [
            ExtensionType.server_name_list(server_names),
            ExtensionType.supported_versions_list(),
            Const.all_signature_algorithms,
            Const.all_supported_groups,
            client_hello_key_share_extension(key_share_entry),
        ]
        if early_data:
            if psk is None:
                raise Exception("early data should only send with psk support")
            extensions.insert(4, ExtensionType.early_data.pack_data(b""))
        if psk is not None:
            if self.psk_only:
                pre_kex_mode_ext = Const.psk_ke_extension
            else:
                pre_kex_mode_ext = Const.psk_dhe_ke_extension
            extensions.append(pre_kex_mode_ext)
            self.psk_list = psk if isinstance(psk, (list, tuple)) else [psk]
            psk_wrappers = [
                PSKWrapper(psk, is_ext=psk_identities is None) for psk in self.psk_list
            ]
            ext, binder_length = client_pre_shared_key_extension(
                psk_identities
                if psk_identities
                else [
                    PskIdentity(psk_label, 0, psk_wrapper.tls_hash.hash_len)
                    for psk_wrapper in psk_wrappers
                ]
            )
            extensions.append(ext)
        self.client_hello_data = self._pack_client_hello(extensions)
        if psk is not None:
            to_verify = self.client_hello_data[:-binder_length]
            binders = pack_psk_binder_entries(
                [
                    psk_wrapper.tls_hash.verify_data(
                        psk_wrapper.binder_key(), to_verify
                    )
                    for psk_wrapper in psk_wrappers
                ]
            )
            self.client_hello_data = to_verify + binders
        self.handshake_context = bytearray(self.client_hello_data)

        if early_data:
            TLSCipher = ciphers.TLS_CHACHA20_POLY1305_SHA256
            psk_wrapper = psk_wrappers[0]
            self.cipher = TLSCipher(
                psk_wrapper.client_early_traffic_secret(self.handshake_context)
            )

            inner_plaintext = ContentType.application_data.tls_inner_plaintext(
                self.early_data
            )
            self.packed_early_data = self.cipher.tls_ciphertext(inner_plaintext)
            print(self.packed_early_data)

    def resumption(self, data_callback=None):
        if self.session_tickets:
            psk = [
                self.key_scheduler.resumption_psk(
                    self.handshake_context, session_ticket.nonce
                )
                for session_ticket in self.session_tickets
            ]
            psk_identities = [
                session_ticket.to_psk_identity(self.TLSCipher.tls_hash.hash_len)
                for session_ticket in self.session_tickets
            ]
            psk_only = bool(self.session_tickets[0].max_early_data_size)
        else:
            psk = self.psk
            psk_identities = None
            psk_only = self.psk_only
        return TLSClientSession(
            self.server_names,
            psk=psk,
            psk_only=psk_only,
            psk_identities=psk_identities,
            data_callback=data_callback,
        )

    def _pack_client_hello(
        self, extensions, cipher_suites=None, compatibility_mode=True, retry=False
    ):
        legacy_version = b"\x03\x03"
        if compatibility_mode:
            legacy_session_id = os.urandom(32)
        else:
            legacy_session_id = b""
        if cipher_suites is None:
            cipher_suites = CipherSuite.pack_all()
        else:
            cipher_suites = pack_list(
                2, (cipher_suite.pack() for cipher_suite in cipher_suites)
            )
        assert 0 < len(cipher_suites) < 32768, "cipher_suites<2..2^16-2>"
        randbytes = bytes.fromhex(
            "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
        )

        msg = b"".join(
            (
                legacy_version,
                randbytes if retry else os.urandom(32),
                pack_int(1, legacy_session_id),
                cipher_suites,
                b"\x01\x00",  # legacy_compression_methods
                pack_list(2, extensions),
            )
        )
        return HandshakeType.client_hello.pack_data(msg)

    def unpack_server_hello(self, mv: memoryview):
        assert mv[:2] == b"\x03\x03", "version must be 0x0303"
        random = bytes(mv[2:34])
        legacy_session_id_echo_length = mv[34]
        legacy_session_id_echo = bytes(mv[35 : 35 + legacy_session_id_echo_length])
        mv = mv[35 + legacy_session_id_echo_length :]
        cipher_suite = CipherSuite.get_cipher(mv[:2])
        assert mv[2] == 0, "legacy_compression_method should be 0"
        extension_length = int.from_bytes(mv[3:5], "big")
        extensions_mv = mv[5:]
        assert (
            len(extensions_mv) == extension_length
        ), "extensions length does not match"
        extensions = ExtensionType.unpack_from(extensions_mv)
        return SimpleNamespace(
            handshake_type=HandshakeType.server_hello,
            random=random,
            legacy_session_id_echo=legacy_session_id_echo,
            cipher_suite=cipher_suite,
            extensions=extensions,
        )

    def unpack_handshake(self, mv: memoryview):
        handshake_type = mv[0]
        length = int.from_bytes(mv[1:4], "big")
        assert len(mv[4:]) == length, f"handshake length does not match"
        handshake_data = mv[4:]
        if handshake_type == HandshakeType.server_hello:
            self.handshake_context.extend(mv)
            return self.unpack_server_hello(handshake_data)
        elif handshake_type == HandshakeType.encrypted_extensions:
            self.handshake_context.extend(mv)
            ext_len = int.from_bytes(handshake_data[:2], "big")
            handshake_data = handshake_data[2:]
            assert (
                len(handshake_data) == ext_len
            ), "encrypted extensions length does not match"
            self.encrypted_extensions = ExtensionType.unpack_from(handshake_data)
        elif handshake_type == HandshakeType.certificate_request:
            self.handshake_context.extend(mv)
        elif handshake_type == HandshakeType.certificate:
            self.handshake_context.extend(mv)
            self.certificate_entry = CertificateEntry.unpack_from(handshake_data)
        elif handshake_type == HandshakeType.certificate_verify:
            self.handshake_context.extend(mv)
            self.certificate_verify = unpack_certificate_verify(handshake_data)
        elif handshake_type == HandshakeType.finished:
            assert handshake_data == self.peer_cipher.verify_data(
                self.handshake_context
            ), "server handshake finished does not match"
            self.handshake_context.extend(mv)
            self.server_finished = True
        elif handshake_type == HandshakeType.new_session_ticket:
            self.session_tickets.append(unpack_new_session_ticket(handshake_data))
        else:
            raise Exception(f"unknown handshake type {handshake_type}")

    def tls_response(self):
        while True:
            head = yield from iofree.read(5)
            assert head[1:3] == b"\x03\x03", f"bad legacy_record_version {head[1:3]}"
            length = int.from_bytes(head[3:], "big")
            if (head[0] == ContentType.application_data and length > (16384 + 256)) or (
                head[0] != ContentType.application_data and length > 16384
            ):
                yield from iofree.write(
                    self.pack_fatal(AlertDescription.record_overflow)
                )
                raise Alert(AlertLevel.fatal, AlertDescription.record_overflow)
            content = memoryview((yield from iofree.read(length)))
            if head[0] == ContentType.alert:
                level = AlertLevel.from_value(content[0])
                description = AlertDescription.from_value(content[1])
                raise Alert(level, description)
            elif head[0] == ContentType.handshake:
                self.peer_handshake = self.unpack_handshake(content)
                assert (
                    self.peer_handshake.handshake_type == HandshakeType.server_hello
                ), "expect server hello"
                peer_pk = self.peer_handshake.extensions[
                    ExtensionType.key_share
                ].key_exchange
                shared_key = crypto_scalarmult(bytes(self.private_key), peer_pk)
                TLSCipher = self.peer_handshake.cipher_suite
                self.TLSCipher = TLSCipher
                key_index = self.peer_handshake.extensions.get(
                    ExtensionType.pre_shared_key
                )
                psk = None if key_index is None else self.psk_list[key_index]
                key_scheduler = TLSCipher.tls_hash.scheduler(shared_key, psk)
                self.key_scheduler = key_scheduler
                secret = key_scheduler.server_handshake_traffic_secret(
                    self.handshake_context
                )
                # server handshake cipher
                self.peer_cipher = TLSCipher(secret)
                client_handshake_traffic_secret = key_scheduler.client_handshake_traffic_secret(
                    self.handshake_context
                )
            elif head[0] == ContentType.application_data:
                plaintext = self.peer_cipher.decrypt(content, head).rstrip(b"\x00")
                content_type = ContentType.from_value(plaintext[-1])
                if content_type == ContentType.handshake:
                    self.unpack_handshake(plaintext[:-1])
                    if self.server_finished:
                        if self.early_data:
                            eoe_data = HandshakeType.end_of_early_data.pack_data(b"")
                            # self.handshake_context.extend(eoe_data)
                            inner_plaintext = ContentType.handshake.tls_inner_plaintext(
                                eoe_data
                            )
                            record = self.cipher.tls_ciphertext(inner_plaintext)
                            yield from iofree.write(record)

                        # client handshake cipher
                        cipher = TLSCipher(client_handshake_traffic_secret)
                        client_finished = cipher.verify_data(self.handshake_context)
                        client_finished_data = HandshakeType.finished.pack_data(
                            client_finished
                        )
                        inner_plaintext = ContentType.handshake.tls_inner_plaintext(
                            client_finished_data
                        )
                        record = cipher.tls_ciphertext(inner_plaintext)
                        change_cipher_spec = ContentType.change_cipher_spec.tls_plaintext(
                            b"\x01"
                        )
                        yield from iofree.write(change_cipher_spec + record)
                        # server application cipher
                        server_secret = key_scheduler.server_application_traffic_secret_0(
                            self.handshake_context
                        )
                        self.peer_cipher = TLSCipher(server_secret)
                        self.server_finished = False

                        # client application cipher
                        client_secret = key_scheduler.client_application_traffic_secret_0(
                            self.handshake_context
                        )
                        self.cipher = TLSCipher(client_secret)
                        self.handshake_context.extend(client_finished_data)
                elif content_type == ContentType.application_data:
                    self.data_callback(plaintext[:-1])
                elif content_type == ContentType.alert:
                    level = AlertLevel.from_value(plaintext[0])
                    description = AlertDescription.from_value(plaintext[1])
                    raise Alert(level, description)
                elif content_type == ContentType.invalid:
                    raise Exception("invalid content type")
                else:
                    raise Exception(f"unexpected content type {content_type}")
            elif head[0] == ContentType.change_cipher_spec:
                assert content == b"\x01", "change_cipher should be 0x01"
            else:
                raise Exception(f"Unknown content type: {head[0]}")

    def pack_client_hello(self):
        data = ContentType.handshake.tls_plaintext(self.client_hello_data)
        return data if not self.early_data else data + self.packed_early_data

    def pack_application_data(self, payload: bytes):
        inner_plaintext = ContentType.application_data.tls_inner_plaintext(payload)
        return self.cipher.tls_ciphertext(inner_plaintext)

    def pack_alert(self, description: AlertDescription, level: AlertLevel):
        payload = level.pack() + description.pack()
        if self.cipher:
            inner_plaintext = ContentType.alert.tls_inner_plaintext(payload)
            return self.cipher.tls_ciphertext(inner_plaintext)
        else:
            return ContentType.alert.tls_plaintext(payload)

    def pack_warning(self, description: AlertDescription):
        return self.pack_alert(description, AlertLevel.warning)

    def pack_fatal(self, description: AlertDescription):
        return self.pack_alert(description, AlertLevel.fatal)

    def pack_close(self):
        return self.pack_warning(AlertDescription.close_notify)

    def pack_canceled(self):
        return self.pack_warning(AlertDescription.user_canceled)

    def parser(self):
        return iofree.Parser(self.tls_response())
