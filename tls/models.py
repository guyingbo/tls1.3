import enum
import time
import random
import iofree
from . import ciphers
from iofree import schema

MAX_LIFETIME = 24 * 3600 * 7
AGE_MOD = 2 ** 32


class AlertLevel(enum.IntEnum):
    warning = 1
    fatal = 2


class AlertDescription(enum.IntEnum):
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


class KeyUpdateRequest(enum.IntEnum):
    update_not_requested = 0
    update_requested = 1


class ExtensionType(enum.IntEnum):
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


class HandshakeType(enum.IntEnum):
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


class NameType(enum.IntEnum):
    host_name = 0


class SignatureScheme(enum.IntEnum):
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


class NamedGroup(enum.IntEnum):
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


class PskKeyExchangeMode(enum.IntEnum):
    psk_ke = 0
    psk_dhe_ke = 1


class CipherSuite(enum.IntEnum):
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305


class ContentType(enum.IntEnum):
    invalid = 0
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23
    heartbeat = 24

    def tls_plaintext(self, payload):
        return TLSPlaintext.pack(self, payload)


class TLSCiphertext(schema.BinarySchema):
    opaque_type = schema.MustEqual(
        schema.SizedIntEnum(schema.uint8, ContentType), ContentType.application_data
    )
    legacy_record_version = schema.MustEqual(schema.Bytes(2), b"\x03\x03")
    encrypted_record = schema.LengthPrefixedBytes(schema.uint16be)


class ServerName(schema.BinarySchema):
    name_type = schema.MustEqual(
        schema.SizedIntEnum(schema.uint8, NameType), NameType.host_name
    )
    name = schema.Switch(
        "name_type", {NameType.host_name: schema.LengthPrefixedString(schema.uint16be)}
    )


class PskIdentity(schema.BinarySchema):
    identity = schema.LengthPrefixedBytes(schema.uint16be)
    obfuscated_ticket_age = schema.uint32be


class OfferedPsks(schema.BinarySchema):
    identities = schema.LengthPrefixedObjectList(schema.uint16be, PskIdentity)
    binders = schema.LengthPrefixedObjectList(
        schema.uint16be, schema.LengthPrefixedBytes(schema.uint8)
    )


class KeyShareEntry(schema.BinarySchema):
    group = schema.SizedIntEnum(schema.uint16be, NamedGroup)
    key_exchange = schema.LengthPrefixedBytes(schema.uint16be)


extensions = {
    ExtensionType.server_name: schema.LengthPrefixedObject(
        schema.uint16be, schema.LengthPrefixedObjectList(schema.uint16be, ServerName)
    ),
    ExtensionType.signature_algorithms: schema.LengthPrefixedObject(
        schema.uint16be,
        schema.LengthPrefixedObjectList(
            schema.uint16be, schema.SizedIntEnum(schema.uint16be, SignatureScheme)
        ),
    ),
    ExtensionType.supported_groups: schema.LengthPrefixedObject(
        schema.uint16be,
        schema.LengthPrefixedObjectList(
            schema.uint16be, schema.SizedIntEnum(schema.uint16be, NamedGroup)
        ),
    ),
    ExtensionType.psk_key_exchange_modes: schema.LengthPrefixedObject(
        schema.uint16be,
        schema.LengthPrefixedObjectList(
            schema.uint8, schema.SizedIntEnum(schema.uint8, PskKeyExchangeMode)
        ),
    ),
    ExtensionType.early_data: schema.LengthPrefixedBytes(schema.uint16be),
    ExtensionType.pre_shared_key: schema.LengthPrefixedObject(
        schema.uint16be, OfferedPsks
    ),
}

client_extensions = extensions.copy()
client_extensions[ExtensionType.supported_versions] = schema.LengthPrefixedObject(
    schema.uint16be, schema.LengthPrefixedObjectList(schema.uint8, schema.Bytes(2))
)
client_extensions[ExtensionType.key_share] = schema.LengthPrefixedObject(
    schema.uint16be, schema.LengthPrefixedObjectList(schema.uint16be, KeyShareEntry)
)
server_extensions = extensions.copy()
server_extensions[ExtensionType.supported_versions] = schema.LengthPrefixedBytes(
    schema.uint16be
)
server_extensions[ExtensionType.key_share] = schema.LengthPrefixedObject(
    schema.uint16be, KeyShareEntry
)


class Extension(schema.BinarySchema):
    @classmethod
    def server_names(cls, names):
        return cls(ExtensionType.server_name, [ServerName(..., name) for name in names])

    @classmethod
    def supported_versions(cls, versions):
        return cls(ExtensionType.supported_versions, versions)

    @classmethod
    def selected_version(cls, version):
        return cls(ExtensionType.supported_versions, version)

    @classmethod
    def signature_algorithms(cls, schemes):
        return cls(ExtensionType.signature_algorithms, schemes)

    @classmethod
    def supported_groups(cls, groups):
        return cls(ExtensionType.supported_groups, groups)

    @classmethod
    def key_share(cls, key_share_entries):
        return cls(ExtensionType.key_share, key_share_entries)

    @classmethod
    def psk_key_exchange_modes(cls, modes):
        return cls(ExtensionType.psk_key_exchange_modes, modes)

    @classmethod
    def early_data(cls, data):
        return cls(ExtensionType.early_data, data)

    @classmethod
    def pre_shared_key(cls, offered_psks: OfferedPsks):
        return cls(ExtensionType.pre_shared_key, offered_psks)


class ServerExtension(Extension):
    ext_type = schema.SizedIntEnum(schema.uint16be, ExtensionType)
    ext_data = schema.Switch("ext_type", server_extensions)


class ClientExtension(Extension):
    ext_type = schema.SizedIntEnum(schema.uint16be, ExtensionType)
    ext_data = schema.Switch("ext_type", client_extensions)


class ClientHello(schema.BinarySchema):
    legacy_version = schema.MustEqual(schema.Bytes(2), b"\x03\x03")
    rand = schema.Bytes(32)
    legacy_session_id = schema.LengthPrefixedBytes(schema.uint8)
    cipher_suites = schema.LengthPrefixedObjectList(
        schema.uint16be, schema.SizedIntEnum(schema.uint16be, CipherSuite)
    )
    legacy_compression_methods = schema.MustEqual(schema.Bytes(2), b"\x01\x00")
    extensions = schema.LengthPrefixedObjectList(schema.uint16be, ClientExtension)


class ServerHello(schema.BinarySchema):
    legacy_version = schema.MustEqual(schema.Bytes(2), b"\x03\x03")
    rand = schema.Bytes(32)
    legacy_session_id_echo = schema.LengthPrefixedBytes(schema.uint8)
    cipher_suite = schema.SizedIntEnum(schema.uint16be, CipherSuite)
    legacy_compression_method = schema.MustEqual(schema.uint8, 0)
    extensions = schema.LengthPrefixedObjectList(schema.uint16be, ServerExtension)

    def get_cipher(self):
        if self.cipher_suite == CipherSuite.TLS_AES_128_GCM_SHA256:
            return ciphers.TLS_AES_128_GCM_SHA256
        elif self.cipher_suite == CipherSuite.TLS_AES_256_GCM_SHA384:
            return ciphers.TLS_AES_256_GCM_SHA384
        elif self.cipher_suite == CipherSuite.TLS_AES_128_CCM_SHA256:
            return ciphers.TLS_AES_128_CCM_SHA256
        elif self.cipher_suite == CipherSuite.TLS_AES_128_CCM_8_SHA256:
            return ciphers.TLS_AES_128_CCM_8_SHA256
        elif self.cipher_suite == CipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            return ciphers.TLS_CHACHA20_POLY1305_SHA256
        else:
            raise Exception("bad cipher suite")

    @property
    def extensions_dict(self):
        return {ext.ext_type: ext.ext_data for ext in self.extensions}


class CertificateEntry(schema.BinarySchema):
    cert_data = schema.LengthPrefixedBytes(schema.uint24be)
    extensions = schema.LengthPrefixedObjectList(schema.uint16be, ServerExtension)
    # # x = x509.load_der_x509_certificate(data=cert_data, backend=backend)
    # # x = load_certificate(FILETYPE_ASN1, cert_data)
    # from Crypto.PublicKey import RSA
    # key = RSA.import_key(cert_data)


class Certificate(schema.BinarySchema):
    certificate_request_context = schema.LengthPrefixedBytes(schema.uint8)
    certificate_list = schema.LengthPrefixedObjectList(
        schema.uint24be, CertificateEntry
    )


class CertificateVerify(schema.BinarySchema):
    algorithm = schema.SizedIntEnum(schema.uint16be, SignatureScheme)
    signature = schema.LengthPrefixedBytes(schema.uint16be)


class NewSessionTicket(schema.BinarySchema):
    ticket_lifetime = schema.uint32be
    ticket_age_add = schema.uint32be
    ticket_nonce = schema.LengthPrefixedBytes(schema.uint8)
    ticket = schema.LengthPrefixedBytes(schema.uint16be)
    extensions = schema.LengthPrefixedObjectList(schema.uint16be, ServerExtension)

    def __post_init__(self):
        self.outdated_time = time.time() + min(self.ticket_lifetime, MAX_LIFETIME)
        self.obfuscated_ticket_age = (
            (self.ticket_lifetime * 1000) + self.ticket_age_add
        ) % AGE_MOD

    def is_outdated(self):
        return time.time() >= self.outdated_time

    def to_psk_identity(self):
        return PskIdentity(self.ticket, self.obfuscated_ticket_age)


class Handshake(schema.BinarySchema):
    msg_type = schema.SizedIntEnum(schema.uint8, HandshakeType)
    msg = schema.LengthPrefixedObject(
        schema.uint24be,
        schema.Switch(
            "msg_type",
            {
                HandshakeType.client_hello: ClientHello,
                HandshakeType.server_hello: ServerHello,
                HandshakeType.encrypted_extensions: schema.LengthPrefixedObjectList(
                    schema.uint16be, ServerExtension
                ),
                HandshakeType.certificate: Certificate,
                HandshakeType.certificate_verify: CertificateVerify,
                HandshakeType.finished: schema.Bytes(32),
                HandshakeType.new_session_ticket: NewSessionTicket,
                HandshakeType.end_of_early_data: schema.MustEqual(
                    schema.Bytes(-1), b""
                ),
                HandshakeType.key_update: schema.SizedIntEnum(
                    schema.uint8, KeyUpdateRequest
                ),
            },
        ),
    )


class Alert(schema.BinarySchema):
    level = schema.SizedIntEnum(schema.uint8, AlertLevel)
    description = schema.SizedIntEnum(schema.uint8, AlertDescription)


conten_type_cases = {
    ContentType.handshake: Handshake,
    ContentType.application_data: schema.Bytes(-1),
    ContentType.alert: Alert,
    ContentType.change_cipher_spec: schema.MustEqual(schema.Bytes(1), b"\x01"),
}


class TLSPlaintext(schema.BinarySchema):
    content_type = schema.SizedIntEnum(schema.uint8, ContentType)
    legacy_record_version = schema.Bytes(2)
    fragment = schema.LengthPrefixedBytes(schema.uint16be)

    # @classmethod
    # def get_handshake(cls, content_type: ContentType):
    #     plaintext = yield from cls.get_value()
    #     return Handshake.parse(plaintext.fragment)

    @classmethod
    def pack(cls, content_type: ContentType, data: bytes) -> bytes:
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
        is_handshake = content_type is ContentType.handshake
        return b"".join(
            cls(
                content_type,
                b"\x03\x01" if i == 0 and is_handshake else b"\x03\x03",
                bytes(frg),
            ).binary
            for i, frg in enumerate(fragments)
        )

    def is_overflow(self):
        return (
            self.content_type is ContentType.application_data
            and len(self.fragment) > (16384 + 256)
        ) or (
            self.content_type is not ContentType.application_data
            and len(self.fragment) > 16384
        )


class TLSInnerPlaintext(schema.BinarySchema):
    content = schema.Bytes(-1)
    content_type = schema.SizedIntEnum(schema.uint8, ContentType)
    padding = schema.Bytes(-1)

    def tls_ciphertext(self, cipher):
        return cipher.tls_ciphertext(self.binary)

    @classmethod
    def pack(cls, content, content_type):
        padding = b"\x00" * random.randint(0, 10)
        return cls(content, content_type, padding)

    @classmethod
    def from_alert(cls, alert: Alert):
        padding = b"\x00" * random.randint(0, 10)
        return cls(alert.binary, ContentType.alert, padding)

    @classmethod
    def from_handshake(cls, handshake: Handshake):
        padding = b"\x00" * random.randint(0, 10)
        return cls(handshake.binary, ContentType.handshake, padding)

    @classmethod
    def from_application_data(cls, payload: bytes):
        padding = b"\x00" * random.randint(0, 10)
        return cls(payload, ContentType.application_data, padding)

    @classmethod
    def get_value(cls):
        yield from iofree.wait()
        bytes_ = yield from iofree.read()
        bytes_without_padding = bytes_.rstrip(b"\x00")
        padding_len = len(bytes_) - len(bytes_without_padding)
        content = bytes_without_padding[:-1]
        content_type = bytes_without_padding[-1]
        return cls(content, ContentType(content_type), b"\x00" * padding_len)
