import hmac
import hkdf
import hashlib


class TlsHash:
    def __init__(self, hashmod=hashlib.sha256):
        self.hashmod = hashmod
        self.hash_len = hashmod().digest_size

    def hkdf_extract(self, salt: bytes, input_key_material: bytes) -> bytes:
        if input_key_material is None:
            input_key_material = b"\x00" * self.hash_len
        return hkdf.hkdf_extract(salt, input_key_material, self.hashmod)

    def hkdf_label(self, label: bytes, context: bytes, length: int) -> bytes:
        label = b"tls13 " + label
        return (
            length.to_bytes(2, "big")
            + len(label).to_bytes(1, "big")
            + label
            + len(context).to_bytes(1, "big")
            + context
        )

    def hkdf_expand_label(
        self, secret: bytes, label: bytes, context: bytes, length: int
    ) -> bytes:
        hkdf_label = self.hkdf_label(label, context, length)
        return hkdf.hkdf_expand(secret, hkdf_label, length, self.hashmod)

    def derive_secret(self, secret: bytes, label: bytes, messages) -> bytes:
        if type(messages) == list:
            messages = b"".join(messages)
        return self.hkdf_expand_label(
            secret, label, self.hashmod(messages).digest(), self.hash_len
        )

    def transcript_hash(self, *msgs):
        return self.hashmod(b"".join(msgs)).digest()

    # def transcript_hash(self, client_hello_data, *others):
    #     digest = self.hashmod(client_hello_data).digest()
    #     return self.hashmod(
    #         b"\xfe\x00\x00"
    #         + self.hash_len.to_bytes(1, "big")
    #         + digest
    #         + b"".join(others)
    #     ).digest()

    def derive_key(self, secret: bytes, key_length: int) -> bytes:
        return self.hkdf_expand_label(secret, b"key", b"", key_length)

    def derive_iv(self, secret: bytes, iv_length: int) -> bytes:
        return self.hkdf_expand_label(secret, b"iv", b"", iv_length)

    def finished_key(self, base_key: bytes) -> bytes:
        return self.hkdf_expand_label(base_key, b"finished", b"", self.hash_len)

    def verify_data(self, secret: bytes, msg: bytes) -> bytes:
        return hmac.new(
            self.finished_key(secret), self.transcript_hash(msg), self.hashmod
        ).digest()

    def scheduler(self, ecdhe: bytes, psk: bytes = None):
        return KeyScheduler(self, ecdhe, psk)


tls_sha256 = TlsHash()
tls_sha384 = TlsHash(hashlib.sha384)


class PSKWrapper:
    def __init__(self, psk: bytes, tls_hash=tls_sha256, is_ext: bool = True):
        self.tls_hash = tls_hash
        self.early_secret = self.tls_hash.hkdf_extract(None, psk)
        self.is_ext = is_ext

    def ext_binder_key(self) -> bytes:
        return self.tls_hash.derive_secret(self.early_secret, b"ext binder", b"")

    def res_binder_key(self) -> bytes:
        return self.tls_hash.derive_secret(self.early_secret, b"res binder", b"")

    def binder_key(self) -> bytes:
        return self.ext_binder_key() if self.is_ext else self.res_binder_key()

    def client_early_traffic_secret(self, messages) -> bytes:
        return self.tls_hash.derive_secret(self.early_secret, b"c e traffic", messages)

    def early_exporter_master_secret(self, messages) -> bytes:
        return self.tls_hash.derive_secret(self.early_secret, b"e exp master", messages)


class KeyScheduler:
    def __init__(self, tls_hash, ecdhe: bytes, psk: bytes = None):
        self.tls_hash = tls_hash
        self.ecdhe = ecdhe

        self.early_secret = self.tls_hash.hkdf_extract(None, psk)
        self.first_salt = self.tls_hash.derive_secret(
            self.early_secret, b"derived", b""
        )
        self.handshake_secret = self.tls_hash.hkdf_extract(self.first_salt, self.ecdhe)
        self.second_salt = self.tls_hash.derive_secret(
            self.handshake_secret, b"derived", b""
        )
        self.master_secret = self.tls_hash.hkdf_extract(self.second_salt, None)

    def client_handshake_traffic_secret(self, messages) -> bytes:
        return self.tls_hash.derive_secret(
            self.handshake_secret, b"c hs traffic", messages
        )

    def server_handshake_traffic_secret(self, messages) -> bytes:
        return self.tls_hash.derive_secret(
            self.handshake_secret, b"s hs traffic", messages
        )

    def client_application_traffic_secret_0(self, messages) -> bytes:
        return self.tls_hash.derive_secret(
            self.master_secret, b"c ap traffic", messages
        )

    def server_application_traffic_secret_0(self, messages) -> bytes:
        return self.tls_hash.derive_secret(
            self.master_secret, b"s ap traffic", messages
        )

    def exporter_master_secret(self, messages) -> bytes:
        return self.tls_hash.derive_secret(self.master_secret, b"exp master", messages)

    def resumption_master_secret(self, messages) -> bytes:
        return self.tls_hash.derive_secret(self.master_secret, b"res master", messages)

    def resumption_psk(self, messages, ticket_nonce: bytes) -> bytes:
        secret = self.resumption_master_secret(messages)
        return self.tls_hash.hkdf_expand_label(
            secret, b"resumption", ticket_nonce, self.tls_hash.hash_len
        )
