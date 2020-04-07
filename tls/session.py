import os
from . import models
import iofree
import typing
from nacl.public import PrivateKey
from nacl.bindings import crypto_scalarmult
from . import ciphers
from .key_schedule import PSKWrapper

# from cryptography.hazmat.backends import default_backend
# from cryptography import x509
# from OpenSSL.crypto import load_certificate, FILETYPE_ASN1
# backend = default_backend()


class ProtocolError(Exception):
    ""


def new_x25519():
    private_key = PrivateKey.generate()
    key_exchange = bytes(private_key.public_key)
    return private_key, key_exchange


class TLSClientSession:
    def __init__(
        self,
        server_names: typing.List[str] = "",
        psk: typing.List[bytes] = None,
        psk_only: bool = False,
        psk_label: bytes = b"Client_identity",
        psk_identities=None,
        early_data: bytes = None,
    ):
        if type(server_names) == str:
            server_names = [server_names]
        self.server_names = server_names
        self.private_key, self.key_exchange = new_x25519()
        self.early_data = early_data
        self.server_finished = False
        self.session_tickets = []
        self.psk_only = psk_only or bool(early_data)
        self.psk_list = isinstance(psk, (list, tuple)) and psk or [psk]
        self.psk_identities = psk_identities
        self.psk_label = psk_label
        self._parser = iofree.Parser(self._client())

    def client_hello(self):
        extensions = [
            models.ClientExtension.server_names(self.server_names),
            models.ClientExtension.supported_versions([b"\x03\x04"]),
            models.ClientExtension.key_share(
                [models.KeyShareEntry(models.NamedGroup.x25519, self.key_exchange)]
            ),
            models.ClientExtension.signature_algorithms(list(models.SignatureScheme)),
            models.ClientExtension.supported_groups([models.NamedGroup.x25519]),
        ]
        if self.early_data:
            if not self.psk_list:
                raise Exception("early data should only send with psk support")
            extensions.insert(2, models.ClientExtension.early_data(b""))
        if self.psk_list:
            if self.psk_only:
                ext = models.ClientExtension.psk_key_exchange_modes(
                    [models.PskKeyExchangeMode.psk_ke]
                )
            else:
                ext = models.ClientExtension.psk_key_exchange_modes(
                    [models.PskKeyExchangeMode.psk_dhe_ke]
                )
            extensions.append(ext)
            psk_wrappers = [
                PSKWrapper(psk, is_ext=self.psk_identities is None)
                for psk in self.psk_list
            ]
            ext = models.ClientExtension.pre_shared_key(
                models.OfferedPsks(
                    [models.PskIdentity(self.psk_label, 0) for _ in psk_wrappers],
                    [
                        b"\x00" * psk_wrapper.tls_hash.hash_len
                        for psk_wrapper in psk_wrappers
                    ],
                )
            )
            binder_length = 2 + sum(
                psk_wrapper.tls_hash.hash_len + 1 for psk_wrapper in psk_wrappers
            )
            extensions.append(ext)
        # hello_retry_request_randbytes = bytes.fromhex(
        #     "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
        # )

        compatibility_mode = True
        handshake = models.Handshake(
            models.HandshakeType.client_hello,
            models.ClientHello(
                ...,
                os.urandom(32),
                os.urandom(32) if compatibility_mode else b"",
                list(models.CipherSuite),
                ...,
                extensions,
            ),
        )
        self.client_hello_data = handshake.binary

        if self.psk_list:
            to_verify = self.client_hello_data[:-binder_length]
            binders = models.OfferedPsks.binders(
                [
                    psk_wrapper.tls_hash.verify_data(
                        psk_wrapper.binder_key(), to_verify
                    )
                    for psk_wrapper in psk_wrappers
                ]
            )
            self.client_hello_data = to_verify + binders
        self.handshake_context = bytearray(self.client_hello_data)

        if self.early_data:
            TLSCipher = ciphers.TLS_CHACHA20_POLY1305_SHA256
            psk_wrapper = psk_wrappers[0]
            self.cipher = TLSCipher(
                psk_wrapper.client_early_traffic_secret(self.handshake_context)
            )

            inner_plaintext = models.TLSInnerPlaintext.from_application_data(
                self.early_data
            )
            self.packed_early_data = inner_plaintext.tls_ciphertext(self.cipher)
        # data = models.TLSPlaintext.pack(
        #     models.ContentType.handshake, self.client_hello_data
        # )
        data = models.ContentType.handshake.tls_plaintext(self.client_hello_data)
        return self.early_data and data + self.packed_early_data or data

    def send(self, data: bytes) -> bytes:
        return self.pack_application_data(data)

    def close(self):
        return self.pack_close()

    def resumption(self):
        if self.session_tickets:
            psk = [
                self.key_scheduler.resumption_psk(
                    self.handshake_context, session_ticket.ticket_nonce
                )
                for session_ticket in self.session_tickets
            ]
            psk_identities = [
                session_ticket.to_psk_identity()
                for session_ticket in self.session_tickets
            ]
            # psk_only = bool(self.session_tickets[0].max_early_data_size)
        else:
            psk = self.psk
            psk_identities = None
            psk_only = self.psk_only
        return TLSClientSession(
            self.server_names, psk=psk, psk_only=psk_only, psk_identities=psk_identities
        )

    def client_finish(self):
        to_send = bytearray()
        if self.early_data:
            data = models.TLSInnerPlaintext.from_handshake(
                models.Handshake(models.HandshakeType.end_of_early_data, b"")
            ).tls_ciphertext(self.cipher)
            to_send.extend(data)

        # client handshake cipher
        change_cipher_spec = models.ContentType.change_cipher_spec.tls_plaintext(
            b"\x01"
        )
        to_send.extend(change_cipher_spec)
        cipher = self.TLSCipher(self.client_handshake_traffic_secret)
        client_finished = cipher.verify_data(self.handshake_context)
        inner_plaintext = models.TLSInnerPlaintext.from_handshake(
            models.Handshake(models.HandshakeType.finished, client_finished)
        )
        record = inner_plaintext.tls_ciphertext(cipher)
        # client application cipher
        client_secret = self.key_scheduler.client_application_traffic_secret_0(
            self.handshake_context
        )
        self.cipher = self.TLSCipher(client_secret)
        self.handshake_context.extend(inner_plaintext.content)
        to_send.extend(record)
        return bytes(to_send)

    def _client(self):
        parser = yield from iofree.get_parser()
        parser.respond(data=self.client_hello())
        plain_text = yield from models.TLSPlaintext.get_value()
        assert plain_text.content_type is models.ContentType.handshake
        self.peer_handshake = models.Handshake.parse(plain_text.fragment)
        self.handshake_context.extend(plain_text.fragment)
        print("plaintext handshake:", self.peer_handshake.msg_type)
        server_hello = self.peer_handshake.msg
        peer_pk = server_hello.extensions_dict[
            models.ExtensionType.key_share
        ].key_exchange
        shared_key = crypto_scalarmult(bytes(self.private_key), peer_pk)
        self.TLSCipher = server_hello.get_cipher()
        key_index = server_hello.extensions_dict.get(
            models.ExtensionType.pre_shared_key
        )
        psk = None if key_index is None else self.psk_list[key_index]
        self.key_scheduler = self.TLSCipher.tls_hash.scheduler(shared_key, psk)
        secret = self.key_scheduler.server_handshake_traffic_secret(
            self.handshake_context
        )
        # server handshake cipher
        self.peer_cipher = self.TLSCipher(secret)
        self.client_handshake_traffic_secret = self.key_scheduler.client_handshake_traffic_secret(
            self.handshake_context
        )
        plain_text = yield from models.TLSPlaintext.get_value()
        assert plain_text.content_type is models.ContentType.change_cipher_spec
        print("plaintext:", plain_text.content_type)
        while True:
            plain_text = yield from models.TLSPlaintext.get_value()
            if plain_text.is_overflow():
                parser.respond(
                    data=self.pack_fatal(models.AlertDescription.record_overflow),
                    close=True,
                    exc=ProtocolError("text overflow"),
                )
                return
            if plain_text.content_type is models.ContentType.application_data:
                content = self.peer_cipher.decrypt(
                    plain_text.fragment, plain_text.binary[:5]
                )  # .rstrip(b"\x00")
                inner_text = models.TLSInnerPlaintext.parse(content)
                if inner_text.content_type is models.ContentType.handshake:
                    handshake = models.Handshake.parse(inner_text.content)
                    print("inner_text:", handshake.msg_type)
                    if handshake.msg_type is models.HandshakeType.key_update:
                        self.server_secret = self.key_scheduler.application_traffic_secret_N(
                            self.server_secret
                        )
                        self.peer_cipher = self.TLSCipher(self.server_secret)
                    if handshake.msg_type is models.HandshakeType.finished:
                        assert handshake.msg == self.peer_cipher.verify_data(
                            self.handshake_context
                        ), "server handshake finished does not match"
                        self.server_finished = True
                    self.handshake_context.extend(inner_text.content)
                    if self.server_finished:
                        # server application cipher
                        self.server_secret = self.key_scheduler.server_application_traffic_secret_0(
                            self.handshake_context
                        )
                        self.peer_cipher = self.TLSCipher(self.server_secret)
                        parser.respond(data=self.client_finish(), result=True)
                        print("connected")
                        self.server_finished = False
                elif inner_text.content_type is models.ContentType.application_data:
                    parser.respond(result=inner_text.content)
                else:
                    print(inner_text)
            elif plain_text.content_type is models.ContentType.alert:
                print(models.Alert.parse(plain_text.fragment))
            else:
                print(plain_text.content_type)

    def pack_application_data(self, payload: bytes) -> bytes:
        return models.TLSInnerPlaintext.from_application_data(payload).tls_ciphertext(
            self.cipher
        )

    def pack_alert(
        self, description: models.AlertDescription, level: models.AlertLevel
    ) -> bytes:
        alert = models.Alert(level, description)
        if self.cipher:
            return models.TLSInnerPlaintext.from_alert(alert).tls_ciphertext(
                self.cipher
            )
        else:
            return models.ContentType.alert.tls_plaintext(alert.binary)

    def pack_warning(self, description: models.AlertDescription) -> bytes:
        return self.pack_alert(description, models.AlertLevel.warning)

    def pack_fatal(self, description: models.AlertDescription) -> bytes:
        return self.pack_alert(description, models.AlertLevel.fatal)

    def pack_close(self) -> bytes:
        return self.pack_warning(models.AlertDescription.close_notify)

    def pack_canceled(self) -> bytes:
        return self.pack_warning(models.AlertDescription.user_canceled)
