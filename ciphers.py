import abc
import nacl.bindings
from Crypto.Cipher import AES
from key_schedule import tls_sha256, tls_sha384


class TLS_AEAD_Cipher(abc.ABC):
    NONCE_LEN = 12

    @property
    @abc.abstractmethod
    def KEY_LEN(self):
        ""

    @property
    @abc.abstractmethod
    def MAC_LEN(self):
        ""

    @property
    @abc.abstractmethod
    def tls_hash(self):
        ""

    @abc.abstractmethod
    def cipher(self):
        ""

    def __init__(self, secret):
        self.reset(secret)

    def reset(self, secret):
        self.secret = secret
        self.key = self.tls_hash.derive_key(self.secret, self.KEY_LEN)
        self.iv = int.from_bytes(
            self.tls_hash.derive_iv(self.secret, self.NONCE_LEN), "big"
        )
        self.sequence_number = 0

    def get_nonce(self):
        # nonce = struct.pack(f"!{self.NONCE_LEN-8}xQ", self.sequence_number)
        nonce = self.sequence_number ^ self.iv
        nonce = nonce.to_bytes(self.NONCE_LEN, "big")
        self.sequence_number += 1
        return nonce

    def decrypt(self, ciphertext, associated_data):
        cipher = self.cipher()
        cipher.update(associated_data)
        return cipher.decrypt_and_verify(
            ciphertext[: -self.MAC_LEN], ciphertext[-self.MAC_LEN :]
        )


class TLS_CHACHA20_POLY1305_SHA256(TLS_AEAD_Cipher):
    KEY_LEN = 32
    MAC_LEN = 16
    tls_hash = tls_sha256

    def cipher(self):
        ""

    def decrypt(self, ciphertext, associated_data):
        nonce = self.get_nonce()
        return nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
            bytes(ciphertext), associated_data, nonce, self.key
        )


class TLS_AES_128_GCM_SHA256(TLS_AEAD_Cipher):
    KEY_LEN = 16
    MAC_LEN = 16
    tls_hash = tls_sha256

    def cipher(self):
        return AES.new(
            self.key, AES.MODE_GCM, nonce=self.get_nonce(), mac_len=self.MAC_LEN
        )


class TLS_AES_256_GCM_SHA384(TLS_AEAD_Cipher):
    KEY_LEN = 32
    MAC_LEN = 16
    tls_hash = tls_sha384

    def cipher(self):
        return AES.new(
            self.key, AES.MODE_GCM, nonce=self.get_nonce(), mac_len=self.MAC_LEN
        )


class TLS_AES_128_CCM_SHA256(TLS_AEAD_Cipher):
    KEY_LEN = 16
    MAC_LEN = 16
    tls_hash = tls_sha256

    def cipher(self):
        return AES.new(
            self.key, AES.MODE_CCM, nonce=self.get_nonce(), mac_len=self.MAC_LEN
        )


class TLS_AES_128_CCM_8_SHA256(TLS_AEAD_Cipher):
    tls_hash = tls_sha256

    def cipher(self):
        return AES.new(
            self.key, AES.MODE_CCM, nonce=self.get_nonce(), mac_len=self.MAC_LEN
        )
