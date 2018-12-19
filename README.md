# tls1.3
pure python tls 1.3 implementation

## test

debug with openssl 1.1 or above:
~~~
/usr/local/opt/openssl@1.1/bin/openssl s_server -accept 1799  -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -key key.pem -cert cert.pem -debug -keylogfile key.txt -msg -state -tlsextdebug
/usr/local/opt/openssl@1.1/bin/openssl s_client -connect 127.0.0.1:1799 -tls1_3 -debug -keylogfile keylog.txt -msg -state -tlsextdebug
~~~

## Current Supported Features

#### Implementations

* Client ✓
* Server x

#### Cipher Suites

* TLS_AES_128_GCM_SHA256 ✓
* TLS_AES_256_GCM_SHA384 ✓
* TLS_CHACHA20_POLY1305_SHA256 ✓
* TLS_AES_128_CCM_SHA256 ✓
* TLS_AES_128_CCM_8_SHA256 ✓

#### Supported Groups Extension

* secp256r1 x
* secp384r1 x
* secp521r1 x
* x25519 ✓
* x448 x
* ffdhe2048 x
* ffdhe3072 x
* ffdhe4096 x
* ffdhe6144 x
* ffdhe8192 x

#### Key Exchange Modes

* (EC)HDE ✓
* PSK-only ✓
* PSK with (EC)DHE ✓

#### Others

* session resumption ✓
* early data ✓
* cookie x
* oid filters x
* post handshake auth x
