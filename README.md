# tls1.3
pure python tls 1.3 implementation

## test

debug with openssl 1.1 or above:
~~~
/usr/local/opt/openssl@1.1/bin/openssl s_server -accept 1799  -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -key key.pem -cert cert.pem -debug -keylogfile key.txt -msg -state -tlsextdebug
/usr/local/opt/openssl@1.1/bin/openssl s_client -connect 127.0.0.1:1799 -tls1_3 -debug -keylogfile keylog.txt -msg -state -tlsextdebug
~~~
