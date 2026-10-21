# Vendored libfido2

libfido2 1.15.0, Windows release from https://developers.yubico.com/libfido2/
License: BSD-2-Clause (Yubico). Bundled LibreSSL (crypto.dll), libcbor, zlib1.

- include/  — public headers (fido.h, fido/*, openssl/*, cbor/*)
- bin/      — runtime DLLs (fido2, cbor, crypto, zlib1) from Win64/Release/v143/dynamic
- lib/      — MinGW import libraries generated from the DLLs via gendef + dlltool

Regenerate import libs:
  cd bin && for d in fido2 cbor crypto zlib1; do \
    gendef $d.dll && x86_64-w64-mingw32-dlltool -d $d.def -D $d.dll -l ../lib/lib$d.a; done
