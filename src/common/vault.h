// Vault: protects a local account's password with AES-256-GCM under a key
// derived by HKDF-SHA256(ikm, salt, "fido2-win-auth vault v1").
//
// Where the ikm comes from is what separates the two modes, and it is the
// entire difference in how much the token is worth:
//
//   Fido2HmacSecret -- ikm is the token's hmac-secret output. It exists only
//     while the physical key is present and unlocked. The record is useless on
//     its own: no key, no plaintext, by arithmetic.
//
//   U2fPresence -- CTAP1 has no extension mechanism, so no hmac-secret and no
//     reproducible secret of any kind; a U2F assertion is a fresh signature
//     each time. The ikm is therefore a random value stored in the record,
//     DPAPI-protected to the machine, and the token's signature only gates
//     whether the software reads it back. Anything running as SYSTEM or
//     administrator can skip the token entirely. This mode trades the
//     cryptographic guarantee for working with CTAP1-only keys; it is opt-in
//     and both front-ends say so before using it.
//
// Record layouts:
//   "F2V1" | credId | salt(32) | nonce(12) | ciphertext+tag
//   "F2U1" | keyHandle | salt(32) | nonce(12) | ciphertext+tag
//           | pubKey | protectedIkm | counter(4)
//
// AAD binds the ciphertext to credId+salt, plus pubKey in U2F mode, so a
// record cannot be transplanted onto a different credential.
#pragma once

#include "bytes.h"

#include <cstdint>
#include <string>

enum class VaultMode {
    Fido2HmacSecret,  // the key holds the secret
    U2fPresence,      // the key only proves it is present
};

struct VaultRecord {
    VaultMode mode = VaultMode::Fido2HmacSecret;

    Bytes credId;      // FIDO2 credential id, or U2F key handle
    Bytes salt;        // 32-byte HKDF salt (also the hmac-secret salt)
    Bytes nonce;       // 12-byte AES-GCM nonce
    Bytes ciphertext;  // encrypted UTF-16LE password, with 16-byte GCM tag appended

    // U2fPresence only.
    Bytes pubKey;         // EC public key, to verify the assertion signature
    Bytes protectedIkm;   // DPAPI(machine) blob holding the vault ikm
    uint32_t counter = 0; // last accepted U2F signature counter

    Bytes Serialize() const;
    static VaultRecord Deserialize(const Bytes& blob);  // throws Fido2Error on bad input
};

namespace vault {

// Derives the 32-byte AES key from the raw hmac-secret output.
Bytes DeriveKey(const Bytes& hmacSecret, const Bytes& salt);

// Builds a Fido2HmacSecret record: generates the nonce, derives the key from
// hmacSecret, encrypts the password. The caller supplies hmacSecret obtained
// with this salt. Pass the salt so enrollment and the stored record agree.
VaultRecord Seal(const Bytes& credId, const Bytes& salt, const Bytes& hmacSecret,
                 const std::wstring& password);

// Recovers the password from a record given the ikm for record.salt -- the
// hmac-secret in FIDO2 mode, the unprotected stored ikm in U2F mode. Returns
// false if authentication fails (wrong key / tampered blob).
bool Open(const VaultRecord& rec, const Bytes& ikm, std::wstring& password);

// Builds a U2fPresence record. Generates a random ikm, seals the password with
// it, then stores the ikm DPAPI-protected to this machine. See the mode note
// above for what this does and does not protect against.
VaultRecord SealU2f(const Bytes& keyHandle, const Bytes& pubKey,
                    uint32_t counter, const std::wstring& password);

// Recovers the ikm of a U2fPresence record. Returns false if the DPAPI blob
// does not belong to this machine or does not match the record.
bool RecoverU2fIkm(const VaultRecord& rec, Bytes& ikm);

}  // namespace vault
