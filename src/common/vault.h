// Vault: protects a local account's password with a key derived from the
// token's hmac-secret output. Nothing in the vault record is secret on its own;
// without the physical key (and its PIN) the ciphertext cannot be opened.
//
// Record layout (all fields serialized by VaultRecord::Serialize):
//   magic "F2V1" | credId | salt(32) | nonce(12) | ciphertext+tag
// The AES-256 key = HKDF-SHA256(ikm = hmac-secret, salt = record.salt,
// info = "fido2-win-auth vault v1"). AAD binds the ciphertext to credId+salt.
#pragma once

#include "bytes.h"

#include <string>

struct VaultRecord {
    Bytes credId;      // FIDO2 credential id, sent in the assertion allow-list
    Bytes salt;        // 32-byte hmac-secret salt (also HKDF salt)
    Bytes nonce;       // 12-byte AES-GCM nonce
    Bytes ciphertext;  // encrypted UTF-16LE password, with 16-byte GCM tag appended

    Bytes Serialize() const;
    static VaultRecord Deserialize(const Bytes& blob);  // throws Fido2Error on bad input
};

namespace vault {

// Derives the 32-byte AES key from the raw hmac-secret output.
Bytes DeriveKey(const Bytes& hmacSecret, const Bytes& salt);

// Builds a record: generates salt+nonce, derives the key from hmacSecret,
// encrypts the password. The caller supplies hmacSecret obtained with this salt.
// Pass the salt so enrollment and the stored record agree.
VaultRecord Seal(const Bytes& credId, const Bytes& salt, const Bytes& hmacSecret,
                 const std::wstring& password);

// Recovers the password from a record given the hmac-secret obtained for
// record.salt. Returns false if authentication fails (wrong key / tampered blob).
bool Open(const VaultRecord& rec, const Bytes& hmacSecret, std::wstring& password);

}  // namespace vault
