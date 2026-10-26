// Vault implementation: HKDF-SHA256 key derivation + AES-256-GCM sealing.
// See vault.h for the record layout and the cryptographic contract.
#include "vault.h"

#include "dpapi.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <cstring>
#include <memory>

namespace {

constexpr char kMagic[4] = {'F', '2', 'V', '1'};
constexpr char kMagicU2f[4] = {'F', '2', 'U', '1'};
constexpr size_t kSaltLen = 32;
constexpr size_t kNonceLen = 12;
constexpr size_t kTagLen = 16;
constexpr size_t kKeyLen = 32;
// Domain-separation string bound into the HKDF expansion.
const char* kInfo = "fido2-win-auth vault v1";

// RAII wrappers so an exception never leaks an OpenSSL object.
struct EvpCipherCtx {
    EVP_CIPHER_CTX* p = EVP_CIPHER_CTX_new();
    ~EvpCipherCtx() { if (p) EVP_CIPHER_CTX_free(p); }
};
struct EvpPkeyCtx {
    EVP_PKEY_CTX* p;
    explicit EvpPkeyCtx(EVP_PKEY_CTX* c) : p(c) {}
    ~EvpPkeyCtx() { if (p) EVP_PKEY_CTX_free(p); }
};

void PutU32(Bytes& b, uint32_t v)
{
    b.push_back((uint8_t)(v >> 24));
    b.push_back((uint8_t)(v >> 16));
    b.push_back((uint8_t)(v >> 8));
    b.push_back((uint8_t)(v));
}

uint32_t GetU32(const Bytes& b, size_t& off)
{
    if (off + 4 > b.size()) throw Fido2Error("vault record truncated");
    uint32_t v = ((uint32_t)b[off] << 24) | ((uint32_t)b[off + 1] << 16) |
                 ((uint32_t)b[off + 2] << 8) | ((uint32_t)b[off + 3]);
    off += 4;
    return v;
}

Bytes GetBytes(const Bytes& b, size_t& off, uint32_t n)
{
    if (off + n > b.size()) throw Fido2Error("vault record truncated");
    Bytes r(b.begin() + off, b.begin() + off + n);
    off += n;
    return r;
}

}  // namespace

Bytes VaultRecord::Serialize() const
{
    const bool u2f = mode == VaultMode::U2fPresence;

    Bytes out;
    out.insert(out.end(), u2f ? kMagicU2f : kMagic, (u2f ? kMagicU2f : kMagic) + 4);
    PutU32(out, (uint32_t)credId.size());
    out.insert(out.end(), credId.begin(), credId.end());
    PutU32(out, (uint32_t)salt.size());
    out.insert(out.end(), salt.begin(), salt.end());
    PutU32(out, (uint32_t)nonce.size());
    out.insert(out.end(), nonce.begin(), nonce.end());
    PutU32(out, (uint32_t)ciphertext.size());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    if (u2f) {
        PutU32(out, (uint32_t)pubKey.size());
        out.insert(out.end(), pubKey.begin(), pubKey.end());
        PutU32(out, (uint32_t)protectedIkm.size());
        out.insert(out.end(), protectedIkm.begin(), protectedIkm.end());
        PutU32(out, counter);
    }
    return out;
}

VaultRecord VaultRecord::Deserialize(const Bytes& blob)
{
    if (blob.size() < 4) throw Fido2Error("vault record: bad magic");

    VaultRecord rec;
    if (std::memcmp(blob.data(), kMagic, 4) == 0) {
        rec.mode = VaultMode::Fido2HmacSecret;
    } else if (std::memcmp(blob.data(), kMagicU2f, 4) == 0) {
        rec.mode = VaultMode::U2fPresence;
    } else {
        throw Fido2Error("vault record: bad magic");
    }

    size_t off = 4;
    rec.credId = GetBytes(blob, off, GetU32(blob, off));
    rec.salt = GetBytes(blob, off, GetU32(blob, off));
    rec.nonce = GetBytes(blob, off, GetU32(blob, off));
    rec.ciphertext = GetBytes(blob, off, GetU32(blob, off));
    if (rec.mode == VaultMode::U2fPresence) {
        rec.pubKey = GetBytes(blob, off, GetU32(blob, off));
        rec.protectedIkm = GetBytes(blob, off, GetU32(blob, off));
        rec.counter = GetU32(blob, off);
        if (rec.pubKey.empty()) throw Fido2Error("vault record: missing public key");
        if (rec.protectedIkm.empty())
            throw Fido2Error("vault record: missing protected key");
    }
    if (off != blob.size()) throw Fido2Error("vault record: trailing bytes");
    if (rec.salt.size() != kSaltLen) throw Fido2Error("vault record: bad salt");
    if (rec.nonce.size() != kNonceLen) throw Fido2Error("vault record: bad nonce");
    if (rec.ciphertext.size() < kTagLen)
        throw Fido2Error("vault record: ciphertext too short");
    return rec;
}

namespace vault {

Bytes DeriveKey(const Bytes& hmacSecret, const Bytes& salt)
{
    if (hmacSecret.empty()) throw Fido2Error("DeriveKey: empty hmac-secret");

    EvpPkeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx.p) throw Fido2Error("HKDF: EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_derive_init(ctx.p) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.p, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.p, salt.data(), (int)salt.size()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.p, hmacSecret.data(),
                                   (int)hmacSecret.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.p, (const uint8_t*)kInfo,
                                    (int)std::strlen(kInfo)) <= 0)
        throw Fido2Error("HKDF: parameter setup failed");

    Bytes key(kKeyLen);
    size_t keyLen = kKeyLen;
    if (EVP_PKEY_derive(ctx.p, key.data(), &keyLen) <= 0 || keyLen != kKeyLen)
        throw Fido2Error("HKDF: derive failed");
    return key;
}

// Associated data binds the ciphertext to this credential and salt so a record
// cannot be transplanted onto a different credId/salt without detection.
static Bytes MakeAad(const Bytes& credId, const Bytes& salt)
{
    return Concat(credId, salt);
}

// In U2F mode the public key is part of the record's identity, so bind it too:
// swapping in another key's public key then invalidates the ciphertext.
static Bytes MakeAadFor(const VaultRecord& rec)
{
    Bytes aad = MakeAad(rec.credId, rec.salt);
    if (rec.mode == VaultMode::U2fPresence)
        aad = Concat(aad, rec.pubKey);
    return aad;
}

// Shared sealing step: fills rec.nonce and rec.ciphertext by encrypting the
// password under HKDF(ikm, rec.salt). Both modes differ only in where ikm
// comes from and in what MakeAadFor() binds, so the GCM code lives once.
static void SealInto(VaultRecord& rec, const Bytes& ikm, const std::wstring& password)
{
    if (rec.salt.size() != kSaltLen) throw Fido2Error("Seal: bad salt length");

    rec.nonce.resize(kNonceLen);
    if (RAND_bytes(rec.nonce.data(), (int)rec.nonce.size()) != 1)
        throw Fido2Error("Seal: RAND_bytes failed");

    Bytes key = DeriveKey(ikm, rec.salt);

    // Plaintext = UTF-16LE password bytes (matches what Windows logon expects).
    Bytes pt;
    pt.resize(password.size() * sizeof(wchar_t));
    for (size_t i = 0; i < password.size(); ++i) {
        uint16_t c = (uint16_t)password[i];
        pt[i * 2] = (uint8_t)(c & 0xff);
        pt[i * 2 + 1] = (uint8_t)(c >> 8);
    }

    Bytes aad = MakeAadFor(rec);

    EvpCipherCtx ctx;
    if (!ctx.p) { SecureClear(key); SecureClear(pt); throw Fido2Error("Seal: ctx alloc failed"); }

    Bytes ct(pt.size());
    Bytes tag(kTagLen);
    int outLen = 0;
    bool ok =
        EVP_EncryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, (int)kNonceLen, nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx.p, nullptr, nullptr, key.data(), rec.nonce.data()) == 1;
    int tmp = 0;
    if (ok && !aad.empty())
        ok = EVP_EncryptUpdate(ctx.p, nullptr, &tmp, aad.data(), (int)aad.size()) == 1;
    if (ok && !pt.empty())
        ok = EVP_EncryptUpdate(ctx.p, ct.data(), &outLen, pt.data(), (int)pt.size()) == 1;
    int finalLen = 0;
    if (ok)
        ok = EVP_EncryptFinal_ex(ctx.p, ct.data() + outLen, &finalLen) == 1;
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_GET_TAG, (int)kTagLen, tag.data()) == 1;

    SecureClear(key);
    SecureClear(pt);
    if (!ok) { SecureClear(ct); throw Fido2Error("Seal: AES-256-GCM encrypt failed"); }

    ct.resize(outLen + finalLen);
    rec.ciphertext = Concat(ct, tag);
    SecureClear(ct);
}

VaultRecord Seal(const Bytes& credId, const Bytes& salt, const Bytes& hmacSecret,
                 const std::wstring& password)
{
    VaultRecord rec;
    rec.mode = VaultMode::Fido2HmacSecret;
    rec.credId = credId;
    rec.salt = salt;
    SealInto(rec, hmacSecret, password);
    return rec;
}

// The DPAPI blob is bound to this credential, so it cannot be lifted from one
// record and dropped into another on the same machine.
static Bytes IkmEntropy(const Bytes& keyHandle, const Bytes& pubKey)
{
    return Concat(keyHandle, pubKey);
}

VaultRecord SealU2f(const Bytes& keyHandle, const Bytes& pubKey, uint32_t counter,
                    const std::wstring& password)
{
    if (keyHandle.empty()) throw Fido2Error("SealU2f: empty key handle");
    if (pubKey.empty()) throw Fido2Error("SealU2f: empty public key");

    VaultRecord rec;
    rec.mode = VaultMode::U2fPresence;
    rec.credId = keyHandle;
    rec.pubKey = pubKey;
    rec.counter = counter;
    rec.salt.resize(kSaltLen);
    if (RAND_bytes(rec.salt.data(), (int)rec.salt.size()) != 1)
        throw Fido2Error("SealU2f: RAND_bytes failed");

    // The ikm the token cannot supply: random, and kept on the machine.
    Bytes ikm(kKeyLen);
    if (RAND_bytes(ikm.data(), (int)ikm.size()) != 1) {
        SecureClear(ikm);
        throw Fido2Error("SealU2f: RAND_bytes failed");
    }

    try {
        SealInto(rec, ikm, password);
        rec.protectedIkm = dpapi::Protect(ikm, IkmEntropy(keyHandle, pubKey));
    } catch (...) {
        SecureClear(ikm);
        throw;
    }
    SecureClear(ikm);
    return rec;
}

bool RecoverU2fIkm(const VaultRecord& rec, Bytes& ikm)
{
    if (rec.mode != VaultMode::U2fPresence) return false;
    return dpapi::Unprotect(rec.protectedIkm, IkmEntropy(rec.credId, rec.pubKey), ikm);
}

bool Open(const VaultRecord& rec, const Bytes& ikm, std::wstring& password)
{
    if (rec.ciphertext.size() < kTagLen) return false;

    Bytes key;
    try {
        key = DeriveKey(ikm, rec.salt);
    } catch (const std::exception&) {
        return false;
    }

    const size_t ctLen = rec.ciphertext.size() - kTagLen;
    const uint8_t* ctPtr = rec.ciphertext.data();
    const uint8_t* tagPtr = rec.ciphertext.data() + ctLen;
    Bytes aad = MakeAadFor(rec);

    EvpCipherCtx ctx;
    if (!ctx.p) { SecureClear(key); return false; }

    Bytes pt(ctLen);
    int outLen = 0, tmp = 0;
    bool ok =
        EVP_DecryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, (int)kNonceLen, nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx.p, nullptr, nullptr, key.data(), rec.nonce.data()) == 1;
    if (ok && !aad.empty())
        ok = EVP_DecryptUpdate(ctx.p, nullptr, &tmp, aad.data(), (int)aad.size()) == 1;
    if (ok && ctLen > 0)
        ok = EVP_DecryptUpdate(ctx.p, pt.data(), &outLen, ctPtr, (int)ctLen) == 1;
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_TAG, (int)kTagLen,
                                 (void*)tagPtr) == 1;
    int finalLen = 0;
    if (ok)
        ok = EVP_DecryptFinal_ex(ctx.p, pt.data() + outLen, &finalLen) == 1;

    SecureClear(key);
    if (!ok) { SecureClear(pt); return false; }

    const size_t total = (size_t)outLen + finalLen;
    if (total % sizeof(wchar_t) != 0) { SecureClear(pt); return false; }

    password.assign(total / sizeof(wchar_t), L'\0');
    for (size_t i = 0; i < password.size(); ++i)
        password[i] = (wchar_t)((uint16_t)pt[i * 2] | ((uint16_t)pt[i * 2 + 1] << 8));
    SecureClear(pt);
    return true;
}

}  // namespace vault
