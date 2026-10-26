// Round-trip and tamper tests for the vault crypto. Builds as a Windows console
// exe and runs under Wine in CI; exercises Seal/Open, serialization, and the
// authentication/tamper paths. No hardware key required.
#include "../src/common/bytes.h"
#include "../src/common/vault.h"

#include <openssl/rand.h>

#include <cstdio>
#include <string>

static int g_fail = 0;

#define CHECK(cond, msg)                                     \
    do {                                                     \
        if (!(cond)) { printf("FAIL: %s\n", msg); ++g_fail; }\
        else printf("ok: %s\n", msg);                        \
    } while (0)

static Bytes RandomBytes(size_t n)
{
    Bytes b(n);
    RAND_bytes(b.data(), (int)n);
    return b;
}

int main()
{
    Bytes hmacSecret = RandomBytes(32);
    Bytes salt = RandomBytes(32);
    std::wstring password = L"Пароль-P@ssw0rd! тест";

    // 1. Basic seal/open round-trip.
    VaultRecord rec = vault::Seal(ToBytes("credential-id-bytes"), salt, hmacSecret,
                                  password);
    std::wstring recovered;
    bool ok = vault::Open(rec, hmacSecret, recovered);
    CHECK(ok, "Open succeeds with correct secret");
    CHECK(recovered == password, "recovered password matches original");

    // 2. Serialize -> Deserialize preserves the record and still opens.
    Bytes blob = rec.Serialize();
    VaultRecord rec2 = VaultRecord::Deserialize(blob);
    CHECK(rec2.credId == rec.credId && rec2.salt == rec.salt &&
              rec2.nonce == rec.nonce && rec2.ciphertext == rec.ciphertext,
          "serialize/deserialize is lossless");
    std::wstring recovered2;
    CHECK(vault::Open(rec2, hmacSecret, recovered2) && recovered2 == password,
          "deserialized record opens");

    // 3. Wrong secret fails to authenticate.
    Bytes wrongSecret = RandomBytes(32);
    std::wstring dummy;
    CHECK(!vault::Open(rec, wrongSecret, dummy), "Open fails with wrong secret");

    // 4. Flipping a ciphertext byte is detected by the GCM tag.
    VaultRecord tampered = rec;
    tampered.ciphertext[0] ^= 0x01;
    CHECK(!vault::Open(tampered, hmacSecret, dummy), "tampered ciphertext rejected");

    // 5. Changing the AAD (credId/salt) breaks authentication.
    VaultRecord movedId = rec;
    movedId.credId = ToBytes("different-credential-id");
    CHECK(!vault::Open(movedId, hmacSecret, dummy),
          "ciphertext bound to credId via AAD");

    // 6. Empty password round-trips.
    VaultRecord emptyRec = vault::Seal(ToBytes("id"), salt, hmacSecret, L"");
    std::wstring emptyOut = L"nonempty";
    CHECK(vault::Open(emptyRec, hmacSecret, emptyOut) && emptyOut.empty(),
          "empty password round-trips");

    // 7. Deserialize rejects a corrupt blob.
    bool threw = false;
    try {
        Bytes bad = {'x', 'x', 'x', 'x'};
        VaultRecord::Deserialize(bad);
    } catch (const std::exception&) { threw = true; }
    CHECK(threw, "Deserialize rejects bad magic");

    // 8. Different salts derive different keys (same secret, same password).
    Bytes salt2 = RandomBytes(32);
    VaultRecord recA = vault::Seal(ToBytes("id"), salt, hmacSecret, L"same");
    VaultRecord recB = vault::Seal(ToBytes("id"), salt2, hmacSecret, L"same");
    CHECK(recA.ciphertext != recB.ciphertext,
          "different salt yields different ciphertext");

    // 9. A U2F record survives serialization with all of its extra fields.
    {
        VaultRecord u2f;
        u2f.mode = VaultMode::U2fPresence;
        u2f.credId = ToBytes("key-handle");
        u2f.salt = RandomBytes(32);
        u2f.nonce = RandomBytes(12);
        u2f.ciphertext = RandomBytes(40);
        u2f.pubKey = RandomBytes(65);
        u2f.protectedIkm = RandomBytes(120);
        u2f.counter = 0x01020304;

        VaultRecord back = VaultRecord::Deserialize(u2f.Serialize());
        CHECK(back.mode == VaultMode::U2fPresence &&
                  back.credId == u2f.credId && back.salt == u2f.salt &&
                  back.nonce == u2f.nonce && back.ciphertext == u2f.ciphertext &&
                  back.pubKey == u2f.pubKey &&
                  back.protectedIkm == u2f.protectedIkm &&
                  back.counter == u2f.counter,
              "u2f record round-trips through serialization");
    }

    // 10. The two record kinds stay distinguishable: a FIDO2 record must not
    //     be read back as U2F, which would skip the hmac-secret entirely.
    {
        VaultRecord f2 = vault::Seal(ToBytes("id"), salt, hmacSecret, L"pw");
        VaultRecord back = VaultRecord::Deserialize(f2.Serialize());
        CHECK(back.mode == VaultMode::Fido2HmacSecret,
              "fido2 record keeps its mode");
    }

    // 11. A U2F record missing its public key or protected key is rejected
    //     rather than opened with whatever happens to be there.
    {
        VaultRecord u2f;
        u2f.mode = VaultMode::U2fPresence;
        u2f.credId = ToBytes("kh");
        u2f.salt = RandomBytes(32);
        u2f.nonce = RandomBytes(12);
        u2f.ciphertext = RandomBytes(40);
        u2f.pubKey = Bytes();
        u2f.protectedIkm = RandomBytes(16);

        bool rejected = false;
        try {
            VaultRecord::Deserialize(u2f.Serialize());
        } catch (const std::exception&) { rejected = true; }
        CHECK(rejected, "u2f record without a public key is rejected");
    }

    // 12. The public key is bound into the AAD: swapping it must break the
    //     ciphertext even when the vault key is right.
    {
        Bytes ikm = RandomBytes(32);
        VaultRecord rec;
        rec.mode = VaultMode::U2fPresence;
        rec.credId = ToBytes("kh");
        rec.pubKey = RandomBytes(65);
        rec.salt = RandomBytes(32);

        // Seal through the same path SealU2f uses, without DPAPI.
        VaultRecord sealed = vault::Seal(rec.credId, rec.salt, ikm, L"secret");
        sealed.mode = VaultMode::U2fPresence;
        sealed.pubKey = rec.pubKey;

        std::wstring out;
        CHECK(!vault::Open(sealed, ikm, out),
              "public key is bound into the AAD");
    }

    printf(g_fail ? "\n%d test(s) FAILED\n" : "\nAll tests passed\n", g_fail);
    return g_fail ? 1 : 0;
}
