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

    printf(g_fail ? "\n%d test(s) FAILED\n" : "\nAll tests passed\n", g_fail);
    return g_fail ? 1 : 0;
}
