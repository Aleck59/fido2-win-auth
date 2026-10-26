#include "unlock.h"

#include "token.h"

namespace unlock {
namespace {

Outcome Fail(const std::wstring& error, bool wrongKey = false)
{
    Outcome o;
    o.ok = false;
    o.error = error;
    o.wrongKey = wrongKey;
    return o;
}

// U2F signature counters must move forward; going backwards is the signal
// CTAP1 gives for a cloned key. A key that always reports 0 does not implement
// the counter, which the spec permits, so that cannot be treated as failure.
bool CounterAcceptable(uint32_t stored, uint32_t got)
{
    if (stored == 0 && got == 0) return true;
    return got > stored;
}

Outcome Fido2(const VaultRecord& rec, const std::string& devicePath,
              const std::string& pin)
{
    Bytes secret;
    try {
        secret = token::GetHmacSecret(devicePath, pin, rec.credId, rec.salt);
    } catch (const Fido2Error& e) {
        return Fail(Utf8ToWide(e.what()), true);
    }

    Outcome o;
    o.ok = vault::Open(rec, secret, o.password);
    SecureClear(secret);
    if (!o.ok)
        return Fail(L"Не удалось расшифровать пароль (неверный ключ?).");
    return o;
}

Outcome U2f(const VaultRecord& rec, const std::string& devicePath,
            int timeoutMs)
{
    uint32_t counter = 0;
    try {
        counter = token::AssertU2f(devicePath, rec.credId, rec.pubKey, timeoutMs);
    } catch (const Fido2Error& e) {
        return Fail(Utf8ToWide(e.what()), true);
    }

    if (!CounterAcceptable(rec.counter, counter))
        return Fail(L"Счётчик ключа не вырос — возможна копия ключа. Вход отклонён.");

    // The signature verified, so the key is present. Now read back the vault
    // key this machine is holding on its behalf.
    Bytes ikm;
    if (!vault::RecoverU2fIkm(rec, ikm))
        return Fail(L"Не удалось прочитать ключ шифрования (DPAPI): запись "
                    L"принадлежит другому компьютеру?");

    Outcome o;
    o.ok = vault::Open(rec, ikm, o.password);
    SecureClear(ikm);
    if (!o.ok)
        return Fail(L"Не удалось расшифровать пароль.");

    o.counter = counter;
    o.counterAdvanced = counter != rec.counter;
    return o;
}

}  // namespace

Outcome WithDevice(const VaultRecord& rec, const std::string& devicePath,
                   const std::string& pin, int timeoutMs)
{
    try {
        if (rec.mode == VaultMode::U2fPresence)
            return U2f(rec, devicePath, timeoutMs);
        return Fido2(rec, devicePath, pin);
    } catch (const std::exception& e) {
        return Fail(Utf8ToWide(e.what()));
    }
}

}  // namespace unlock
