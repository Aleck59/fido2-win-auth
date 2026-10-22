#include "enrollment.h"

#include "store.h"
#include "token.h"
#include "vault.h"

#include <openssl/rand.h>
#include <windows.h>
#include <lm.h>

namespace enrollment {
namespace {

void Report(const ProgressFn& progress, Step s)
{
    if (progress) progress(s);
}

}  // namespace

std::wstring Account::Display() const
{
    if (!Resolved()) return sid;
    return domain.empty() ? user : domain + L"\\" + user;
}

PasswordCheck CheckWindowsPassword(const std::wstring& account,
                                   const std::wstring& password)
{
    // A network logon validates the credentials without loading a profile.
    HANDLE token = nullptr;
    if (LogonUserW(account.c_str(), L".", password.c_str(), LOGON32_LOGON_NETWORK,
                   LOGON32_PROVIDER_DEFAULT, &token)) {
        CloseHandle(token);
        return PasswordCheck::Valid;
    }
    return GetLastError() == ERROR_LOGON_FAILURE ? PasswordCheck::Wrong
                                                 : PasswordCheck::Unknown;
}

std::vector<std::wstring> LocalUserNames()
{
    std::vector<std::wstring> names;
    USER_INFO_0* buf = nullptr;
    DWORD read = 0, total = 0;
    DWORD_PTR resume = 0;

    do {
        const NET_API_STATUS rc =
            NetUserEnum(nullptr, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&buf,
                        MAX_PREFERRED_LENGTH, &read, &total, (LPDWORD)&resume);
        if (rc != NERR_Success && rc != ERROR_MORE_DATA) break;
        if (buf) {
            for (DWORD i = 0; i < read; ++i)
                if (buf[i].usri0_name) names.push_back(buf[i].usri0_name);
            NetApiBufferFree(buf);
            buf = nullptr;
        }
        if (rc != ERROR_MORE_DATA) break;
    } while (resume != 0);

    return names;
}

std::vector<Account> Enrolled()
{
    std::vector<Account> out;
    for (const auto& sid : store::ListEnrolledSids()) {
        Account a;
        a.sid = sid;
        store::AccountForSid(sid, a.domain, a.user);  // leaves both empty if gone
        out.push_back(a);
    }
    return out;
}

bool IsEnrolled(const std::wstring& account)
{
    try {
        Bytes blob;
        const bool found = store::LoadRecord(store::SidForAccount(account), blob);
        SecureClear(blob);
        return found;
    } catch (const std::exception&) {
        return false;
    }
}

Status Enroll(const std::wstring& account, const std::string& devicePath,
              const std::string& pin, const std::wstring& password,
              const ProgressFn& progress)
{
    std::wstring sid;
    try {
        sid = store::SidForAccount(account);
    } catch (const std::exception& e) {
        return Status::Fail(L"Учётная запись не найдена: " + Utf8ToWide(e.what()));
    }

    // Without user verification a found or stolen key would be enough to log
    // in, so refuse a key with no PIN set rather than silently degrading.
    try {
        if (!token::HasClientPin(devicePath))
            return Status::Fail(L"На ключе не задан PIN. Задайте PIN ключа "
                                L"(Параметры Windows или ykman) и повторите — "
                                L"вход без PIN небезопасен.");
    } catch (const std::exception& e) {
        return Status::Fail(L"Не удалось опросить ключ: " + Utf8ToWide(e.what()));
    }

    // The credential's user id must be stable; derive it from the account SID.
    const Bytes userId = ToBytes(WideToUtf8(sid));
    const std::string userName = WideToUtf8(account);

    Report(progress, Step::CreatingCredential);
    Bytes credId;
    try {
        credId = token::Enroll(devicePath, pin, userId, userName);
    } catch (const Fido2Error& e) {
        return Status::Fail(L"Регистрация на ключе не удалась: " + Utf8ToWide(e.what()));
    }

    Bytes salt(token::kSaltLen);
    if (RAND_bytes(salt.data(), (int)salt.size()) != 1)
        return Status::Fail(L"Сбой генератора случайных чисел.");

    Report(progress, Step::FetchingSecret);
    Bytes hmacSecret;
    try {
        hmacSecret = token::GetHmacSecret(devicePath, pin, credId, salt);
    } catch (const Fido2Error& e) {
        return Status::Fail(L"Не удалось получить hmac-secret: " + Utf8ToWide(e.what()));
    }

    VaultRecord rec;
    try {
        rec = vault::Seal(credId, salt, hmacSecret, password);
    } catch (const std::exception& e) {
        SecureClear(hmacSecret);
        return Status::Fail(L"Ошибка шифрования: " + Utf8ToWide(e.what()));
    }
    SecureClear(hmacSecret);

    // Round-trip the record with a fresh assertion before storing it, so an
    // unusable enrollment is never persisted.
    Report(progress, Step::Verifying);
    try {
        Bytes verifySecret = token::GetHmacSecret(devicePath, pin, credId, rec.salt);
        std::wstring recovered;
        const bool opened = vault::Open(rec, verifySecret, recovered);
        SecureClear(verifySecret);
        const bool match = opened && recovered == password;  // GCM auth + exact round-trip
        SecureClear(recovered);
        if (!match)
            return Status::Fail(L"Контрольная расшифровка не удалась — регистрация отменена.");
    } catch (const Fido2Error& e) {
        return Status::Fail(L"Контрольная проверка не удалась: " + Utf8ToWide(e.what()));
    }

    Report(progress, Step::Saving);
    try {
        store::SaveRecord(sid, rec.Serialize());
    } catch (const std::exception& e) {
        return Status::Fail(L"Не удалось записать в реестр (нужны права "
                            L"администратора): " + Utf8ToWide(e.what()));
    }
    return Status::Success();
}

Status Test(const std::wstring& account, const std::string& devicePath,
            const std::string& pin, const ProgressFn& progress)
{
    Bytes blob;
    try {
        if (!store::LoadRecord(store::SidForAccount(account), blob))
            return Status::Fail(L"Для этой учётной записи нет регистрации ключа.");
    } catch (const std::exception& e) {
        return Status::Fail(L"Учётная запись не найдена: " + Utf8ToWide(e.what()));
    }

    VaultRecord rec;
    try {
        rec = VaultRecord::Deserialize(blob);
    } catch (const std::exception&) {
        return Status::Fail(L"Повреждённая запись ключа.");
    }

    Report(progress, Step::Verifying);
    Bytes secret;
    try {
        secret = token::GetHmacSecret(devicePath, pin, rec.credId, rec.salt);
    } catch (const Fido2Error& e) {
        return Status::Fail(L"Ключ не подтвердил учётные данные: " + Utf8ToWide(e.what()));
    }

    std::wstring password;
    const bool opened = vault::Open(rec, secret, password);
    SecureClear(secret);
    if (!opened)
        return Status::Fail(L"Не удалось расшифровать пароль (неверный ключ?).");

    const PasswordCheck check = CheckWindowsPassword(account, password);
    SecureClear(password);

    if (check == PasswordCheck::Wrong)
        return Status::Fail(L"Пароль расшифрован, но Windows его отклонила — "
                            L"он был изменён. Выполните регистрацию заново.");
    if (check == PasswordCheck::Unknown)
        return Status::Fail(L"Пароль расшифрован, но проверить его у Windows не "
                            L"удалось. Вход, скорее всего, работает.");
    return Status::Success();
}

Status RemoveBySid(const std::wstring& sid)
{
    try {
        store::DeleteRecord(sid);
    } catch (const std::exception& e) {
        return Status::Fail(L"Не удалось удалить запись: " + Utf8ToWide(e.what()));
    }
    return Status::Success();
}

Status Remove(const std::wstring& account)
{
    try {
        return RemoveBySid(store::SidForAccount(account));
    } catch (const std::exception& e) {
        return Status::Fail(L"Учётная запись не найдена: " + Utf8ToWide(e.what()));
    }
}

}  // namespace enrollment
