// enroll.exe — console utility to register a FIDO2 key for a local account,
// list enrolled accounts, and remove an enrollment.
//
// Usage:
//   enroll                 enroll the current user (interactive)
//   enroll --account NAME   enroll a specific local account
//   enroll --list           list enrolled accounts
//   enroll --remove NAME    remove an account's enrollment
//
// Must run elevated (writes under HKLM with a SYSTEM/Administrators DACL).
#include "../common/bytes.h"
#include "../common/store.h"
#include "../common/token.h"
#include "../common/vault.h"

#include <openssl/rand.h>
#include <windows.h>

#include <cstdio>
#include <iostream>
#include <string>

namespace {

void Print(const std::wstring& s) { std::wcout << s << L"\n"; }
void Err(const std::wstring& s) { std::wcerr << s << L"\n"; }

std::wstring CurrentUserName()
{
    wchar_t name[256];
    DWORD len = 256;
    if (GetUserNameW(name, &len)) return std::wstring(name, len - 1);
    return L"";
}

std::wstring ReadLine(const std::wstring& prompt)
{
    std::wcout << prompt << std::flush;
    std::wstring line;
    std::getline(std::wcin, line);
    return line;
}

// Reads a secret from the console with echo disabled.
std::wstring ReadSecret(const std::wstring& prompt)
{
    std::wcout << prompt << std::flush;
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(in, &mode);
    SetConsoleMode(in, mode & ~(DWORD)ENABLE_ECHO_INPUT);
    std::wstring line;
    std::getline(std::wcin, line);
    SetConsoleMode(in, mode);
    std::wcout << L"\n";
    return line;
}

bool IsElevated()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elev{};
    DWORD sz = sizeof(elev);
    bool ok = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &sz);
    CloseHandle(token);
    return ok && elev.TokenIsElevated;
}

int DoList()
{
    auto sids = store::ListEnrolledSids();
    if (sids.empty()) {
        Print(L"Нет зарегистрированных учётных записей.");
        return 0;
    }
    Print(L"Зарегистрированные учётные записи:");
    for (const auto& sid : sids) {
        std::wstring domain, user;
        if (store::AccountForSid(sid, domain, user))
            Print(L"  " + domain + L"\\" + user + L"  (" + sid + L")");
        else
            Print(L"  " + sid + L"  (SID не разрешается на этой машине)");
    }
    return 0;
}

int DoRemove(const std::wstring& account)
{
    std::wstring sid = store::SidForAccount(account);
    store::DeleteRecord(sid);
    Print(L"Регистрация удалена для " + account + L" (" + sid + L").");
    Print(L"Убедитесь, что остаётся другой способ входа в систему.");
    return 0;
}

int DoEnroll(const std::wstring& accountW)
{
    std::wstring sid = store::SidForAccount(accountW);
    Print(L"Учётная запись: " + accountW + L"  SID: " + sid);

    auto devices = token::ListDevices();
    if (devices.empty()) {
        Err(L"FIDO2-ключ не найден. Вставьте ключ и повторите.");
        return 2;
    }
    size_t idx = 0;
    if (devices.size() > 1) {
        Print(L"Найдено несколько ключей:");
        for (size_t i = 0; i < devices.size(); ++i) {
            std::wstring label = Utf8ToWide(devices[i].manufacturer + " " +
                                            devices[i].product);
            Print(L"  [" + std::to_wstring(i) + L"] " + label);
        }
        std::wstring sel = ReadLine(L"Выберите номер ключа: ");
        try { idx = (size_t)std::stoul(sel); } catch (...) { idx = 0; }
        if (idx >= devices.size()) idx = 0;
    }
    const std::string path = devices[idx].path;

    std::string pin;
    {
        bool hasPin = false;
        try { hasPin = token::HasClientPin(path); }
        catch (const std::exception& e) {
            Err(L"Не удалось опросить ключ: " + Utf8ToWide(e.what()));
            return 2;
        }
        if (!hasPin) {
            Err(L"На ключе не задан PIN. Задайте PIN ключа (например, через");
            Err(L"Параметры Windows или ykman) — вход без PIN небезопасен.");
            return 2;
        }
        std::wstring pinW = ReadSecret(L"PIN ключа: ");
        pin = WideToUtf8(pinW);
        SecureClear(pinW);
    }

    std::wstring password = ReadSecret(L"Пароль учётной записи Windows: ");
    std::wstring confirm = ReadSecret(L"Повторите пароль: ");
    if (password != confirm) {
        SecureClear(password);
        SecureClear(confirm);
        Err(L"Пароли не совпадают.");
        return 2;
    }
    SecureClear(confirm);

    Print(L"Коснитесь ключа для регистрации…");
    // The credential's user id must be stable; derive it from the account SID.
    Bytes userId = ToBytes(WideToUtf8(sid));
    std::string userName = WideToUtf8(accountW);

    Bytes credId;
    try {
        credId = token::Enroll(path, pin, userId, userName);
    } catch (const Fido2Error& e) {
        SecureClear(password);
        Err(L"Регистрация на ключе не удалась: " + Utf8ToWide(e.what()));
        return 3;
    }

    // Obtain the hmac-secret for a fresh random salt (second touch).
    Bytes salt(token::kSaltLen);
    if (RAND_bytes(salt.data(), (int)salt.size()) != 1) {
        SecureClear(password);
        Err(L"Сбой генератора случайных чисел.");
        return 3;
    }
    Print(L"Коснитесь ключа ещё раз для получения секрета…");
    Bytes hmacSecret;
    try {
        hmacSecret = token::GetHmacSecret(path, pin, credId, salt);
    } catch (const Fido2Error& e) {
        SecureClear(password);
        Err(L"Не удалось получить hmac-secret: " + Utf8ToWide(e.what()));
        return 3;
    }

    VaultRecord rec;
    try {
        rec = vault::Seal(credId, salt, hmacSecret, password);
    } catch (const std::exception& e) {
        SecureClear(password);
        SecureClear(hmacSecret);
        Err(L"Ошибка шифрования: " + Utf8ToWide(e.what()));
        return 3;
    }
    // Verify the record opens with a fresh assertion before clearing the
    // plaintext, so we never persist an unusable enrollment.
    Print(L"Проверка: коснитесь ключа для контрольной расшифровки…");
    try {
        Bytes verifySecret = token::GetHmacSecret(path, pin, credId, rec.salt);
        std::wstring recovered;
        bool ok = vault::Open(rec, verifySecret, recovered);
        SecureClear(verifySecret);
        bool match = ok && recovered == password;  // GCM auth + exact round-trip
        SecureClear(recovered);
        if (!match) {
            SecureClear(password);
            SecureClear(hmacSecret);
            Err(L"Контрольная расшифровка не удалась — регистрация отменена.");
            return 3;
        }
    } catch (const Fido2Error& e) {
        SecureClear(password);
        SecureClear(hmacSecret);
        Err(L"Контрольная проверка не удалась: " + Utf8ToWide(e.what()));
        return 3;
    }
    SecureClear(password);
    SecureClear(hmacSecret);

    try {
        store::SaveRecord(sid, rec.Serialize());
    } catch (const std::exception& e) {
        Err(L"Не удалось записать в реестр: " + Utf8ToWide(e.what()));
        Err(L"Запустите enroll от имени администратора.");
        return 4;
    }

    Print(L"Готово. Ключ зарегистрирован для " + accountW + L".");
    Print(L"ВАЖНО: сохраните запасной способ входа (второй ключ или пароль");
    Print(L"администратора) на случай утери ключа.");
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv)
{
    // Line-buffered wide console I/O.
    std::ios::sync_with_stdio(false);

    std::wstring mode, account;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--list") mode = L"list";
        else if (a == L"--remove" && i + 1 < argc) { mode = L"remove"; account = argv[++i]; }
        else if (a == L"--account" && i + 1 < argc) { account = argv[++i]; }
        else if (a == L"--help" || a == L"-h") {
            Print(L"Использование:");
            Print(L"  enroll                 регистрация текущего пользователя");
            Print(L"  enroll --account ИМЯ   регистрация указанной учётной записи");
            Print(L"  enroll --list          список зарегистрированных");
            Print(L"  enroll --remove ИМЯ    удалить регистрацию");
            return 0;
        }
    }

    if (mode != L"list" && !IsElevated()) {
        Err(L"Требуются права администратора. Запустите от имени администратора.");
        return 1;
    }

    try {
        if (mode == L"list") return DoList();
        if (mode == L"remove") return DoRemove(account);
        if (account.empty()) account = CurrentUserName();
        if (account.empty()) { Err(L"Не удалось определить имя пользователя."); return 1; }
        return DoEnroll(account);
    } catch (const std::exception& e) {
        Err(L"Ошибка: " + Utf8ToWide(e.what()));
        return 1;
    }
}
