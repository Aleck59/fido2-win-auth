// enroll.exe — console front-end for registering a FIDO2 key against a local
// account. The key-touching sequence itself lives in src/common/enrollment.*,
// shared with the GUI (fido2gui.exe); this file only collects input and prints.
//
// Usage:
//   enroll                  enroll the current user (interactive)
//   enroll --account NAME   enroll a specific local account
//   enroll --list           list enrolled accounts
//   enroll --test NAME      check an enrollment still works
//   enroll --remove NAME    remove an account's enrollment
//
// Must run elevated (writes under HKLM with a SYSTEM/Administrators DACL).
#include "../common/bytes.h"
#include "../common/enrollment.h"
#include "../common/plog.h"
#include "../common/settings.h"
#include "../common/token.h"
#include "../common/vault.h"

#include <windows.h>

#include <cstdio>
#include <string>

namespace {

// Console I/O that survives non-ASCII.
//
// std::wcout with the default locale cannot convert anything outside the
// narrow character set: the first Cyrillic character puts the stream in a
// failed state and every later write is silently dropped, so the tool printed
// nothing at all. std::wcin mangles the same characters on the way in, which
// for a Windows password means storing the wrong one.
//
// So write through the console directly when there is one, and fall back to
// UTF-8 bytes when the output is redirected -- which also makes a redirected
// log readable.
void WriteTo(DWORD stdHandle, const std::wstring& text)
{
    HANDLE h = GetStdHandle(stdHandle);
    if (h == INVALID_HANDLE_VALUE || !h) return;

    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        DWORD written = 0;
        WriteConsoleW(h, text.c_str(), (DWORD)text.size(), &written, nullptr);
        return;
    }

    const int cb = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(),
                                       nullptr, 0, nullptr, nullptr);
    if (cb <= 0) return;
    std::string utf8((size_t)cb, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), &utf8[0], cb,
                        nullptr, nullptr);
    DWORD written = 0;
    WriteFile(h, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
}

void Print(const std::wstring& s) { WriteTo(STD_OUTPUT_HANDLE, s + L"\r\n"); }
void Err(const std::wstring& s) { WriteTo(STD_ERROR_HANDLE, s + L"\r\n"); }

std::wstring CurrentUserName()
{
    wchar_t name[256];
    DWORD len = 256;
    if (GetUserNameW(name, &len)) return std::wstring(name, len - 1);
    return L"";
}

// Reads one line. ReadConsoleW on a console keeps every character intact;
// the redirected case decodes UTF-8 so a scripted answer works too.
std::wstring ReadRawLine()
{
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;

    std::wstring line;
    if (GetConsoleMode(in, &mode)) {
        wchar_t buf[512];
        DWORD read = 0;
        if (ReadConsoleW(in, buf, ARRAYSIZE(buf), &read, nullptr))
            line.assign(buf, read);
        SecureZeroMemory(buf, sizeof(buf));
    } else {
        std::string bytes;
        char c = 0;
        DWORD read = 0;
        while (ReadFile(in, &c, 1, &read, nullptr) && read == 1) {
            if (c == '\n') break;
            bytes.push_back(c);
        }
        if (!bytes.empty()) {
            const int cch = MultiByteToWideChar(CP_UTF8, 0, bytes.data(),
                                                (int)bytes.size(), nullptr, 0);
            if (cch > 0) {
                line.resize((size_t)cch);
                MultiByteToWideChar(CP_UTF8, 0, bytes.data(), (int)bytes.size(),
                                    &line[0], cch);
            }
        }
        SecureClear(bytes);
    }

    while (!line.empty() && (line.back() == L'\r' || line.back() == L'\n'))
        line.pop_back();
    return line;
}

std::wstring ReadLine(const std::wstring& prompt)
{
    WriteTo(STD_OUTPUT_HANDLE, prompt);
    return ReadRawLine();
}

// Reads a secret from the console with echo disabled.
std::wstring ReadSecret(const std::wstring& prompt)
{
    WriteTo(STD_OUTPUT_HANDLE, prompt);

    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    const bool isConsole = GetConsoleMode(in, &mode) != 0;
    if (isConsole) SetConsoleMode(in, mode & ~(DWORD)ENABLE_ECHO_INPUT);

    std::wstring line = ReadRawLine();

    if (isConsole) SetConsoleMode(in, mode);
    WriteTo(STD_OUTPUT_HANDLE, L"\r\n");
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

void ShowStep(enrollment::Step s)
{
    switch (s) {
        case enrollment::Step::CreatingCredential:
            Print(L"Коснитесь ключа для регистрации…");
            break;
        case enrollment::Step::FetchingSecret:
            Print(L"Коснитесь ключа ещё раз для получения секрета…");
            break;
        case enrollment::Step::Verifying:
            Print(L"Проверка: коснитесь ключа для контрольной расшифровки…");
            break;
        case enrollment::Step::Saving:
            Print(L"Сохранение записи…");
            break;
    }
}

// Asks for the next presence event on the console. A key with a button can
// just be touched while the operation runs; a key without one has to be taken
// out and put back, because registering already used up the presence it gave
// when it was plugged in.
std::string WaitForKeyAgain(const std::string& currentPath)
{
    Print(L"");
    Print(L"Нужно второе подтверждение на ключе.");
    Print(L"Извлеките ключ и вставьте его снова (ключ с кнопкой можно оставить");
    Print(L"на месте), затем нажмите Enter.");
    ReadLine(L"> ");

    auto devices = token::ListDevices();
    if (devices.empty()) {
        Err(L"Ключ не найден.");
        return std::string();
    }
    // A re-plugged key can come back under a different path.
    for (const auto& d : devices)
        if (d.path == currentPath) return currentPath;
    return devices[0].path;
}

// Picks a key, prompting only when there is more than one.
bool ChooseDevice(std::string& path)
{
    auto devices = token::ListDevices();
    if (devices.empty()) {
        Err(L"FIDO2-ключ не найден. Вставьте ключ и повторите.");
        return false;
    }

    size_t idx = 0;
    if (devices.size() > 1) {
        Print(L"Найдено несколько ключей:");
        for (size_t i = 0; i < devices.size(); ++i) {
            std::wstring label =
                Utf8ToWide(devices[i].manufacturer + " " + devices[i].product);
            Print(L"  [" + std::to_wstring(i) + L"] " + label);
        }
        std::wstring sel = ReadLine(L"Выберите номер ключа: ");
        try { idx = (size_t)std::stoul(sel); } catch (...) { idx = 0; }
        if (idx >= devices.size()) idx = 0;
    }
    path = devices[idx].path;
    return true;
}

// Prints what each connected key can do. The first thing to run when
// enrollment refuses a key.
int DoKeys()
{
    const auto keys = token::ProbeAll();
    if (keys.empty()) {
        Print(L"Ключи не найдены. Вставьте ключ и повторите.");
        return 0;
    }

    for (size_t i = 0; i < keys.size(); ++i) {
        const auto& k = keys[i];
        std::wstring label = Utf8ToWide(k.manufacturer + " " + k.product);
        Print(L"[" + std::to_wstring(i) + L"] " + label);

        if (k.probeFailed) {
            Print(L"    опросить не удалось: " + Utf8ToWide(k.probeError));
            Print(L"");
            continue;
        }

        Print(std::wstring(L"    протокол:    ") +
              (k.isFido2 ? L"CTAP2 (FIDO2)" : L"только U2F (CTAP1)"));
        if (!k.versions.empty()) {
            std::wstring v;
            for (const auto& s : k.versions) {
                if (!v.empty()) v += L", ";
                v += Utf8ToWide(s);
            }
            Print(L"    версии:      " + v);
        }
        Print(std::wstring(L"    hmac-secret: ") + (k.hmacSecret ? L"есть" : L"нет"));
        Print(std::wstring(L"    PIN:         ") +
              (k.pinSet ? L"задан"
                        : (k.clientPinSupported ? L"поддерживается, но не задан"
                                                : L"не поддерживается")));
        if (k.usable)
            Print(L"    пригоден для регистрации.");
        else
            Print(L"    НЕ пригоден: " + Utf8ToWide(k.reason) + L".");
        Print(L"");
    }
    return 0;
}

// The credential provider runs inside LogonUI with no console and no window,
// so when the logon screen misbehaves this log is the only way to see where it
// stopped. It records steps and the messages the tile shows -- never a
// password, a PIN or any key material.
int DoDebug(const std::wstring& arg)
{
    if (arg == L"on" || arg == L"off") {
        if (!plog::SetEnabled(arg == L"on")) {
            Err(L"Не удалось изменить настройку (нужны права администратора).");
            return 2;
        }
    } else if (!arg.empty()) {
        Err(L"Укажите on или off.");
        return 2;
    }

    Print(std::wstring(L"Журнал провайдера: ") +
          (plog::Enabled() ? L"включён" : L"выключен"));
    Print(L"Файл: " + plog::Path());
    if (plog::Enabled())
        Print(L"Заблокируйте экран (Win+L), попробуйте вход, затем посмотрите файл.");
    return 0;
}

// Whether plugging the key in may log the user in without them first choosing
// this sign-in option.
int DoAutoLogon(const std::wstring& arg)
{
    if (arg == L"on" || arg == L"off") {
        if (!settings::SetAutoLogon(arg == L"on")) {
            Err(L"Не удалось изменить настройку (нужны права администратора).");
            return 2;
        }
    } else if (!arg.empty()) {
        Err(L"Укажите on или off.");
        return 2;
    }

    Print(std::wstring(L"Вход по подключению ключа: ") +
          (settings::AutoLogon() ? L"включён" : L"выключен"));
    Print(L"Действует только для записей U2F: в них нечего вводить.");
    Print(L"Записи FIDO2 требуют PIN, для них плитка лишь выбирается.");
    return 0;
}

int DoList()
{
    const auto accounts = enrollment::Enrolled();
    if (accounts.empty()) {
        Print(L"Нет зарегистрированных учётных записей.");
        return 0;
    }
    Print(L"Зарегистрированные учётные записи:");
    for (const auto& a : accounts) {
        if (a.Resolved())
            Print(L"  " + a.Display() + L"  (" + a.sid + L")");
        else
            Print(L"  " + a.sid + L"  (SID не разрешается на этой машине)");
    }
    return 0;
}

int DoRemove(const std::wstring& account)
{
    const auto status = enrollment::Remove(account);
    if (!status.ok) {
        Err(status.error);
        return 2;
    }
    Print(L"Регистрация удалена для " + account + L".");
    Print(L"Убедитесь, что остаётся другой способ входа в систему.");
    return 0;
}

int DoTest(const std::wstring& account)
{
    VaultMode mode = VaultMode::Fido2HmacSecret;
    if (!enrollment::EnrolledMode(account, mode)) {
        Err(L"Для этой учётной записи нет регистрации ключа.");
        return 2;
    }

    std::string path;
    if (!ChooseDevice(path)) return 2;

    std::string pin;
    if (mode == VaultMode::Fido2HmacSecret) {
        std::wstring pinW = ReadSecret(L"PIN ключа: ");
        pin = WideToUtf8(pinW);
        SecureClear(pinW);
    } else {
        Print(L"Режим U2F: PIN не используется.");
    }

    const auto status = enrollment::Test(account, path, pin, ShowStep);
    SecureClear(pin);

    if (!status.ok) {
        Err(status.error);
        return 3;
    }
    Print(L"Проверка пройдена: вход по ключу работает.");
    return 0;
}

int DoEnroll(const std::wstring& account, VaultMode mode)
{
    Print(L"Учётная запись: " + account);

    if (mode == VaultMode::U2fPresence) {
        Print(L"");
        Print(L"ВНИМАНИЕ: режим U2F слабее.");
        Print(L"В CTAP1 нет hmac-secret, поэтому ключ шифрования пароля хранится");
        Print(L"на этом компьютере (DPAPI), а ключ только подтверждает присутствие.");
        Print(L"Любой, кто получил права SYSTEM или администратора на этой машине,");
        Print(L"расшифрует пароль, не имея токена. В обычном режиме это невозможно.");
        Print(L"");
        const std::wstring answer = ReadLine(L"Введите «u2f» для подтверждения: ");
        if (answer != L"u2f") {
            Err(L"Отменено.");
            return 2;
        }
        Print(L"");
    }

    std::string path;
    if (!ChooseDevice(path)) return 2;

    std::string pin;
    if (mode == VaultMode::Fido2HmacSecret) {
        std::wstring pinW = ReadSecret(L"PIN ключа: ");
        pin = WideToUtf8(pinW);
        SecureClear(pinW);
    }

    std::wstring password = ReadSecret(L"Пароль учётной записи Windows: ");
    std::wstring confirm = ReadSecret(L"Повторите пароль: ");
    if (password != confirm) {
        SecureClear(pin);
        SecureClear(password);
        SecureClear(confirm);
        Err(L"Пароли не совпадают.");
        return 2;
    }
    SecureClear(confirm);

    // Catch a mistyped password here rather than at the logon screen.
    if (enrollment::CheckWindowsPassword(account, password) ==
        enrollment::PasswordCheck::Wrong) {
        SecureClear(pin);
        SecureClear(password);
        Err(L"Windows отклонила этот пароль для указанной учётной записи.");
        return 2;
    }

    const auto status = enrollment::Enroll(account, path, pin, password, mode,
                                           ShowStep, WaitForKeyAgain);
    SecureClear(pin);
    SecureClear(password);

    if (!status.ok) {
        Err(status.error);
        return 3;
    }

    Print(L"Готово. Ключ зарегистрирован для " + account + L".");
    Print(L"ВАЖНО: сохраните запасной способ входа (второй ключ или пароль");
    Print(L"администратора) на случай утери ключа.");
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv)
{
    std::wstring mode, account;
    VaultMode vaultMode = VaultMode::Fido2HmacSecret;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--list") mode = L"list";
        else if (a == L"--keys") mode = L"keys";
        else if (a == L"--remove" && i + 1 < argc) { mode = L"remove"; account = argv[++i]; }
        else if (a == L"--test" && i + 1 < argc) { mode = L"test"; account = argv[++i]; }
        else if (a == L"--u2f") vaultMode = VaultMode::U2fPresence;
        else if (a == L"--autologon") {
            mode = L"autologon";
            if (i + 1 < argc) account = argv[++i];  // reuse as the on/off word
            else account.clear();
        }
        else if (a == L"--debug") {
            mode = L"debug";
            if (i + 1 < argc) account = argv[++i];  // reuse as the on/off word
            else account.clear();
        }
        else if (a == L"--account" && i + 1 < argc) { account = argv[++i]; }
        else if (a == L"--help" || a == L"-h") {
            Print(L"Использование:");
            Print(L"  enroll                 регистрация текущего пользователя");
            Print(L"  enroll --account ИМЯ   регистрация указанной учётной записи");
            Print(L"  enroll --list          список зарегистрированных");
            Print(L"  enroll --keys          что умеют вставленные ключи");
            Print(L"  enroll --test ИМЯ      проверить регистрацию");
            Print(L"  enroll --remove ИМЯ    удалить регистрацию");
            Print(L"  enroll --u2f           регистрация ключа U2F (СЛАБЕЕ, см. README)");
            Print(L"  enroll --debug on|off  журнал провайдера для разбора входа");
            Print(L"  enroll --autologon on|off  вход по подключению ключа (U2F)");
            Print(L"");
            Print(L"То же самое в окне: fido2gui.exe");
            return 0;
        }
    }

    if (mode != L"list" && mode != L"keys" && !IsElevated()) {
        Err(L"Требуются права администратора. Запустите от имени администратора.");
        return 1;
    }

    try {
        if (mode == L"list") return DoList();
        if (mode == L"keys") return DoKeys();
        if (mode == L"debug") return DoDebug(account);
        if (mode == L"autologon") return DoAutoLogon(account);
        if (mode == L"remove") return DoRemove(account);
        if (mode == L"test") return DoTest(account);
        if (account.empty()) account = CurrentUserName();
        if (account.empty()) { Err(L"Не удалось определить имя пользователя."); return 1; }
        return DoEnroll(account, vaultMode);
    } catch (const std::exception& e) {
        Err(L"Ошибка: " + Utf8ToWide(e.what()));
        return 1;
    }
}
