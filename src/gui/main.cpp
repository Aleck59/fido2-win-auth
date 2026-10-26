// fido2gui.exe — a small window over the same enrollment operations as
// enroll.exe, for people who would rather not use a console.
//
// Every operation that touches the key blocks until the user touches it, so
// each one runs on a worker thread and reports back by posted message; the
// dialog stays responsive and says which touch it is waiting for.
//
// The manifest marks this requireAdministrator: enrollment writes under HKLM
// and reaches the key over raw HID.
#include "../common/bytes.h"
#include "../common/enrollment.h"
#include "../common/token.h"
#include "../common/vault.h"
#include "resource.h"

#include <windows.h>
#include <commctrl.h>

#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace {

// Posted by a worker to the dialog that started it.
constexpr UINT WM_JOB_PROGRESS = WM_APP + 1;  // wParam = enrollment::Step
constexpr UINT WM_JOB_DONE = WM_APP + 2;      // lParam = enrollment::Status*

HINSTANCE g_inst = nullptr;

using JobFn = std::function<enrollment::Status(const enrollment::ProgressFn&)>;

struct Job {
    HWND dlg;
    JobFn run;
};

DWORD WINAPI JobProc(LPVOID param)
{
    std::unique_ptr<Job> job(static_cast<Job*>(param));
    const HWND dlg = job->dlg;

    enrollment::ProgressFn progress = [dlg](enrollment::Step s) {
        PostMessageW(dlg, WM_JOB_PROGRESS, (WPARAM)s, 0);
    };

    auto* status = new enrollment::Status(job->run(progress));
    PostMessageW(dlg, WM_JOB_DONE, 0, (LPARAM)status);
    return 0;
}

// Hands `run` to a worker thread. Ownership of the job passes to the thread.
bool StartJob(HWND dlg, JobFn run)
{
    auto* job = new Job{dlg, std::move(run)};
    HANDLE thread = CreateThread(nullptr, 0, JobProc, job, 0, nullptr);
    if (!thread) {
        delete job;
        return false;
    }
    CloseHandle(thread);
    return true;
}

const wchar_t* StepText(enrollment::Step s)
{
    switch (s) {
        case enrollment::Step::CreatingCredential:
            return L"Коснитесь ключа: создание учётных данных…";
        case enrollment::Step::FetchingSecret:
            return L"Коснитесь ключа ещё раз: получение секрета…";
        case enrollment::Step::Verifying:
            return L"Коснитесь ключа: контрольная проверка…";
        case enrollment::Step::Saving:
            return L"Сохранение записи…";
    }
    return L"";
}

std::wstring GetText(HWND dlg, int id)
{
    HWND ctl = GetDlgItem(dlg, id);
    const int len = GetWindowTextLengthW(ctl);
    if (len <= 0) return std::wstring();
    std::wstring text((size_t)len + 1, L'\0');
    GetWindowTextW(ctl, &text[0], len + 1);
    text.resize((size_t)len);
    return text;
}

// Clears a password box. The control keeps its own copy of the text until it
// is reused, so this limits exposure rather than eliminating it.
void ClearText(HWND dlg, int id) { SetDlgItemTextW(dlg, id, L""); }

// Input mistakes belong in a dialog the user has to dismiss, not on a status
// line they may never look at.
void ErrorBox(HWND dlg, const wchar_t* text)
{
    MessageBoxW(dlg, text, L"Ошибка", MB_OK | MB_ICONERROR);
}

void SetStatus(HWND dlg, int id, const std::wstring& text)
{
    SetDlgItemTextW(dlg, id, text.c_str());
}

// Fills a combo with the attached keys and returns their paths by index.
std::vector<std::string> FillDeviceCombo(HWND dlg, int id)
{
    std::vector<std::string> paths;
    HWND combo = GetDlgItem(dlg, id);
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);

    std::vector<token::Device> devices;
    try {
        devices = token::ListDevices();
    } catch (const std::exception&) {
        // Treated the same as no key attached.
    }

    for (const auto& dev : devices) {
        std::string label = dev.manufacturer;
        if (!label.empty() && !dev.product.empty()) label += " ";
        label += dev.product;
        if (label.empty()) label = dev.path;
        SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)Utf8ToWide(label).c_str());
        paths.push_back(dev.path);
    }
    if (!paths.empty()) SendMessageW(combo, CB_SETCURSEL, 0, 0);
    return paths;
}

// One line about a key, for the label under the device picker.
std::wstring ShortCapabilities(const token::Capabilities& c)
{
    if (c.probeFailed) return L"опросить ключ не удалось";
    if (c.usable) return L"CTAP2, hmac-secret есть, PIN задан — подходит";
    return L"не подходит: " + Utf8ToWide(c.reason);
}

// One row of the keys table.
struct KeyRow {
    std::string path;
    std::wstring name;
    std::wstring type;
    std::wstring info;
    bool registered = false;
};

// Everything the table says about one key, gathered without touching it.
KeyRow DescribeKey(const token::Capabilities& c)
{
    KeyRow r;
    r.path = c.path;

    std::string label = c.manufacturer;
    if (!label.empty() && !c.product.empty()) label += " ";
    label += c.product;
    r.name = label.empty() ? L"(безымянный ключ)" : Utf8ToWide(label);

    if (c.probeFailed) {
        r.type = L"—";
        r.info = L"опрос не удался: " + Utf8ToWide(c.probeError);
        return r;
    }

    r.type = c.isFido2 ? L"FIDO2" : L"U2F";

    std::wstring info;
    for (const auto& v : c.versions) {
        if (!info.empty()) info += L", ";
        info += Utf8ToWide(v);
    }
    if (c.isFido2) {
        if (!info.empty()) info += L"; ";
        info += c.hmacSecret ? L"hmac-secret есть" : L"hmac-secret нет";
    }
    info += L"; PIN ";
    info += c.pinSet ? L"задан"
                     : (c.clientPinSupported ? L"не задан" : L"не поддерживается");

    // Asking whether this key already holds one of our credentials needs an
    // assertion with user presence switched off -- no touch, no PIN.
    switch (enrollment::KeyRegistered(c.path)) {
        case token::Held::Yes:
            r.registered = true;
            break;
        case token::Held::No:
            break;
        case token::Held::Unknown:
            // Not the same as "no": say so rather than showing a bare
            // unticked box that reads as a definite answer.
            info += L"; регистрацию проверить не удалось";
            break;
    }

    r.info = info;
    return r;
}

// --------------------------------------------------------------- confirm ---
//
// The window that drives the key. It exists because of how user presence
// works: a key with a button signals presence when touched, but a key without
// one signals it only for a few seconds right after it is plugged in. Waiting
// for the key to appear and firing the operation at that moment is the only
// sequence that works for both, so this dialog watches for an arrival instead
// of demanding that a key already be there.

constexpr UINT_PTR kArrivalTimer = 1;
constexpr UINT kArrivalPollMs = 600;

struct ConfirmParams {
    std::wstring account;
    VaultMode mode = VaultMode::Fido2HmacSecret;
    bool isTest = false;

    std::string pin;            // wiped by the dialog
    std::wstring password;      // wiped by the dialog
    std::string preferredPath;  // whatever was picked in the previous dialog

    enrollment::Status status;  // out
};

struct ConfirmState {
    ConfirmParams* p = nullptr;
    HBITMAP bmp = nullptr;
    std::set<std::string> baseline;  // keys already present when we opened
    bool running = false;
};

std::set<std::string> CurrentPaths()
{
    std::set<std::string> paths;
    try {
        for (const auto& d : token::ListDevices()) paths.insert(d.path);
    } catch (const std::exception&) {
    }
    return paths;
}

void ShowWaitingText(HWND dlg, bool anyPresent)
{
    SetStatus(dlg, IDC_CTITLE, L"Вставьте ключ");
    SetStatus(
        dlg, IDC_CTEXT,
        anyPresent
            ? L"Ключ уже вставлен — извлеките его и вставьте заново.\n\n"
              L"На ключах без кнопки подтверждение действует только первые "
              L"секунды после подключения, поэтому операция запускается в "
              L"момент, когда ключ появляется.\n\n"
              L"Если на ключе есть кнопка — можно нажать «Использовать "
              L"вставленный ключ»."
            : L"Вставьте ключ в USB-порт — операция начнётся сама.\n\n"
              L"На ключах без кнопки подтверждение действует только первые "
              L"секунды после подключения, поэтому ждать приходится именно "
              L"подключения.\n\n"
              L"Если на ключе есть кнопка — коснитесь её, когда он замигает.");
}

void StartKeyJob(HWND dlg, ConfirmState* st, const std::string& path)
{
    if (!st || st->running) return;
    st->running = true;
    KillTimer(dlg, kArrivalTimer);

    EnableWindow(GetDlgItem(dlg, IDC_USEPRESENT), FALSE);
    EnableWindow(GetDlgItem(dlg, IDCANCEL), FALSE);
    SetStatus(dlg, IDC_CTITLE, L"Работа с ключом");
    SetStatus(dlg, IDC_CTEXT,
              L"Не извлекайте ключ. Если он замигает, коснитесь его.");
    SetStatus(dlg, IDC_CSTATUS, L"Обращение к ключу…");

    ConfirmParams* p = st->p;
    const std::wstring account = p->account;
    const VaultMode mode = p->mode;
    const bool isTest = p->isTest;
    std::string pin = p->pin;
    std::wstring password = p->password;

    const bool started = StartJob(
        dlg, [account, path, pin, password, mode, isTest](
                 const enrollment::ProgressFn& progress) mutable {
            auto result =
                isTest ? enrollment::Test(account, path, pin, progress)
                       : enrollment::Enroll(account, path, pin, password, mode,
                                            progress);
            SecureClear(pin);
            SecureClear(password);
            return result;
        });
    SecureClear(pin);
    SecureClear(password);

    if (!started) {
        st->running = false;
        EnableWindow(GetDlgItem(dlg, IDCANCEL), TRUE);
        SetStatus(dlg, IDC_CSTATUS, L"Не удалось запустить операцию.");
        SetTimer(dlg, kArrivalTimer, kArrivalPollMs, nullptr);
    }
}

INT_PTR CALLBACK ConfirmProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    auto* st = (ConfirmState*)GetWindowLongPtrW(dlg, GWLP_USERDATA);

    switch (msg) {
        case WM_INITDIALOG: {
            st = new ConfirmState();
            st->p = (ConfirmParams*)lp;
            SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)st);

            st->bmp = LoadBitmapW(g_inst, MAKEINTRESOURCEW(IDB_KEY));
            if (st->bmp)
                SendDlgItemMessageW(dlg, IDC_KEYPIC, STM_SETIMAGE, IMAGE_BITMAP,
                                    (LPARAM)st->bmp);

            SetWindowTextW(dlg, st->p->isTest ? L"Проверка ключа"
                                              : L"Регистрация ключа");

            st->baseline = CurrentPaths();
            ShowWaitingText(dlg, !st->baseline.empty());
            EnableWindow(GetDlgItem(dlg, IDC_USEPRESENT),
                         st->baseline.empty() ? FALSE : TRUE);
            SetTimer(dlg, kArrivalTimer, kArrivalPollMs, nullptr);
            return TRUE;
        }

        case WM_TIMER: {
            if (!st || st->running) return TRUE;
            const std::set<std::string> now = CurrentPaths();

            // A key that was not there a moment ago has just been plugged in:
            // this is the window in which a button-less key will accept the
            // operation, so take it immediately.
            for (const auto& path : now) {
                if (st->baseline.count(path) == 0) {
                    StartKeyJob(dlg, st, path);
                    return TRUE;
                }
            }

            // Keys removed since we opened can be inserted again to trigger
            // the branch above.
            st->baseline = now;
            EnableWindow(GetDlgItem(dlg, IDC_USEPRESENT),
                         now.empty() ? FALSE : TRUE);
            return TRUE;
        }

        case WM_JOB_PROGRESS:
            SetStatus(dlg, IDC_CSTATUS, StepText((enrollment::Step)wp));
            return TRUE;

        case WM_JOB_DONE: {
            std::unique_ptr<enrollment::Status> status((enrollment::Status*)lp);
            if (!st) return TRUE;
            st->running = false;

            if (status->ok) {
                st->p->status = *status;
                EndDialog(dlg, IDOK);
                return TRUE;
            }

            // Not fatal: the usual cause is missing the presence window, and
            // the fix is simply to plug the key in again. Keep waiting.
            st->p->status = *status;
            SetStatus(dlg, IDC_CSTATUS, status->error);
            st->baseline = CurrentPaths();
            ShowWaitingText(dlg, !st->baseline.empty());
            EnableWindow(GetDlgItem(dlg, IDC_USEPRESENT),
                         st->baseline.empty() ? FALSE : TRUE);
            EnableWindow(GetDlgItem(dlg, IDCANCEL), TRUE);
            SetTimer(dlg, kArrivalTimer, kArrivalPollMs, nullptr);
            return TRUE;
        }

        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case IDC_USEPRESENT: {
                    if (!st || st->running) return TRUE;
                    const std::set<std::string> now = CurrentPaths();
                    if (now.empty()) {
                        SetStatus(dlg, IDC_CSTATUS, L"Ключ не найден.");
                        return TRUE;
                    }
                    // Prefer whatever was chosen a dialog ago, if it is still
                    // attached.
                    const std::string path =
                        now.count(st->p->preferredPath) ? st->p->preferredPath
                                                        : *now.begin();
                    StartKeyJob(dlg, st, path);
                    return TRUE;
                }

                case IDCANCEL:
                    if (st && st->running) return TRUE;
                    EndDialog(dlg, IDCANCEL);
                    return TRUE;
            }
            return FALSE;

        case WM_DESTROY:
            if (st) {
                KillTimer(dlg, kArrivalTimer);
                if (st->bmp) DeleteObject(st->bmp);
                delete st;
                SetWindowLongPtrW(dlg, GWLP_USERDATA, 0);
            }
            return FALSE;
    }
    return FALSE;
}

// Runs one key operation, showing the confirmation window. Returns true on
// success; `p.status` carries the reason otherwise.
bool RunWithKey(HWND parent, ConfirmParams& p)
{
    const INT_PTR r = DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_CONFIRM),
                                      parent, ConfirmProc, (LPARAM)&p);
    SecureClear(p.pin);
    SecureClear(p.password);
    return r == IDOK;
}

// ---------------------------------------------------------------- enroll ---

struct EnrollState {
    std::vector<std::string> devicePaths;
};

// U2F has no PIN, so grey the box out and say so.
void ApplyModeToDialog(HWND dlg)
{
    const bool u2f = IsDlgButtonChecked(dlg, IDC_U2F) == BST_CHECKED;
    EnableWindow(GetDlgItem(dlg, IDC_EPIN), u2f ? FALSE : TRUE);
    if (u2f) ClearText(dlg, IDC_EPIN);
    SetStatus(dlg, IDC_HINT,
              u2f ? L"Режим U2F: PIN не используется. Пароль будет защищён "
                    L"ключом, который хранится на этом компьютере."
                  : L"");
}

void ShowSelectedDevice(HWND dlg, EnrollState* st)
{
    if (!st) return;
    const LRESULT idx = SendMessageW(GetDlgItem(dlg, IDC_DEVICE), CB_GETCURSEL, 0, 0);
    if (idx == CB_ERR || (size_t)idx >= st->devicePaths.size()) {
        SetStatus(dlg, IDC_DEVINFO, L"");
        return;
    }
    SetStatus(dlg, IDC_DEVINFO,
              ShortCapabilities(token::Probe(st->devicePaths[(size_t)idx])));
}

INT_PTR CALLBACK EnrollProc(HWND dlg, UINT msg, WPARAM wp, LPARAM)
{
    auto* st = (EnrollState*)GetWindowLongPtrW(dlg, GWLP_USERDATA);

    switch (msg) {
        case WM_INITDIALOG: {
            st = new EnrollState();
            SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)st);

            HWND accounts = GetDlgItem(dlg, IDC_ACCOUNT);
            for (const auto& name : enrollment::LocalUserNames())
                SendMessageW(accounts, CB_ADDSTRING, 0, (LPARAM)name.c_str());

            // Preselect whoever is running the tool, since that is usually the
            // account being enrolled.
            wchar_t me[256];
            DWORD cch = ARRAYSIZE(me);
            if (GetUserNameW(me, &cch)) {
                const LRESULT idx = SendMessageW(accounts, CB_FINDSTRINGEXACT,
                                                 (WPARAM)-1, (LPARAM)me);
                SendMessageW(accounts, CB_SETCURSEL,
                             idx == CB_ERR ? 0 : (WPARAM)idx, 0);
            } else {
                SendMessageW(accounts, CB_SETCURSEL, 0, 0);
            }

            // No key needs to be attached yet: the confirmation window waits
            // for one, and on button-less keys it has to be plugged in there
            // anyway.
            st->devicePaths = FillDeviceCombo(dlg, IDC_DEVICE);
            ShowSelectedDevice(dlg, st);
            ApplyModeToDialog(dlg);
            return TRUE;
        }

        case WM_COMMAND:
            if (LOWORD(wp) == IDC_DEVICE && HIWORD(wp) == CBN_SELCHANGE) {
                ShowSelectedDevice(dlg, st);
                return TRUE;
            }
            if (LOWORD(wp) == IDC_U2F) {
                ApplyModeToDialog(dlg);
                return TRUE;
            }
            switch (LOWORD(wp)) {
                case IDOK: {
                    if (!st) return TRUE;

                    const bool u2f =
                        IsDlgButtonChecked(dlg, IDC_U2F) == BST_CHECKED;
                    const std::wstring account = GetText(dlg, IDC_ACCOUNT);
                    if (account.empty()) {
                        ErrorBox(dlg, L"Выберите учётную запись.");
                        return TRUE;
                    }

                    std::wstring pinW = u2f ? std::wstring() : GetText(dlg, IDC_EPIN);
                    std::wstring pw1 = GetText(dlg, IDC_PW1);
                    std::wstring pw2 = GetText(dlg, IDC_PW2);

                    auto bail = [&](const wchar_t* why) {
                        SecureClear(pinW);
                        SecureClear(pw1);
                        SecureClear(pw2);
                        ErrorBox(dlg, why);
                    };

                    if (!u2f && pinW.empty()) {
                        bail(L"Введите PIN ключа.");
                        return TRUE;
                    }
                    if (pw1.empty()) {
                        bail(L"Введите пароль Windows. Пустой пароль не подходит.");
                        return TRUE;
                    }
                    if (pw1 != pw2) {
                        bail(L"Пароли не совпадают.");
                        return TRUE;
                    }
                    SecureClear(pw2);

                    // Catch a mistyped password now, rather than at the logon
                    // screen where it is much harder to diagnose.
                    if (enrollment::CheckWindowsPassword(account, pw1) ==
                        enrollment::PasswordCheck::Wrong) {
                        bail(L"Windows отклонила этот пароль для выбранной "
                             L"учётной записи.");
                        return TRUE;
                    }

                    if (u2f &&
                        MessageBoxW(dlg,
                                    L"Режим U2F слабее обычного.\n\n"
                                    L"В CTAP1 нет hmac-secret, поэтому ключ "
                                    L"шифрования пароля хранится на этом "
                                    L"компьютере (DPAPI), а токен только "
                                    L"подтверждает присутствие. Любой, кто "
                                    L"получил права SYSTEM или администратора "
                                    L"на этой машине, расшифрует пароль, не "
                                    L"имея токена.\n\nПродолжить?",
                                    L"Подтверждение режима U2F",
                                    MB_YESNO | MB_ICONWARNING |
                                        MB_DEFBUTTON2) != IDYES) {
                        SecureClear(pinW);
                        SecureClear(pw1);
                        return TRUE;
                    }

                    if (enrollment::IsEnrolled(account) &&
                        MessageBoxW(dlg,
                                    L"Для этой учётной записи ключ уже "
                                    L"зарегистрирован. Заменить регистрацию?",
                                    L"Подтверждение",
                                    MB_YESNO | MB_ICONQUESTION) != IDYES) {
                        SecureClear(pinW);
                        SecureClear(pw1);
                        return TRUE;
                    }

                    ConfirmParams p;
                    p.account = account;
                    p.mode = u2f ? VaultMode::U2fPresence
                                 : VaultMode::Fido2HmacSecret;
                    p.isTest = false;
                    p.pin = WideToUtf8(pinW);
                    p.password = pw1;
                    const LRESULT devIdx = SendMessageW(
                        GetDlgItem(dlg, IDC_DEVICE), CB_GETCURSEL, 0, 0);
                    if (devIdx != CB_ERR &&
                        (size_t)devIdx < st->devicePaths.size())
                        p.preferredPath = st->devicePaths[(size_t)devIdx];

                    SecureClear(pinW);
                    SecureClear(pw1);
                    ClearText(dlg, IDC_EPIN);
                    ClearText(dlg, IDC_PW1);
                    ClearText(dlg, IDC_PW2);

                    const bool ok = RunWithKey(dlg, p);
                    if (ok) {
                        MessageBoxW(dlg,
                                    L"Ключ зарегистрирован.\n\nСохраните "
                                    L"запасной способ входа (пароль "
                                    L"администратора или второй ключ) на "
                                    L"случай утери ключа.",
                                    L"Готово", MB_OK | MB_ICONINFORMATION);
                        EndDialog(dlg, IDOK);
                    }
                    return TRUE;
                }

                case IDCANCEL:
                    EndDialog(dlg, IDCANCEL);
                    return TRUE;
            }
            return FALSE;

        case WM_DESTROY:
            delete st;
            SetWindowLongPtrW(dlg, GWLP_USERDATA, 0);
            return FALSE;
    }
    return FALSE;
}

// ------------------------------------------------------------------ test ---

struct KeyState {
    std::wstring account;
    std::vector<std::string> devicePaths;
    bool noPin = false;  // U2F record: nothing to type
};

INT_PTR CALLBACK KeyProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    auto* st = (KeyState*)GetWindowLongPtrW(dlg, GWLP_USERDATA);

    switch (msg) {
        case WM_INITDIALOG: {
            st = new KeyState();
            st->account = *(const std::wstring*)lp;
            SetWindowLongPtrW(dlg, GWLP_USERDATA, (LONG_PTR)st);

            VaultMode mode = VaultMode::Fido2HmacSecret;
            const bool u2f = enrollment::EnrolledMode(st->account, mode) &&
                             mode == VaultMode::U2fPresence;
            SetStatus(dlg, IDC_KPROMPT,
                      L"Проверка входа для «" + st->account +
                          L"»: ключ расшифрует пароль, затем он будет сверен с "
                          L"Windows." +
                          (u2f ? L" Режим U2F: PIN не нужен." : L""));
            if (u2f) {
                EnableWindow(GetDlgItem(dlg, IDC_KPIN), FALSE);
                st->noPin = true;
            }

            st->devicePaths = FillDeviceCombo(dlg, IDC_KDEVICE);
            return TRUE;
        }

        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case IDOK: {
                    if (!st) return TRUE;

                    std::wstring pinW = st->noPin ? std::wstring()
                                                  : GetText(dlg, IDC_KPIN);
                    if (!st->noPin && pinW.empty()) {
                        ErrorBox(dlg, L"Введите PIN ключа.");
                        return TRUE;
                    }

                    ConfirmParams p;
                    p.account = st->account;
                    p.isTest = true;
                    p.pin = WideToUtf8(pinW);
                    const LRESULT devIdx = SendMessageW(
                        GetDlgItem(dlg, IDC_KDEVICE), CB_GETCURSEL, 0, 0);
                    if (devIdx != CB_ERR &&
                        (size_t)devIdx < st->devicePaths.size())
                        p.preferredPath = st->devicePaths[(size_t)devIdx];

                    SecureClear(pinW);
                    ClearText(dlg, IDC_KPIN);

                    if (RunWithKey(dlg, p)) {
                        MessageBoxW(dlg,
                                    L"Проверка пройдена: вход по ключу работает.",
                                    L"Готово", MB_OK | MB_ICONINFORMATION);
                        EndDialog(dlg, IDOK);
                    }
                    return TRUE;
                }

                case IDCANCEL:
                    EndDialog(dlg, IDCANCEL);
                    return TRUE;
            }
            return FALSE;

        case WM_DESTROY:
            delete st;
            SetWindowLongPtrW(dlg, GWLP_USERDATA, 0);
            return FALSE;
    }
    return FALSE;
}

// ------------------------------------------------------------------ main ---

std::vector<enrollment::Account> g_rows;
std::vector<KeyRow> g_keys;

// Set while we write the check states ourselves, so the guard that keeps the
// user from toggling them does not fight our own updates.
bool g_settingChecks = false;

void RefreshKeys(HWND dlg)
{
    HWND list = GetDlgItem(dlg, IDC_KEYLIST);

    g_settingChecks = true;
    ListView_DeleteAllItems(list);
    g_keys.clear();

    for (const auto& cap : token::ProbeAll()) g_keys.push_back(DescribeKey(cap));

    for (size_t i = 0; i < g_keys.size(); ++i) {
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = (int)i;
        item.pszText = &g_keys[i].name[0];
        ListView_InsertItem(list, &item);
        ListView_SetItemText(list, (int)i, 1, &g_keys[i].type[0]);
        ListView_SetItemText(list, (int)i, 2, &g_keys[i].info[0]);
        ListView_SetCheckState(list, (int)i, g_keys[i].registered ? TRUE : FALSE);
    }
    g_settingChecks = false;
}

void RefreshList(HWND dlg)
{
    HWND list = GetDlgItem(dlg, IDC_LIST);
    ListView_DeleteAllItems(list);
    g_rows = enrollment::Enrolled();

    for (size_t i = 0; i < g_rows.size(); ++i) {
        std::wstring name = g_rows[i].Display();
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = (int)i;
        item.pszText = &name[0];
        ListView_InsertItem(list, &item);

        std::wstring mode = g_rows[i].mode == VaultMode::U2fPresence ? L"U2F"
                                                                     : L"FIDO2";
        ListView_SetItemText(list, (int)i, 1, &mode[0]);

        std::wstring sid = g_rows[i].sid;
        ListView_SetItemText(list, (int)i, 2, &sid[0]);
    }

    std::wstring status;
    if (g_keys.empty())
        status = L"Ключей не найдено. Вставьте ключ и нажмите «Обновить». ";
    status += g_rows.empty()
                  ? L"Ни одна учётная запись не зарегистрирована."
                  : L"Зарегистрировано записей: " + std::to_wstring(g_rows.size()) + L".";
    SetStatus(dlg, IDC_STATUS, status);
}

// Index into g_rows, or -1.
int SelectedRow(HWND dlg)
{
    return ListView_GetNextItem(GetDlgItem(dlg, IDC_LIST), -1, LVNI_SELECTED);
}

INT_PTR CALLBACK MainProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
        case WM_INITDIALOG: {
            LVCOLUMNW col{};
            col.mask = LVCF_TEXT | LVCF_WIDTH;

            // The check box marks a key this program already has a record
            // for; it is a readout, not an input (see LVN_ITEMCHANGING).
            HWND keys = GetDlgItem(dlg, IDC_KEYLIST);
            ListView_SetExtendedListViewStyle(
                keys, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
                          LVS_EX_CHECKBOXES);
            col.cx = 190;
            col.pszText = const_cast<PWSTR>(L"Ключ (зарегистрирован)");
            ListView_InsertColumn(keys, 0, &col);
            col.cx = 60;
            col.pszText = const_cast<PWSTR>(L"Тип");
            ListView_InsertColumn(keys, 1, &col);
            col.cx = 330;
            col.pszText = const_cast<PWSTR>(L"Служебные данные");
            ListView_InsertColumn(keys, 2, &col);

            HWND list = GetDlgItem(dlg, IDC_LIST);
            ListView_SetExtendedListViewStyle(
                list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
            col.cx = 180;
            col.pszText = const_cast<PWSTR>(L"Учётная запись");
            ListView_InsertColumn(list, 0, &col);
            col.cx = 60;
            col.pszText = const_cast<PWSTR>(L"Режим");
            ListView_InsertColumn(list, 1, &col);
            col.cx = 240;
            col.pszText = const_cast<PWSTR>(L"SID");
            ListView_InsertColumn(list, 2, &col);

            RefreshKeys(dlg);
            RefreshList(dlg);
            return TRUE;
        }

        case WM_NOTIFY: {
            auto* nm = (LPNMHDR)lp;
            if (nm->idFrom == IDC_KEYLIST && nm->code == LVN_ITEMCHANGING &&
                !g_settingChecks) {
                auto* nv = (LPNMLISTVIEW)lp;
                // Refuse user edits of the check box: it reports what the
                // registry holds, and letting it be ticked would invent a
                // registration that does not exist.
                if ((nv->uChanged & LVIF_STATE) &&
                    ((nv->uNewState ^ nv->uOldState) & LVIS_STATEIMAGEMASK)) {
                    SetWindowLongPtrW(dlg, DWLP_MSGRESULT, TRUE);
                    return TRUE;
                }
            }
            return FALSE;
        }

        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case IDC_REFRESH:
                    RefreshKeys(dlg);
                    RefreshList(dlg);
                    return TRUE;

                case IDC_ENROLL:
                    if (DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_ENROLL), dlg,
                                        EnrollProc, 0) == IDOK) {
                        RefreshKeys(dlg);
                        RefreshList(dlg);
                    }
                    return TRUE;

                case IDC_TEST: {
                    const int row = SelectedRow(dlg);
                    if (row < 0 || (size_t)row >= g_rows.size()) {
                        SetStatus(dlg, IDC_STATUS, L"Выберите учётную запись в списке.");
                        return TRUE;
                    }
                    if (!g_rows[(size_t)row].Resolved()) {
                        SetStatus(dlg, IDC_STATUS,
                                  L"Эта учётная запись больше не существует — "
                                  L"проверять нечего, запись можно удалить.");
                        return TRUE;
                    }
                    const std::wstring account = g_rows[(size_t)row].user;
                    DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_KEY), dlg, KeyProc,
                                    (LPARAM)&account);
                    return TRUE;
                }

                case IDC_REMOVE: {
                    const int row = SelectedRow(dlg);
                    if (row < 0 || (size_t)row >= g_rows.size()) {
                        SetStatus(dlg, IDC_STATUS, L"Выберите учётную запись в списке.");
                        return TRUE;
                    }
                    const auto& acc = g_rows[(size_t)row];
                    const std::wstring text =
                        L"Удалить регистрацию ключа для «" + acc.Display() +
                        L"»?\n\nВход по ключу для этой учётной записи перестанет "
                        L"работать. Убедитесь, что помните её пароль.";
                    if (MessageBoxW(dlg, text.c_str(), L"Подтверждение",
                                    MB_YESNO | MB_ICONWARNING) != IDYES)
                        return TRUE;

                    const auto status = enrollment::RemoveBySid(acc.sid);
                    RefreshKeys(dlg);
                    RefreshList(dlg);
                    if (!status.ok) SetStatus(dlg, IDC_STATUS, status.error);
                    return TRUE;
                }

                case IDCANCEL:
                    EndDialog(dlg, 0);
                    return TRUE;
            }
            return FALSE;

        case WM_CLOSE:
            EndDialog(dlg, 0);
            return TRUE;
    }
    return FALSE;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int)
{
    g_inst = inst;

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    DialogBoxParamW(inst, MAKEINTRESOURCEW(IDD_MAIN), nullptr, MainProc, 0);
    return 0;
}
