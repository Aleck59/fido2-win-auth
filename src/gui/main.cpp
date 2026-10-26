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

void SetStatus(HWND dlg, int id, const std::wstring& text)
{
    SetDlgItemTextW(dlg, id, text.c_str());
}

void EnableControls(HWND dlg, const int* ids, size_t count, bool on)
{
    for (size_t i = 0; i < count; ++i)
        EnableWindow(GetDlgItem(dlg, ids[i]), on ? TRUE : FALSE);
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

// The full report, for the "Ключи…" button.
std::wstring DescribeKeys()
{
    const auto keys = token::ProbeAll();
    if (keys.empty())
        return L"Ключи не найдены. Вставьте ключ и нажмите «Ключи…» ещё раз.";

    std::wstring text;
    for (const auto& k : keys) {
        if (!text.empty()) text += L"\n";
        std::wstring label = Utf8ToWide(k.manufacturer + " " + k.product);
        text += label.empty() ? L"(безымянный ключ)" : label;
        text += L"\n";

        if (k.probeFailed) {
            text += L"    опросить не удалось: " + Utf8ToWide(k.probeError) + L"\n";
            continue;
        }

        text += std::wstring(L"    протокол: ") +
                (k.isFido2 ? L"CTAP2 (FIDO2)" : L"только U2F (CTAP1)") + L"\n";
        text += std::wstring(L"    hmac-secret: ") +
                (k.hmacSecret ? L"есть" : L"нет") + L"\n";
        text += std::wstring(L"    PIN: ") +
                (k.pinSet ? L"задан"
                          : (k.clientPinSupported ? L"поддерживается, но не задан"
                                                  : L"не поддерживается")) + L"\n";
        text += k.usable ? L"    Пригоден для регистрации.\n"
                         : L"    НЕ пригоден: " + Utf8ToWide(k.reason) + L".\n";
    }
    return text;
}

// ---------------------------------------------------------------- enroll ---

struct EnrollState {
    std::vector<std::string> devicePaths;
    bool running = false;
};

// U2F has no PIN, so grey the box out and say which touches to expect.
void ApplyModeToDialog(HWND dlg)
{
    const bool u2f = IsDlgButtonChecked(dlg, IDC_U2F) == BST_CHECKED;
    EnableWindow(GetDlgItem(dlg, IDC_EPIN), u2f ? FALSE : TRUE);
    if (u2f) ClearText(dlg, IDC_EPIN);
    SetStatus(dlg, IDC_HINT,
              u2f ? L"Режим U2F: PIN не используется, потребуется дважды "
                    L"коснуться ключа. Пароль будет защищён ключом, который "
                    L"хранится на этом компьютере."
                  : L"Потребуется трижды коснуться ключа: создание, получение "
                    L"секрета и контрольная проверка.");
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

INT_PTR CALLBACK EnrollProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    static const int kInputs[] = {IDC_ACCOUNT, IDC_DEVICE, IDC_EPIN,
                                  IDC_PW1,     IDC_PW2,    IDOK};
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

            st->devicePaths = FillDeviceCombo(dlg, IDC_DEVICE);
            if (st->devicePaths.empty())
                SetStatus(dlg, IDC_ESTATUS, L"Ключ не найден. Вставьте ключ и "
                                            L"откройте это окно заново.");
            ShowSelectedDevice(dlg, st);
            ApplyModeToDialog(dlg);
            return TRUE;
        }

        case WM_JOB_PROGRESS:
            SetStatus(dlg, IDC_ESTATUS, StepText((enrollment::Step)wp));
            return TRUE;

        case WM_JOB_DONE: {
            std::unique_ptr<enrollment::Status> status((enrollment::Status*)lp);
            if (st) st->running = false;
            EnableControls(dlg, kInputs, ARRAYSIZE(kInputs), true);
            EnableWindow(GetDlgItem(dlg, IDCANCEL), TRUE);

            if (status->ok) {
                MessageBoxW(dlg,
                            L"Ключ зарегистрирован.\n\nСохраните запасной способ "
                            L"входа (пароль администратора или второй ключ) на "
                            L"случай утери ключа.",
                            L"Готово", MB_OK | MB_ICONINFORMATION);
                EndDialog(dlg, IDOK);
            } else {
                SetStatus(dlg, IDC_ESTATUS, status->error);
            }
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
                    if (!st || st->running) return TRUE;

                    const LRESULT devIdx =
                        SendMessageW(GetDlgItem(dlg, IDC_DEVICE), CB_GETCURSEL, 0, 0);
                    if (devIdx == CB_ERR || (size_t)devIdx >= st->devicePaths.size()) {
                        SetStatus(dlg, IDC_ESTATUS, L"Выберите ключ.");
                        return TRUE;
                    }

                    const std::wstring account = GetText(dlg, IDC_ACCOUNT);
                    if (account.empty()) {
                        SetStatus(dlg, IDC_ESTATUS, L"Выберите учётную запись.");
                        return TRUE;
                    }

                    const bool u2f =
                        IsDlgButtonChecked(dlg, IDC_U2F) == BST_CHECKED;

                    std::wstring pinW = u2f ? std::wstring() : GetText(dlg, IDC_EPIN);
                    std::wstring pw1 = GetText(dlg, IDC_PW1);
                    std::wstring pw2 = GetText(dlg, IDC_PW2);

                    auto bail = [&](const wchar_t* why) {
                        SecureClear(pinW);
                        SecureClear(pw1);
                        SecureClear(pw2);
                        SetStatus(dlg, IDC_ESTATUS, why);
                    };

                    if (!u2f && pinW.empty()) {
                        bail(L"Введите PIN ключа.");
                        return TRUE;
                    }
                    if (pw1.empty()) {
                        bail(L"Введите пароль Windows. Пустой пароль не подходит.");
                        return TRUE;
                    }
                    if (pw1 != pw2) { bail(L"Пароли не совпадают."); return TRUE; }
                    SecureClear(pw2);
                    ClearText(dlg, IDC_PW2);

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

                    st->running = true;
                    EnableControls(dlg, kInputs, ARRAYSIZE(kInputs), false);
                    EnableWindow(GetDlgItem(dlg, IDCANCEL), FALSE);
                    SetStatus(dlg, IDC_ESTATUS, L"Обращение к ключу…");
                    ClearText(dlg, IDC_EPIN);
                    ClearText(dlg, IDC_PW1);

                    const std::string path = st->devicePaths[(size_t)devIdx];
                    std::string pin = WideToUtf8(pinW);
                    SecureClear(pinW);

                    const VaultMode vmode = u2f ? VaultMode::U2fPresence
                                                : VaultMode::Fido2HmacSecret;
                    const bool started = StartJob(
                        dlg, [account, path, pin, pw1, vmode](
                                 const enrollment::ProgressFn& p) mutable {
                            auto result =
                                enrollment::Enroll(account, path, pin, pw1, vmode, p);
                            SecureClear(pin);
                            SecureClear(pw1);
                            return result;
                        });
                    SecureClear(pin);
                    SecureClear(pw1);

                    if (!started) {
                        st->running = false;
                        EnableControls(dlg, kInputs, ARRAYSIZE(kInputs), true);
                        EnableWindow(GetDlgItem(dlg, IDCANCEL), TRUE);
                        SetStatus(dlg, IDC_ESTATUS, L"Не удалось запустить операцию.");
                    }
                    return TRUE;
                }

                case IDCANCEL:
                    if (st && st->running) return TRUE;  // let the key finish
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
    bool running = false;
    bool noPin = false;  // U2F record: nothing to type
};

INT_PTR CALLBACK KeyProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    static const int kInputs[] = {IDC_KDEVICE, IDC_KPIN, IDOK};
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
            if (st->devicePaths.empty())
                SetStatus(dlg, IDC_ESTATUS, L"Ключ не найден.");
            return TRUE;
        }

        case WM_JOB_PROGRESS:
            SetStatus(dlg, IDC_ESTATUS, StepText((enrollment::Step)wp));
            return TRUE;

        case WM_JOB_DONE: {
            std::unique_ptr<enrollment::Status> status((enrollment::Status*)lp);
            if (st) st->running = false;
            EnableControls(dlg, kInputs, ARRAYSIZE(kInputs), true);
            EnableWindow(GetDlgItem(dlg, IDCANCEL), TRUE);

            if (status->ok) {
                MessageBoxW(dlg, L"Проверка пройдена: вход по ключу работает.",
                            L"Готово", MB_OK | MB_ICONINFORMATION);
                EndDialog(dlg, IDOK);
            } else {
                SetStatus(dlg, IDC_ESTATUS, status->error);
            }
            return TRUE;
        }

        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case IDOK: {
                    if (!st || st->running) return TRUE;

                    const LRESULT devIdx =
                        SendMessageW(GetDlgItem(dlg, IDC_KDEVICE), CB_GETCURSEL, 0, 0);
                    if (devIdx == CB_ERR || (size_t)devIdx >= st->devicePaths.size()) {
                        SetStatus(dlg, IDC_ESTATUS, L"Выберите ключ.");
                        return TRUE;
                    }

                    std::wstring pinW = st->noPin ? std::wstring()
                                                  : GetText(dlg, IDC_KPIN);
                    if (!st->noPin && pinW.empty()) {
                        SetStatus(dlg, IDC_ESTATUS, L"Введите PIN ключа.");
                        return TRUE;
                    }

                    st->running = true;
                    EnableControls(dlg, kInputs, ARRAYSIZE(kInputs), false);
                    EnableWindow(GetDlgItem(dlg, IDCANCEL), FALSE);
                    SetStatus(dlg, IDC_ESTATUS, L"Обращение к ключу…");
                    ClearText(dlg, IDC_KPIN);

                    const std::string path = st->devicePaths[(size_t)devIdx];
                    const std::wstring account = st->account;
                    std::string pin = WideToUtf8(pinW);
                    SecureClear(pinW);

                    const bool started = StartJob(
                        dlg, [account, path, pin](
                                 const enrollment::ProgressFn& p) mutable {
                            auto result = enrollment::Test(account, path, pin, p);
                            SecureClear(pin);
                            return result;
                        });
                    SecureClear(pin);

                    if (!started) {
                        st->running = false;
                        EnableControls(dlg, kInputs, ARRAYSIZE(kInputs), true);
                        EnableWindow(GetDlgItem(dlg, IDCANCEL), TRUE);
                        SetStatus(dlg, IDC_ESTATUS, L"Не удалось запустить операцию.");
                    }
                    return TRUE;
                }

                case IDCANCEL:
                    if (st && st->running) return TRUE;
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

    SetStatus(dlg, IDC_STATUS,
              g_rows.empty()
                  ? L"Ни одна учётная запись не зарегистрирована. Нажмите "
                    L"«Зарегистрировать…»."
                  : L"Зарегистрировано записей: " + std::to_wstring(g_rows.size()) + L".");
}

// Index into g_rows, or -1.
int SelectedRow(HWND dlg)
{
    return ListView_GetNextItem(GetDlgItem(dlg, IDC_LIST), -1, LVNI_SELECTED);
}

INT_PTR CALLBACK MainProc(HWND dlg, UINT msg, WPARAM wp, LPARAM)
{
    switch (msg) {
        case WM_INITDIALOG: {
            HWND list = GetDlgItem(dlg, IDC_LIST);
            ListView_SetExtendedListViewStyle(
                list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

            LVCOLUMNW col{};
            col.mask = LVCF_TEXT | LVCF_WIDTH;
            col.cx = 180;
            col.pszText = const_cast<PWSTR>(L"Учётная запись");
            ListView_InsertColumn(list, 0, &col);
            col.cx = 60;
            col.pszText = const_cast<PWSTR>(L"Режим");
            ListView_InsertColumn(list, 1, &col);
            col.cx = 240;
            col.pszText = const_cast<PWSTR>(L"SID");
            ListView_InsertColumn(list, 2, &col);

            RefreshList(dlg);
            return TRUE;
        }

        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case IDC_REFRESH:
                    RefreshList(dlg);
                    return TRUE;

                case IDC_KEYS:
                    MessageBoxW(dlg, DescribeKeys().c_str(), L"Вставленные ключи",
                                MB_OK | MB_ICONINFORMATION);
                    return TRUE;

                case IDC_ENROLL:
                    if (DialogBoxParamW(g_inst, MAKEINTRESOURCEW(IDD_ENROLL), dlg,
                                        EnrollProc, 0) == IDOK)
                        RefreshList(dlg);
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
