#include "Credential.h"

#include "../common/plog.h"
#include "../common/store.h"
#include "../common/token.h"
#include "../common/unlock.h"
#include "../common/vault.h"
#include "guid.h"
#include "kerb.h"
#include "resource.h"

#include <strsafe.h>

#include <set>

namespace {

// How long to ask an already-attached U2F key whether it will answer now.
// Long enough for a key that already holds user presence, short enough that
// learning otherwise is not a visible stall.
constexpr int kU2fProbeTimeoutMs = 2500;

// How often to look for a key being plugged in, and how long to keep looking.
constexpr DWORD kArrivalPollMs = 500;
constexpr DWORD kArrivalGiveUpMs = 120000;

std::set<std::string> AttachedPaths()
{
    std::set<std::string> paths;
    try {
        for (const auto& d : token::ListDevices()) paths.insert(d.path);
    } catch (const std::exception&) {
    }
    return paths;
}

}  // namespace

CFido2Credential::CFido2Credential()
    : ref_(1), cpus_(CPUS_INVALID), events_(nullptr), unlocked_(false),
      mode_(VaultMode::Fido2HmacSecret), haveMode_(false)
{
    DllAddRef();
    for (int i = 0; i < FI_NUM_FIELDS; ++i) fieldStrings_[i] = nullptr;
}

CFido2Credential::~CFido2Credential()
{
    for (int i = 0; i < FI_NUM_FIELDS; ++i)
        if (fieldStrings_[i]) CoTaskMemFree(fieldStrings_[i]);
    ClearSecrets();
    DllRelease();
}

HRESULT CFido2Credential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                     const std::wstring& sid,
                                     const std::wstring& domain,
                                     const std::wstring& user)
{
    cpus_ = cpus;
    sid_ = sid;
    domain_ = domain;
    user_ = user;
    // Peek at the record so the tile can describe itself correctly. A failure
    // here is not fatal: Connect() reports the real problem.
    {
        Bytes blob;
        if (store::LoadRecord(sid_, blob)) {
            try {
                mode_ = VaultRecord::Deserialize(blob).mode;
                haveMode_ = true;
            } catch (const std::exception&) {
            }
            SecureClear(blob);
        }
    }

    const bool u2f = haveMode_ && mode_ == VaultMode::U2fPresence;
    plog::Write(L"Initialize: user=" + user_ + L" record=" +
                (haveMode_ ? (u2f ? L"U2F" : L"FIDO2") : L"(нет или нечитаема)"));
    initialStatus_ = u2f ? L"Вставьте ключ — вход начнётся сам."
                         : L"";
    displayLabel_ = u2f ? L"Вход по ключу U2F" : L"Вход по ключу FIDO2";
    if (!user_.empty()) displayLabel_ += L" (" + user_ + L")";

    // Seed the per-field string values from the static descriptors.
    HRESULT hr = SHStrDupWHelper(displayLabel_.c_str(), &fieldStrings_[FI_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupWHelper(L"", &fieldStrings_[FI_PIN]);
    if (SUCCEEDED(hr)) hr = SHStrDupWHelper(g_fieldDescriptors[FI_SUBMIT].pszLabel,
                                            &fieldStrings_[FI_SUBMIT]);
    if (SUCCEEDED(hr))
        hr = SHStrDupWHelper(initialStatus_.c_str(), &fieldStrings_[FI_STATUS]);
    return hr;
}

IFACEMETHODIMP_(ULONG) CFido2Credential::Release()
{
    LONG r = --ref_;
    if (r == 0) delete this;
    return r;
}

IFACEMETHODIMP CFido2Credential::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential ||
        riid == IID_ICredentialProviderCredential2) {
        *ppv = static_cast<ICredentialProviderCredential2*>(this);
        AddRef();
        return S_OK;
    }
    if (riid == IID_IConnectableCredentialProviderCredential) {
        // Answering this is what makes LogonUI call Connect() on a background
        // thread before asking for the serialization.
        *ppv = static_cast<IConnectableCredentialProviderCredential*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

IFACEMETHODIMP CFido2Credential::Advise(ICredentialProviderCredentialEvents* e)
{
    if (events_) events_->Release();
    events_ = e;
    if (events_) events_->AddRef();
    return S_OK;
}

IFACEMETHODIMP CFido2Credential::UnAdvise()
{
    if (events_) events_->Release();
    events_ = nullptr;
    return S_OK;
}

IFACEMETHODIMP CFido2Credential::SetSelected(BOOL* autoLogon)
{
    // A U2F tile has nothing to type: the PIN box is hidden because CTAP1 has
    // no PIN. Starting as soon as the sign-in option is chosen is both what
    // the user means by choosing it and the only way the key-arrival wait in
    // Connect() ever gets a chance to run.
    //
    // This tile is never the default (the provider reports
    // CREDENTIAL_PROVIDER_NO_DEFAULT), so this only fires on a deliberate
    // selection, and QueryContinue lets the user back out.
    *autoLogon = (haveMode_ && mode_ == VaultMode::U2fPresence) ? TRUE : FALSE;
    plog::Write(std::wstring(L"SetSelected: autoLogon=") +
                (*autoLogon ? L"TRUE" : L"FALSE"));
    return S_OK;
}

IFACEMETHODIMP CFido2Credential::SetDeselected()
{
    // Clear the typed PIN and anything Connect() recovered.
    ClearSecrets();
    if (fieldStrings_[FI_PIN]) {
        CoTaskMemFree(fieldStrings_[FI_PIN]);
        SHStrDupWHelper(L"", &fieldStrings_[FI_PIN]);
        if (events_)
            events_->SetFieldString(AsCredential(), FI_PIN, L"");
    }
    SetStatus(initialStatus_.c_str());
    return S_OK;
}

IFACEMETHODIMP CFido2Credential::GetFieldState(
    DWORD field, CREDENTIAL_PROVIDER_FIELD_STATE* fs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* is)
{
    if (field >= FI_NUM_FIELDS || !fs || !is) return E_INVALIDARG;
    *fs = g_fieldStatePairs[field].cpfs;
    *is = g_fieldStatePairs[field].cpfis;
    // U2F has no PIN: showing an input that is ignored would only mislead.
    if (field == FI_PIN && haveMode_ && mode_ == VaultMode::U2fPresence) {
        *fs = CPFS_HIDDEN;
        *is = CPFIS_NONE;
    }
    return S_OK;
}

IFACEMETHODIMP CFido2Credential::GetStringValue(DWORD field, PWSTR* value)
{
    if (field >= FI_NUM_FIELDS || !value) return E_INVALIDARG;
    return SHStrDupWHelper(fieldStrings_[field] ? fieldStrings_[field] : L"", value);
}

IFACEMETHODIMP CFido2Credential::GetBitmapValue(DWORD field, HBITMAP* bmp)
{
    if (field != FI_TILEIMAGE || !bmp) return E_INVALIDARG;
    HBITMAP loaded = LoadBitmapW(DllInstance(), MAKEINTRESOURCEW(IDB_TILE));
    if (!loaded) {
        // Fall back to the system default credential-provider logo.
        *bmp = nullptr;
        return E_NOTIMPL;
    }
    *bmp = loaded;
    return S_OK;
}

IFACEMETHODIMP CFido2Credential::GetCheckboxValue(DWORD, BOOL*, PWSTR*)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFido2Credential::GetSubmitButtonValue(DWORD field, DWORD* adjacentTo)
{
    if (field != FI_SUBMIT || !adjacentTo) return E_INVALIDARG;
    // The button is drawn beside the field named here, so that field has to be
    // one that is actually displayed. For a U2F record the PIN box is hidden,
    // and pointing at it left the tile with no way to submit at all.
    *adjacentTo = (haveMode_ && mode_ == VaultMode::U2fPresence) ? FI_STATUS
                                                                 : FI_PIN;
    return S_OK;
}

IFACEMETHODIMP CFido2Credential::GetComboBoxValueCount(DWORD, DWORD*, DWORD*)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFido2Credential::GetComboBoxValueAt(DWORD, DWORD, PWSTR*)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFido2Credential::SetStringValue(DWORD field, PCWSTR value)
{
    if (field >= FI_NUM_FIELDS) return E_INVALIDARG;
    if (field == FI_PIN) {
        if (!pin_.empty()) SecureZeroMemory(&pin_[0], pin_.size() * sizeof(wchar_t));
        pin_ = value ? value : L"";
        return S_OK;
    }
    // Other fields are read-only labels; ignore writes.
    return S_OK;
}

IFACEMETHODIMP CFido2Credential::SetCheckboxValue(DWORD, BOOL) { return E_NOTIMPL; }
IFACEMETHODIMP CFido2Credential::SetComboBoxSelectedValue(DWORD, DWORD) { return E_NOTIMPL; }
IFACEMETHODIMP CFido2Credential::CommandLinkClicked(DWORD) { return E_NOTIMPL; }

void CFido2Credential::SetStatus(PCWSTR text)
{
    if (fieldStrings_[FI_STATUS]) CoTaskMemFree(fieldStrings_[FI_STATUS]);
    SHStrDupWHelper(text ? text : L"", &fieldStrings_[FI_STATUS]);
    if (events_) events_->SetFieldString(AsCredential(), FI_STATUS, text ? text : L"");
}

void CFido2Credential::Fail(const std::wstring& message)
{
    connectError_ = message;
    SetStatus(message.c_str());
}

void CFido2Credential::ClearSecrets()
{
    SecureClear(pin_);
    SecureClear(password_);
    unlocked_ = false;
}

// Talks to the key: finds the one holding this account's credential, obtains
// the hmac-secret and decrypts the password. LogonUI runs this on a worker
// thread, so waiting for a touch here does not freeze the logon screen, and it
// can show progress while we wait.
unlock::Outcome CFido2Credential::WaitForU2fKey(const VaultRecord& rec,
                                                IQueryContinueWithStatus* qcws,
                                                std::wstring& lastError)
{
    unlock::Outcome out;
    std::set<std::string> baseline = AttachedPaths();

    // Only the IQueryContinueWithStatus channel is touched from here: this
    // runs on LogonUI's worker thread, and the field-events interface belongs
    // to its UI thread.
    const wchar_t* waiting =
        baseline.empty() ? L"Вставьте ключ безопасности…"
                         : L"Извлеките ключ и вставьте его снова…";
    if (qcws) qcws->SetStatusMessage(waiting);

    const DWORD start = GetTickCount();
    for (;;) {
        if (qcws && qcws->QueryContinue() != S_OK) {
            lastError = L"Отменено.";
            return out;
        }
        if (GetTickCount() - start > kArrivalGiveUpMs) {
            lastError = L"Ключ так и не был подключён. Повторите вход.";
            return out;
        }

        Sleep(kArrivalPollMs);
        const std::set<std::string> now = AttachedPaths();

        for (const auto& path : now) {
            if (baseline.count(path)) continue;

            // Just plugged in: this is the moment a button-less key will
            // answer, and the moment a key with a button starts asking to be
            // touched. The full timeout applies here on purpose.
            if (qcws) qcws->SetStatusMessage(L"Ключ обнаружен, проверяем…");
            plog::Write(L"WaitForU2fKey: ключ подключён, проверяем");
            out = unlock::WithDevice(rec, path, std::string());
            if (out.ok) return out;

            lastError = out.error;
            // A verdict that will not change on another insertion.
            if (!out.wrongKey) return out;

            if (qcws)
                qcws->SetStatusMessage(L"Этот ключ не подошёл. Вставьте нужный ключ…");
        }
        baseline = now;
    }
}

IFACEMETHODIMP CFido2Credential::Connect(IQueryContinueWithStatus* qcws)
{
    plog::Write(L"Connect: начало");
    SecureClear(password_);
    unlocked_ = false;
    connectError_.clear();

    // Load this account's vault record.
    Bytes blob;
    if (!store::LoadRecord(sid_, blob)) {
        Fail(L"Для этой учётной записи нет регистрации ключа.");
        return S_OK;
    }

    VaultRecord rec;
    try {
        rec = VaultRecord::Deserialize(blob);
    } catch (const std::exception&) {
        Fail(L"Повреждённая запись ключа.");
        return S_OK;
    }

    if (qcws) qcws->SetStatusMessage(L"Поиск ключа безопасности...");

    auto devices = token::ListDevices();
    plog::Write(L"Connect: подключённых ключей " +
                std::to_wstring(devices.size()));
    if (devices.empty() && rec.mode != VaultMode::U2fPresence) {
        Fail(L"Вставьте ключ безопасности и повторите.");
        return S_OK;
    }

    if (qcws && qcws->QueryContinue() != S_OK) {
        Fail(L"Отменено.");
        return S_OK;
    }
    if (qcws)
        qcws->SetStatusMessage(rec.mode == VaultMode::U2fPresence
                                   ? L"Проверяем подключённые ключи…"
                                   : L"Коснитесь ключа безопасности…");

    std::string pinUtf8;
    {
        int n = WideCharToMultiByte(CP_UTF8, 0, pin_.c_str(), (int)pin_.size(),
                                    nullptr, 0, nullptr, nullptr);
        pinUtf8.resize(n > 0 ? n : 0);
        if (n > 0)
            WideCharToMultiByte(CP_UTF8, 0, pin_.c_str(), (int)pin_.size(),
                                &pinUtf8[0], n, nullptr, nullptr);
    }

    // Try each present key; the one this record belongs to succeeds, the others
    // answer with a benign error. unlock::WithDevice dispatches on the record's
    // mode, so FIDO2 and U2F records follow the same loop here.
    const bool u2f = rec.mode == VaultMode::U2fPresence;
    unlock::Outcome out;
    std::wstring lastError = L"Ключ не распознал учётные данные.";
    bool decided = false;

    for (const auto& dev : devices) {
        // Each attempt can wait on a touch, so honour a cancelled logon
        // between keys rather than only at the end.
        if (qcws && qcws->QueryContinue() != S_OK) {
            SecureClear(pinUtf8);
            Fail(L"Отменено.");
            return S_OK;
        }

        // For U2F this pass is only a quick question -- "is this key willing
        // right now?" -- because a key with no button is willing only in the
        // seconds after it was plugged in. Asking with the full timeout is
        // what made the logon screen sit there doing nothing.
        out = unlock::WithDevice(rec, dev.path, pinUtf8,
                                 u2f ? kU2fProbeTimeoutMs : 0);
        plog::Write(L"Connect: попытка на вставленном ключе -> " +
                    (out.ok ? std::wstring(L"успех") : out.error));
        if (out.ok) break;

        lastError = out.error;
        // A definite verdict about this record (a cloned-key counter, an
        // unreadable DPAPI blob, a failed decrypt) will not change on another
        // key, so stop rather than making the user touch every one.
        if (!out.wrongKey) {
            decided = true;
            break;
        }
    }

    // Nothing attached would answer. For U2F that is the normal case rather
    // than a failure: wait for the key to be plugged in and run the assertion
    // at that moment, which is when a button-less key grants user presence and
    // when a key with a button starts asking to be touched.
    if (!out.ok && u2f && !decided) {
        plog::Write(L"Connect: ждём подключения ключа");
        out = WaitForU2fKey(rec, qcws, lastError);
        plog::Write(L"Connect: ожидание завершено -> " +
                    (out.ok ? std::wstring(L"успех") : lastError));
    }
    SecureClear(pinUtf8);

    if (!out.ok) {
        SecureClear(out.password);
        Fail(lastError);
        return S_OK;
    }

    // A U2F logon consumes a counter value; persist it so a replay of this
    // assertion cannot be used again.
    if (out.counterAdvanced) {
        rec.counter = out.counter;
        try {
            store::SaveRecord(sid_, rec.Serialize());
        } catch (const std::exception&) {
            // Logon still proceeds: refusing to let the user in because a
            // counter could not be written would be the worse failure.
        }
    }

    password_ = out.password;
    SecureClear(out.password);
    unlocked_ = true;
    SetStatus(L"Ключ подтверждён. Вход...");
    if (qcws) qcws->SetStatusMessage(L"Вход...");
    return S_OK;
}

IFACEMETHODIMP CFido2Credential::Disconnect()
{
    // The password must survive until GetSerialization() consumes it; the PIN
    // has done its job and can go now.
    SecureClear(pin_);
    return S_OK;
}

// Packs the password Connect() recovered into a KERB logon blob for LSA. No
// key access happens here, so this returns promptly.
IFACEMETHODIMP CFido2Credential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
    PWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon)
{
    *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *statusText = nullptr;
    *statusIcon = CPSI_NONE;

    if (!unlocked_) {
        // Connect() either never ran or left a reason on connectError_.
        SHStrDupWHelper(connectError_.empty() ? L"Вход по ключу не выполнен."
                                              : connectError_.c_str(),
                        statusText);
        *statusIcon = CPSI_ERROR;
        plog::Write(L"GetSerialization: нечего отдавать — " + connectError_);
        return S_FALSE;
    }

    plog::Write(L"GetSerialization: отдаём учётные данные LSA");
    std::wstring domain = domain_;
    std::wstring user = user_;
    PWSTR protectedPwd = nullptr;
    HRESULT hr = ProtectIfNecessaryAndCopyPassword(password_.c_str(), cpus_, &protectedPwd);

    // The plaintext is either packed below or lost; either way our copy goes.
    SecureClear(password_);
    unlocked_ = false;

    if (FAILED(hr)) {
        SHStrDupWHelper(L"Внутренняя ошибка (пароль).", statusText);
        *statusIcon = CPSI_ERROR;
        return hr;
    }

    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
    hr = KerbInteractiveUnlockLogonInit((PWSTR)domain.c_str(), (PWSTR)user.c_str(),
                                        protectedPwd, cpus_, &kiul);
    if (SUCCEEDED(hr)) {
        hr = KerbInteractiveUnlockLogonPack(kiul, &serialization->rgbSerialization,
                                            &serialization->cbSerialization);
    }
    if (SUCCEEDED(hr)) {
        ULONG authPackage = 0;
        hr = RetrieveNegotiateAuthPackage(&authPackage);
        if (SUCCEEDED(hr)) {
            serialization->ulAuthenticationPackage = authPackage;
            serialization->clsidCredentialProvider = CLSID_Fido2Provider;
            *response = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }
    }

    // Scrub and free the protected password copy.
    if (protectedPwd) {
        SecureZeroMemory(protectedPwd, wcslen(protectedPwd) * sizeof(WCHAR));
        CoTaskMemFree(protectedPwd);
    }

    if (FAILED(hr)) {
        SHStrDupWHelper(L"Не удалось подготовить вход.", statusText);
        *statusIcon = CPSI_ERROR;
        return hr;
    }
    return S_OK;
}

// Logon failure codes, spelled out rather than pulling in <ntstatus.h>, which
// collides with the subset <windows.h> already defines.
#ifndef STATUS_LOGON_FAILURE
#define STATUS_LOGON_FAILURE ((NTSTATUS)0xC000006DL)
#endif
#ifndef STATUS_WRONG_PASSWORD
#define STATUS_WRONG_PASSWORD ((NTSTATUS)0xC000006AL)
#endif

IFACEMETHODIMP CFido2Credential::ReportResult(NTSTATUS status, NTSTATUS, PWSTR* statusText,
                                              CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon)
{
    *statusText = nullptr;
    *statusIcon = CPSI_NONE;
    plog::Write(L"ReportResult: NTSTATUS 0x" + std::to_wstring((unsigned long)status));

    // The key worked but Windows rejected the password: it was almost
    // certainly changed outside this tool, so point at the fix.
    if (status == STATUS_LOGON_FAILURE || status == STATUS_WRONG_PASSWORD) {
        SHStrDupWHelper(L"Сохранённый пароль устарел — выполните регистрацию заново.",
                        statusText);
        *statusIcon = CPSI_ERROR;
    }

    ClearSecrets();
    return S_OK;
}

IFACEMETHODIMP CFido2Credential::GetUserSid(PWSTR* sid)
{
    if (!sid) return E_INVALIDARG;
    if (sid_.empty()) { *sid = nullptr; return S_FALSE; }
    return SHStrDupWHelper(sid_.c_str(), sid);
}
