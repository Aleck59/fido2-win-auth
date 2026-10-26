#include "Credential.h"

#include "../common/store.h"
#include "../common/token.h"
#include "../common/unlock.h"
#include "../common/vault.h"
#include "guid.h"
#include "kerb.h"
#include "resource.h"

#include <strsafe.h>

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
    displayLabel_ = u2f ? L"Вход по ключу U2F" : L"Вход по ключу FIDO2";
    if (!user_.empty()) displayLabel_ += L" (" + user_ + L")";

    // Seed the per-field string values from the static descriptors.
    HRESULT hr = SHStrDupWHelper(displayLabel_.c_str(), &fieldStrings_[FI_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupWHelper(L"", &fieldStrings_[FI_PIN]);
    if (SUCCEEDED(hr)) hr = SHStrDupWHelper(g_fieldDescriptors[FI_SUBMIT].pszLabel,
                                            &fieldStrings_[FI_SUBMIT]);
    if (SUCCEEDED(hr)) hr = SHStrDupWHelper(L"", &fieldStrings_[FI_STATUS]);
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
    *autoLogon = FALSE;  // require the user to touch the key and submit
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
    SetStatus(L"");
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
    *adjacentTo = FI_PIN;  // Enter in the PIN box submits
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
IFACEMETHODIMP CFido2Credential::Connect(IQueryContinueWithStatus* qcws)
{
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
    if (devices.empty()) {
        Fail(L"Вставьте ключ безопасности и повторите.");
        return S_OK;
    }

    if (qcws && qcws->QueryContinue() != S_OK) {
        Fail(L"Отменено.");
        return S_OK;
    }
    if (qcws) qcws->SetStatusMessage(L"Коснитесь ключа безопасности...");

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
    unlock::Outcome out;
    std::wstring lastError = L"Ключ не распознал учётные данные.";
    for (const auto& dev : devices) {
        // Each attempt can wait on a touch, so honour a cancelled logon
        // between keys rather than only at the end.
        if (qcws && qcws->QueryContinue() != S_OK) {
            SecureClear(pinUtf8);
            Fail(L"Отменено.");
            return S_OK;
        }

        out = unlock::WithDevice(rec, dev.path, pinUtf8);
        if (out.ok) break;

        lastError = out.error;
        // A definite verdict about this record (a cloned-key counter, an
        // unreadable DPAPI blob, a failed decrypt) will not change on another
        // key, so stop rather than making the user touch every one.
        if (!out.wrongKey) break;
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
        return S_FALSE;
    }

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
