#include "Credential.h"

#include "../common/store.h"
#include "../common/token.h"
#include "../common/vault.h"
#include "guid.h"
#include "kerb.h"

#include <strsafe.h>

CFido2Credential::CFido2Credential()
    : ref_(1), cpus_(CPUS_INVALID), events_(nullptr)
{
    DllAddRef();
    for (int i = 0; i < FI_NUM_FIELDS; ++i) fieldStrings_[i] = nullptr;
}

CFido2Credential::~CFido2Credential()
{
    for (int i = 0; i < FI_NUM_FIELDS; ++i)
        if (fieldStrings_[i]) CoTaskMemFree(fieldStrings_[i]);
    if (!pin_.empty()) SecureZeroMemory(&pin_[0], pin_.size() * sizeof(wchar_t));
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
    displayLabel_ = L"Вход по ключу FIDO2";
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
    // Clear any typed PIN when the tile loses focus.
    if (!pin_.empty()) SecureZeroMemory(&pin_[0], pin_.size() * sizeof(wchar_t));
    pin_.clear();
    if (fieldStrings_[FI_PIN]) {
        CoTaskMemFree(fieldStrings_[FI_PIN]);
        SHStrDupWHelper(L"", &fieldStrings_[FI_PIN]);
        if (events_)
            events_->SetFieldString(this, FI_PIN, L"");
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
    *bmp = nullptr;  // use the system default credential-provider logo
    return E_NOTIMPL;
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
    if (events_) events_->SetFieldString(this, FI_STATUS, text ? text : L"");
}

// Performs the FIDO2 assertion against whichever present key holds the
// credential, recovers the account password, and packs it for LSA.
IFACEMETHODIMP CFido2Credential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
    PWSTR* statusText, CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon)
{
    *response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *statusText = nullptr;
    *statusIcon = CPSI_NONE;

    // Load this account's vault record.
    Bytes blob;
    if (!store::LoadRecord(sid_, blob)) {
        SHStrDupWHelper(L"Для этой учётной записи нет регистрации ключа.", statusText);
        *statusIcon = CPSI_ERROR;
        return S_FALSE;
    }

    VaultRecord rec;
    try {
        rec = VaultRecord::Deserialize(blob);
    } catch (const std::exception&) {
        SHStrDupWHelper(L"Повреждённая запись ключа.", statusText);
        *statusIcon = CPSI_ERROR;
        return S_FALSE;
    }

    auto devices = token::ListDevices();
    if (devices.empty()) {
        SHStrDupWHelper(L"Вставьте FIDO2-ключ и повторите.", statusText);
        *statusIcon = CPSI_WARNING;
        return S_FALSE;
    }

    std::string pinUtf8;
    {
        int n = WideCharToMultiByte(CP_UTF8, 0, pin_.c_str(), (int)pin_.size(),
                                    nullptr, 0, nullptr, nullptr);
        pinUtf8.resize(n > 0 ? n : 0);
        if (n > 0)
            WideCharToMultiByte(CP_UTF8, 0, pin_.c_str(), (int)pin_.size(),
                                &pinUtf8[0], n, nullptr, nullptr);
    }

    // Try each present key; the one holding the credential succeeds, others
    // fail with a benign CTAP error.
    Bytes hmacSecret;
    bool gotSecret = false;
    std::wstring lastError = L"Ключ не распознал учётные данные.";
    for (const auto& dev : devices) {
        try {
            hmacSecret = token::GetHmacSecret(dev.path, pinUtf8, rec.credId, rec.salt);
            gotSecret = true;
            break;
        } catch (const Fido2Error& e) {
            lastError = Utf8ToWide(e.what());
        }
    }
    SecureZeroMemory(&pinUtf8[0], pinUtf8.size());

    if (!gotSecret) {
        SHStrDupWHelper(lastError.c_str(), statusText);
        *statusIcon = CPSI_ERROR;
        return S_FALSE;
    }

    std::wstring password;
    bool opened = vault::Open(rec, hmacSecret, password);
    SecureClear(hmacSecret);
    if (!opened) {
        SHStrDupWHelper(L"Не удалось расшифровать пароль (неверный ключ?).", statusText);
        *statusIcon = CPSI_ERROR;
        return S_FALSE;
    }

    // Build the KERB logon blob.
    std::wstring domain = domain_;
    std::wstring user = user_;
    PWSTR protectedPwd = nullptr;
    HRESULT hr = ProtectIfNecessaryAndCopyPassword(password.c_str(), cpus_, &protectedPwd);
    SecureClear(password);
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

IFACEMETHODIMP CFido2Credential::ReportResult(NTSTATUS, NTSTATUS, PWSTR* statusText,
                                              CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon)
{
    *statusText = nullptr;
    *statusIcon = CPSI_NONE;
    return S_OK;
}

IFACEMETHODIMP CFido2Credential::GetUserSid(PWSTR* sid)
{
    if (!sid) return E_INVALIDARG;
    if (sid_.empty()) { *sid = nullptr; return S_FALSE; }
    return SHStrDupWHelper(sid_.c_str(), sid);
}
