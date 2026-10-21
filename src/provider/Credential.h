// CFido2Credential — one logon tile bound to a single enrolled local account.
// Implements ICredentialProviderCredential2 so it can advertise its user SID on
// Windows 8+ (where tiles are grouped per user).
#pragma once

#include "common.h"

#include <credentialprovider.h>
#include <string>

class CFido2Credential : public ICredentialProviderCredential2 {
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++ref_; }
    IFACEMETHODIMP_(ULONG) Release() override;
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* e) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP SetSelected(BOOL* autoLogon) override;
    IFACEMETHODIMP SetDeselected() override;
    IFACEMETHODIMP GetFieldState(DWORD field, CREDENTIAL_PROVIDER_FIELD_STATE* fs,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* is) override;
    IFACEMETHODIMP GetStringValue(DWORD field, PWSTR* value) override;
    IFACEMETHODIMP GetBitmapValue(DWORD field, HBITMAP* bmp) override;
    IFACEMETHODIMP GetCheckboxValue(DWORD field, BOOL* checked, PWSTR* label) override;
    IFACEMETHODIMP GetSubmitButtonValue(DWORD field, DWORD* adjacentTo) override;
    IFACEMETHODIMP GetComboBoxValueCount(DWORD field, DWORD* count, DWORD* selected) override;
    IFACEMETHODIMP GetComboBoxValueAt(DWORD field, DWORD item, PWSTR* text) override;
    IFACEMETHODIMP SetStringValue(DWORD field, PCWSTR value) override;
    IFACEMETHODIMP SetCheckboxValue(DWORD field, BOOL checked) override;
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD field, DWORD item) override;
    IFACEMETHODIMP CommandLinkClicked(DWORD field) override;
    IFACEMETHODIMP GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
        PWSTR* statusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
    IFACEMETHODIMP ReportResult(NTSTATUS status, NTSTATUS substatus,
                                PWSTR* statusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;

    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(PWSTR* sid) override;

    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                       const std::wstring& sid, const std::wstring& domain,
                       const std::wstring& user);

    CFido2Credential();

private:
    ~CFido2Credential();

    void SetStatus(PCWSTR text);

    LONG ref_;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus_;
    ICredentialProviderCredentialEvents* events_;

    std::wstring sid_;
    std::wstring domain_;
    std::wstring user_;
    std::wstring displayLabel_;

    PWSTR fieldStrings_[FI_NUM_FIELDS];  // CoTaskMem-owned per-field strings
    std::wstring pin_;                   // the key PIN typed into FI_PIN
};
