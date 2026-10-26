// CFido2Credential — one logon tile bound to a single enrolled local account.
// Implements ICredentialProviderCredential2 so it can advertise its user SID on
// Windows 8+ (where tiles are grouped per user).
//
// It also implements IConnectableCredentialProviderCredential: the key exchange
// (which blocks until the user touches the token) runs in Connect(), on a
// background thread, instead of in GetSerialization(), which LogonUI calls on
// its UI thread. GetSerialization() then only packs the password Connect()
// recovered.
#pragma once

#include "common.h"

#include "../common/vault.h"

#include <credentialprovider.h>
#include <string>

class CFido2Credential : public ICredentialProviderCredential2,
                         public IConnectableCredentialProviderCredential {
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

    // IConnectableCredentialProviderCredential. Connect() does the whole FIDO2
    // exchange and leaves the decrypted password in password_; it reports
    // progress through the IQueryContinueWithStatus LogonUI hands it, and
    // always returns S_OK, surfacing failures as text on the status line.
    IFACEMETHODIMP Connect(IQueryContinueWithStatus* qcws) override;
    IFACEMETHODIMP Disconnect() override;

    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                       const std::wstring& sid, const std::wstring& domain,
                       const std::wstring& user);

    CFido2Credential();

private:
    ~CFido2Credential();

    void SetStatus(PCWSTR text);

    // ICredentialProviderCredential is inherited twice (through
    // ICredentialProviderCredential2 and through the connectable interface),
    // so `this` is ambiguous where the events sink wants that type. Always
    // hand out the same subobject, since LogonUI treats it as our identity.
    ICredentialProviderCredential* AsCredential()
    {
        return static_cast<ICredentialProviderCredential2*>(this);
    }

    // Records why Connect() could not unlock, for both the status line and the
    // error GetSerialization() hands back.
    void Fail(const std::wstring& message);

    // Drops the decrypted password and the typed PIN.
    void ClearSecrets();

    LONG ref_;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus_;
    ICredentialProviderCredentialEvents* events_;

    std::wstring sid_;
    std::wstring domain_;
    std::wstring user_;
    std::wstring displayLabel_;

    PWSTR fieldStrings_[FI_NUM_FIELDS];  // CoTaskMem-owned per-field strings
    std::wstring pin_;                   // the key PIN typed into FI_PIN

    // Filled by Connect(), consumed and wiped by GetSerialization().
    std::wstring password_;
    std::wstring connectError_;
    bool unlocked_;

    // Mode of this account's record, read once at Initialize(): a U2F record
    // has no PIN, so the PIN field is hidden for it.
    VaultMode mode_;
    bool haveMode_;
};
