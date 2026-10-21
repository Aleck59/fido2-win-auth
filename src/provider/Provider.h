// CFido2Provider — the ICredentialProvider. On Windows 8+ it consumes the
// system user array (ICredentialProviderSetUserArray) and exposes one FIDO2
// tile for each listed user that has an enrollment. On Windows 7 it lists one
// tile per enrolled account.
#pragma once

#include "common.h"

#include <credentialprovider.h>
#include <vector>

class CFido2Credential;

class CFido2Provider : public ICredentialProvider,
                       public ICredentialProviderSetUserArray {
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++ref_; }
    IFACEMETHODIMP_(ULONG) Release() override;
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                    DWORD flags) override;
    IFACEMETHODIMP SetSerialization(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization) override;
    IFACEMETHODIMP Advise(ICredentialProviderEvents* events, UINT_PTR context) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override;
    IFACEMETHODIMP GetFieldDescriptorAt(
        DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** field) override;
    IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* defaultIndex,
                                      BOOL* autoLogonWithDefault) override;
    IFACEMETHODIMP GetCredentialAt(DWORD index,
                                   ICredentialProviderCredential** cred) override;

    // ICredentialProviderSetUserArray
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users) override;

    CFido2Provider();

private:
    ~CFido2Provider();

    void ReleaseCredentials();
    HRESULT CreateCredentials();

    LONG ref_;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus_;
    ICredentialProviderUserArray* userArray_;
    std::vector<CFido2Credential*> credentials_;
};
