#include "Provider.h"

#include "../common/store.h"
#include "Credential.h"

#include <propkey.h>
#include <set>
#include <string>

CFido2Provider::CFido2Provider()
    : ref_(1), cpus_(CPUS_INVALID), userArray_(nullptr)
{
    DllAddRef();
}

CFido2Provider::~CFido2Provider()
{
    ReleaseCredentials();
    if (userArray_) userArray_->Release();
    DllRelease();
}

void CFido2Provider::ReleaseCredentials()
{
    for (auto* c : credentials_)
        if (c) c->Release();
    credentials_.clear();
}

IFACEMETHODIMP_(ULONG) CFido2Provider::Release()
{
    LONG r = --ref_;
    if (r == 0) delete this;
    return r;
}

IFACEMETHODIMP CFido2Provider::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    if (riid == IID_IUnknown || riid == IID_ICredentialProvider) {
        *ppv = static_cast<ICredentialProvider*>(this);
    } else if (riid == IID_ICredentialProviderSetUserArray) {
        *ppv = static_cast<ICredentialProviderSetUserArray*>(this);
    } else {
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    AddRef();
    return S_OK;
}

IFACEMETHODIMP CFido2Provider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                                DWORD)
{
    switch (cpus) {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        cpus_ = cpus;
        return S_OK;
    default:
        // Not applicable to change-password or CredUI.
        return E_NOTIMPL;
    }
}

IFACEMETHODIMP CFido2Provider::SetSerialization(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CFido2Provider::Advise(ICredentialProviderEvents*, UINT_PTR)
{
    return S_OK;
}

IFACEMETHODIMP CFido2Provider::UnAdvise() { return S_OK; }

IFACEMETHODIMP CFido2Provider::GetFieldDescriptorCount(DWORD* count)
{
    *count = FI_NUM_FIELDS;
    return S_OK;
}

IFACEMETHODIMP CFido2Provider::GetFieldDescriptorAt(
    DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** field)
{
    if (index >= FI_NUM_FIELDS || !field) return E_INVALIDARG;
    return FieldDescriptorCoAllocCopy(g_fieldDescriptors[index], field);
}

// Builds one credential per enrolled account. Uses the system user array on
// Win8+; falls back to enumerating enrolled SIDs directly otherwise.
HRESULT CFido2Provider::CreateCredentials()
{
    ReleaseCredentials();

    std::set<std::wstring> enrolled;
    for (const auto& s : store::ListEnrolledSids()) enrolled.insert(s);
    if (enrolled.empty()) return S_OK;

    if (userArray_) {
        DWORD userCount = 0;
        if (FAILED(userArray_->GetCount(&userCount))) userCount = 0;
        for (DWORD i = 0; i < userCount; ++i) {
            ICredentialProviderUser* user = nullptr;
            if (FAILED(userArray_->GetAt(i, &user)) || !user) continue;

            PWSTR sidStr = nullptr;
            if (SUCCEEDED(user->GetSid(&sidStr)) && sidStr &&
                enrolled.count(sidStr)) {
                std::wstring sid = sidStr;
                std::wstring domain, acct;
                store::AccountForSid(sid, domain, acct);

                auto* cred = new (std::nothrow) CFido2Credential();
                if (cred) {
                    if (SUCCEEDED(cred->Initialize(cpus_, sid, domain, acct)))
                        credentials_.push_back(cred);
                    else
                        cred->Release();
                }
            }
            if (sidStr) CoTaskMemFree(sidStr);
            user->Release();
        }
    } else {
        // Windows 7 path: no user array, enumerate enrolled accounts.
        for (const auto& sid : enrolled) {
            std::wstring domain, acct;
            if (!store::AccountForSid(sid, domain, acct)) continue;
            auto* cred = new (std::nothrow) CFido2Credential();
            if (cred) {
                if (SUCCEEDED(cred->Initialize(cpus_, sid, domain, acct)))
                    credentials_.push_back(cred);
                else
                    cred->Release();
            }
        }
    }
    return S_OK;
}

IFACEMETHODIMP CFido2Provider::GetCredentialCount(DWORD* count, DWORD* defaultIndex,
                                                  BOOL* autoLogonWithDefault)
{
    if (credentials_.empty()) CreateCredentials();
    *count = (DWORD)credentials_.size();
    *defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *autoLogonWithDefault = FALSE;
    return S_OK;
}

IFACEMETHODIMP CFido2Provider::GetCredentialAt(DWORD index,
                                               ICredentialProviderCredential** cred)
{
    if (!cred || index >= credentials_.size()) return E_INVALIDARG;
    return credentials_[index]->QueryInterface(IID_ICredentialProviderCredential,
                                               (void**)cred);
}

IFACEMETHODIMP CFido2Provider::SetUserArray(ICredentialProviderUserArray* users)
{
    if (userArray_) userArray_->Release();
    userArray_ = users;
    if (userArray_) userArray_->AddRef();
    return S_OK;
}
