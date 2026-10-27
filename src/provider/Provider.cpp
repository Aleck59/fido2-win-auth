#include "Provider.h"

#include "../common/plog.h"
#include "../common/store.h"
#include "../common/token.h"
#include "Credential.h"

#include <propkey.h>
#include <set>
#include <string>

CFido2Provider::CFido2Provider()
    : ref_(1), cpus_(CPUS_INVALID), userArray_(nullptr), events_(nullptr),
      adviseContext_(0), monitorThread_(nullptr), monitorStop_(nullptr),
      keyArrived_(0)
{
    DllAddRef();
}

CFido2Provider::~CFido2Provider()
{
    // LogonUI normally calls UnAdvise first; do it anyway so the thread can
    // never outlive the object it calls back into.
    StopMonitor();
    if (events_) events_->Release();
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

// How often to look for a key appearing while the logon screen is up.
constexpr DWORD kMonitorPollMs = 700;

// Whether inserting a key may log the user in by itself. On by default for
// U2F records, because such a record has nothing to type -- see the note in
// GetCredentialCount for what that does and does not change.
bool AutoLogonAllowed()
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\fido2-win-auth", 0,
                      KEY_READ, &key) != ERROR_SUCCESS)
        return true;

    DWORD value = 1, size = sizeof(value), type = 0;
    const LONG rc = RegQueryValueExW(key, L"AutoLogon", nullptr, &type,
                                     (BYTE*)&value, &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_DWORD) return true;
    return value != 0;
}

DWORD WINAPI CFido2Provider::MonitorProc(LPVOID param)
{
    static_cast<CFido2Provider*>(param)->MonitorLoop();
    return 0;
}

void CFido2Provider::MonitorLoop()
{
    std::set<std::string> baseline = token::AttachedPaths();

    for (;;) {
        if (WaitForSingleObject(monitorStop_, kMonitorPollMs) == WAIT_OBJECT_0)
            return;

        const std::set<std::string> now = token::AttachedPaths();
        bool arrived = false;
        for (const auto& path : now)
            if (baseline.count(path) == 0) arrived = true;
        baseline = now;

        if (!arrived) continue;

        // Record the arrival and ask LogonUI to come back and ask again. The
        // decision of what to do about it is made in GetCredentialCount, on
        // LogonUI's own thread, where the credential list is safe to touch.
        InterlockedExchange(&keyArrived_, 1);
        plog::Write(L"Monitor: ключ подключён, запрашиваем переопрос");
        if (events_) events_->CredentialsChanged(adviseContext_);
    }
}

void CFido2Provider::StartMonitor()
{
    if (monitorThread_) return;
    // Only the logon and unlock screens; nothing else should log a user in by
    // itself.
    if (cpus_ != CPUS_LOGON && cpus_ != CPUS_UNLOCK_WORKSTATION) return;

    monitorStop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!monitorStop_) return;

    monitorThread_ = CreateThread(nullptr, 0, MonitorProc, this, 0, nullptr);
    if (!monitorThread_) {
        CloseHandle(monitorStop_);
        monitorStop_ = nullptr;
    }
}

void CFido2Provider::StopMonitor()
{
    if (!monitorThread_) return;
    SetEvent(monitorStop_);
    // The loop only ever waits on that event or enumerates devices, so this
    // returns promptly.
    WaitForSingleObject(monitorThread_, 5000);
    CloseHandle(monitorThread_);
    monitorThread_ = nullptr;
    CloseHandle(monitorStop_);
    monitorStop_ = nullptr;
}

IFACEMETHODIMP CFido2Provider::Advise(ICredentialProviderEvents* events,
                                      UINT_PTR context)
{
    if (events_) events_->Release();
    events_ = events;
    adviseContext_ = context;
    if (events_) {
        events_->AddRef();
        StartMonitor();
    }
    return S_OK;
}

IFACEMETHODIMP CFido2Provider::UnAdvise()
{
    // Stop the thread before dropping the sink: the thread calls through it.
    StopMonitor();
    if (events_) {
        events_->Release();
        events_ = nullptr;
    }
    adviseContext_ = 0;
    return S_OK;
}

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

    // Nothing was plugged in since the last enumeration: stay out of the way
    // and let whatever tile the user had stay selected.
    if (InterlockedExchange(&keyArrived_, 0) == 0) return S_OK;

    // Which tile the key belongs to is not knowable without asking the key,
    // and asking costs a round trip that a button-less key cannot spare --
    // its user presence lasts only moments after insertion. So this only acts
    // when there is exactly one enrolled account and therefore no ambiguity.
    if (credentials_.size() != 1) {
        plog::Write(L"GetCredentialCount: ключ подключён, но учётных записей "
                    L"не одна — выбор за пользователем");
        return S_OK;
    }

    *defaultIndex = 0;

    // Logging in on insertion alone is only honest where the record needs no
    // input. A U2F record has none: CTAP1 has no PIN, so the click this
    // removes was the only thing between the key and the session -- the key
    // itself is already the whole credential. A FIDO2 record still wants its
    // PIN, so the tile is merely preselected.
    *autoLogonWithDefault =
        (credentials_[0]->IsU2f() && AutoLogonAllowed()) ? TRUE : FALSE;

    plog::Write(std::wstring(L"GetCredentialCount: плитка выбрана, автовход ") +
                (*autoLogonWithDefault ? L"да" : L"нет"));
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
