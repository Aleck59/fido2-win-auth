#include "kerb.h"

#include <intsafe.h>
#include <strsafe.h>
#include <wincred.h>

static void UnicodeStringInitWithString(PWSTR pwz, UNICODE_STRING* pus)
{
    if (pwz) {
        size_t len = wcslen(pwz);
        pus->Length = (USHORT)(len * sizeof(WCHAR));
        pus->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
        pus->Buffer = pwz;
    } else {
        pus->Length = 0;
        pus->MaximumLength = 0;
        pus->Buffer = nullptr;
    }
}

HRESULT KerbInteractiveUnlockLogonInit(PWSTR domain, PWSTR username, PWSTR password,
                                       CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                       KERB_INTERACTIVE_UNLOCK_LOGON* pkiul)
{
    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
    ZeroMemory(&kiul, sizeof(kiul));

    KERB_INTERACTIVE_LOGON* pkil = &kiul.Logon;
    UnicodeStringInitWithString(domain, &pkil->LogonDomainName);
    UnicodeStringInitWithString(username, &pkil->UserName);
    UnicodeStringInitWithString(password, &pkil->Password);

    switch (cpus) {
    case CPUS_UNLOCK_WORKSTATION:
        pkil->MessageType = KerbWorkstationUnlockLogon;
        break;
    case CPUS_LOGON:
        pkil->MessageType = KerbInteractiveLogon;
        break;
    case CPUS_CREDUI:
        pkil->MessageType = (KERB_LOGON_SUBMIT_TYPE)0;  // ignored for CredUI
        break;
    default:
        return E_FAIL;
    }

    *pkiul = kiul;
    return S_OK;
}

// Appends a UNICODE_STRING's bytes to the packed buffer and rebases Buffer to an
// offset relative to the start of the buffer.
static void AppendAndRebase(UNICODE_STRING* pus, BYTE* pbBuffer,
                            ULONG* pcbUsed)
{
    if (pus->Length && pus->Buffer) {
        CopyMemory(pbBuffer + *pcbUsed, pus->Buffer, pus->Length);
        pus->Buffer = (PWSTR)ULongToPtr(*pcbUsed);
        *pcbUsed += pus->Length;
    } else {
        pus->Buffer = (PWSTR)ULongToPtr(*pcbUsed);
    }
}

HRESULT KerbInteractiveUnlockLogonPack(const KERB_INTERACTIVE_UNLOCK_LOGON& kiulIn,
                                       BYTE** prgb, DWORD* pcb)
{
    const KERB_INTERACTIVE_LOGON* pkilIn = &kiulIn.Logon;

    DWORD cb = sizeof(kiulIn) + pkilIn->LogonDomainName.Length +
               pkilIn->UserName.Length + pkilIn->Password.Length;

    KERB_INTERACTIVE_UNLOCK_LOGON* pkiul =
        (KERB_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);
    if (!pkiul) return E_OUTOFMEMORY;

    KERB_INTERACTIVE_LOGON* pkil = &pkiul->Logon;

    // Copy the fixed part, then lay strings out immediately after it.
    CopyMemory(pkiul, &kiulIn, sizeof(kiulIn));

    BYTE* pbBuffer = (BYTE*)pkiul + sizeof(*pkiul);
    ULONG cbUsed = sizeof(*pkiul);

    AppendAndRebase(&pkil->LogonDomainName, (BYTE*)pkiul, &cbUsed);
    AppendAndRebase(&pkil->UserName, (BYTE*)pkiul, &cbUsed);
    AppendAndRebase(&pkil->Password, (BYTE*)pkiul, &cbUsed);
    (void)pbBuffer;

    *prgb = (BYTE*)pkiul;
    *pcb = cb;
    return S_OK;
}

HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage)
{
    HANDLE hLsa = nullptr;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status != 0) return HRESULT_FROM_NT(status);

    ULONG ulAuthPackage = 0;
    LSA_STRING lsaszPackageName;
    char szNegotiate[] = "Negotiate";
    lsaszPackageName.Buffer = szNegotiate;
    lsaszPackageName.Length = (USHORT)(sizeof(szNegotiate) - 1);
    lsaszPackageName.MaximumLength = (USHORT)sizeof(szNegotiate);

    status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
    LsaDeregisterLogonProcess(hLsa);
    if (status != 0) return HRESULT_FROM_NT(status);

    *pulAuthPackage = ulAuthPackage;
    return S_OK;
}

HRESULT ProtectIfNecessaryAndCopyPassword(PCWSTR password,
                                          CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                          PWSTR* ppwzProtected)
{
    *ppwzProtected = nullptr;
    if (!password) return E_INVALIDARG;

    // For logon/unlock we hand the raw password to LSA. CredUI off-box would
    // require CredProtect; this provider only supports local logon/unlock, so a
    // plain copy is correct.
    (void)cpus;
    size_t cch = wcslen(password) + 1;
    PWSTR copy = (PWSTR)CoTaskMemAlloc(cch * sizeof(WCHAR));
    if (!copy) return E_OUTOFMEMORY;
    StringCchCopyW(copy, cch, password);
    *ppwzProtected = copy;
    return S_OK;
}
