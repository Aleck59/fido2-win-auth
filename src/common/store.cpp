// Store implementation over the Win32 registry + SID conversion helpers.
#include "store.h"

#include <windows.h>
#include <sddl.h>    // ConvertSidToStringSid / security descriptor strings
#include <aclapi.h>

#include <memory>

// advapi32 is linked via the build system (see Makefile).

namespace store {

namespace {

const wchar_t* kBaseKey = L"SOFTWARE\\fido2-win-auth\\vaults";
const wchar_t* kValueName = L"record";

[[noreturn]] void FailWin(const char* what, LONG err)
{
    char buf[256];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s (Win32 error %ld)", what, err);
    throw Fido2Error(buf);
}

// DACL: SYSTEM and Administrators full control, nobody else. Written in SDDL.
//   O:BA  owner Administrators
//   G:BA  group Administrators
//   D:PAI protected, no inheritance
//   (A;;KA;;;SY)  allow key-all-access to Local System
//   (A;;KA;;;BA)  allow key-all-access to Administrators
bool BuildSecurityAttributes(SECURITY_ATTRIBUTES& sa, PSECURITY_DESCRIPTOR& sd)
{
    const wchar_t* sddl = L"O:BAG:BAD:PAI(A;;KA;;;SY)(A;;KA;;;BA)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sd, nullptr))
        return false;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    return true;
}

// Opens (creating if needed) HKLM\...\vaults\<sid>. The parent "vaults" node is
// created with the restrictive DACL; the per-SID subkey inherits nothing but is
// under the protected parent.
HKEY OpenSidKey(const std::wstring& sidString, bool create)
{
    std::wstring sub = std::wstring(kBaseKey) + L"\\" + sidString;

    if (!create) {
        HKEY k = nullptr;
        LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.c_str(), 0, KEY_READ, &k);
        if (r == ERROR_FILE_NOT_FOUND) return nullptr;
        if (r != ERROR_SUCCESS) FailWin("RegOpenKeyEx", r);
        return k;
    }

    PSECURITY_DESCRIPTOR sd = nullptr;
    SECURITY_ATTRIBUTES sa{};
    bool haveSa = BuildSecurityAttributes(sa, sd);
    std::unique_ptr<void, decltype(&LocalFree)> sdGuard(sd, LocalFree);

    HKEY k = nullptr;
    DWORD disp = 0;
    LONG r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, sub.c_str(), 0, nullptr,
                             REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE,
                             haveSa ? &sa : nullptr, &k, &disp);
    if (r != ERROR_SUCCESS) FailWin("RegCreateKeyEx", r);
    return k;
}

}  // namespace

void SaveRecord(const std::wstring& sidString, const Bytes& record)
{
    HKEY k = OpenSidKey(sidString, true);
    LONG r = RegSetValueExW(k, kValueName, 0, REG_BINARY, record.data(),
                            (DWORD)record.size());
    RegCloseKey(k);
    if (r != ERROR_SUCCESS) FailWin("RegSetValueEx", r);
}

bool LoadRecord(const std::wstring& sidString, Bytes& record)
{
    HKEY k = OpenSidKey(sidString, false);
    if (!k) return false;

    DWORD type = 0, size = 0;
    LONG r = RegQueryValueExW(k, kValueName, nullptr, &type, nullptr, &size);
    if (r == ERROR_FILE_NOT_FOUND || size == 0) { RegCloseKey(k); return false; }
    if (r != ERROR_SUCCESS || type != REG_BINARY) {
        RegCloseKey(k);
        if (r != ERROR_SUCCESS) FailWin("RegQueryValueEx(size)", r);
        return false;
    }
    record.resize(size);
    r = RegQueryValueExW(k, kValueName, nullptr, &type, record.data(), &size);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS) { record.clear(); FailWin("RegQueryValueEx", r); }
    record.resize(size);
    return true;
}

void DeleteRecord(const std::wstring& sidString)
{
    std::wstring sub = std::wstring(kBaseKey) + L"\\" + sidString;
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, sub.c_str(), KEY_WOW64_64KEY, 0);
}

std::vector<std::wstring> ListEnrolledSids()
{
    std::vector<std::wstring> out;
    HKEY base = nullptr;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kBaseKey, 0, KEY_READ, &base);
    if (r != ERROR_SUCCESS) return out;

    for (DWORD i = 0;; ++i) {
        wchar_t name[256];
        DWORD len = 256;
        r = RegEnumKeyExW(base, i, name, &len, nullptr, nullptr, nullptr, nullptr);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) break;
        out.emplace_back(name, len);
    }
    RegCloseKey(base);
    return out;
}

std::wstring SidForAccount(const std::wstring& accountName)
{
    BYTE sidBuf[SECURITY_MAX_SID_SIZE];
    DWORD sidLen = sizeof(sidBuf);
    wchar_t domain[256];
    DWORD domainLen = 256;
    SID_NAME_USE use;
    if (!LookupAccountNameW(nullptr, accountName.c_str(), sidBuf, &sidLen, domain,
                            &domainLen, &use))
        FailWin("LookupAccountName", GetLastError());

    LPWSTR str = nullptr;
    if (!ConvertSidToStringSidW(sidBuf, &str))
        FailWin("ConvertSidToStringSid", GetLastError());
    std::wstring result(str);
    LocalFree(str);
    return result;
}

bool AccountForSid(const std::wstring& sidString, std::wstring& outDomain,
                   std::wstring& outUser)
{
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(sidString.c_str(), &sid)) return false;
    std::unique_ptr<void, decltype(&LocalFree)> sidGuard(sid, LocalFree);

    wchar_t user[256], domain[256];
    DWORD userLen = 256, domainLen = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(nullptr, sid, user, &userLen, domain, &domainLen, &use))
        return false;
    outUser.assign(user, userLen);
    outDomain.assign(domain, domainLen);
    return true;
}

}  // namespace store
