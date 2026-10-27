#include "settings.h"

#include <windows.h>

namespace settings {
namespace {

constexpr const wchar_t* kKey = L"SOFTWARE\\fido2-win-auth";
constexpr const wchar_t* kAutoLogon = L"AutoLogon";

bool ReadFlag(const wchar_t* name, bool fallback)
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKey, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return fallback;

    DWORD value = 0, size = sizeof(value), type = 0;
    const LONG rc = RegQueryValueExW(key, name, nullptr, &type, (BYTE*)&value,
                                     &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || type != REG_DWORD) return fallback;
    return value != 0;
}

bool WriteFlag(const wchar_t* name, bool on)
{
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kKey, 0, nullptr, 0, KEY_WRITE,
                        nullptr, &key, nullptr) != ERROR_SUCCESS)
        return false;

    DWORD value = on ? 1 : 0;
    const LONG rc = RegSetValueExW(key, name, 0, REG_DWORD, (const BYTE*)&value,
                                   sizeof(value));
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

}  // namespace

bool AutoLogon() { return ReadFlag(kAutoLogon, true); }
bool SetAutoLogon(bool on) { return WriteFlag(kAutoLogon, on); }

}  // namespace settings
