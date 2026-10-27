#include "plog.h"

#include <windows.h>

#include <string>

namespace plog {
namespace {

constexpr const wchar_t* kKey = L"SOFTWARE\\fido2-win-auth";
constexpr const wchar_t* kValue = L"Debug";

std::wstring Directory()
{
    wchar_t buf[MAX_PATH];
    const DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    std::wstring base = (n > 0 && n < MAX_PATH) ? std::wstring(buf, n)
                                                : L"C:\\ProgramData";
    return base + L"\\fido2-win-auth";
}

std::wstring Stamp()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[32];
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u.%03u", st.wYear, st.wMonth,
               st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

}  // namespace

std::wstring Path() { return Directory() + L"\\provider.log"; }

bool Enabled()
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKey, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return false;

    DWORD value = 0, size = sizeof(value), type = 0;
    const LONG rc = RegQueryValueExW(key, kValue, nullptr, &type, (BYTE*)&value,
                                     &size);
    RegCloseKey(key);
    return rc == ERROR_SUCCESS && type == REG_DWORD && value != 0;
}

bool SetEnabled(bool on)
{
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kKey, 0, nullptr, 0, KEY_WRITE,
                        nullptr, &key, nullptr) != ERROR_SUCCESS)
        return false;

    DWORD value = on ? 1 : 0;
    const LONG rc = RegSetValueExW(key, kValue, 0, REG_DWORD, (const BYTE*)&value,
                                   sizeof(value));
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

void Write(const std::wstring& line)
{
    if (!Enabled()) return;

    CreateDirectoryW(Directory().c_str(), nullptr);

    HANDLE h = CreateFileW(Path().c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    const std::wstring text = Stamp() + L"  " + line + L"\r\n";
    const int cb = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(),
                                       nullptr, 0, nullptr, nullptr);
    if (cb > 0) {
        std::string utf8((size_t)cb, '\0');
        WideCharToMultiByte(CP_UTF8, 0, text.c_str(), (int)text.size(), &utf8[0],
                            cb, nullptr, nullptr);
        DWORD written = 0;
        WriteFile(h, utf8.data(), (DWORD)utf8.size(), &written, nullptr);
    }
    CloseHandle(h);
}

}  // namespace plog
