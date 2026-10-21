// Common byte-buffer helpers and the error type used across the project.
#pragma once

#include <windows.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;

// Error carrying an optional CTAP status code (0 when not a CTAP error).
class Fido2Error : public std::runtime_error {
public:
    explicit Fido2Error(const std::string& msg, int ctapStatus = 0)
        : std::runtime_error(msg), ctapStatus_(ctapStatus) {}
    int CtapStatus() const { return ctapStatus_; }

private:
    int ctapStatus_;
};

inline void SecureClear(Bytes& b)
{
    if (!b.empty()) SecureZeroMemory(b.data(), b.size());
    b.clear();
}

inline void SecureClear(std::wstring& s)
{
    if (!s.empty()) SecureZeroMemory(&s[0], s.size() * sizeof(wchar_t));
    s.clear();
}

inline void SecureClear(std::string& s)
{
    if (!s.empty()) SecureZeroMemory(&s[0], s.size());
    s.clear();
}

inline Bytes Concat(const Bytes& a, const Bytes& b)
{
    Bytes r(a);
    r.insert(r.end(), b.begin(), b.end());
    return r;
}

inline Bytes ToBytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

inline std::string ToHex(const Bytes& b)
{
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t c : b) {
        s.push_back(digits[c >> 4]);
        s.push_back(digits[c & 15]);
    }
    return s;
}

// Constant-time comparison for secrets and MACs.
inline bool ConstantTimeEqual(const Bytes& a, const Bytes& b)
{
    if (a.size() != b.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

std::wstring Utf8ToWide(const std::string& s);
std::string WideToUtf8(const std::wstring& s);
