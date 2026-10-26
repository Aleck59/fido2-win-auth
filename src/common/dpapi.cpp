#include "dpapi.h"

#include <windows.h>
#include <dpapi.h>

#include <string>

namespace dpapi {
namespace {

// Scopes the blob to this application so it cannot be confused with another
// product's DPAPI data; purely descriptive, DPAPI does not enforce it.
const wchar_t* kDescription = L"fido2-win-auth vault key";

DATA_BLOB AsBlob(const Bytes& b)
{
    DATA_BLOB blob;
    blob.pbData = const_cast<BYTE*>(b.data());
    blob.cbData = (DWORD)b.size();
    return blob;
}

}  // namespace

Bytes Protect(const Bytes& plain, const Bytes& entropy)
{
    DATA_BLOB in = AsBlob(plain);
    DATA_BLOB ent = AsBlob(entropy);
    DATA_BLOB out{};

    if (!CryptProtectData(&in, kDescription, entropy.empty() ? nullptr : &ent,
                          nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                          &out)) {
        throw Fido2Error("CryptProtectData failed, win32 error " +
                         std::to_string((unsigned long)GetLastError()));
    }

    Bytes result(out.pbData, out.pbData + out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return result;
}

bool Unprotect(const Bytes& blob, const Bytes& entropy, Bytes& plain)
{
    DATA_BLOB in = AsBlob(blob);
    DATA_BLOB ent = AsBlob(entropy);
    DATA_BLOB out{};

    if (!CryptUnprotectData(&in, nullptr, entropy.empty() ? nullptr : &ent,
                            nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        return false;

    plain.assign(out.pbData, out.pbData + out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return true;
}

}  // namespace dpapi
