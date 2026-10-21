#include "common.h"

#include <strsafe.h>

// Field descriptors. The PIN box is a masked password edit; the submit button
// is attached to the PIN field so Enter submits.
const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR g_fieldDescriptors[FI_NUM_FIELDS] = {
    {FI_TILEIMAGE, CPFT_TILE_IMAGE, (PWSTR)L"Image", GUID_NULL},
    {FI_LABEL, CPFT_LARGE_TEXT, (PWSTR)L"Вход по ключу FIDO2"},
    {FI_PIN, CPFT_PASSWORD_TEXT, (PWSTR)L"PIN ключа"},
    {FI_SUBMIT, CPFT_SUBMIT_BUTTON, (PWSTR)L"Войти"},
    {FI_STATUS, CPFT_SMALL_TEXT, (PWSTR)L""},
};

// Initial field states. The PIN box is interactive and focused; the status line
// is hidden until there is something to say.
const FIELD_STATE_PAIR g_fieldStatePairs[FI_NUM_FIELDS] = {
    {CPFS_DISPLAY_IN_BOTH, CPFIS_NONE},                   // FI_TILEIMAGE
    {CPFS_DISPLAY_IN_BOTH, CPFIS_NONE},                   // FI_LABEL
    {CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED},       // FI_PIN
    {CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE},          // FI_SUBMIT
    {CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE},          // FI_STATUS
};

HRESULT SHStrDupWHelper(PCWSTR source, PWSTR* dest)
{
    *dest = nullptr;
    if (!source) return S_OK;
    size_t cch = wcslen(source) + 1;
    *dest = (PWSTR)CoTaskMemAlloc(cch * sizeof(WCHAR));
    if (!*dest) return E_OUTOFMEMORY;
    return StringCchCopyW(*dest, cch, source);
}

HRESULT FieldDescriptorCopy(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& in,
                            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* out)
{
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR tmp = in;
    PWSTR label = nullptr;
    HRESULT hr = SHStrDupWHelper(in.pszLabel, &label);
    if (SUCCEEDED(hr)) {
        tmp.pszLabel = label;
        *out = tmp;
    }
    return hr;
}

HRESULT FieldDescriptorCoAllocCopy(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& in,
                                   CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out)
{
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* copy =
        (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(*copy));
    if (!copy) return E_OUTOFMEMORY;
    HRESULT hr = FieldDescriptorCopy(in, copy);
    if (SUCCEEDED(hr)) *out = copy;
    else CoTaskMemFree(copy);
    return hr;
}
