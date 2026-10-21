// Field layout shared by the provider and the credential, plus small COM
// helpers. The credential shows: a tile image, the account label, a masked box
// for the key PIN, a submit button, and a status line.
#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <new>

// Pairs a field's display state with its interactive state. (Not a system
// type; defined here as the credential-provider samples do.)
struct FIELD_STATE_PAIR {
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

enum FIELD_ID {
    FI_TILEIMAGE = 0,  // the FIDO/key icon
    FI_LABEL,          // "Вход по ключу FIDO2" / account name
    FI_PIN,            // masked edit box for the key PIN
    FI_SUBMIT,         // submit button
    FI_STATUS,         // small status text (errors / progress)
    FI_NUM_FIELDS
};

// Static descriptors for the fields above. Defined in Credential.cpp.
extern const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR g_fieldDescriptors[FI_NUM_FIELDS];
extern const FIELD_STATE_PAIR g_fieldStatePairs[FI_NUM_FIELDS];

// Duplicates a field descriptor (deep copy of its pszLabel/guid) for the caller.
HRESULT FieldDescriptorCoAllocCopy(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& in,
                                   CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out);
HRESULT FieldDescriptorCopy(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& in,
                            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* out);

// Allocates a CoTaskMem copy of a wide string.
HRESULT SHStrDupWHelper(PCWSTR source, PWSTR* dest);

// DLL lifetime refcount (keeps the module loaded while objects are alive).
void DllAddRef();
void DllRelease();

// This module's instance handle, for loading bitmaps and other resources.
HINSTANCE DllInstance();
