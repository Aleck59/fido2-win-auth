// CLSID of this credential provider. Registered under the system
// "Credential Providers" key (see Dll.cpp) and as an InprocServer32 COM class.
#pragma once

#include <guiddef.h>

// Declared here, defined once in guids.cpp (which is compiled with INITGUID).
// {b167f262-672c-49f7-ba9c-b981e7d5bb6d}
DEFINE_GUID(CLSID_Fido2Provider, 0xb167f262, 0x672c, 0x49f7, 0xba, 0x9c, 0xb9,
            0x81, 0xe7, 0xd5, 0xbb, 0x6d);

#define FIDO2_PROVIDER_CLSID_STR L"{b167f262-672c-49f7-ba9c-b981e7d5bb6d}"
#define FIDO2_PROVIDER_NAME L"FIDO2 Windows Logon Provider"
