// Single translation unit that *defines* every GUID the provider references.
// With INITGUID, each DEFINE_GUID in the headers below allocates the symbol
// here (IID_IUnknown, IID_IClassFactory, GUID_NULL, the credential-provider
// IIDs, and our CLSID), so no uuid import library is needed.
#include <initguid.h>

#include <windows.h>
#include <unknwn.h>
#include <credentialprovider.h>

#include "guid.h"
