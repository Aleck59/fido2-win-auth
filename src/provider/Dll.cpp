// DLL entry points, COM class factory, and self-registration for the
// credential provider.
#include "Provider.h"
#include "common.h"
#include "guid.h"

#include <new>
#include <strsafe.h>

static LONG g_dllRef = 0;
static HINSTANCE g_hinst = nullptr;

void DllAddRef() { InterlockedIncrement(&g_dllRef); }
void DllRelease() { InterlockedDecrement(&g_dllRef); }

// ---- Class factory --------------------------------------------------------

class CClassFactory : public IClassFactory {
public:
    CClassFactory() : ref_(1) { DllAddRef(); }

    IFACEMETHODIMP_(ULONG) AddRef() override { return ++ref_; }
    IFACEMETHODIMP_(ULONG) Release() override
    {
        LONG r = --ref_;
        if (r == 0) delete this;
        return r;
    }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override
    {
        if (outer) return CLASS_E_NOAGGREGATION;
        auto* p = new (std::nothrow) CFido2Provider();
        if (!p) return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }

    IFACEMETHODIMP LockServer(BOOL lock) override
    {
        if (lock) DllAddRef();
        else DllRelease();
        return S_OK;
    }

private:
    ~CClassFactory() { DllRelease(); }
    LONG ref_;
};

// ---- Exports --------------------------------------------------------------

extern "C" BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_hinst = hinst;
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}

STDAPI DllCanUnloadNow()
{
    return (g_dllRef == 0) ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (rclsid != CLSID_Fido2Provider) return CLASS_E_CLASSNOTAVAILABLE;
    auto* factory = new (std::nothrow) CClassFactory();
    if (!factory) return E_OUTOFMEMORY;
    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

// ---- Self-registration ----------------------------------------------------

static HRESULT SetKeyValue(HKEY root, PCWSTR subkey, PCWSTR name, PCWSTR value)
{
    HKEY k = nullptr;
    LONG r = RegCreateKeyExW(root, subkey, 0, nullptr, REG_OPTION_NON_VOLATILE,
                             KEY_WRITE, nullptr, &k, nullptr);
    if (r != ERROR_SUCCESS) return HRESULT_FROM_WIN32(r);
    r = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)value,
                       (DWORD)((wcslen(value) + 1) * sizeof(WCHAR)));
    RegCloseKey(k);
    return HRESULT_FROM_WIN32(r);
}

STDAPI DllRegisterServer()
{
    wchar_t modulePath[MAX_PATH];
    if (!GetModuleFileNameW(g_hinst, modulePath, MAX_PATH))
        return HRESULT_FROM_WIN32(GetLastError());

    // COM class: InprocServer32 -> this DLL, apartment threaded.
    PCWSTR clsidKey = L"CLSID\\" FIDO2_PROVIDER_CLSID_STR;
    PCWSTR inprocKey = L"CLSID\\" FIDO2_PROVIDER_CLSID_STR L"\\InprocServer32";

    HRESULT hr = SetKeyValue(HKEY_CLASSES_ROOT, clsidKey, nullptr, FIDO2_PROVIDER_NAME);
    if (SUCCEEDED(hr))
        hr = SetKeyValue(HKEY_CLASSES_ROOT, inprocKey, nullptr, modulePath);
    if (SUCCEEDED(hr))
        hr = SetKeyValue(HKEY_CLASSES_ROOT, inprocKey, L"ThreadingModel", L"Apartment");

    // Register as a credential provider.
    if (SUCCEEDED(hr)) {
        PCWSTR cpKey =
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\"
            L"Credential Providers\\" FIDO2_PROVIDER_CLSID_STR;
        hr = SetKeyValue(HKEY_LOCAL_MACHINE, cpKey, nullptr, FIDO2_PROVIDER_NAME);
    }
    return hr;
}

STDAPI DllUnregisterServer()
{
    RegDeleteTreeW(HKEY_CLASSES_ROOT, L"CLSID\\" FIDO2_PROVIDER_CLSID_STR);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE,
                  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\"
                  L"Credential Providers\\" FIDO2_PROVIDER_CLSID_STR);
    return S_OK;
}
