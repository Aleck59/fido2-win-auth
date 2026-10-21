// Token implementation over libfido2. Every entry point opens the device,
// performs one operation, and closes it; no device handle outlives a call.
#include "token.h"

#include <fido.h>

#include <cstring>
#include <memory>

namespace token {

namespace {

// Fixed client-data. This is a local logon factor, not a web authentication,
// so there is no server challenge; the hmac-secret (gated by PIN + touch) is
// the actual secret. The value only needs to be stable between enroll and login.
const unsigned char kClientData[] = "fido2-win-auth/local-logon/v1";
constexpr size_t kClientDataLen = sizeof(kClientData) - 1;

struct DevHandle {
    fido_dev_t* dev = nullptr;
    ~DevHandle()
    {
        if (dev) {
            fido_dev_close(dev);
            fido_dev_free(&dev);
        }
    }
};

[[noreturn]] void Fail(const char* what, int r)
{
    std::string msg = std::string(what) + ": " + fido_strerr(r);
    throw Fido2Error(msg, r);
}

void OpenDevice(DevHandle& h, const std::string& path)
{
    h.dev = fido_dev_new();
    if (!h.dev) throw Fido2Error("fido_dev_new failed");
    int r = fido_dev_open(h.dev, path.c_str());
    if (r != FIDO_OK) Fail("fido_dev_open", r);
    if (!fido_dev_is_fido2(h.dev))
        throw Fido2Error("device is not a FIDO2 authenticator");
}

}  // namespace

std::vector<Device> ListDevices()
{
    std::vector<Device> out;
    fido_init(0);

    const size_t kMax = 16;
    fido_dev_info_t* list = fido_dev_info_new(kMax);
    if (!list) return out;

    size_t n = 0;
    if (fido_dev_info_manifest(list, kMax, &n) == FIDO_OK) {
        for (size_t i = 0; i < n; ++i) {
            const fido_dev_info_t* di = fido_dev_info_ptr(list, i);
            if (!di) continue;
            Device d;
            const char* p = fido_dev_info_path(di);
            const char* prod = fido_dev_info_product_string(di);
            const char* manf = fido_dev_info_manufacturer_string(di);
            if (p) d.path = p;
            if (prod) d.product = prod;
            if (manf) d.manufacturer = manf;
            if (!d.path.empty()) out.push_back(std::move(d));
        }
    }
    fido_dev_info_free(&list, kMax);
    return out;
}

bool HasClientPin(const std::string& path)
{
    fido_init(0);
    DevHandle h;
    OpenDevice(h, path);
    return fido_dev_has_pin(h.dev);
}

Bytes Enroll(const std::string& path, const std::string& pin,
             const Bytes& userId, const std::string& userName)
{
    fido_init(0);
    DevHandle h;
    OpenDevice(h, path);

    fido_cred_t* cred = fido_cred_new();
    if (!cred) throw Fido2Error("fido_cred_new failed");
    std::unique_ptr<fido_cred_t, void (*)(fido_cred_t*)> credGuard(
        cred, [](fido_cred_t* c) { fido_cred_free(&c); });

    int r;
    if ((r = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK)
        Fail("fido_cred_set_type", r);
    if ((r = fido_cred_set_clientdata(cred, kClientData, kClientDataLen)) != FIDO_OK)
        Fail("fido_cred_set_clientdata", r);
    if ((r = fido_cred_set_rp(cred, kRpId, kRpName)) != FIDO_OK)
        Fail("fido_cred_set_rp", r);
    if ((r = fido_cred_set_user(cred, userId.data(), userId.size(),
                                userName.c_str(), userName.c_str(), nullptr)) != FIDO_OK)
        Fail("fido_cred_set_user", r);
    if ((r = fido_cred_set_extensions(cred, FIDO_EXT_HMAC_SECRET)) != FIDO_OK)
        Fail("fido_cred_set_extensions", r);
    // Non-discoverable credential: we store the credId ourselves, so the key
    // does not need to spend resident-key slots.
    if ((r = fido_cred_set_rk(cred, FIDO_OPT_FALSE)) != FIDO_OK)
        Fail("fido_cred_set_rk", r);
    // Require user verification (PIN) at creation time.
    if ((r = fido_cred_set_uv(cred, FIDO_OPT_TRUE)) != FIDO_OK)
        Fail("fido_cred_set_uv", r);

    const char* pinArg = pin.empty() ? nullptr : pin.c_str();
    if ((r = fido_dev_make_cred(h.dev, cred, pinArg)) != FIDO_OK)
        Fail("fido_dev_make_cred", r);

    const unsigned char* idPtr = fido_cred_id_ptr(cred);
    size_t idLen = fido_cred_id_len(cred);
    if (!idPtr || idLen == 0) throw Fido2Error("credential has no id");
    return Bytes(idPtr, idPtr + idLen);
}

Bytes GetHmacSecret(const std::string& path, const std::string& pin,
                    const Bytes& credId, const Bytes& salt)
{
    if (salt.size() != kSaltLen) throw Fido2Error("GetHmacSecret: bad salt length");

    fido_init(0);
    DevHandle h;
    OpenDevice(h, path);

    fido_assert_t* assert = fido_assert_new();
    if (!assert) throw Fido2Error("fido_assert_new failed");
    std::unique_ptr<fido_assert_t, void (*)(fido_assert_t*)> assertGuard(
        assert, [](fido_assert_t* a) { fido_assert_free(&a); });

    int r;
    if ((r = fido_assert_set_clientdata(assert, kClientData, kClientDataLen)) != FIDO_OK)
        Fail("fido_assert_set_clientdata", r);
    if ((r = fido_assert_set_rp(assert, kRpId)) != FIDO_OK)
        Fail("fido_assert_set_rp", r);
    if ((r = fido_assert_allow_cred(assert, credId.data(), credId.size())) != FIDO_OK)
        Fail("fido_assert_allow_cred", r);
    if ((r = fido_assert_set_extensions(assert, FIDO_EXT_HMAC_SECRET)) != FIDO_OK)
        Fail("fido_assert_set_extensions", r);
    if ((r = fido_assert_set_hmac_salt(assert, salt.data(), salt.size())) != FIDO_OK)
        Fail("fido_assert_set_hmac_salt", r);
    // Require user presence (touch) and user verification (PIN).
    if ((r = fido_assert_set_up(assert, FIDO_OPT_TRUE)) != FIDO_OK)
        Fail("fido_assert_set_up", r);
    if ((r = fido_assert_set_uv(assert, FIDO_OPT_TRUE)) != FIDO_OK)
        Fail("fido_assert_set_uv", r);

    const char* pinArg = pin.empty() ? nullptr : pin.c_str();
    if ((r = fido_dev_get_assert(h.dev, assert, pinArg)) != FIDO_OK)
        Fail("fido_dev_get_assert", r);

    if (fido_assert_count(assert) < 1)
        throw Fido2Error("assertion returned no statements");

    const unsigned char* hs = fido_assert_hmac_secret_ptr(assert, 0);
    size_t hsLen = fido_assert_hmac_secret_len(assert, 0);
    if (!hs || hsLen != kHmacSecretLen)
        throw Fido2Error("hmac-secret missing or wrong length");
    return Bytes(hs, hs + hsLen);
}

}  // namespace token
