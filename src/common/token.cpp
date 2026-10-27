// Token implementation over libfido2. Every entry point opens the device,
// performs one operation, and closes it; no device handle outlives a call.
#include "token.h"

#include <fido.h>
#include <fido/es256.h>

#include <cstring>
#include <memory>

namespace token {

namespace {

// Fixed client-data. This is a local logon factor, not a web authentication,
// so there is no server challenge; the hmac-secret (gated by PIN + touch) is
// the actual secret. The value only needs to be stable between enroll and login.
const unsigned char kClientData[] = "fido2-win-auth/local-logon/v1";
constexpr size_t kClientDataLen = sizeof(kClientData) - 1;

// A user-presence operation waits for a human; a silent query must not.
constexpr int kTouchTimeoutMs = 25000;
constexpr int kSilentTimeoutMs = 2000;

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

// Opens without insisting on CTAP2. Used by the U2F paths and by Probe().
void OpenDeviceAnyProtocol(DevHandle& h, const std::string& path)
{
    h.dev = fido_dev_new();
    if (!h.dev) throw Fido2Error("fido_dev_new failed");
    int r = fido_dev_open(h.dev, path.c_str());
    if (r != FIDO_OK) Fail("fido_dev_open", r);
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

namespace {

// Collects the strings out of a libfido2 string array.
std::vector<std::string> CollectStrings(char* const* ptr, size_t len)
{
    std::vector<std::string> out;
    for (size_t i = 0; i < len; ++i)
        if (ptr[i]) out.push_back(ptr[i]);
    return out;
}

}  // namespace

Held HoldsCredential(const std::string& path, const Bytes& credId, bool u2f)
{
    if (credId.empty()) return Held::Unknown;

    fido_init(0);
    try {
        DevHandle h;
        OpenDeviceAnyProtocol(h, path);
        if (u2f) fido_dev_force_u2f(h.dev);
        fido_dev_set_timeout(h.dev, kSilentTimeoutMs);

        fido_assert_t* assert = fido_assert_new();
        if (!assert) return Held::Unknown;
        std::unique_ptr<fido_assert_t, void (*)(fido_assert_t*)> guard(
            assert, [](fido_assert_t* a) { fido_assert_free(&a); });

        if (fido_assert_set_clientdata(assert, kClientData, kClientDataLen) != FIDO_OK ||
            fido_assert_set_rp(assert, kRpId) != FIDO_OK ||
            fido_assert_allow_cred(assert, credId.data(), credId.size()) != FIDO_OK ||
            // No touch: this is a question, not an authentication.
            fido_assert_set_up(assert, FIDO_OPT_FALSE) != FIDO_OK)
            return Held::Unknown;

        const int r = fido_dev_get_assert(h.dev, assert, nullptr);
        switch (r) {
            case FIDO_OK:
                return Held::Yes;
            // The key recognised the credential and is only withholding the
            // assertion until someone touches it -- which is still a yes.
            case FIDO_ERR_UP_REQUIRED:
            case FIDO_ERR_USER_PRESENCE_REQUIRED:
                return Held::Yes;
            case FIDO_ERR_NO_CREDENTIALS:
                return Held::No;
            default:
                // Includes keys that refuse presence-less assertions at all.
                return Held::Unknown;
        }
    } catch (const std::exception&) {
        return Held::Unknown;
    }
}

Capabilities Probe(const std::string& path)
{
    fido_init(0);

    Capabilities c;
    c.path = path;

    // Deliberately not OpenDevice(): that rejects a CTAP1-only key, and such a
    // key is exactly what this function exists to describe.
    DevHandle h;
    h.dev = fido_dev_new();
    if (!h.dev) {
        c.probeFailed = true;
        c.probeError = "fido_dev_new failed";
        return c;
    }
    int r = fido_dev_open(h.dev, path.c_str());
    if (r != FIDO_OK) {
        c.probeFailed = true;
        c.probeError = std::string("fido_dev_open: ") + fido_strerr(r);
        return c;
    }

    c.isFido2 = fido_dev_is_fido2(h.dev);
    c.pinSet = fido_dev_has_pin(h.dev);

    if (c.isFido2) {
        fido_cbor_info_t* info = fido_cbor_info_new();
        if (info) {
            if (fido_dev_get_cbor_info(h.dev, info) == FIDO_OK) {
                c.versions = CollectStrings(fido_cbor_info_versions_ptr(info),
                                            fido_cbor_info_versions_len(info));
                c.extensions = CollectStrings(fido_cbor_info_extensions_ptr(info),
                                              fido_cbor_info_extensions_len(info));
                for (const auto& e : c.extensions)
                    if (e == "hmac-secret") c.hmacSecret = true;

                char* const* names = fido_cbor_info_options_name_ptr(info);
                const bool* values = fido_cbor_info_options_value_ptr(info);
                const size_t n = fido_cbor_info_options_len(info);
                for (size_t i = 0; i < n; ++i) {
                    if (!names[i]) continue;
                    if (std::strcmp(names[i], "clientPin") == 0) {
                        c.clientPinSupported = true;
                        // The option's value doubles as "a PIN is set".
                        c.pinSet = c.pinSet || values[i];
                    }
                }
            }
            fido_cbor_info_free(&info);
        }
    }

    // Decide usability in one place, so the UI never has to reason about it.
    if (!c.isFido2) {
        c.reason = "ключ отвечает только по U2F (CTAP1): расширений в этом "
                   "протоколе нет, поэтому hmac-secret недоступен";
    } else if (!c.hmacSecret) {
        c.reason = "ключ не поддерживает расширение hmac-secret";
    } else if (!c.pinSet) {
        c.reason = "на ключе не задан PIN";
    } else {
        c.usable = true;
    }
    return c;
}

std::vector<Capabilities> ProbeAll()
{
    std::vector<Capabilities> out;
    for (const auto& d : ListDevices()) {
        Capabilities c = Probe(d.path);
        c.product = d.product;
        c.manufacturer = d.manufacturer;
        out.push_back(std::move(c));
    }
    return out;
}

std::set<std::string> AttachedPaths()
{
    std::set<std::string> paths;
    try {
        for (const auto& d : ListDevices()) paths.insert(d.path);
    } catch (const std::exception&) {
        // An unreadable bus looks the same as an empty one here; the caller
        // only compares successive answers.
    }
    return paths;
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

U2fCredential EnrollU2f(const std::string& path, const Bytes& userId,
                        const std::string& userName)
{
    fido_init(0);
    DevHandle h;
    OpenDeviceAnyProtocol(h, path);
    // Pin the protocol so a CTAP2 key behaves exactly like a CTAP1-only one;
    // otherwise the record would depend on which key happened to be used.
    fido_dev_force_u2f(h.dev);
    fido_dev_set_timeout(h.dev, kTouchTimeoutMs);

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
    // CTAP1 has neither resident keys nor user verification; asking for either
    // would be rejected.
    if ((r = fido_cred_set_rk(cred, FIDO_OPT_FALSE)) != FIDO_OK)
        Fail("fido_cred_set_rk", r);
    if ((r = fido_cred_set_uv(cred, FIDO_OPT_FALSE)) != FIDO_OK)
        Fail("fido_cred_set_uv", r);

    if ((r = fido_dev_make_cred(h.dev, cred, nullptr)) != FIDO_OK)
        Fail("fido_dev_make_cred (u2f)", r);

    const unsigned char* idPtr = fido_cred_id_ptr(cred);
    const size_t idLen = fido_cred_id_len(cred);
    if (!idPtr || idLen == 0) throw Fido2Error("u2f credential has no key handle");

    const unsigned char* pkPtr = fido_cred_pubkey_ptr(cred);
    const size_t pkLen = fido_cred_pubkey_len(cred);
    if (!pkPtr || pkLen == 0) throw Fido2Error("u2f credential has no public key");

    U2fCredential out;
    out.keyHandle.assign(idPtr, idPtr + idLen);
    out.pubKey.assign(pkPtr, pkPtr + pkLen);
    out.counter = 0;
    return out;
}

uint32_t AssertU2f(const std::string& path, const Bytes& keyHandle,
                   const Bytes& pubKey, int timeoutMs)
{
    if (keyHandle.empty()) throw Fido2Error("AssertU2f: empty key handle");
    if (pubKey.empty()) throw Fido2Error("AssertU2f: empty public key");

    fido_init(0);
    DevHandle h;
    OpenDeviceAnyProtocol(h, path);
    fido_dev_force_u2f(h.dev);
    fido_dev_set_timeout(h.dev, timeoutMs > 0 ? timeoutMs : kTouchTimeoutMs);

    fido_assert_t* assert = fido_assert_new();
    if (!assert) throw Fido2Error("fido_assert_new failed");
    std::unique_ptr<fido_assert_t, void (*)(fido_assert_t*)> assertGuard(
        assert, [](fido_assert_t* a) { fido_assert_free(&a); });

    int r;
    if ((r = fido_assert_set_clientdata(assert, kClientData, kClientDataLen)) != FIDO_OK)
        Fail("fido_assert_set_clientdata", r);
    if ((r = fido_assert_set_rp(assert, kRpId)) != FIDO_OK)
        Fail("fido_assert_set_rp", r);
    if ((r = fido_assert_allow_cred(assert, keyHandle.data(), keyHandle.size())) != FIDO_OK)
        Fail("fido_assert_allow_cred", r);
    if ((r = fido_assert_set_up(assert, FIDO_OPT_TRUE)) != FIDO_OK)
        Fail("fido_assert_set_up", r);

    if ((r = fido_dev_get_assert(h.dev, assert, nullptr)) != FIDO_OK)
        Fail("fido_dev_get_assert (u2f)", r);
    if (fido_assert_count(assert) < 1)
        throw Fido2Error("u2f assertion returned no statements");

    // Verify against the public key recorded at registration. Without this the
    // "assertion" would prove nothing at all: any key could answer.
    es256_pk_t* pk = es256_pk_new();
    if (!pk) throw Fido2Error("es256_pk_new failed");
    std::unique_ptr<es256_pk_t, void (*)(es256_pk_t*)> pkGuard(
        pk, [](es256_pk_t* p) { es256_pk_free(&p); });

    if ((r = es256_pk_from_ptr(pk, pubKey.data(), pubKey.size())) != FIDO_OK)
        Fail("es256_pk_from_ptr", r);
    if ((r = fido_assert_verify(assert, 0, COSE_ES256, pk)) != FIDO_OK)
        Fail("fido_assert_verify", r);

    return fido_assert_sigcount(assert, 0);
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
