// Token: all interaction with the FIDO2 authenticator, delegated to libfido2.
// Enrollment creates a non-discoverable credential with the hmac-secret
// extension; login obtains the hmac-secret for a stored salt. User verification
// (PIN + touch) is always required so a stolen key alone is useless.
#pragma once

#include "bytes.h"

#include <set>
#include <string>
#include <vector>

namespace token {

// Relying-party identity. Not a web origin; it only scopes the credential to
// this application on the key.
constexpr const char* kRpId = "fido2-win-auth.local";
constexpr const char* kRpName = "FIDO2 Windows local logon";

// Length of the hmac-secret output (and the HKDF salt).
constexpr size_t kHmacSecretLen = 32;
constexpr size_t kSaltLen = 32;

struct Device {
    std::string path;     // opaque HID path passed back to Open*
    std::string product;  // human-readable, best-effort
    std::string manufacturer;
};

// Enumerates FIDO authenticators currently connected. Never throws for an
// empty bus; returns an empty vector.
std::vector<Device> ListDevices();

// Just the paths, as a set, for spotting a key being plugged in: a path that
// was not in the previous answer is an arrival. Never throws.
std::set<std::string> AttachedPaths();

// What a connected key can actually do.
//
// Worth reporting because "U2F key" is mostly a label on the casing: almost
// everything sold in the last several years speaks CTAP2 as well. A key that
// really is CTAP1-only cannot be used by the hmac-secret scheme at all --
// CTAP1 has no extension mechanism, so there is no reproducible secret to
// derive a key from -- and saying so plainly beats a generic failure.
struct Capabilities {
    std::string path;
    std::string product;
    std::string manufacturer;

    bool isFido2 = false;        // speaks CTAP2
    bool hmacSecret = false;     // advertises the hmac-secret extension
    bool clientPinSupported = false;
    bool pinSet = false;         // a PIN has actually been configured
    std::vector<std::string> versions;    // e.g. U2F_V2, FIDO_2_0, FIDO_2_1
    std::vector<std::string> extensions;

    // Whether this key can be enrolled by the current scheme, and if not, why.
    bool usable = false;
    std::string reason;

    // Set when the key could not be opened or queried at all.
    bool probeFailed = false;
    std::string probeError;
};

// Queries one key. Unlike the other entry points this tolerates a CTAP1-only
// device instead of throwing: reporting what is there is the whole point.
Capabilities Probe(const std::string& path);

// Probes every connected key.
std::vector<Capabilities> ProbeAll();

// Creates a credential on the device identified by path, bound to kRpId and the
// given user entity, with the hmac-secret extension enabled and user
// verification required. Returns the opaque credential id to store. Requires PIN
// and a touch. Throws Fido2Error on failure (message is safe to log; it carries
// no secret).
Bytes Enroll(const std::string& path, const std::string& pin,
             const Bytes& userId, const std::string& userName);

// Runs an assertion for credId with the given 32-byte salt and returns the
// 32-byte hmac-secret. Requires PIN and a touch. Throws Fido2Error on failure.
Bytes GetHmacSecret(const std::string& path, const std::string& pin,
                    const Bytes& credId, const Bytes& salt);

// Whether a key holds a given credential, asked without a touch.
//
// Answering needs an assertion with user presence switched off, which CTAP2
// allows outright and CTAP1 answers through its check-only control byte. Not
// every key or driver honours that, so the third value is not a formality:
// "could not tell" must not be shown as "not registered".
enum class Held { Yes, No, Unknown };

// Silent: never prompts, never waits for a touch. `u2f` selects the protocol
// to ask over, which must match how the credential was created.
Held HoldsCredential(const std::string& path, const Bytes& credId, bool u2f);

// True if the device requires/holds a client PIN (used to prompt correctly).
bool HasClientPin(const std::string& path);

// ---------------------------------------------------------------- U2F -----
//
// CTAP1. No extensions, no PIN, no hmac-secret: a U2F key can only register
// and then sign a challenge. The signature proves the key is present, which is
// all the U2fPresence vault mode asks of it -- see vault.h for why that is
// strictly weaker.

struct U2fCredential {
    Bytes keyHandle;
    Bytes pubKey;     // EC public key, stored so assertions can be verified
    uint32_t counter; // signature counter at registration
};

// Registers over CTAP1. The protocol is forced, so this behaves the same on a
// CTAP1-only key and on a CTAP2 key asked to act as one. Requires a touch.
U2fCredential EnrollU2f(const std::string& path, const Bytes& userId,
                        const std::string& userName);

// Asserts over CTAP1 and verifies the signature against pubKey. Returns the
// key's signature counter, which the caller should check moves forward --
// a counter that goes backwards suggests a cloned key. Requires a touch.
// Throws Fido2Error if the key refuses or the signature does not verify.
//
// `timeoutMs` of 0 means the default, which is long enough for someone to
// press a button. Pass something short to find out quickly whether a key is
// already willing -- a key with no button only is in the seconds right after
// it was plugged in, and waiting out the full timeout to learn otherwise is
// what makes a logon screen look frozen.
uint32_t AssertU2f(const std::string& path, const Bytes& keyHandle,
                   const Bytes& pubKey, int timeoutMs = 0);

}  // namespace token
