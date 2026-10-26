// Token: all interaction with the FIDO2 authenticator, delegated to libfido2.
// Enrollment creates a non-discoverable credential with the hmac-secret
// extension; login obtains the hmac-secret for a stored salt. User verification
// (PIN + touch) is always required so a stolen key alone is useless.
#pragma once

#include "bytes.h"

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

// True if the device requires/holds a client PIN (used to prompt correctly).
bool HasClientPin(const std::string& path);

}  // namespace token
