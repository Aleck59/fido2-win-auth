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
