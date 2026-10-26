// DPAPI, machine scope.
//
// Used only by the U2F vault mode, where there is no token-derived secret to
// encrypt with (CTAP1 has no hmac-secret) and the vault key therefore has to
// live on the machine. Protecting it with DPAPI keeps it off the disk in
// cleartext, but makes no claim beyond that: anything running as SYSTEM or as
// an administrator on this machine can call Unprotect() just as the credential
// provider does. That is the whole reason U2F mode is weaker, and it is stated
// here rather than discovered later.
#pragma once

#include "bytes.h"

namespace dpapi {

// Encrypts to the machine (CRYPTPROTECT_LOCAL_MACHINE), so the credential
// provider running as SYSTEM can decrypt what the enrollment tool wrote.
// `entropy` is additional authenticated input and must match on both sides.
// Throws Fido2Error on failure.
Bytes Protect(const Bytes& plain, const Bytes& entropy);

// Returns false if the blob does not belong to this machine, the entropy does
// not match, or the blob was tampered with.
bool Unprotect(const Bytes& blob, const Bytes& entropy, Bytes& plain);

}  // namespace dpapi
