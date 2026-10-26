// Opening a stored record with the key that guards it.
//
// Both the credential provider (at logon) and the enrollment tool's self-test
// do exactly this, and they must agree down to the counter rule, so it lives
// here once. Deliberately free of any dependency the provider should not carry
// -- vault, token and dpapi only.
#pragma once

#include "vault.h"

#include <string>

namespace unlock {

struct Outcome {
    bool ok = false;
    std::wstring error;     // user-facing, Russian, safe to display
    std::wstring password;  // meaningful only when ok

    // U2F only: the counter the key reported, and whether the record should be
    // rewritten to remember it.
    uint32_t counter = 0;
    bool counterAdvanced = false;

    // True when the key answered but is not the one this record belongs to, so
    // a caller walking several attached keys should simply try the next.
    bool wrongKey = false;
};

// One attempt against one device. Dispatches on rec.mode. `pin` is ignored for
// U2F records, which have no PIN. Never throws.
//
// `timeoutMs` of 0 means the default. A short one turns the U2F attempt into a
// quick "is this key willing right now?" probe, which is how a caller can tell
// a key that already has user presence from one that needs to be re-plugged
// without stalling on a full timeout.
Outcome WithDevice(const VaultRecord& rec, const std::string& devicePath,
                   const std::string& pin, int timeoutMs = 0);

}  // namespace unlock
