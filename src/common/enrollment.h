// Enrollment: the key-touching parts of registering, testing and removing an
// account, with no console or window of its own.
//
// The sequence is delicate (three touches, and a verification that must happen
// before the plaintext is dropped but after the record is built), so it lives
// here once and both front-ends -- enroll.exe and the GUI -- drive it.
// Collecting the PIN, the password and the choice of key stays with the
// front-end, which knows whether it has a console or a dialog.
#pragma once

#include "bytes.h"

#include <functional>
#include <string>
#include <vector>

namespace enrollment {

// Points at which the user has to do something, or a slow step begins. Each
// front-end renders these in its own words.
enum class Step {
    CreatingCredential,  // first touch
    FetchingSecret,      // second touch
    Verifying,           // third touch
    Saving,
};

using ProgressFn = std::function<void(Step)>;

struct Account {
    std::wstring sid;
    std::wstring domain;
    std::wstring user;

    // "DOMAIN\user", or the bare SID when it no longer resolves (the account
    // was deleted but its record was left behind).
    std::wstring Display() const;
    bool Resolved() const { return !user.empty(); }
};

struct Status {
    bool ok = false;
    std::wstring error;

    static Status Success() { return Status{true, L""}; }
    static Status Fail(const std::wstring& e) { return Status{false, e}; }
};

// Three-valued on purpose: a failed network logon only proves the password is
// wrong when Windows says so in those words. Any other failure (disabled
// account, blank-password policy, a locked-out account) says nothing about
// what the user typed, and must not block enrollment.
enum class PasswordCheck { Valid, Wrong, Unknown };

PasswordCheck CheckWindowsPassword(const std::wstring& account,
                                   const std::wstring& password);

// Local, enrollable accounts (normal user accounts, not machine or trust ones).
std::vector<std::wstring> LocalUserNames();

// Accounts that currently have a record.
std::vector<Account> Enrolled();

bool IsEnrolled(const std::wstring& account);

// Creates the credential, seals the password and stores the record. Requires
// an elevated process. Never persists a record it has not round-tripped.
Status Enroll(const std::wstring& account, const std::string& devicePath,
              const std::string& pin, const std::wstring& password,
              const ProgressFn& progress);

// Recovers the stored password with the key and checks Windows still accepts
// it -- the way to catch a password changed outside this tool.
Status Test(const std::wstring& account, const std::string& devicePath,
            const std::string& pin, const ProgressFn& progress);

Status Remove(const std::wstring& account);

// Removes by SID, which is the only way to clear a record left behind by a
// deleted account -- its name no longer resolves.
Status RemoveBySid(const std::wstring& sid);

}  // namespace enrollment
