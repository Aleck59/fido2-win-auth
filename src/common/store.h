// Store: persistence of vault records in the registry, keyed by user SID.
//
// Records live under HKLM so they are machine-global and readable by the
// LogonUI/SYSTEM context that runs the credential provider, yet the key is
// ACL'd to SYSTEM + Administrators only (see store.cpp). A record is not a
// secret on its own, but restricting it keeps a standard user from enumerating
// or tampering with other accounts' blobs.
//
//   HKLM\SOFTWARE\fido2-win-auth\vaults\<SID>  value "record" (REG_BINARY)
#pragma once

#include "bytes.h"

#include <string>
#include <vector>

namespace store {

// Writes (or replaces) the record for sidString. Creates the subtree with a
// SYSTEM+Administrators-only DACL on first use. Requires administrative rights.
// Throws Fido2Error (with the Win32 error) on failure.
void SaveRecord(const std::wstring& sidString, const Bytes& record);

// Reads the record for sidString. Returns false if none exists.
bool LoadRecord(const std::wstring& sidString, Bytes& record);

// Removes the record for sidString (no error if it does not exist).
void DeleteRecord(const std::wstring& sidString);

// Lists the SIDs that currently have a record.
std::vector<std::wstring> ListEnrolledSids();

// Resolves the SID string for a local account name (e.g. L"Alice"). Throws if
// the account cannot be resolved.
std::wstring SidForAccount(const std::wstring& accountName);

// Resolves "DOMAIN\\user" (or just "user") for a SID string. Returns false if
// the SID cannot be resolved on this machine.
bool AccountForSid(const std::wstring& sidString, std::wstring& outDomain,
                   std::wstring& outUser);

}  // namespace store
