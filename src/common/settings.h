// Machine-wide settings, under HKLM\SOFTWARE\fido2-win-auth.
#pragma once

namespace settings {

// Whether plugging a key in may log the user in by itself, without them first
// choosing this sign-in option. Only ever acts on a U2F record, which has
// nothing to type; a FIDO2 record still wants its PIN. Defaults to on.
//
// This removes a click, not a factor: a U2F record is already unlocked by the
// key alone. It does mean an unattended locked machine opens the moment that
// key is plugged into it.
bool AutoLogon();
bool SetAutoLogon(bool on);  // needs administrative rights

}  // namespace settings
