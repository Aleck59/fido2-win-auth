// Optional log for the credential provider.
//
// The provider runs as SYSTEM inside LogonUI: no console, no window, and a
// failure there costs a reboot to retry. When something does not work on the
// logon screen this is the only way to find out where it stopped.
//
// Off unless HKLM\SOFTWARE\fido2-win-auth\Debug (DWORD) is 1, and it never
// records a password, a PIN, a credential id or any key material -- only which
// step was reached and the same messages the tile already shows.
#pragma once

#include <string>

namespace plog {

// Re-read on each call so turning the log on does not need a reboot.
bool Enabled();

// Appends one timestamped line to
// %ProgramData%\fido2-win-auth\provider.log. Silent on any failure: logging
// must never be the reason a logon does not happen.
void Write(const std::wstring& line);

// Turns the log on or off. Needs administrative rights.
bool SetEnabled(bool on);

// Where the log lives, for the CLI to print.
std::wstring Path();

}  // namespace plog
