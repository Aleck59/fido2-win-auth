// Helpers to build the KERB_INTERACTIVE_UNLOCK_LOGON blob that Windows expects
// from a password credential provider, and to look up the Negotiate auth
// package. Mirrors the well-known Microsoft credential-provider sample pattern.
#pragma once

#include <windows.h>
#include <credentialprovider.h>

#define SECURITY_WIN32
#include <ntsecapi.h>

// Fills a KERB_INTERACTIVE_UNLOCK_LOGON from plain strings for the given usage.
HRESULT KerbInteractiveUnlockLogonInit(PWSTR domain, PWSTR username, PWSTR password,
                                       CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                       KERB_INTERACTIVE_UNLOCK_LOGON* pkiul);

// Serializes the logon struct into a single CoTaskMem buffer with the string
// pointers rebased to offsets (as LSA requires).
HRESULT KerbInteractiveUnlockLogonPack(const KERB_INTERACTIVE_UNLOCK_LOGON& kiul,
                                       BYTE** prgb, DWORD* pcb);

// Resolves the "Negotiate" authentication package id.
HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage);

// Copies (and, only for CredUI off-box, protects) the password into a fresh
// CoTaskMem string.
HRESULT ProtectIfNecessaryAndCopyPassword(PCWSTR password,
                                          CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                          PWSTR* ppwzProtected);
