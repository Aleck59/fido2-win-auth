// Product identity, shared by every resource script so the name and publisher
// are stated once.
//
// The displayed name and the internal identifiers are deliberately separate:
// the install directory and the uninstall registry key stay "fido2-win-auth"
// so an existing installation keeps working, while what people read says
// "FIDO win auth".
#pragma once

#define PRODUCT_NAME      "FIDO win auth"
#define PRODUCT_PUBLISHER "Aleck59"
#define PRODUCT_COPYRIGHT "Copyright (C) 2026 Aleck59"
#define PRODUCT_VERSION   "0.3.0.0"
#define PRODUCT_VERSION_N 0,3,0,0
