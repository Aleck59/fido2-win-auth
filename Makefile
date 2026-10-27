# Cross-compilation build for fido2-win-auth (MinGW-w64, x86-64).
#
# Targets:
#   make            build enroll.exe, the provider DLL, and the test exe
#   make test       build and run the vault round-trip tests under Wine
#   make dist       stage binaries + runtime DLLs into dist/
#   make installer  build the NSIS installer into dist/
#   make clean      remove build/ and dist/
#
# Requires: g++-mingw-w64-x86-64, nsis, wine64 (for `make test`).

CXX      := x86_64-w64-mingw32-g++
WINDRES  := x86_64-w64-mingw32-windres
MAKENSIS := makensis
WINE     := wine

FIDO_DIR := third_party/libfido2
INC      := -I$(FIDO_DIR)/include
LIBDIR   := -L$(FIDO_DIR)/lib
FIDO_LIBS := -lfido2 -lcrypto -lcbor -lzlib1

# -MMD -MP makes the compiler emit a .d file listing the headers each object
# depends on; without it a changed header leaves stale objects behind and the
# link fails on signatures that no longer match.
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wno-delete-non-virtual-dtor \
            -Wno-missing-field-initializers -MMD -MP $(INC)
# Statically link the C++/GCC runtime so no MinGW DLLs are needed at runtime.
LDSTATIC := -static -static-libgcc -static-libstdc++

BUILD := build
DIST  := dist

COMMON_SRC := src/common/bytes.cpp src/common/vault.cpp \
              src/common/token.cpp src/common/store.cpp \
              src/common/dpapi.cpp src/common/unlock.cpp src/common/plog.cpp \
              src/common/settings.cpp
COMMON_OBJ := $(patsubst src/common/%.cpp,$(BUILD)/common_%.o,$(COMMON_SRC))

# Enrollment logic, shared by enroll.exe and the GUI but not by the provider:
# the provider never enrolls, and this pulls in netapi32.
FRONTEND_OBJ := $(BUILD)/common_enrollment.o

PROVIDER_SRC := src/provider/common.cpp src/provider/kerb.cpp \
                src/provider/Credential.cpp src/provider/Provider.cpp \
                src/provider/Dll.cpp src/provider/guids.cpp
PROVIDER_OBJ := $(patsubst src/provider/%.cpp,$(BUILD)/prov_%.o,$(PROVIDER_SRC))

# Compiled resources (the tile bitmap shown next to the sign-in option).
PROVIDER_RES := $(BUILD)/prov_resources.o

ENROLL_EXE   := $(BUILD)/enroll.exe
GUI_EXE      := $(BUILD)/fido2gui.exe
PROVIDER_DLL := $(BUILD)/fido2provider.dll
TEST_EXE     := $(BUILD)/test_vault.exe

RUNTIME_DLLS := $(wildcard $(FIDO_DIR)/bin/*.dll)

# System import libraries for the provider DLL.
PROVIDER_SYSLIBS := -lole32 -loleaut32 -ladvapi32 -lsecur32 -luser32 \
                    -lgdi32 -lcrypt32 -lws2_32 -luuid
ENROLL_SYSLIBS   := -ladvapi32 -lole32 -lcrypt32 -lws2_32 -lnetapi32
GUI_SYSLIBS      := -lcomctl32 -luser32 -lgdi32 -lshell32 $(ENROLL_SYSLIBS)
GUI_RES          := $(BUILD)/gui_resources.o
ENROLL_RES       := $(BUILD)/enroll_resources.o

# Header dependencies recorded by -MMD, pulled in if they exist.
DEPS := $(wildcard $(BUILD)/*.d)

.PHONY: all clean test dist installer
all: $(ENROLL_EXE) $(GUI_EXE) $(PROVIDER_DLL) $(TEST_EXE)

$(BUILD):
	mkdir -p $(BUILD)

# --- object files ---------------------------------------------------------
$(BUILD)/common_%.o: src/common/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -municode -c $< -o $@

$(BUILD)/prov_%.o: src/provider/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -municode -c $< -o $@

$(PROVIDER_RES): src/provider/provider.rc src/provider/resource.h \
                 src/provider/tile.bmp src/common/product.h | $(BUILD)
	$(WINDRES) --codepage=65001 -I src/provider $< -O coff -o $@

$(GUI_RES): src/gui/gui.rc src/gui/resource.h src/gui/app.manifest \
            src/gui/key.bmp src/gui/app.ico src/common/product.h | $(BUILD)
	$(WINDRES) --codepage=65001 -I src/gui $< -O coff -o $@

$(BUILD)/test_vault.o: tests/test_vault.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# --- enroll utility -------------------------------------------------------
$(ENROLL_RES): src/enroll/enroll.rc src/common/product.h src/gui/app.ico | $(BUILD)
	$(WINDRES) --codepage=65001 -I src/enroll $< -O coff -o $@

$(ENROLL_EXE): src/enroll/main.cpp $(COMMON_OBJ) $(FRONTEND_OBJ) $(ENROLL_RES) \
               | $(BUILD)
	$(CXX) $(CXXFLAGS) -municode $(LDSTATIC) $< $(COMMON_OBJ) $(FRONTEND_OBJ) \
	    $(ENROLL_RES) $(LIBDIR) $(FIDO_LIBS) $(ENROLL_SYSLIBS) -o $@

# --- GUI ------------------------------------------------------------------
$(GUI_EXE): src/gui/main.cpp $(COMMON_OBJ) $(FRONTEND_OBJ) $(GUI_RES) | $(BUILD)
	$(CXX) $(CXXFLAGS) -municode -mwindows $(LDSTATIC) $< $(COMMON_OBJ) \
	    $(FRONTEND_OBJ) $(GUI_RES) $(LIBDIR) $(FIDO_LIBS) $(GUI_SYSLIBS) -o $@

# --- credential provider DLL ---------------------------------------------
$(PROVIDER_DLL): $(PROVIDER_OBJ) $(PROVIDER_RES) $(COMMON_OBJ) \
                 src/provider/provider.def | $(BUILD)
	$(CXX) -municode -shared $(LDSTATIC) src/provider/provider.def \
	    $(PROVIDER_OBJ) $(PROVIDER_RES) $(COMMON_OBJ) \
	    $(LIBDIR) $(FIDO_LIBS) $(PROVIDER_SYSLIBS) -o $@

# --- tests ----------------------------------------------------------------
$(TEST_EXE): $(BUILD)/test_vault.o $(BUILD)/common_vault.o \
             $(BUILD)/common_bytes.o $(BUILD)/common_dpapi.o
	$(CXX) $(LDSTATIC) $^ $(LIBDIR) -lcrypto -lcrypt32 -o $@

test: $(TEST_EXE)
	@cp -f $(RUNTIME_DLLS) $(BUILD)/
	cd $(BUILD) && WINEDEBUG=-all $(WINE) test_vault.exe

# --- distribution ---------------------------------------------------------
dist: all
	mkdir -p $(DIST)
	cp -f $(ENROLL_EXE) $(GUI_EXE) $(PROVIDER_DLL) $(DIST)/
	cp -f $(RUNTIME_DLLS) $(DIST)/

installer: dist
	$(MAKENSIS) -DDIST=$(CURDIR)/$(DIST) installer/installer.nsi

clean:
	rm -rf $(BUILD) $(DIST)

-include $(DEPS)
