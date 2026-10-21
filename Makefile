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

CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wno-delete-non-virtual-dtor \
            -Wno-missing-field-initializers $(INC)
# Statically link the C++/GCC runtime so no MinGW DLLs are needed at runtime.
LDSTATIC := -static -static-libgcc -static-libstdc++

BUILD := build
DIST  := dist

COMMON_SRC := src/common/bytes.cpp src/common/vault.cpp \
              src/common/token.cpp src/common/store.cpp
COMMON_OBJ := $(patsubst src/common/%.cpp,$(BUILD)/common_%.o,$(COMMON_SRC))

PROVIDER_SRC := src/provider/common.cpp src/provider/kerb.cpp \
                src/provider/Credential.cpp src/provider/Provider.cpp \
                src/provider/Dll.cpp src/provider/guids.cpp
PROVIDER_OBJ := $(patsubst src/provider/%.cpp,$(BUILD)/prov_%.o,$(PROVIDER_SRC))

ENROLL_EXE   := $(BUILD)/enroll.exe
PROVIDER_DLL := $(BUILD)/fido2provider.dll
TEST_EXE     := $(BUILD)/test_vault.exe

RUNTIME_DLLS := $(wildcard $(FIDO_DIR)/bin/*.dll)

# System import libraries for the provider DLL.
PROVIDER_SYSLIBS := -lole32 -loleaut32 -ladvapi32 -lsecur32 -luser32 \
                    -lcrypt32 -lws2_32 -luuid
ENROLL_SYSLIBS   := -ladvapi32 -lole32 -lcrypt32 -lws2_32

.PHONY: all clean test dist installer
all: $(ENROLL_EXE) $(PROVIDER_DLL) $(TEST_EXE)

$(BUILD):
	mkdir -p $(BUILD)

# --- object files ---------------------------------------------------------
$(BUILD)/common_%.o: src/common/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -municode -c $< -o $@

$(BUILD)/prov_%.o: src/provider/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -municode -c $< -o $@

$(BUILD)/test_vault.o: tests/test_vault.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# --- enroll utility -------------------------------------------------------
$(ENROLL_EXE): src/enroll/main.cpp $(COMMON_OBJ) | $(BUILD)
	$(CXX) $(CXXFLAGS) -municode $(LDSTATIC) $< $(COMMON_OBJ) \
	    $(LIBDIR) $(FIDO_LIBS) $(ENROLL_SYSLIBS) -o $@

# --- credential provider DLL ---------------------------------------------
$(PROVIDER_DLL): $(PROVIDER_OBJ) $(COMMON_OBJ) src/provider/provider.def | $(BUILD)
	$(CXX) -municode -shared $(LDSTATIC) src/provider/provider.def \
	    $(PROVIDER_OBJ) $(COMMON_OBJ) \
	    $(LIBDIR) $(FIDO_LIBS) $(PROVIDER_SYSLIBS) -o $@

# --- tests ----------------------------------------------------------------
$(TEST_EXE): $(BUILD)/test_vault.o $(BUILD)/common_vault.o $(BUILD)/common_bytes.o
	$(CXX) $(LDSTATIC) $^ $(LIBDIR) -lcrypto -o $@

test: $(TEST_EXE)
	@cp -f $(RUNTIME_DLLS) $(BUILD)/
	cd $(BUILD) && WINEDEBUG=-all $(WINE) test_vault.exe

# --- distribution ---------------------------------------------------------
dist: all
	mkdir -p $(DIST)
	cp -f $(ENROLL_EXE) $(PROVIDER_DLL) $(DIST)/
	cp -f $(RUNTIME_DLLS) $(DIST)/

installer: dist
	$(MAKENSIS) -DDIST=$(CURDIR)/$(DIST) installer/installer.nsi

clean:
	rm -rf $(BUILD) $(DIST)
