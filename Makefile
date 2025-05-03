# ND100X Makefile - CMake wrapper
# This Makefile provides backward compatibility by calling CMake

# Build directories
BUILD_DIR = build
BUILD_DIR_DEBUG = build
BUILD_DIR_RELEASE = build
BUILD_DIR_SANITIZE = build


# Commands with full paths
CMAKE := $(shell command -v cmake 2>/dev/null)

# Default target is debug
.PHONY: all
all: sanitize

# Build targets
.PHONY: debug release sanitize clean rundbg runsrv help

debug: 
	@echo "Building debug version..."
	$(CMAKE) -B $(BUILD_DIR_DEBUG) -S . -DCMAKE_BUILD_TYPE=Debug -DBUILD_EXECUTABLES=ON
	$(CMAKE) --build $(BUILD_DIR_DEBUG) -- -j$$(nproc 2>/dev/null || echo 4)

release: 
	@echo "Building release version..."
	$(CMAKE) -B $(BUILD_DIR_RELEASE) -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_EXECUTABLES=ON
	$(CMAKE) --build $(BUILD_DIR_RELEASE) -- -j$$(nproc 2>/dev/null || echo 4)

sanitize:
	@echo "Building with sanitizers..."
	$(CMAKE) -B $(BUILD_DIR_SANITIZE) -S . -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer" -DBUILD_EXECUTABLES=ON
	$(CMAKE) --build $(BUILD_DIR_SANITIZE) -- -j$$(nproc 2>/dev/null || echo 4) 

clean:
	@echo "Cleaning build directories..."
	rm -rf $(BUILD_DIR) $(BUILD_DIR_DEBUG) $(BUILD_DIR_RELEASE) $(BUILD_DIR_SANITIZE) $(BUILD_DIR_WASM)

runsrv: debug	
	@echo "Running mock server..."
	valgrind --leak-check=full $(BUILD_DIR_SANITIZE)/bin/dap_mock_server 

run: debug	
	@echo "Running debugger..."
	valgrind --leak-check=full  $(BUILD_DIR_SANITIZE)/bin/dap_debugger ../tests/test_program.exe

help:
	@echo "libDAP makefile - CMake wrapper"	
	@echo "-------------------------------------------------------------------------------"
	@echo "Targets:"
	@echo "  all (default) - Same as 'debug'"
	@echo "  debug         - Build debug version"
	@echo "  release       - Build release version"
	@echo "  sanitize      - Build with address sanitizer"
	@echo "  clean         - Remove build directories"	
	@echo "  runsrv        - Build and run mock server"
	@echo "  rund          - Build and run the debugger"
	@echo "  help          - Show this help"
	@echo ""
	@echo "This Makefile is a wrapper around CMake. If you prefer, you can use CMake directly:"
	@echo "  cmake -B build"
	@echo "  cmake --build build"