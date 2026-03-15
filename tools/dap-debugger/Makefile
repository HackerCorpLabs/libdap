BUILD_DIR = build
BINARY    = $(BUILD_DIR)/dap_gui_debugger
CMAKE     = cmake

# Mock server (built from root project)
ROOT_BUILD  = ../../build
MOCK_SERVER = $(ROOT_BUILD)/bin/dap_mock_server
TEST_PROG   = ../../tests/test_program.exe

HOST = localhost
PORT = 5555

.PHONY: all clean run run-mock server debug rebuild

all: $(BINARY)

$(BINARY): CMakeLists.txt $(wildcard src/*.cpp src/*.h src/ui/*.cpp src/ui/*.h)
	$(CMAKE) -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Debug
	$(CMAKE) --build $(BUILD_DIR) -j$$(nproc)

clean:
	rm -rf $(BUILD_DIR)

rebuild: clean all

# Connect to nd100x (or any DAP server on PORT)
run: $(BINARY)
	./$(BINARY) --port $(PORT)

# Connect to mock server with test program
run-mock: $(BINARY)
	./$(BINARY) --port 4711 --program $(TEST_PROG)

debug: $(BINARY)
	./$(BINARY) --port $(PORT) --debug

server:
	$(MOCK_SERVER) --debug
