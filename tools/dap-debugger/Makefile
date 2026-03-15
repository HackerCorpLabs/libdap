BUILD_DIR = build
BINARY    = $(BUILD_DIR)/dap_gui_debugger
CMAKE     = cmake

# Mock server (built from root project)
ROOT_BUILD  = ../../build
MOCK_SERVER = $(ROOT_BUILD)/bin/dap_mock_server
TEST_PROG   = ../../tests/test_program.exe

HOST = localhost
PORT = 4711

.PHONY: all clean run server debug rebuild

all: $(BINARY)

$(BINARY): CMakeLists.txt $(wildcard src/*.cpp src/*.h src/ui/*.cpp src/ui/*.h)
	$(CMAKE) -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Debug
	$(CMAKE) --build $(BUILD_DIR) -j$$(nproc)

clean:
	rm -rf $(BUILD_DIR)

rebuild: clean all

run: $(BINARY)
	./$(BINARY) --port $(PORT) --program $(TEST_PROG)

debug: $(BINARY)
	./$(BINARY) --port $(PORT) --program $(TEST_PROG) --debug

server:
	$(MOCK_SERVER) --debug
