################################################################################
# ND100X Debug Adapter Protocol (DAP) Implementation
# 
# Makefile for building the DAP client and mock debugger components
################################################################################

CC = gcc
AR = ar
CFLAGS = -Wall -Wextra -std=c99 -pedantic -I./include -I./libdap/include -I./libdap -I/usr/include/cjson -D_GNU_SOURCE -g -O0
LDFLAGS = -g -L$(LIB_DIR)
LIBS = -lm -l:libdap.a -lcjson

# Directories
SRC_DIR = src
LIBDAP_SRC_DIR = libdap/src
LIBDAP_INCLUDE_DIR = libdap/include
INCLUDE_DIR = include
OBJ_DIR = obj
BIN_DIR = bin
LIB_DIR = lib
TEST_DIR = tests

# Create directories if they don't exist
$(shell mkdir -p $(OBJ_DIR) $(BIN_DIR) $(LIB_DIR))

# Source files for libdap
LIBDAP_SOURCES = $(LIBDAP_SRC_DIR)/dap_protocol.c \
                 $(LIBDAP_SRC_DIR)/dap_server.c \
                 $(LIBDAP_SRC_DIR)/dap_error.c \
                 $(LIBDAP_SRC_DIR)/dap_transport.c \
                 $(LIBDAP_SRC_DIR)/dap_message.c \
				$(LIBDAP_SRC_DIR)/dap_client.c

LIBDAP_OBJECTS = $(patsubst $(LIBDAP_SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(LIBDAP_SRC_DIR)/%.c,$(LIBDAP_SOURCES)))

# Source files for mock debugger
MOCK_SRV_SRC_DIR = $(SRC_DIR)/dap_mock_server
MOCK_SRV_SOURCES = $(wildcard $(MOCK_SRV_SRC_DIR)/*.c)
MOCK_SRV_OBJECTS = $(patsubst $(MOCK_SRV_SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(MOCK_SRV_SOURCES))


# Source files for DAP debugger
DAP_DEBUGGER_SRC_DIR = $(SRC_DIR)/dap_debugger
DAP_DEBUGGER_SOURCES = $(wildcard $(DAP_DEBUGGER_SRC_DIR)/*.c)
DAP_DEBUGGER_OBJECTS = $(patsubst $(DAP_DEBUGGER_SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(DAP_DEBUGGER_SOURCES))

# Test files
TEST_SOURCES = $(wildcard $(TEST_DIR)/*.c)
TEST_OBJECTS = $(patsubst $(TEST_DIR)/%.c,$(OBJ_DIR)/%.o,$(TEST_SOURCES))
TEST_BINS = $(patsubst $(TEST_DIR)/%.c,$(BIN_DIR)/test_%,$(TEST_SOURCES))

# Default target
all: lib dap_debugger dap_mock_server

# Library target
lib: $(LIB_DIR)/libdap.a

$(LIB_DIR)/libdap.a: $(LIBDAP_OBJECTS)
	$(AR) rcs $@ $^

# DAP debugger executable
dap_debugger: $(BIN_DIR)/dap_debugger

$(BIN_DIR)/dap_debugger: $(DAP_DEBUGGER_OBJECTS) $(LIB_DIR)/libdap.a
	$(CC) $(LDFLAGS) -Isrc/dap_debugger -o $@ $^ $(LIBS)

# Compile libdap source files (must be first)
$(OBJ_DIR)/%.o: $(LIBDAP_SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile dap_debugger source files
$(OBJ_DIR)/%.o: $(DAP_DEBUGGER_SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Isrc/dap_debugger -c $< -o $@

# Compile dap_mock_server source files
$(OBJ_DIR)/%.o: $(MOCK_SRV_SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Isrc/dap_mock_server -c $< -o $@

# DAP mock server executable
dap_mock_server: $(BIN_DIR)/dap_mock_server

$(BIN_DIR)/dap_mock_server: $(MOCK_SRV_OBJECTS) $(LIB_DIR)/libdap.a
	$(CC) $(LDFLAGS) -Isrc/dap_mock_server -o $@ $^ $(LIBS)

# Clean
clean:
	rm -rf $(OBJ_DIR)/* $(BIN_DIR)/* $(LIB_DIR)/*

# Install
install: all
	mkdir -p $(DESTDIR)/usr/local/bin
	cp $(BIN_DIR)/dap_debugger $(BIN_DIR)/dap_mock_server $(DESTDIR)/usr/local/bin/
	mkdir -p $(DESTDIR)/usr/local/lib
	cp $(LIB_DIR)/libdap.a $(DESTDIR)/usr/local/lib/
	mkdir -p $(DESTDIR)/usr/local/include/libdap
	cp $(LIBDAP_INCLUDE_DIR)/*.h $(DESTDIR)/usr/local/include/libdap/

# Dependencies
-include $(LIBDAP_OBJECTS:.o=.d)
-include $(MOCK_OBJECTS:.o=.d)
-include $(DAP_DEBUGGER_OBJECTS:.o=.d)
-include $(TEST_OBJECTS:.o=.d)

# Generate dependencies
$(OBJ_DIR)/%.d: $(LIBDAP_SRC_DIR)/%.c
	@mkdir -p $(@D)
	@set -e; rm -f $@; \
	$(CC) -MM -MT $(@:.d=.o) $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

$(OBJ_DIR)/%.d: $(DAP_DEBUGGER_SRC_DIR)/%.c
	@mkdir -p $(@D)
	@set -e; rm -f $@; \
	$(CC) -MM -MT $(@:.d=.o) $(CFLAGS) -Isrc/dap_debugger $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

.PHONY: all clean install lib dap_debugger dap_mock_server