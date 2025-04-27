# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -I./include -I/usr/include/cjson
AR = ar
ARFLAGS = rcs

# Directories
SRC_DIR = src
OBJ_DIR = obj
LIB_DIR = lib
INC_DIR = include
TEST_DIR = tests

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))

# Library name
LIB_NAME = libdap.a
TARGET = $(LIB_DIR)/$(LIB_NAME)

# Default target
all: directories $(TARGET)

# Create necessary directories
directories:
	@mkdir -p $(OBJ_DIR) $(LIB_DIR)

# Build the static library
$(TARGET): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | directories
	$(CC) $(CFLAGS) -c $< -o $@

# Build and run tests
test: all
	$(MAKE) -C $(TEST_DIR) test

# Run tests with Valgrind
test-valgrind: all
	$(MAKE) -C $(TEST_DIR) test-valgrind

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(LIB_DIR)
	$(MAKE) -C $(TEST_DIR) clean

# Install headers
install-headers:
	@mkdir -p $(INC_DIR)
	cp -r include/* $(INC_DIR)/

.PHONY: all clean directories install-headers test test-valgrind 