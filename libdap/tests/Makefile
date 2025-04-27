# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -I../include
LDFLAGS = -L../lib -ldap

# Test programs
TESTS = test_breakpoint test_suite
OBJS = $(TESTS:%=%.o)

# Default target
all: $(TESTS)

# Build test programs
test_breakpoint: test_breakpoint.o ../lib/libdap.a
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_suite: test_suite.o ../lib/libdap.a
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Compile test sources
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Run all tests
test: all
	@for t in $(TESTS); do \
		echo "Running $$t..."; \
		./$$t || exit 1; \
	done

# Run tests with Valgrind
test-valgrind: all
	@for t in $(TESTS); do \
		echo "Running $$t with Valgrind..."; \
		valgrind --leak-check=full \
		         --show-leak-kinds=all \
		         --track-origins=yes \
		         --error-exitcode=1 \
		         ./$$t || exit 1; \
	done

# Clean build artifacts
clean:
	rm -f $(TESTS) $(OBJS)

.PHONY: all clean test test-valgrind 