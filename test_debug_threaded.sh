#!/bin/bash
# Start nd100x emulator and launch dap_debugger_threaded for manual testing
# of the C hello program with full source-level debugging.
#
# Uses the multi-threaded debugger client (separate DAP I/O and UI threads).
#
# Usage: ./test_debug_threaded.sh
#        ./test_debug_threaded.sh --no-client   # start only nd100x, no debugger client

set -e

ND100X=~/repos/nd100x/build/bin/nd100x
DAP_DEBUGGER=~/repos/libdap/build/bin/dap_debugger_threaded
SOURCE=~/repos/ndasm/c/hello.c
PORT=4711

# Check binaries exist
if [ ! -x "$ND100X" ]; then
    echo "ERROR: nd100x not found at $ND100X"
    echo "Build it: cd ~/repos/nd100x && cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build"
    exit 1
fi

if [ ! -x "$DAP_DEBUGGER" ]; then
    echo "ERROR: dap_debugger_threaded not found at $DAP_DEBUGGER"
    echo "Build it: cd ~/repos/libdap && make debug"
    exit 1
fi

if [ ! -f "$SOURCE" ]; then
    echo "ERROR: Source file not found at $SOURCE"
    echo "Build it: cd ~/repos/ndasm/c && make"
    exit 1
fi

# Kill any existing nd100x
if pgrep -x nd100x > /dev/null 2>&1; then
    echo "Killing existing nd100x..."
    kill $(pgrep -x nd100x) 2>/dev/null
    sleep 1
fi

# Start nd100x in background
echo "Starting nd100x emulator (DAP server on port $PORT)..."
$ND100X --debugger > /tmp/nd100x_test.log 2>&1 &
ND100X_PID=$!
echo "nd100x PID: $ND100X_PID"

# Wait for DAP server to be ready (check log output instead of connecting)
DAP_READY=0
for i in $(seq 1 20); do
    if grep -q "DAP Debugger enabled" /tmp/nd100x_test.log 2>/dev/null; then
        echo "DAP server ready on port $PORT"
        DAP_READY=1
        break
    fi
    if ! kill -0 $ND100X_PID 2>/dev/null; then
        echo "ERROR: nd100x exited unexpectedly. Log:"
        cat /tmp/nd100x_test.log
        exit 1
    fi
    sleep 0.25
done

if [ "$DAP_READY" -eq 0 ]; then
    echo "ERROR: DAP server not ready after 5s. Log:"
    cat /tmp/nd100x_test.log
    kill $ND100X_PID 2>/dev/null
    exit 1
fi

# Cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down nd100x (PID $ND100X_PID)..."
    kill $ND100X_PID 2>/dev/null
    wait $ND100X_PID 2>/dev/null
    echo "Done."
}
trap cleanup EXIT

if [ "$1" = "--no-client" ]; then
    echo ""
    echo "nd100x running. Connect manually with:"
    echo "  $DAP_DEBUGGER $SOURCE -e -d"
    echo ""
    echo "Or use MCP tools (debug_connect, debug_launch, etc.)"
    echo "Press Ctrl+C to stop."
    wait $ND100X_PID
else
    echo ""
    echo "Launching dap_debugger_threaded..."
    echo ""
    $DAP_DEBUGGER "$SOURCE" -e -d || true
fi
