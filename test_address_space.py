#!/usr/bin/env python3
"""End-to-end test for DAP address_space prefix on memoryReference.

Spawns dap_mock_server on a TCP port, sends initialize + readMemory /
writeMemory requests with and without the "phys:" prefix, and verifies
that:

  - virtual reads return the virtual mock memory ("HELLO WORLD" at 0x1000)
  - physical reads return the physical mock memory ("PHYSICAL" at 0x1000)
  - virtual / physical writes land in the correct space and round-trip

Run with libdap built (cmake --build build).
"""

import base64
import json
import os
import socket
import struct
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
MOCK = os.path.join(ROOT, "build", "bin", "dap_mock_server")
PORT = 47119
HOST = "127.0.0.1"

if not os.path.isfile(MOCK):
    print("ERROR: build mock server first (cmake --build build)", file=sys.stderr)
    sys.exit(2)


def recv_message(sock):
    """Read one DAP message (Content-Length framed) from a TCP socket."""
    header = b""
    while b"\r\n\r\n" not in header:
        chunk = sock.recv(1)
        if not chunk:
            raise RuntimeError("server closed")
        header += chunk
    headers, _, rest = header.partition(b"\r\n\r\n")
    length = 0
    for line in headers.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    body = rest
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise RuntimeError("server closed mid-body")
        body += chunk
    return json.loads(body.decode("utf-8"))


def send(sock, seq, command, args):
    msg = {"seq": seq, "type": "request", "command": command, "arguments": args}
    body = json.dumps(msg).encode("utf-8")
    sock.sendall(b"Content-Length: %d\r\n\r\n" % len(body) + body)


def wait_response(sock, seq, command, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = recv_message(sock)
        if msg.get("type") == "response" and msg.get("request_seq") == seq and msg.get("command") == command:
            return msg
        # ignore events / outputs
    raise TimeoutError(f"no response for {command}")


def main():
    proc = subprocess.Popen([MOCK, "-p", str(PORT)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # wait for listen
        for _ in range(50):
            try:
                sock = socket.create_connection((HOST, PORT), timeout=1.0)
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("mock server never opened port")

        seq = 1
        send(sock, seq, "initialize", {"clientID": "test", "adapterID": "mock"})
        wait_response(sock, seq, "initialize"); seq += 1

        # 1. virtual read at 0x1000 should yield "HELLO WORLD"
        send(sock, seq, "readMemory", {"memoryReference": "0x1000", "count": 11})
        r = wait_response(sock, seq, "readMemory"); seq += 1
        assert r["success"], f"virtual read failed: {r}"
        data = base64.b64decode(r["body"]["data"])
        assert data.startswith(b"HELLO WORLD"), f"got {data!r}"
        print("OK: virtual read returns HELLO WORLD")

        # 2. physical read at phys:0x1000 should yield "PHYSICAL"
        send(sock, seq, "readMemory", {"memoryReference": "phys:0x1000", "count": 8})
        r = wait_response(sock, seq, "readMemory"); seq += 1
        assert r["success"], f"physical read failed: {r}"
        addr_str = r["body"]["address"]
        assert addr_str.startswith("phys:"), f"address not re-prefixed: {addr_str}"
        data = base64.b64decode(r["body"]["data"])
        assert data == b"PHYSICAL", f"got {data!r}"
        print("OK: physical read returns PHYSICAL, address tag = " + addr_str)

        # 3. P: short prefix also works
        send(sock, seq, "readMemory", {"memoryReference": "P:0x1000", "count": 8})
        r = wait_response(sock, seq, "readMemory"); seq += 1
        data = base64.b64decode(r["body"]["data"])
        assert data == b"PHYSICAL"
        print("OK: P: short prefix recognized")

        # 4. write physical, read it back
        payload = base64.b64encode(b"ZZZZ").decode()
        send(sock, seq, "writeMemory",
             {"memoryReference": "phys:0x2000", "data": payload})
        r = wait_response(sock, seq, "writeMemory"); seq += 1
        assert r["success"], f"phys write failed: {r}"

        send(sock, seq, "readMemory", {"memoryReference": "phys:0x2000", "count": 4})
        r = wait_response(sock, seq, "readMemory"); seq += 1
        data = base64.b64decode(r["body"]["data"])
        assert data == b"ZZZZ", f"got {data!r}"
        print("OK: physical write/read round-trip")

        # 5. confirm virtual at same address is unchanged
        send(sock, seq, "readMemory", {"memoryReference": "0x2000", "count": 4})
        r = wait_response(sock, seq, "readMemory"); seq += 1
        data = base64.b64decode(r["body"]["data"])
        assert data != b"ZZZZ", "virtual was clobbered by physical write!"
        print("OK: virtual address space is isolated from physical")

        sock.close()
        print("\nAll address-space tests passed.")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
