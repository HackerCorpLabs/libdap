"""DAP TCP connection with protocol framing.

Handles the Content-Length based framing and JSON message exchange
with a DAP server over TCP.
"""

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class DAPConnection:
    """Manages a TCP connection to a DAP server."""

    def __init__(self) -> None:
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._seq: int = 1
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._event_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._read_task: asyncio.Task[None] | None = None
        self.connected: bool = False

    async def connect(self, host: str, port: int, timeout: float = 5.0) -> None:
        """Connect to a DAP server."""
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        self.connected = True
        self._read_task = asyncio.create_task(self._read_loop())

    async def disconnect(self) -> None:
        """Disconnect from the DAP server."""
        if self._read_task:
            self._read_task.cancel()
            try:
                await self._read_task
            except asyncio.CancelledError:
                pass
            self._read_task = None

        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

        self.connected = False
        # Cancel any pending requests
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(ConnectionError("Disconnected"))
        self._pending.clear()

    async def send_request(
        self, command: str, arguments: dict[str, Any] | None = None, timeout: float = 30.0
    ) -> dict[str, Any]:
        """Send a DAP request and wait for the matching response."""
        if not self._writer or not self.connected:
            raise ConnectionError("Not connected to DAP server")

        seq = self._seq
        self._seq += 1

        msg: dict[str, Any] = {
            "seq": seq,
            "type": "request",
            "command": command,
        }
        if arguments:
            msg["arguments"] = arguments

        # Set up future for response
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending[seq] = fut

        # Send the framed message
        body = json.dumps(msg)
        frame = f"Content-Length: {len(body)}\r\n\r\n{body}"
        self._writer.write(frame.encode("utf-8"))
        await self._writer.drain()
        logger.debug("Sent: %s %s", command, arguments)

        try:
            response = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(seq, None)
            raise TimeoutError(f"Timeout waiting for response to {command}")
        return response

    async def wait_for_event(
        self, event_names: set[str], timeout: float = 30.0
    ) -> dict[str, Any]:
        """Wait for a specific event type. Returns the event body."""
        deadline = asyncio.get_event_loop().time() + timeout
        buffered_events: list[dict[str, Any]] = []

        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                # Put buffered events back
                for ev in buffered_events:
                    await self._event_queue.put(ev)
                return {
                    "event": "timeout",
                    "body": {"reason": "Program still running", "buffered_events": buffered_events},
                }
            try:
                event = await asyncio.wait_for(self._event_queue.get(), timeout=remaining)
            except asyncio.TimeoutError:
                for ev in buffered_events:
                    await self._event_queue.put(ev)
                return {
                    "event": "timeout",
                    "body": {"reason": "Program still running", "buffered_events": buffered_events},
                }

            if event.get("event") in event_names:
                event["buffered_events"] = buffered_events
                return event
            else:
                buffered_events.append(event)

    async def drain_events(self) -> list[dict[str, Any]]:
        """Drain all currently queued events."""
        events: list[dict[str, Any]] = []
        while not self._event_queue.empty():
            try:
                events.append(self._event_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return events

    async def _read_loop(self) -> None:
        """Continuously read DAP messages from the TCP connection."""
        assert self._reader is not None
        try:
            while True:
                msg = await self._read_message()
                if msg is None:
                    break
                msg_type = msg.get("type")

                if msg_type == "response":
                    request_seq = msg.get("request_seq")
                    fut = self._pending.pop(request_seq, None)
                    if fut and not fut.done():
                        fut.set_result(msg)
                    else:
                        logger.warning("Unmatched response for seq %s", request_seq)
                elif msg_type == "event":
                    await self._event_queue.put(msg)
                else:
                    logger.warning("Unknown message type: %s", msg_type)

        except asyncio.CancelledError:
            raise
        except (ConnectionError, asyncio.IncompleteReadError):
            logger.info("DAP connection closed")
        except Exception as exc:
            logger.error("Read loop error: %s", exc)
        finally:
            self.connected = False
            # Fail all pending requests
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(ConnectionError("Connection lost"))
            self._pending.clear()

    async def _read_message(self) -> dict[str, Any] | None:
        """Read a single DAP message (Content-Length framed)."""
        assert self._reader is not None

        # Read headers
        content_length = -1
        while True:
            line = await self._reader.readline()
            if not line:
                return None
            line_str = line.decode("utf-8").rstrip("\r\n")
            if line_str == "":
                break
            if line_str.lower().startswith("content-length:"):
                content_length = int(line_str.split(":", 1)[1].strip())

        if content_length < 0:
            return None

        # Read body
        body_bytes = await self._reader.readexactly(content_length)
        body_str = body_bytes.decode("utf-8")
        logger.debug("Received: %s", body_str[:200])
        return json.loads(body_str)
