#!/usr/bin/env python3
import json
import os
import socket
import sys
from dataclasses import dataclass, field

try:
    import h11
except ModuleNotFoundError:
    print("missing dependency: h11 (install with: python3 -m pip install h11)", file=sys.stderr)
    sys.exit(1)

SOCKET_PATH = os.environ.get("HELLO_TCP_SOCKET_PATH", "/tmp/hello_tcp_events.sock")


@dataclass
class FlowState:
    request_parser: h11.Connection = field(default_factory=lambda: h11.Connection(h11.SERVER))
    response_parser: h11.Connection = field(default_factory=lambda: h11.Connection(h11.CLIENT))


flows: dict[tuple[int, str, int, str], FlowState] = {}


def flow_key(event: dict) -> tuple[int, str, int, str]:
    return (
        int(event.get("pid", 0)),
        str(event.get("dst", "unknown")),
        int(event.get("dport", 0)),
        str(event.get("comm", "unknown")),
    )


def decode_payload(event: dict) -> bytes:
    payload_hex = event.get("payload_hex", "")
    captured_len = int(event.get("captured_len", 0))
    if not payload_hex or captured_len <= 0:
        return b""
    try:
        data = bytes.fromhex(payload_hex)
    except ValueError:
        return b""
    return data[:captured_len]


def to_text(data: bytes) -> str:
    text = data.decode("latin-1", errors="replace")
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text


def print_event(prefix: str, event: object, key: tuple[int, str, int, str]) -> None:
    base = f"[{prefix}] pid={key[0]} comm={key[3]} dst={key[1]}:{key[2]}"
    if isinstance(event, h11.Request):
        method = event.method.decode("ascii", errors="replace")
        target = event.target.decode("ascii", errors="replace")
        print(f"{base} request {method} {target}")
        return
    if isinstance(event, h11.Response):
        print(f"{base} response {event.status_code} {event.reason.decode('latin-1', errors='replace')}")
        return
    if isinstance(event, h11.InformationalResponse):
        print(f"{base} informational {event.status_code}")
        return
    if isinstance(event, h11.Data):
        print(f"{base} body {to_text(event.data)}")
        return
    if isinstance(event, h11.EndOfMessage):
        print(f"{base} end-of-message")
        return
    if isinstance(event, h11.ConnectionClosed):
        print(f"{base} connection-closed")
        return


def feed_http(parser: h11.Connection, data: bytes, prefix: str, key: tuple[int, str, int, str]) -> None:
    if not data:
        return
    try:
        parser.receive_data(data)
    except h11.RemoteProtocolError:
        return

    while True:
        event = parser.next_event()
        if event is h11.NEED_DATA:
            break
        if event is h11.PAUSED:
            try:
                parser.start_next_cycle()
            except h11.LocalProtocolError:
                break
            continue
        print_event(prefix, event, key)
        if isinstance(event, h11.EndOfMessage):
            try:
                parser.start_next_cycle()
            except h11.LocalProtocolError:
                break


def handle_message(raw_line: bytes) -> None:
    try:
        event = json.loads(raw_line.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return

    event_type = int(event.get("type", 0))
    if event_type not in (3, 4):
        return

    payload = decode_payload(event)
    if not payload:
        return

    key = flow_key(event)
    state = flows.setdefault(key, FlowState())

    if event_type == 3:
        feed_http(state.request_parser, payload, "tx", key)
    elif event_type == 4:
        feed_http(state.response_parser, payload, "rx", key)


def serve() -> None:
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(1)
    print(f"listening on unix socket: {SOCKET_PATH}")

    try:
        while True:
            conn, _ = server.accept()
            print("collector connected")
            with conn:
                reader = conn.makefile("rb")
                while True:
                    line = reader.readline()
                    if not line:
                        print("collector disconnected")
                        break
                    handle_message(line)
    finally:
        server.close()
        try:
            os.unlink(SOCKET_PATH)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    serve()
