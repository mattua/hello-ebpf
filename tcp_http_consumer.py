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
FTP_CONTROL_PORT = 2121
FTP_DATA_PORT = 30000
CSV_HEADER = "cusip,datetime,recordid,transactionid,price,yield,spread"


@dataclass
class FlowState:
    request_parser: h11.Connection = field(default_factory=lambda: h11.Connection(h11.SERVER))
    response_parser: h11.Connection = field(default_factory=lambda: h11.Connection(h11.CLIENT))


flows: dict[tuple[int, str, int, str], FlowState] = {}
ftp_data_flows: dict[tuple[int, str, int, str], bytearray] = {}


def emit(line: str) -> None:
    print(line, flush=True)


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


def format_ftp_line(line: str) -> str:
    parts = line.split(" ", 1)
    keyword = parts[0].upper()
    remainder = parts[1] if len(parts) > 1 else ""

    if keyword.isdigit() and len(keyword) == 3:
        if keyword in {"125", "150", "226"}:
            return f"ftp transfer {keyword} {remainder}".rstrip()
        if keyword == "227":
            return f"ftp passive {keyword} {remainder}".rstrip()
        return f"ftp reply {keyword} {remainder}".rstrip()

    if keyword == "RETR":
        return f"ftp retrieve {remainder}".rstrip()
    if keyword == "USER":
        return f"ftp login-user {remainder}".rstrip()
    if keyword == "PASS":
        return f"ftp login-pass {remainder}".rstrip()
    if keyword == "PASV":
        return "ftp passive-request"
    if keyword == "TYPE":
        return f"ftp type {remainder}".rstrip()
    if keyword == "QUIT":
        return "ftp quit"

    return f"ftp command {line}"


def extract_csv_payload(text: str) -> str:
    header_index = text.find(CSV_HEADER)
    if header_index < 0:
        return text

    csv_text = text[header_index:]
    for marker in ("\r\n226 ", "\n226 ", "\r\n221 ", "\n221 "):
        marker_index = csv_text.find(marker)
        if marker_index >= 0:
            csv_text = csv_text[:marker_index]
            break

    return csv_text


def print_ftp_lines(prefix: str, payload: bytes, key: tuple[int, str, int, str]) -> None:
    base = f"[{prefix}] pid={key[0]} comm={key[3]} dst={key[1]}:{key[2]}"
    text = payload.decode("latin-1", errors="replace")
    for line in text.splitlines():
        if not line:
            continue
        emit(f"{base} {format_ftp_line(line)}")


def print_ftp_data(prefix: str, payload: bytes, key: tuple[int, str, int, str]) -> None:
    base = f"[{prefix}] pid={key[0]} comm={key[3]} dst={key[1]}:{key[2]}"
    combined = ftp_data_flows.setdefault(key, bytearray())
    combined.extend(payload)
    text = bytes(combined).decode("latin-1", errors="replace")
    if CSV_HEADER not in text:
        return
    csv_text = extract_csv_payload(text)
    emit(f"{base} ftp-data body\n{csv_text}")


def print_event(prefix: str, event: object, key: tuple[int, str, int, str]) -> None:
    base = f"[{prefix}] pid={key[0]} comm={key[3]} dst={key[1]}:{key[2]}"
    if isinstance(event, h11.Request):
        method = event.method.decode("ascii", errors="replace")
        target = event.target.decode("ascii", errors="replace")
        emit(f"{base} request {method} {target}")
        return
    if isinstance(event, h11.Response):
        emit(f"{base} response {event.status_code} {event.reason.decode('latin-1', errors='replace')}")
        return
    if isinstance(event, h11.InformationalResponse):
        emit(f"{base} informational {event.status_code}")
        return
    if isinstance(event, h11.Data):
        emit(f"{base} body {to_text(event.data)}")
        return
    if isinstance(event, h11.EndOfMessage):
        emit(f"{base} end-of-message")
        return
    if isinstance(event, h11.ConnectionClosed):
        emit(f"{base} connection-closed")
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
    if key[2] == FTP_CONTROL_PORT:
        if event_type == 3:
            print_ftp_lines("tx", payload, key)
        elif event_type == 4:
            print_ftp_lines("rx", payload, key)
        return

    if key[2] == FTP_DATA_PORT:
        if event_type == 4:
            print_ftp_data("rx", payload, key)
        return

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
    emit(f"listening on unix socket: {SOCKET_PATH}")

    try:
        while True:
            conn, _ = server.accept()
            emit("collector connected")
            with conn:
                reader = conn.makefile("rb")
                while True:
                    line = reader.readline()
                    if not line:
                        emit("collector disconnected")
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
