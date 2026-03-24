# hello-ebpf setup log

This repository records the exact bootstrap steps used on my Raspberry Pi sandbox to:
1. compile a basic C hello-world program, and
2. prepare for future eBPF development.

Date: 2026-03-23

## Environment

- OS family: Debian-based Raspberry Pi Linux
- Workspace: `/home/mattua/hello-ebpf`
- Kernel (at setup time): `6.12.75+rpt-rpi-2712`

## 1) Verify/prepare minimum C toolchain

### Check existing tools

```bash
gcc --version | head -n 1
make --version | head -n 1
```

Observed:
- `gcc (Debian 14.2.0-19) 14.2.0`
- `GNU Make 4.4.1`

### (If missing) install minimum C build tools

```bash
sudo apt update
sudo apt install -y build-essential
```

## 2) Build and run C hello world

Create `hello.c`:

```c
#include <stdio.h>
int main(void) {
    puts("hello");
    return 0;
}
```

Compile and run:

```bash
gcc hello.c -o hello
./hello
ls -l hello hello.c
```

Observed:
- Program output: `hello`
- Binary created: `hello`

### Add a minimal Makefile

Create `Makefile`:

```make
CC := gcc
CFLAGS := -Wall -Wextra -O2
TARGET := hello
SRC := hello.c

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SRC)
    $(CC) $(CFLAGS) $(SRC) -o $(TARGET)

run: $(TARGET)
    ./$(TARGET)

clean:
    rm -f $(TARGET)
```

Use it:

```bash
make
make run
make clean
```

Observed:
- `make` builds `hello`
- `make run` prints `hello`
- `make clean` removes the binary

## 3) Install eBPF-compatible base dependencies

### Attempted package set

```bash
export DEBIAN_FRONTEND=noninteractive
sudo -n apt-get update
sudo -n apt-get install -y clang llvm libelf-dev libbpf-dev bpftool pkg-config raspberrypi-kernel-headers
```

Note: `raspberrypi-kernel-headers` was not available on this system.

### Detect correct kernel headers package

```bash
uname -r
apt-cache policy "linux-headers-$(uname -r)"
```

Observed:
- Kernel: `6.12.75+rpt-rpi-2712`
- Matching headers package available/installed: `linux-headers-6.12.75+rpt-rpi-2712`

### Install working eBPF userland package set

```bash
export DEBIAN_FRONTEND=noninteractive
sudo -n apt-get install -y clang llvm libelf-dev libbpf-dev bpftool pkg-config
```

Installed key packages:
- `clang` / `llvm`
- `libelf-dev`
- `libbpf-dev`
- `bpftool`
- `pkg-config`

## 4) Post-install verification

```bash
clang --version | head -n 1
bpftool version
pkg-config --modversion libbpf
dpkg -s "linux-headers-$(uname -r)" >/dev/null 2>&1 && echo installed
```

Observed:
- `clang=Debian clang version 19.1.7 (3+b1)`
- `bpftool=bpftool v7.5.0` (using libbpf v1.5)
- `libbpf=1.5.0`
- Kernel headers: `installed`

## 5) Quick re-bootstrap command block (copy/paste)

```bash
set -e
export DEBIAN_FRONTEND=noninteractive

# C basics
sudo apt-get update
sudo apt-get install -y build-essential

# eBPF-ready userland
sudo apt-get install -y clang llvm libelf-dev libbpf-dev bpftool pkg-config

# Ensure matching kernel headers
sudo apt-get install -y "linux-headers-$(uname -r)"
```

## 6) Repo state after setup

- `hello.c` (sample C program)
- `Makefile` (minimal build/run/clean flow)
- `hello` (compiled binary, recreated by `make`)
- `README.md` (this setup log)

## 7) Suggested next step for this repo

When ready, add:
- an initial eBPF skeleton example using `clang -target bpf` + `bpftool`/`libbpf`

## 8) First TCP-layer eBPF hello world

This repo now includes a minimal eBPF example that hooks TCP connect attempts, TCP send calls, and TCP receive returns.

Why this hook:
- It attaches to `tcp_v4_connect` and `tcp_v6_connect`.
- It also attaches to `tcp_sendmsg` to measure outgoing byte counts.
- It also attaches to `tcp_recvmsg` (return probe) to measure incoming byte counts.
- It does not depend on kernel BTF being exposed.
- It sends small events to user space with a ring buffer, so output appears directly in the terminal.

Files:
- `hello_tcp.bpf.c`: kernel-side eBPF program
- `hello_tcp_user.c`: user-space loader/reader using `libbpf`
- `hello_tcp.h`: shared event definition

### Build the eBPF example

```bash
make ebpf
```

Expected build artifacts:
- `hello_tcp.bpf.o`
- `hello_tcp.skel.h`
- `hello_tcp_user`

### Run it

```bash
sudo ./hello_tcp_user
```

Or:

```bash
make ebpf-run
```

The loader will wait for TCP connection attempts and print lines like:

```text
hello from eBPF: pid=1234 comm=curl dst=127.0.0.1:8080 hook=tcp_v4_connect
hello from eBPF: pid=1234 comm=curl hook=tcp_sendmsg bytes=78
hello from eBPF: pid=1234 comm=curl hook=tcp_recvmsg bytes=512
```

Observed on this Raspberry Pi during verification:

```text
listening for TCP connect events, press Ctrl+C to stop
hello from eBPF: pid=1683 comm=node dst=140.82.112.22:443 hook=tcp_v4_connect
hello from eBPF: pid=8683 comm=curl dst=127.0.0.1:18080 hook=tcp_v4_connect
hello from eBPF: pid=8683 comm=curl hook=tcp_sendmsg bytes=78
```

Note: background tools on the system, including the editor, may also create TCP events while the tracer is running.

The tracer currently reports:
- process ID
- process name
- destination IP address
- destination port
- IPv4 vs IPv6 connect hook
- requested byte count at `tcp_sendmsg`
- returned byte count at `tcp_recvmsg`
- captured payload bytes (up to 256 bytes per SEND/RECV event)

Payload capture is bounded (default 256 bytes) to keep ring buffer overhead predictable.

## 9) Python HTTP stream parser bridge

`hello_tcp_user` now forwards each event as JSON over a local Unix domain socket.

- Default socket path: `/tmp/hello_tcp_events.sock`
- Override with env var: `HELLO_TCP_SOCKET_PATH=/tmp/custom.sock`

### Install Python dependency

Recommended (local virtualenv):

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

If you use system Python on Debian/Raspberry Pi, `pip` may be blocked by PEP 668 unless you use a virtualenv.

### Run the parser and collector

Run these steps in order — the Python consumer must be started first so the Unix socket exists before the collector tries to connect.

**Step 1 — start the HTTP consumer** (Terminal 1):

```bash
make python-consumer
# or equivalently:
.venv/bin/python3 tcp_http_consumer.py
```

You should see:
```
listening on unix socket: /tmp/hello_tcp_events.sock
```

**Step 2 — start the eBPF collector** (Terminal 2, requires root):

```bash
sudo ./hello_tcp_user
```

You should see:
```
listening for TCP events, press Ctrl+C to stop
```

**Step 3 — start the bond price server** (Terminal 3):

```bash
make bond-server
```

You should see uvicorn start on `http://127.0.0.1:8080`.

**Step 4 — generate HTTP traffic** (Terminal 4):

```bash
curl -s http://127.0.0.1:8080/prices | python3 -m json.tool
```

Parsed HTTP request/response events will appear in the Python consumer terminal (Terminal 1), for example:

```
[tx] pid=1234 comm=curl dst=127.0.0.1:8080 request GET /prices
[tx] pid=1234 comm=curl dst=127.0.0.1:8080 end-of-message
[rx] pid=1234 comm=curl dst=127.0.0.1:8080 response 200 OK
[rx] pid=1234 comm=curl dst=127.0.0.1:8080 body [{"cusip": ...}]
[rx] pid=1234 comm=curl dst=127.0.0.1:8080 end-of-message
```

Notes:
- HTTP parsing is best-effort from sampled payload slices.
- HTTPS traffic is encrypted and will not decode into HTTP text.

## 10) Simple FTP control-channel demo

You can also demonstrate the same eBPF -> C collector -> Python consumer flow with a plain FTP server.

Install dependency with the same virtualenv step above:

```bash
.venv/bin/pip install -r requirements.txt
```

The BPF allowlist now captures localhost traffic to both `127.0.0.1:8080` and `127.0.0.1:2121`.

### Run the FTP flow

**Step 1 — start the Python consumer** (Terminal 1):

```bash
make python-consumer
```

**Step 2 — start the eBPF collector** (Terminal 2):

```bash
sudo ./hello_tcp_user
```

**Step 3 — start the FTP server** (Terminal 3):

```bash
make ftp-server
```

By default it exposes only one file:
- `ACME_EOD_BondPrices.csv`

Default credentials:
- user: `bonduser`
- password: `bondpass`

**Step 4 — generate FTP traffic** (Terminal 4):

```bash
curl --user bonduser:bondpass ftp://127.0.0.1:2121/ACME_EOD_BondPrices.csv
```

That single client command logs in, opens the FTP data connection, retrieves the CSV, and prints it to stdout.

The FTP server uses a single fixed passive data port so the eBPF tracer can capture both:
- FTP control channel on `127.0.0.1:2121`
- FTP data channel on `127.0.0.1:30000`

If you want to see the directory listing first, use:

```bash
python3 -c "from ftplib import FTP; ftp = FTP(); ftp.connect('127.0.0.1', 2121); ftp.login('bonduser', 'bondpass'); print(ftp.nlst()); ftp.quit()"
```

The Python consumer will print FTP control-channel messages such as:

```text
[rx] pid=1234 comm=curl dst=127.0.0.1:2121 ftp reply 220 hello-ebpf FTP server ready
[tx] pid=1234 comm=curl dst=127.0.0.1:2121 ftp login-user bonduser
[rx] pid=1234 comm=curl dst=127.0.0.1:2121 ftp reply 331 Username ok, send password.
[tx] pid=1234 comm=curl dst=127.0.0.1:2121 ftp login-pass bondpass
[rx] pid=1234 comm=curl dst=127.0.0.1:2121 ftp reply 230 Login successful.
[tx] pid=1234 comm=curl dst=127.0.0.1:2121 ftp passive-request
[rx] pid=1234 comm=curl dst=127.0.0.1:2121 ftp passive 227 Entering passive mode (...)
[tx] pid=1234 comm=curl dst=127.0.0.1:2121 ftp retrieve ACME_EOD_BondPrices.csv
[rx] pid=1234 comm=curl dst=127.0.0.1:30000 ftp-data body cusip,datetime,recordid,transactionid,price,yield,spread
```

For the `curl` retrieval, a typical FTP control-channel exchange looks like:

```text
[rx] ... ftp reply 220 hello-ebpf FTP server ready
[tx] ... ftp login-user bonduser
[rx] ... ftp reply 331 Username ok, send password.
[tx] ... ftp login-pass bondpass
[rx] ... ftp reply 230 Login successful.
[tx] ... ftp type I
[rx] ... ftp reply 200 Type set to: Binary.
[tx] ... ftp passive-request
[rx] ... ftp passive 227 Entering passive mode (...)
[tx] ... ftp retrieve ACME_EOD_BondPrices.csv
[rx] ... ftp transfer 125 Data connection already open. Transfer starting.
[rx] ... ftp transfer 226 Transfer complete.
[rx] ... ftp-data body cusip,datetime,recordid,transactionid,price,yield,spread
```

Note:
- This FTP demo captures both the plaintext control channel on port `2121` and the CSV file payload on passive data port `30000`.
- The Python consumer prints the full CSV payload captured from the FTP data connection.

### Destination allowlist (current behavior)

Logging is restricted to destination pairs listed in `destination_allowlist` in `hello_tcp.bpf.c`.

Current starter values:
- `127.0.0.1:8080`
- `127.0.0.1:2121`
- `127.0.0.1:30000`

Example edit (host-order values in the list):

```c
static const struct hello_tcp_filter_v4 destination_allowlist[] = {
    { .daddr_v4_host = 0x7f000001U, .dport_host = 8080 },
};
```

Only connections that match this list will emit connect/send/recv events.

### Trigger some TCP traffic

In another terminal, create a local TCP connection:

```bash
python3 -m http.server 8080
curl http://127.0.0.1:8080
```

Or generate outbound traffic:

```bash
curl http://example.com
```

### Stop it

Press `Ctrl+C` in the loader terminal.
