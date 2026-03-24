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

These `tcp_sendmsg`/`tcp_recvmsg` hooks are measurement only. They tell you send-request and receive-return byte counts, but do not yet copy or decode payload contents.

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
