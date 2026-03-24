CC := gcc
CFLAGS := -Wall -Wextra -O2
TARGET := hello
SRC := hello.c
ARCH := $(shell uname -m | sed 's/aarch64/arm64/; s/x86_64/x86/')
CLANG := clang
BPFTOOL := bpftool
BPF_CFLAGS := -Wall -Wextra -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)
INCLUDES := -I/usr/include/$(shell uname -m)-linux-gnu
HELLO_TCP_BPF_OBJ := hello_tcp.bpf.o
HELLO_TCP_SKEL := hello_tcp.skel.h
HELLO_TCP_USER := hello_tcp_user

.PHONY: all run clean ebpf ebpf-run python-consumer

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

run: $(TARGET)
	./$(TARGET)

ebpf: $(HELLO_TCP_USER)

$(HELLO_TCP_BPF_OBJ): hello_tcp.bpf.c hello_tcp.h
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c hello_tcp.bpf.c -o $(HELLO_TCP_BPF_OBJ)

$(HELLO_TCP_SKEL): $(HELLO_TCP_BPF_OBJ)
	$(BPFTOOL) gen skeleton $(HELLO_TCP_BPF_OBJ) > $(HELLO_TCP_SKEL)

$(HELLO_TCP_USER): hello_tcp_user.c hello_tcp.h $(HELLO_TCP_SKEL)
	$(CC) $(CFLAGS) hello_tcp_user.c -o $(HELLO_TCP_USER) -lbpf -lelf -lz

ebpf-run: $(HELLO_TCP_USER)
	sudo ./$(HELLO_TCP_USER)

python-consumer:
	@if [ -x .venv/bin/python ]; then \
		.venv/bin/python tcp_http_consumer.py; \
	else \
		python3 tcp_http_consumer.py; \
	fi

clean:
	rm -f $(TARGET) $(HELLO_TCP_BPF_OBJ) $(HELLO_TCP_SKEL) $(HELLO_TCP_USER)