#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "hello_tcp.h"
#include "hello_tcp.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int signo)
{
    (void)signo;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct hello_tcp_event *event = data;
    char address[INET6_ADDRSTRLEN] = "unknown";
    const char *family = "unknown";
    unsigned short dport;

    (void)ctx;

    if (data_sz < sizeof(*event)) {
        fprintf(stderr, "short event: %zu bytes\n", data_sz);
        return 0;
    }

    if (event->type == HELLO_TCP_EVENT_SEND) {
        printf("hello from eBPF: pid=%u comm=%s hook=tcp_sendmsg bytes=%u\n",
            event->pid,
            event->comm,
            event->bytes);
        fflush(stdout);
        return 0;
    }

    if (event->type == HELLO_TCP_EVENT_RECV) {
        printf("hello from eBPF: pid=%u comm=%s hook=tcp_recvmsg bytes=%u\n",
            event->pid,
            event->comm,
            event->bytes);
        fflush(stdout);
        return 0;
    }

    if (event->type == HELLO_TCP_EVENT_V4) {
        family = "tcp_v4_connect";
        if (!inet_ntop(AF_INET, &event->daddr_v4, address, sizeof(address))) {
            strncpy(address, "invalid-v4", sizeof(address));
            address[sizeof(address) - 1] = '\0';
        }
    } else if (event->type == HELLO_TCP_EVENT_V6) {
        family = "tcp_v6_connect";
        if (!inet_ntop(AF_INET6, event->daddr_v6, address, sizeof(address))) {
            strncpy(address, "invalid-v6", sizeof(address));
            address[sizeof(address) - 1] = '\0';
        }
    }

    dport = ntohs(event->dport);

    printf("hello from eBPF: pid=%u comm=%s dst=%s:%u hook=%s\n",
        event->pid,
        event->comm,
        address,
        dport,
        family);
    fflush(stdout);
    return 0;
}

int main(void)
{
    struct ring_buffer *ring_buffer = NULL;
    struct hello_tcp_bpf *skeleton = NULL;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skeleton = hello_tcp_bpf__open_and_load();
    if (!skeleton) {
        fprintf(stderr, "failed to open and load BPF skeleton\n");
        return 1;
    }

    err = hello_tcp_bpf__attach(skeleton);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs: %d\n", err);
        hello_tcp_bpf__destroy(skeleton);
        return 1;
    }

    ring_buffer = ring_buffer__new(bpf_map__fd(skeleton->maps.events), handle_event, NULL, NULL);
    if (!ring_buffer) {
        fprintf(stderr, "failed to create ring buffer\n");
        hello_tcp_bpf__destroy(skeleton);
        return 1;
    }

    printf("listening for TCP connect events, press Ctrl+C to stop\n");

    while (!stop) {
        err = ring_buffer__poll(ring_buffer, 250);
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
            ring_buffer__free(ring_buffer);
            hello_tcp_bpf__destroy(skeleton);
            return 1;
        }
    }

    ring_buffer__free(ring_buffer);
    hello_tcp_bpf__destroy(skeleton);
    return 0;
}