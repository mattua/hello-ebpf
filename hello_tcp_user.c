#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "hello_tcp.h"
#include "hello_tcp.skel.h"

static volatile sig_atomic_t stop;
static int ipc_fd = -1;

static const char *socket_path(void)
{
    const char *path = getenv("HELLO_TCP_SOCKET_PATH");

    if (path && path[0] != '\0') {
        return path;
    }

    return "/tmp/hello_tcp_events.sock";
}

static void close_ipc(void)
{
    if (ipc_fd >= 0) {
        close(ipc_fd);
        ipc_fd = -1;
    }
}

static int connect_ipc(void)
{
    struct sockaddr_un address = {};
    const char *path = socket_path();
    size_t path_len;

    if (ipc_fd >= 0) {
        return 0;
    }

    path_len = strlen(path);
    if (path_len >= sizeof(address.sun_path)) {
        return -ENAMETOOLONG;
    }

    ipc_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ipc_fd < 0) {
        return -errno;
    }

    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, path_len + 1);

    if (connect(ipc_fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
        int saved_errno = errno;
        close_ipc();
        return -saved_errno;
    }

    return 0;
}

static void sanitize_text(const char *input, size_t input_size, char *output, size_t output_size)
{
    size_t index;
    size_t written = 0;

    if (output_size == 0) {
        return;
    }

    for (index = 0; index < input_size && input[index] != '\0'; index++) {
        unsigned char character = (unsigned char)input[index];

        if (written + 1 >= output_size) {
            break;
        }
        if (character < 32 || character == '\\' || character == '"') {
            output[written++] = '_';
            continue;
        }
        output[written++] = (char)character;
    }

    output[written] = '\0';
}

static void payload_to_hex(const unsigned char *payload, unsigned int captured_len, char *hex, size_t hex_size)
{
    static const char digits[] = "0123456789abcdef";
    size_t index;
    size_t needed;

    if (hex_size == 0) {
        return;
    }

    needed = (size_t)captured_len * 2 + 1;
    if (needed > hex_size) {
        captured_len = (unsigned int)((hex_size - 1) / 2);
    }

    for (index = 0; index < captured_len; index++) {
        unsigned char value = payload[index];
        hex[index * 2] = digits[value >> 4];
        hex[index * 2 + 1] = digits[value & 0x0f];
    }

    hex[captured_len * 2] = '\0';
}

static void emit_json_event(const struct hello_tcp_event *event, const char *hook, const char *address)
{
    char payload_hex[HELLO_TCP_PAYLOAD_MAX * 2 + 1];
    char comm_sanitized[TASK_COMM_LEN + 1];
    char json[2048];
    unsigned short dport = ntohs(event->dport);
    ssize_t sent;
    int err;

    sanitize_text(event->comm, sizeof(event->comm), comm_sanitized, sizeof(comm_sanitized));
    payload_to_hex(event->payload, event->captured_len, payload_hex, sizeof(payload_hex));

    snprintf(json,
        sizeof(json),
        "{\"pid\":%u,\"comm\":\"%s\",\"type\":%u,\"hook\":\"%s\",\"dst\":\"%s\",\"dport\":%u,\"bytes\":%u,\"captured_len\":%u,\"payload_hex\":\"%s\"}\n",
        event->pid,
        comm_sanitized,
        event->type,
        hook,
        address,
        dport,
        event->bytes,
        event->captured_len,
        payload_hex);

    err = connect_ipc();
    if (err < 0) {
        return;
    }

    sent = send(ipc_fd, json, strlen(json), MSG_NOSIGNAL);
    if (sent < 0) {
        close_ipc();
    }
}

static void handle_signal(int signo)
{
    (void)signo;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct hello_tcp_event *event = data;
    char address[INET6_ADDRSTRLEN] = "unknown";
    const char *hook = "unknown";
    unsigned short dport;

    (void)ctx;

    if (data_sz < sizeof(*event)) {
        fprintf(stderr, "short event: %zu bytes\n", data_sz);
        return 0;
    }

    if (event->type == HELLO_TCP_EVENT_SEND) {
        hook = "tcp_send_payload";
        if (!inet_ntop(AF_INET, &event->daddr_v4, address, sizeof(address))) {
            strncpy(address, "invalid-v4", sizeof(address));
            address[sizeof(address) - 1] = '\0';
        }
        printf("hello from eBPF: pid=%u comm=%s hook=%s dst=%s:%u bytes=%u captured=%u\n",
            event->pid,
            event->comm,
            hook,
            address,
            ntohs(event->dport),
            event->bytes,
            event->captured_len);
        emit_json_event(event, hook, address);
        fflush(stdout);
        return 0;
    }

    if (event->type == HELLO_TCP_EVENT_RECV) {
        hook = "tcp_recv_payload";
        if (!inet_ntop(AF_INET, &event->daddr_v4, address, sizeof(address))) {
            strncpy(address, "invalid-v4", sizeof(address));
            address[sizeof(address) - 1] = '\0';
        }
        printf("hello from eBPF: pid=%u comm=%s hook=%s dst=%s:%u bytes=%u captured=%u\n",
            event->pid,
            event->comm,
            hook,
            address,
            ntohs(event->dport),
            event->bytes,
            event->captured_len);
        emit_json_event(event, hook, address);
        fflush(stdout);
        return 0;
    }

    if (event->type == HELLO_TCP_EVENT_V4) {
        hook = "tcp_v4_connect";
        if (!inet_ntop(AF_INET, &event->daddr_v4, address, sizeof(address))) {
            strncpy(address, "invalid-v4", sizeof(address));
            address[sizeof(address) - 1] = '\0';
        }
    } else if (event->type == HELLO_TCP_EVENT_V6) {
        hook = "tcp_v6_connect";
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
        hook);
    emit_json_event(event, hook, address);
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

    printf("listening for TCP events, press Ctrl+C to stop\n");

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
    close_ipc();
    return 0;
}