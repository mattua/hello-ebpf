#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "hello_tcp.h"

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, unsigned long long);
    __type(value, struct hello_tcp_conn_v4);
} allowed_tasks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, unsigned long long);
    __type(value, struct hello_tcp_pending_recv);
} pending_recvs SEC(".maps");

struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    unsigned long long unused;
    long id;
    long ret;
};

static const struct hello_tcp_filter_v4 destination_allowlist[] = {
    { .daddr_v4_host = 0x7f000001U, .dport_host = 8080 },
};

static __always_inline int is_allowed_v4(unsigned int daddr_v4_host, unsigned short dport_host)
{
    int index;

#pragma clang loop unroll(full)
    for (index = 0; index < HELLO_TCP_FILTER_MAX; index++) {
        if (index >= (int)(sizeof(destination_allowlist) / sizeof(destination_allowlist[0]))) {
            break;
        }
        if (destination_allowlist[index].daddr_v4_host == daddr_v4_host &&
            destination_allowlist[index].dport_host == dport_host) {
            return 1;
        }
    }

    return 0;
}

static __always_inline void set_task_allowed(unsigned long long pid_tgid, const struct hello_tcp_conn_v4 *connection)
{
    if (connection) {
        bpf_map_update_elem(&allowed_tasks, &pid_tgid, connection, BPF_ANY);
        return;
    }

    bpf_map_delete_elem(&allowed_tasks, &pid_tgid);
}

static __always_inline const struct hello_tcp_conn_v4 *task_connection(unsigned long long pid_tgid)
{
    return bpf_map_lookup_elem(&allowed_tasks, &pid_tgid);
}

static __always_inline int submit_send_event(unsigned long long pid_tgid, const unsigned char *buffer, unsigned int bytes)
{
    struct hello_tcp_event *event;
    const struct hello_tcp_conn_v4 *connection;
    unsigned int captured_len;

    connection = task_connection(pid_tgid);
    if (!connection || !buffer || bytes == 0) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->pid = pid_tgid >> 32;
    event->type = HELLO_TCP_EVENT_SEND;
    event->bytes = bytes;
    event->dport = connection->dport;
    event->daddr_v4 = connection->daddr_v4;
    event->captured_len = 0;
    event->reserved = 0;
    captured_len = bytes;
    if (captured_len > HELLO_TCP_PAYLOAD_MAX) {
        captured_len = HELLO_TCP_PAYLOAD_MAX;
    }
    if (bpf_probe_read_user(event->payload, captured_len, buffer) < 0) {
        captured_len = 0;
    }
    event->captured_len = captured_len;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);

    return 0;
}

static __always_inline int submit_recv_event(unsigned long long pid_tgid, const unsigned char *buffer, unsigned int bytes, unsigned int requested)
{
    struct hello_tcp_event *event;
    const struct hello_tcp_conn_v4 *connection;
    unsigned int captured_len;

    connection = task_connection(pid_tgid);
    if (!connection || !buffer || bytes == 0) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->pid = pid_tgid >> 32;
    event->type = HELLO_TCP_EVENT_RECV;
    event->bytes = bytes;
    event->dport = connection->dport;
    event->daddr_v4 = connection->daddr_v4;
    event->captured_len = 0;
    event->reserved = 0;
    captured_len = bytes;
    if (captured_len > requested) {
        captured_len = requested;
    }
    if (captured_len > HELLO_TCP_PAYLOAD_MAX) {
        captured_len = HELLO_TCP_PAYLOAD_MAX;
    }
    if (bpf_probe_read_user(event->payload, captured_len, buffer) < 0) {
        captured_len = 0;
    }
    event->captured_len = captured_len;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);

    return 0;
}

static __always_inline int submit_event_v4(const void *uaddr)
{
    struct hello_tcp_event *event;
    struct hello_tcp_conn_v4 connection = {};
    struct sockaddr_in dest = {};
    unsigned long long pid_tgid;
    unsigned short dport_host;
    unsigned int daddr_v4_host;

    if (bpf_probe_read_kernel(&dest, sizeof(dest), uaddr) < 0) {
        return 0;
    }

    if (dest.sin_family != AF_INET) {
        return 0;
    }

    dport_host = bpf_ntohs(dest.sin_port);
    daddr_v4_host = bpf_ntohl(dest.sin_addr.s_addr);

    pid_tgid = bpf_get_current_pid_tgid();
    if (!is_allowed_v4(daddr_v4_host, dport_host)) {
        set_task_allowed(pid_tgid, 0);
        return 0;
    }

    connection.daddr_v4 = dest.sin_addr.s_addr;
    connection.dport = dest.sin_port;
    set_task_allowed(pid_tgid, &connection);

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->pid = pid_tgid >> 32;
    event->type = HELLO_TCP_EVENT_V4;
    event->dport = dest.sin_port;
    event->daddr_v4 = dest.sin_addr.s_addr;
    event->bytes = 0;
    event->captured_len = 0;
    event->reserved = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);

    return 0;
}

static __always_inline int submit_event_v6(const void *uaddr)
{
    unsigned long long pid_tgid;

    (void)uaddr;
    pid_tgid = bpf_get_current_pid_tgid();
    set_task_allowed(pid_tgid, 0);

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_v4_connect, void *sk, const struct sockaddr *uaddr)
{
    (void)ctx;
    (void)sk;

    return submit_event_v4(uaddr);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(handle_tcp_v6_connect, void *sk, const struct sockaddr *uaddr)
{
    (void)ctx;
    (void)sk;

    return submit_event_v6(uaddr);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long long pid_tgid;
    const unsigned char *buffer;
    unsigned int size;

    pid_tgid = bpf_get_current_pid_tgid();
    if (!task_connection(pid_tgid)) {
        return 0;
    }

    buffer = (const unsigned char *)(unsigned long)ctx->args[1];
    size = (unsigned int)ctx->args[2];
    return submit_send_event(pid_tgid, buffer, size);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int handle_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
    struct hello_tcp_pending_recv pending = {};
    unsigned long long pid_tgid;

    pid_tgid = bpf_get_current_pid_tgid();
    if (!task_connection(pid_tgid)) {
        return 0;
    }

    pending.user_buffer = (unsigned long long)ctx->args[1];
    pending.requested_len = (unsigned int)ctx->args[2];
    bpf_map_update_elem(&pending_recvs, &pid_tgid, &pending, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int handle_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx)
{
    const struct hello_tcp_pending_recv *pending;
    unsigned long long pid_tgid;

    if (ctx->ret <= 0) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    pending = bpf_map_lookup_elem(&pending_recvs, &pid_tgid);
    if (!pending) {
        return 0;
    }

    submit_recv_event(pid_tgid,
        (const unsigned char *)(unsigned long)pending->user_buffer,
        (unsigned int)ctx->ret,
        pending->requested_len);
    bpf_map_delete_elem(&pending_recvs, &pid_tgid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";