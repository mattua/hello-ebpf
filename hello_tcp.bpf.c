#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

static __always_inline int submit_event_v4(const void *uaddr)
{
    struct hello_tcp_event *event;
    struct sockaddr_in dest = {};
    unsigned long long pid_tgid;

    if (bpf_probe_read_kernel(&dest, sizeof(dest), uaddr) < 0) {
        return 0;
    }

    if (dest.sin_family != AF_INET) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->type = HELLO_TCP_EVENT_V4;
    event->dport = dest.sin_port;
    event->daddr_v4 = dest.sin_addr.s_addr;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);

    return 0;
}

static __always_inline int submit_event_v6(const void *uaddr)
{
    struct hello_tcp_event *event;
    struct sockaddr_in6 dest = {};
    unsigned long long pid_tgid;

    if (bpf_probe_read_kernel(&dest, sizeof(dest), uaddr) < 0) {
        return 0;
    }

    if (dest.sin6_family != AF_INET6) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->type = HELLO_TCP_EVENT_V6;
    event->dport = dest.sin6_port;
    __builtin_memcpy(event->daddr_v6, &dest.sin6_addr.in6_u.u6_addr8, sizeof(event->daddr_v6));
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);

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

char LICENSE[] SEC("license") = "GPL";