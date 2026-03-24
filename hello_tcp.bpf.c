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
    __type(value, unsigned char);
} allowed_tasks SEC(".maps");

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

static __always_inline void set_task_allowed(unsigned long long pid_tgid, int allowed)
{
    unsigned char value = 1;

    if (allowed) {
        bpf_map_update_elem(&allowed_tasks, &pid_tgid, &value, BPF_ANY);
        return;
    }

    bpf_map_delete_elem(&allowed_tasks, &pid_tgid);
}

static __always_inline int task_is_allowed(unsigned long long pid_tgid)
{
    return bpf_map_lookup_elem(&allowed_tasks, &pid_tgid) != 0;
}

static __always_inline int submit_send_event(unsigned int bytes)
{
    struct hello_tcp_event *event;
    unsigned long long pid_tgid;

    pid_tgid = bpf_get_current_pid_tgid();
    if (!task_is_allowed(pid_tgid)) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->pid = pid_tgid >> 32;
    event->type = HELLO_TCP_EVENT_SEND;
    event->bytes = bytes;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);

    return 0;
}

static __always_inline int submit_recv_event(unsigned int bytes)
{
    struct hello_tcp_event *event;
    unsigned long long pid_tgid;

    pid_tgid = bpf_get_current_pid_tgid();
    if (!task_is_allowed(pid_tgid)) {
        return 0;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->pid = pid_tgid >> 32;
    event->type = HELLO_TCP_EVENT_RECV;
    event->bytes = bytes;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);

    return 0;
}

static __always_inline int submit_event_v4(const void *uaddr)
{
    struct hello_tcp_event *event;
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

    set_task_allowed(pid_tgid, 1);

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
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

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, void *sk, void *msg, unsigned long size)
{
    (void)ctx;
    (void)sk;
    (void)msg;

    return submit_send_event((unsigned int)size);
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(handle_tcp_recvmsg_ret, int ret)
{
    (void)ctx;

    if (ret <= 0) {
        return 0;
    }

    return submit_recv_event((unsigned int)ret);
}

char LICENSE[] SEC("license") = "GPL";