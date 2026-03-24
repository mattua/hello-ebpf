#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "hello_tcp.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int submit_event(unsigned int type)
{
    struct hello_tcp_event *event;
    unsigned long long pid_tgid;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->type = type;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int handle_tcp_v4_connect(struct pt_regs *ctx)
{
    (void)ctx;
    return submit_event(HELLO_TCP_EVENT_V4);
}

SEC("kprobe/tcp_v6_connect")
int handle_tcp_v6_connect(struct pt_regs *ctx)
{
    (void)ctx;
    return submit_event(HELLO_TCP_EVENT_V6);
}

char LICENSE[] SEC("license") = "GPL";