#ifndef HELLO_TCP_H
#define HELLO_TCP_H

#define TASK_COMM_LEN 16

#define HELLO_TCP_FILTER_MAX 8
#define HELLO_TCP_PAYLOAD_MAX 1024

struct hello_tcp_filter_v4 {
    unsigned int daddr_v4_host;
    unsigned short dport_host;
};

struct hello_tcp_conn_v4 {
    unsigned int daddr_v4;
    unsigned short dport;
    unsigned short reserved;
};

struct hello_tcp_pending_recv {
    unsigned long long user_buffer;
    unsigned int requested_len;
};

enum hello_tcp_event_type {
    HELLO_TCP_EVENT_V4 = 1,
    HELLO_TCP_EVENT_V6 = 2,
    HELLO_TCP_EVENT_SEND = 3,
    HELLO_TCP_EVENT_RECV = 4,
};

struct hello_tcp_event {
    unsigned int pid;
    unsigned int type;
    unsigned int bytes;
    unsigned int captured_len;
    unsigned short dport;
    unsigned short reserved;
    char comm[TASK_COMM_LEN];
    unsigned int daddr_v4;
    unsigned char daddr_v6[16];
    unsigned char payload[HELLO_TCP_PAYLOAD_MAX];
};

#endif