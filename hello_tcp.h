#ifndef HELLO_TCP_H
#define HELLO_TCP_H

#define TASK_COMM_LEN 16

enum hello_tcp_event_type {
    HELLO_TCP_EVENT_V4 = 1,
    HELLO_TCP_EVENT_V6 = 2,
};

struct hello_tcp_event {
    unsigned int pid;
    unsigned int type;
    unsigned short dport;
    char comm[TASK_COMM_LEN];
    unsigned int daddr_v4;
    unsigned char daddr_v6[16];
};

#endif