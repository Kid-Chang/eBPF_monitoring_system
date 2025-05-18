// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2

struct connect_event {
    u64 timestamp;
    u32 pid;
    char comm[16];
    u32 daddr;
    u16 dport;
};


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} connect_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_tcp_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct connect_event *e;

    // syscall 인자 1: sockfd, 인자 2: struct sockaddr __user *addr
    void *user_sockaddr = (void *)ctx->args[1];
    if (!user_sockaddr)
        return 0;

    struct sockaddr_in sa = {};
    // 사용자 메모리에서 안전하게 복사
    if (bpf_probe_read_user(&sa, sizeof(sa), user_sockaddr))
        return 0;

    // AF_INET는 
    // AF_INET-> 2 IPv4 주소 체계 
    // AF_INET-> 6 10 IPv6 주소 체계

    if (sa.sin_family != AF_INET)
        return 0;

    e = bpf_ringbuf_reserve(&connect_events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // The bpf_ntohl macro is used to convert a 32-bit number from network byte order to host byte order.
    e->daddr = bpf_ntohl(sa.sin_addr.s_addr);
    // The bpf_ntohs macro is used to convert a 16-bit number from network byte order to host byte order.
    e->dport = bpf_ntohs(sa.sin_port);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


char LICENSE[] SEC("license") = "GPL";