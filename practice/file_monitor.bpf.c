// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct file_event {
    u64 timestamp;
    u32 pid;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} file_events SEC(".maps");

// File Open
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    struct file_event *e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
    // 할당받지 못하면 return 0
    if (!e) return 0;

    // PID, comm 가져오기
    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // filename 인자는 syscall 두 번째 인자(ctx->args[1])에 위치
    // 근데 args[1]가 경로 문자열을 가리키는 user space 메모리 주소임. 즉 e->filename = *(ctx->args[1]); 불가능
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), (void *)ctx->args[1]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 없으면 “missing license” 오류 발생. 통상 GPL로 많이 작성함.
char LICENSE[] SEC("license") = "GPL";
