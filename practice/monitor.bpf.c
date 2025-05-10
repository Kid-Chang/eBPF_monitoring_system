// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct event {
    u64 timestamp;
    u32 pid;
    u32 ppid;
    char comm[16];
    bool is_exit;
    // bool(1byte) 다음 7byte 패딩 → struct 전체 크기 8의 배수로 맞추기 (Go와 메모리 정렬 일치)
    char _pad[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// 프로세스 생성 (fork)
SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
    // bpf_ringbuf_reserve: 링버퍼에 event 크기만큼의 공간 할당
    // sizeof(*e): e는 아직 메모리 할당 안됐지만, 포인터 타입은 struct event* → sizeof(*e) == sizeof(struct event)
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    // 할당받지 못하면 return 0
    if (!e) return 0;

    // eBPF 프로그램은 커널 메모리를 직접 접근할 수 없기에 bpf_core_read를 이용
    // u32: unsigned int
    // trace_event_raw_sched_process_fork 구조체에서는 pid가 pid_t(int)이지만
    // bpf에서는 u32를 많이 사용한다.
    u32 child_pid, parent_pid;
    char child_comm[16];
    bpf_core_read(&child_pid, sizeof(child_pid), &ctx->child_pid);
    bpf_core_read(&parent_pid, sizeof(parent_pid), &ctx->parent_pid);
    bpf_core_read(child_comm, sizeof(child_comm), ctx->child_comm);

    // map에 보낼 event에 정보 담기
    e->timestamp = bpf_ktime_get_ns();
    e->pid = child_pid;
    e->ppid = parent_pid;
    __builtin_memcpy(e->comm, child_comm, sizeof(e->comm));
    // 커널이 fork인지, exit인지 구분
    e->is_exit = false;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 프로세스 종료 (exit)
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    // ctx 대신 현재 PID 직접 획득, 프로세스 아이디와 쓰레드그룹 아이디를 리턴받고, shift연산으로 뒤에 값은 날림
    e->pid = bpf_get_current_pid_tgid() >> 32;  
    // 종료 이벤트는 ppid 정보 전달하지 않으므로 0으로 초기화
    e->ppid = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->is_exit = true;
    // 0은 wakeup과 관련된 값 조정.
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 없으면 “missing license” 오류 발생. 통상 GPL로 많이 작성함.
char LICENSE[] SEC("license") = "GPL";
