#### BTF: BPF Type Format
BTF는 커널이 자신에 대한 타입 정보(구조체 레이아웃, offset 등)를 메타데이터로 제공
`vmlinux.h`는 커널의 BTF 메타데이터를 이용해서 해당 커널 버전에 맞게 만들어진 커널 타입 정의집

### ELF: Executable and Linkable Format
리눅스에서 사용하는 바이너리 파일 포맷 표준
ELF는 여러 개의 ’섹션(section)’으로 나뉘어 있습니다.

#### SEC()
“SEC() 매크로는 ELF 섹션 이름을 지정하여, libbpf 또는 다른 eBPF 로더 (예: Go의 github.com/cilium/ebpf, bpftool 등)가 이 섹션을 기반으로 프로그램, map, license 등의 용도를 파싱할 수 있도록 합니다.”


#### event 구조체
> map을 통해서 유저 스페이스로 보낼 정보들을 정의합니다.
```
struct event {
    u64 timestamp;
    u32 pid;
    u32 ppid;
    char comm[16];
    bool is_exit;
};
```

#### BPF map 구조체
커널 스페이스에 있는 BPF에서 데이터를 유저 스페이스에 전달하기 위해서는 
pipe를 통하거나 map을 이용해야합니다.
전자는 테스트용에 사용되고, 실질적으로는 map을 이용하는데, 두 스페이스간 데이터를 주고받는 커널스페이스의 저장소입니다.

> 어떤 타입의 map을 사용할 건지, 크기는 얼마나 되는지를 정의합니다.
```
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
```

# #include "vmlinux.h"
vmlinux.h는 커널의 BTF 정보를 기반으로 생성된 헤더 파일로, eBPF 프로그램에서 커널의 내부 구조체 및 타입 정의(예: ctx 구조체, task_struct 등)를 참조할 수 있도록 합니다. 커널 구조체/타입을 직접 사용하는 경우 필수로 포함해야 합니다.

이 파일은 커널 버전별로 달라질 수 있는 내부 구조체 정의를 포함하고 있어, 커널과 eBPF 프로그램 간의 호환성을 보장합니다.

vmlinux.h를 생성하기 위해서는 커널의 BTF 메타데이터가 필요하며, 이 데이터는 /sys/kernel/btf/vmlinux 또는 vmlinux 바이너리 파일에 저장됩니다.
리눅스 시스템에는 기본적으로 이 파일이 없거나 tools가 부족한 경우가 있어, 이를 위한 패키지를 설치해야합니다.
`sudo apt install linux-tools-common linux-tools-$(uname -r)`
이 도구를 설치 한 후 아래 명령어를 통해 vmlinux.h를 만들 수 있습니다.
`bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`


# 커널에 BPF 올리기
유저스페이스의 Go 프로그램에서 .o 파일을 직접 로드 및 attach할 수도 있고, 사용자가 별도로 bpftool과 같은 도구를 사용해 수동으로 로드 및 attach할 수도 있습니다.
일반적으로 Go 언어를 이용해 유저스페이스 BPF 프로그램을 작성할 경우, .o 파일의 로드와 attach 작업까지 Go 코드 내에서 처리하는 방식이 더 편리하고 관리하기 용이합니다.

## 1. 수동 작업
### load하기
```
> sudo -s
chang@chang-pc:~/dev/monitoring_system/practice# ls /sys/fs/bpf
chang@chang-pc:~/dev/monitoring_system/practice# ls
```

sys/fs/bpf에 /sys/fs/bpf/ 아래에 개별 이름으로 load한다.
```
sudo bpftool prog loadall monitor.bpf.o /sys/fs/bpf

```

각각 프로그램 fd가 각각 저장되고 커널에 load됨. 또한 bpf map도 같이 로드된다.
```
chang@chang-pc:~/dev/monitoring_system/practice# sudo ls /sys/fs/bpf
handle_exit  handle_fork
```

BPF 프로그램들을 출력하는 `sudo bpftool prog show` 을 통해서 아래와 같은 결과를 확인할 수 있습니다.
```
189: tracepoint  name handle_fork  tag a77892b96b717397  gpl
        loaded_at 2025-05-09T01:29:27+0000  uid 0
        xlated 592B  jited 340B  memlock 4096B  map_ids 136
        btf_id 303
190: tracepoint  name handle_exit  tag 590dd72e42060de4  gpl
        loaded_at 2025-05-09T01:29:27+0000  uid 0
        xlated 200B  jited 120B  memlock 4096B  map_ids 136
        btf_id 303
```


아래처럼 BPF프로그램과 BPF맵도 상세 정보도 확인이 가능합니다.
```
> bpftool prog show id 199 --pretty
{
    "id": 199,
    "type": "tracepoint",
    "name": "handle_fork",
    "tag": "a77892b96b717397",
    "gpl_compatible": true,
    "loaded_at": 1746755797,
    "uid": 0,
    "orphaned": false,
    "bytes_xlated": 592,
    "jited": true,
    "bytes_jited": 340,
    "bytes_memlock": 4096,
    "map_ids": [137
    ],
    "btf_id": 313
}
```

```
> bpftool map show id 137 --pretty
{
    "id": 137,
    "type": "ringbuf",
    "name": "events",
    "flags": 0,
    "bytes_key": 0,
    "bytes_value": 0,
    "max_entries": 16777216,
    "bytes_memlock": 16855448,
    "frozen": 0
}
```

### 삭제하기
```
sudo rm /sys/fs/bpf/events
sudo rm /sys/fs/bpf/handle_exit
sudo rm /sys/fs/bpf/handle_fork
```

# 코드 뜯어보기
아래에 process fork 및 exit에 대한 event를 수집하는 코드를 보고 분석해봅시다.

> ctx는 **“context”**의 줄임말
	이 tracepoint handler 함수가 호출될 때 커널이 넘겨주는 데이터
	•	→ 이벤트에 대한 정보가 담긴 구조체 포인터

```
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
```
`vmlinux.h`는 커널 내부 구조체/타입 정의
`<bpf/bpf_helpers.h>`는 bpf_trace_printk(), bpf_get_current_pid_tgid()같은 helper 함수 및 SEC() 매크로 정의
<bpf/bpf_tracing.h>는 trace_event_raw_sched_process_fork 같은 tracepoint용 context 구조체 정의

bpf_probe_read()는 <bpf/bpf_tracing.h> 헤더에 포함된 함수로, 직접 메모리 주소에서 값을 읽지만 커널 구조체 레이아웃 변경에 취약합니다.
bpf_core_read()는 <bpf/bpf_core_read.h> 헤더에 포함된 매크로로, BTF 메타데이터를 이용해 필드 offset을 자동 계산하므로 커널 버전 차이에도 안전하게 동작합니다 (CO-RE 지원).


## kprobe vs tracepoint
`kprobe`는 커널에 존재하는 함수에 바인딩 되는 만큼 함수 이름이 바뀔 경우 프로그램을 재사용하기 어려울 수 있습니다. 반면  `tracepoint`는 새로운 커널에 대해서도 어느정도 동작이 보장됩니다.
Start the Extension Bisect
```
// 커널 함수에 kprobe attach
SEC("kprobe/_do_fork")

// tracepoint에 attach
SEC("tracepoint/sched/sched_process_fork")
```