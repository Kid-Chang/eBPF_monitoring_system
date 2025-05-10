# eBPF로 모니터링 시스템 구축하기


##  chap 1. Sensor 만들기

## 실행방법
```

// bpf 프로그램에서 "vmlinux.h"를 이용한 커널 구조체를 사용하기 위함
sudo apt install linux-tools-common linux-tools-$(uname -r)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
// <커널 스페이스> bpf 프로그램 빌드
clang -target bpf -O2 -g -c monitor.bpf.c -o monitor.bpf.o
// <유저 스페이스> main.go 빌드
go build -o process-monitor main.go

// go 프로그램이 monitor.bpf.o를 커널에 삽입하고, 생성된 bpf map을 통해 로그 수집 시작
sudo ./process-monitor
```

## 트러블슈팅
> fatal error: 'asm/types.h' file not found
`sudo apt-get install -y gcc-multilib`

> fatal error: 'bpf/bpf_helpers.h' file not found
`apt install libbpf-dev`

> (헤더파일 탐색을 위해) vscode에서 커널헤더를 찾지 못한다면
.c_cpp_properties.json에
```
{
    "configurations": [
        {
            "name": "Linux",
            "includePath": [
                "${workspaceFolder}/**",
                "/usr/include",
                "/usr/local/include",
                // 아래 코드 추가
                "/usr/src/linux-headers-6.8.0-59-generic/include"            ],
            "defines": [],
            "compilerPath": "/usr/bin/clang",
            "cStandard": "c99",
            "cppStandard": "c++17",
            "intelliSenseMode": "linux-clang-x64"
        }
    ],
    "version": 4
}
```