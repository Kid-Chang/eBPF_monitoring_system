package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	// 커널 5.11 이후 버전에서는 필수 아님
	// "github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/ringbuf"
)

// C의 struct event와 반드시 메모리 레이아웃이 일치해야 합니다.
type Event struct {
	Timestamp uint64
	Pid       uint32
	Ppid      uint32
	Comm      [16]byte
	IsExit    bool
	// bool은 1바이트를 차지. CPU는 4바이트나 8바이트로 정렬된 메모리 액세스로 맞춰질 수 있음
	// 이에 따라 구조체의 크기가 다르게 인식 될 수 있음으로 안정성을 위해 여기서 패딩을 추가함.
	// 파이썬에서는 고려하지 않아도 됨.
	_ [7]byte // padding: bool(1) + 7 = 8 bytes (align to 8 bytes)
}

// json 형태로 로그를 출력하기 위함.
type OutputEvent struct {
	Event     string `json:"event"`
	WallTime  string `json:"wall_time"`
	Pid       uint32 `json:"pid"`
	Ppid      uint32 `json:"ppid"`
	Comm      string `json:"comm"`
	Timestamp uint64 `json:"timestamp"`
}

// 시스템 부팅 시간을 계산합니다.
func getBootTime() (time.Time, error) {

	// 해당 프로그램을 실행하는 os의 uptime(실행으로부터 지난 시간)을 측정함
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read /proc/uptime: %w", err)
	}

	// 시간 계산 코드
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return time.Time{}, fmt.Errorf("unexpected format in /proc/uptime")
	}
	uptimeSeconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse uptime: %w", err)
	}

	bootTime := time.Now().Add(-time.Duration(uptimeSeconds * float64(time.Second)))
	return bootTime, nil
}

// 안전하게 comm 문자열 파싱
func safeComm(raw []byte) string {
	idx := bytes.IndexByte(raw[:], 0)
	if idx == -1 {
		idx = len(raw)
	}
	cleaned := raw[:idx]

	// 혹시 이상한 비프린트 문자 제거
	for i, b := range cleaned {
		if b < 32 || b > 126 { // printable ASCII만 허용
			cleaned[i] = '.'
		}
	}

	return string(cleaned)
}

func main() {
	// MEMLOCK 한도 해제
	// 커널 5.11 이후 버전에서는 필수 아님.
	// 기본적으로 리눅스의 memlock 제한이 작아 map, ring buffer 등의 메모리 할당에 실패할 수 있어, 실행 전 해당 제한을 해제하여 map 생성 실패를 방지합니다.
	// eBPF에서 만든 map, ring buffer 같은 자료구조는 커널 메모리 공간에 생성됨.
	// 그리고 이 메모리는 항상 상주해야함. swap-out 되는 것을 방지하기 위해 락을 검.
	// https://pkg.go.dev/github.com/cilium/ebpf/rlimit#RemoveMemlock 참고
	// if err := rlimit.RemoveMemlock(); err != nil {
	// 	log.Fatalf("failed to remove memlock limit: %v", err)
	// }

	// 다른 ebpf.LoadCollectionSpec의 LoadAndAssign에서 같은 spec을 설정하면 에러 발생
	// .bpf.c 에 따라 spec 분리
	spec, err := ebpf.LoadCollectionSpec("monitor.bpf.o")
	if err != nil {
		log.Fatalf("failed to load BPF object: %v", err)
	}

	file_spec, err := ebpf.LoadCollectionSpec("file_monitor.bpf.o")
	if err != nil {
		log.Fatalf("failed to load BPF object: %v", err)
	}

	// objs는
	objs := struct {
		Programs struct {
			HandleFork *ebpf.Program `ebpf:"handle_fork"`
			HandleExit *ebpf.Program `ebpf:"handle_exit"`
			// HandleOpenat *ebpf.Program `ebpf:"handle_openat"`
		}
		Maps struct {
			Events *ebpf.Map `ebpf:"events"`
			// FileEvents *ebpf.Map `ebpf:"file_events"`
		}
	}{}
	fileObjs := struct {
		Programs struct {
			HandleOpenat *ebpf.Program `ebpf:"handle_openat"`
		}
		Maps struct {
			FileEvents *ebpf.Map `ebpf:"file_events"`
		}
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to load and assign BPF objects: %v", err)
	}
	if err := file_spec.LoadAndAssign(&fileObjs, nil); err != nil {
		log.Fatalf("failed to load and assign BPF objects: %v", err)
	}

	defer objs.Programs.HandleFork.Close()
	defer objs.Programs.HandleExit.Close()
	defer objs.Maps.Events.Close()

	defer fileObjs.Programs.HandleOpenat.Close()
	defer fileObjs.Maps.FileEvents.Close()

	// tracepoint attach
	forkLink, err := link.Tracepoint("sched", "sched_process_fork", objs.Programs.HandleFork, nil)
	if err != nil {
		log.Fatalf("failed to attach fork tracepoint: %v", err)
	}
	defer forkLink.Close()

	exitLink, err := link.Tracepoint("sched", "sched_process_exit", objs.Programs.HandleExit, nil)
	if err != nil {
		log.Fatalf("failed to attach exit tracepoint: %v", err)
	}
	defer exitLink.Close()

	openatLink, err := link.Tracepoint("syscalls", "sys_enter_openat", fileObjs.Programs.HandleOpenat, nil)
	if err != nil {
		log.Fatalf("failed to attach openat tracepoint: %v", err)
	}
	defer openatLink.Close()

	rd, err := ringbuf.NewReader(objs.Maps.Events)
	if err != nil {
		log.Fatalf("failed to open ringbuf: %v", err)
	}
	defer rd.Close()

	file_rd, err := ringbuf.NewReader(fileObjs.Maps.FileEvents)
	if err != nil {
		log.Fatalf("failed to open ringbuf: %v", err)
	}
	defer file_rd.Close()

	// 부팅 시간 계산
	bootTime, err := getBootTime()
	if err != nil {
		log.Fatalf("failed to get boot time: %v", err)
	}

	log.Println("Listening for process events... (press Ctrl+C to exit)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	// go func() {
	// 	defer close(done)
	// 	for {
	// 		select {
	// 		case <-ctx.Done():
	// 			return
	// 		default:
	// 			record, err := rd.Read()
	// 			if err != nil {
	// 				if err == ringbuf.ErrClosed {
	// 					log.Println("ringbuf closed, exiting reader")
	// 					return
	// 				}
	// 				log.Printf("reading ringbuf: %v", err)
	// 				continue
	// 			}

	// 			if len(record.RawSample) < int(unsafe.Sizeof(Event{})) {
	// 				log.Printf("invalid event size: %d", len(record.RawSample))
	// 				continue
	// 			}

	// 			var event Event
	// 			buf := bytes.NewBuffer(record.RawSample[:unsafe.Sizeof(Event{})])
	// 			if err := binary.Read(buf, binary.LittleEndian, &event); err != nil {
	// 				log.Printf("failed to parse event: %v", err)
	// 				continue
	// 			}

	// 			comm := safeComm(event.Comm[:])
	// 			wallTime := bootTime.Add(time.Duration(event.Timestamp))

	// 			out := OutputEvent{
	// 				Event:     map[bool]string{false: "create", true: "exit"}[event.IsExit],
	// 				Comm:      comm,
	// 				WallTime:  wallTime.Format(time.RFC3339Nano),
	// 				Pid:       event.Pid,
	// 				Ppid:      event.Ppid,
	// 				Timestamp: event.Timestamp,
	// 			}

	// 			j, _ := json.Marshal(out)
	// 			fmt.Println(string(j))
	// 		}
	// 	}
	// }()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := file_rd.Read()
				if err != nil {
					if err == ringbuf.ErrClosed {
						log.Println("file ringbuf closed, exiting reader")
						return
					}
					log.Printf("reading file ringbuf: %v", err)
					continue
				}

				type FileEvent struct {
					Timestamp uint64
					Pid       uint32
					Comm      [16]byte
					Filename  [256]byte
				}

				if len(record.RawSample) < int(unsafe.Sizeof(FileEvent{})) {
					log.Printf("invalid file event size: %d", len(record.RawSample))
					continue
				}

				var fe FileEvent
				buf := bytes.NewBuffer(record.RawSample[:unsafe.Sizeof(FileEvent{})])
				if err := binary.Read(buf, binary.LittleEndian, &fe); err != nil {
					log.Printf("failed to parse file event: %v", err)
					continue
				}

				comm := safeComm(fe.Comm[:])
				filename := safeComm(fe.Filename[:])
				wallTime := bootTime.Add(time.Duration(fe.Timestamp))

				out := map[string]interface{}{
					"event":     "file_open",
					"comm":      comm,
					"filename":  filename,
					"wall_time": wallTime.Format(time.RFC3339Nano),
					"pid":       fe.Pid,
					"timestamp": fe.Timestamp,
				}

				j, _ := json.Marshal(out)
				fmt.Println(string(j))
			}
		}
	}()

	<-sig
	log.Println("Exiting...")
	cancel()
	<-done
}
