//go:build windows

package sysutil

import (
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/yourorg/endpoint-edr/agent/internal/model"
)

// 에이전트 "자기 자신"의 메모리만 조회한다(다른 프로세스는 보지 않음).
var procK32GetProcessMemoryInfo = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")

type processMemoryCounters struct {
	cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// HealthMonitor 는 에이전트의 CPU·메모리·수집 소요 시간·최근 오류를 모은다.
type HealthMonitor struct {
	mu       sync.Mutex
	start    time.Time
	lastWall time.Time
	lastCPU  time.Duration
	scanMs   map[string]int64
	errs     []string
}

func NewHealthMonitor() *HealthMonitor {
	m := &HealthMonitor{start: time.Now(), scanMs: map[string]int64{}}
	m.lastWall, m.lastCPU = time.Now(), selfCPU()
	return m
}

// Time 은 수집기 하나의 소요 시간을 잰다:  defer hm.Time("process")()
func (m *HealthMonitor) Time(name string) func() {
	t0 := time.Now()
	return func() {
		m.mu.Lock()
		m.scanMs[name] = time.Since(t0).Milliseconds()
		m.mu.Unlock()
	}
}

func (m *HealthMonitor) Error(format string, a ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errs = append(m.errs, time.Now().UTC().Format("15:04:05 ")+fmt.Sprintf(format, a...))
	if len(m.errs) > 5 {
		m.errs = m.errs[len(m.errs)-5:]
	}
}

func (m *HealthMonitor) Snapshot(spoolFiles int, spoolBytes int64) *model.AgentHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, cpu := time.Now(), selfCPU()
	wall := now.Sub(m.lastWall)
	pct := 0.0
	if wall > 0 {
		pct = float64(cpu-m.lastCPU) / float64(wall) / float64(runtime.NumCPU()) * 100
	}
	m.lastWall, m.lastCPU = now, cpu

	scan := make(map[string]int64, len(m.scanMs))
	for k, v := range m.scanMs {
		scan[k] = v
	}
	h := &model.AgentHealth{
		UptimeSec:  int64(now.Sub(m.start).Seconds()),
		CPUPercent: float64(int(pct*100)) / 100,
		Goroutines: runtime.NumGoroutine(),
		SpoolFiles: spoolFiles,
		SpoolBytes: spoolBytes,
		ScanMillis: scan,
		LastErrors: append([]string(nil), m.errs...),
	}
	var pmc processMemoryCounters
	pmc.cb = uint32(unsafe.Sizeof(pmc))
	if r, _, _ := procK32GetProcessMemoryInfo.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.cb)); r != 0 {
		h.WorkingSetMB = float64(int(float64(pmc.WorkingSetSize)/(1<<20)*10)) / 10
	}
	return h
}

func selfCPU() time.Duration {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u); err != nil {
		return 0
	}
	return time.Duration(k.Nanoseconds() + u.Nanoseconds())
}
