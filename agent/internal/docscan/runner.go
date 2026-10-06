package docscan

// 검사 일정: 서버 정책(켜짐·간격·"지금 검사" 요청)을 보고, 차례가 되면 백그라운드에서 한 번 실행한다.
// 마지막 검사 시각·처리한 요청 번호는 에이전트 자기 데이터 폴더(C:\ProgramData\EndpointEDR)의 상태 파일에 남긴다.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yourorg/endpoint-edr/agent/internal/model"
)

type State struct {
	LastScanAt    time.Time `json:"last_scan_at"`
	LastRequestID int64     `json:"last_request_id"`
}

type Runner struct {
	file    string
	mu      sync.Mutex
	state   State
	running bool
}

func NewRunner(dataDir string) *Runner {
	r := &Runner{file: filepath.Join(dataDir, "docscan_state.json")}
	if b, err := os.ReadFile(r.file); err == nil {
		_ = json.Unmarshal(b, &r.state)
	}
	return r
}

// ParsePolicy 는 GET /v1/policy 응답에서 문서 감사 정책을 꺼낸다.
func ParsePolicy(body []byte) (Policy, error) {
	var resp struct {
		DocScan Policy `json:"doc_scan"`
	}
	err := json.Unmarshal(body, &resp)
	return resp.DocScan, err
}

// Due 는 지금 검사할 차례인지와 그 이유(request | schedule)를 돌려준다.
func (r *Runner) Due(p Policy, now time.Time) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !p.Enabled || r.running {
		return "", false
	}
	if p.RequestID > r.state.LastRequestID {
		return "request", true
	}
	interval := time.Duration(p.IntervalHours) * time.Hour
	if interval <= 0 {
		return "", false
	}
	if r.state.LastScanAt.IsZero() || now.Sub(r.state.LastScanAt) >= interval {
		return "schedule", true
	}
	return "", false
}

// Start 는 검사를 백그라운드로 돌린다. 결과 배치는 out 으로 넘기고(받는 쪽이 전송), 끝나면 상태 파일을 갱신한다.
func (r *Runner) Start(p Policy, roots []string, trigger string, lim Limits, out chan<- *model.DocScanBatch, stop <-chan struct{}) {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	r.running = true
	r.mu.Unlock()
	if trigger != "request" {
		p.RequestID = 0
	}
	go func() {
		started := time.Now()
		done := false
		defer func() {
			recover() // 예기치 못한 오류로 에이전트 전체가 멈추지 않게
			r.mu.Lock()
			r.running = false
			if done { // 끝까지 마친 검사만 기록한다. 중간에 멈추면 다음 차례에 다시 한다
				r.state.LastScanAt = started
				if p.RequestID > r.state.LastRequestID {
					r.state.LastRequestID = p.RequestID
				}
				if b, err := json.Marshal(r.state); err == nil {
					_ = os.WriteFile(r.file, b, 0o600)
				}
			}
			r.mu.Unlock()
		}()
		done = Run(p, roots, trigger, lim, func(b *model.DocScanBatch) bool {
			select {
			case out <- b:
				return true
			case <-stop:
				return false
			}
		}, stop)
	}()
}

func (r *Runner) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}
