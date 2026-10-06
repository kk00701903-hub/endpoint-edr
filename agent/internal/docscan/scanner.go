package docscan

// 문서 감사 실행: 정책의 폴더를 돌며 문서를 읽기만 하고, 결과(위치·건수)를 배치로 넘긴다.
// 배치의 FilesScanned·FilesSkipped·Errors 는 그 배치 구간의 수이며, 서버가 더한다.
// OS 에 따라 다른 부분(공유 모드로 열기, 클라우드 전용·연결 지점 판별, 사용자 폴더 찾기)은 open_*.go 에 있다.

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourorg/endpoint-edr/agent/internal/model"
)

// Policy 는 서버(GET /v1/policy)가 주는 문서 감사 정책이다. 관리자가 콘솔에서 정한다.
type Policy struct {
	Enabled       bool     `json:"enabled"`
	IntervalHours int      `json:"interval_hours"` // 정기 검사 간격
	Folders       []string `json:"folders"`        // 각 사용자 폴더 아래 이름 예: Desktop, Documents, Downloads
	ExtraPaths    []string `json:"extra_paths"`    // 추가로 볼 절대 경로 예: D:\업무
	Extensions    []string `json:"extensions"`
	Detect        []string `json:"detect"`   // 검출 종류
	Keywords      []string `json:"keywords"` // 최대 50개
	StaleDays     int      `json:"stale_days"`
	MaxFileMB     int      `json:"max_file_mb"`
	RequestID     int64    `json:"request_id,omitempty"` // 콘솔 "지금 검사" 요청이 있으면
	Version       string   `json:"version"`
}

// Limits 는 PC 부담을 줄이는 상한이다(에이전트 설정).
type Limits struct {
	BytesPerSec  int64         // 초당 읽기 상한
	MaxFiles     int           // 한 번 검사에서 볼 문서 수 상한
	MaxStale     int           // 내용 문제 없이 "오래된 문서"로만 보낼 개수 상한
	PausePerFile time.Duration // 파일마다 잠깐 쉬기(CPU 점유를 낮게)
	BatchSize    int
}

func DefaultLimits() Limits {
	return Limits{BytesPerSec: 8 << 20, MaxFiles: 100_000, MaxStale: 5000, PausePerFile: 3 * time.Millisecond, BatchSize: 200}
}

// 건너뛸 폴더(프로그램·캐시·휴지통 등). 소문자 이름
var skipDirs = map[string]bool{
	"appdata": true, "node_modules": true, ".git": true, "$recycle.bin": true, "windows": true,
	"program files": true, "program files (x86)": true, "programdata": true, ".vscode": true, ".cache": true,
}

// Run 은 검사를 한 번 실행하고, 끝까지 마쳤으면 true 를 돌려준다.
// emit 은 배치를 넘기고, false 를 돌려주면(에이전트 종료 등) 검사를 멈춘다.
// 중간에 멈추면(stop 이 닫히거나 emit 실패) 마지막 배치(final)를 보내지 않는다.
// 서버는 final 배치를 받을 때만 이전 검사 결과를 정리하므로, 덜 본 검사가 기존 결과를 지우지 않는다.
// 파일 수 상한(MaxFiles)에 걸린 경우는 정상 종료로 본다(매번 같은 순서로 돌므로 같은 파일까지 본다).
func Run(p Policy, roots []string, trigger string, lim Limits, emit func(*model.DocScanBatch) bool, stop <-chan struct{}) bool {
	det := NewDetector(p.Detect, p.Keywords)
	exts := map[string]bool{}
	for _, e := range p.Extensions {
		exts[strings.TrimPrefix(strings.ToLower(strings.TrimSpace(e)), ".")] = true
	}
	maxSize := int64(p.MaxFileMB) << 20
	if maxSize <= 0 || maxSize > 100<<20 {
		maxSize = 20 << 20
	}
	var staleBefore time.Time
	if p.StaleDays > 0 {
		staleBefore = time.Now().AddDate(0, 0, -p.StaleDays)
	}

	batch := &model.DocScanBatch{ScanID: newID(), Trigger: trigger, RequestID: p.RequestID, StartedAt: time.Now().UTC()}
	head := *batch
	staleOnly := 0
	stopped := false // 더 보지 않음(상한 포함)
	aborted := false // 중간에 멈춤(최종 배치를 보내지 않음)
	flush := func(final bool) bool {
		batch.Final = final
		if final {
			batch.FinishedAt = time.Now().UTC()
		}
		ok := emit(batch)
		next := head
		next.FilesScanned, next.FilesSkipped, next.Errors = 0, 0, 0
		batch = &next
		return ok
	}

	seen := map[string]bool{}
	for _, root := range roots {
		if stopped {
			break
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			select {
			case <-stop:
				stopped, aborted = true, true
				return filepath.SkipAll
			default:
			}
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir // 권한 없는 폴더 등
				}
				return nil
			}
			if d.IsDir() {
				if path != root && (skipDirs[strings.ToLower(d.Name())] || strings.HasPrefix(d.Name(), ".")) {
					return filepath.SkipDir
				}
				if path != root && isLinkOrCloud(d) { // 연결 지점·바로 가기 폴더는 따라가지 않는다
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || !exts[Ext(path)] {
				return nil
			}
			key := strings.ToLower(path)
			if seen[key] {
				return nil
			}
			seen[key] = true
			if len(seen) > lim.MaxFiles {
				stopped = true
				return filepath.SkipAll
			}
			info, err := d.Info()
			if err != nil {
				batch.Errors++
				return nil
			}
			f, skip := scanFile(path, info, det, maxSize, staleBefore, lim)
			switch {
			case skip:
				batch.FilesSkipped++
			default:
				batch.FilesScanned++
			}
			if f != nil {
				contentHit := len(f.PII) > 0 || len(f.Keywords) > 0
				if contentHit || staleOnly < lim.MaxStale {
					if !contentHit {
						staleOnly++
					}
					batch.Findings = append(batch.Findings, *f)
				}
			}
			if len(batch.Findings) >= lim.BatchSize {
				if !flush(false) {
					stopped, aborted = true, true
					return filepath.SkipAll
				}
			}
			if lim.PausePerFile > 0 {
				time.Sleep(lim.PausePerFile)
			}
			return nil
		})
	}
	if aborted {
		return false
	}
	select {
	case <-stop: // 마지막 파일을 보는 사이 종료 요청이 온 경우
		return false
	default:
	}
	return flush(true)
}

// scanFile 은 파일 하나를 검사한다. 보낼 결과가 없으면 nil. skip 은 읽지 못했거나 일부러 건너뛴 경우.
func scanFile(path string, info fs.FileInfo, det *Detector, maxSize int64, staleBefore time.Time, lim Limits) (*model.DocFinding, bool) {
	mod := info.ModTime()
	stale := !staleBefore.IsZero() && mod.Before(staleBefore)
	finding := &model.DocFinding{Path: path, Size: info.Size(), ModifiedAt: mod.UTC(), Stale: stale}
	result := func(reason string) (*model.DocFinding, bool) {
		if stale {
			finding.Unreadable = reason
			return finding, reason != ""
		}
		return nil, reason != ""
	}
	if isCloudOnly(info) {
		return result("클라우드 전용 파일(내려받지 않음)")
	}
	if !det.HasContentChecks() {
		return result("")
	}
	if info.Size() > maxSize {
		return result("크기 상한 초과")
	}
	if info.Size() == 0 {
		return result("")
	}
	fh, err := openShared(path)
	if err != nil {
		return result("열 수 없음")
	}
	defer fh.Close()
	text, err := ExtractText(Ext(path), &throttledReaderAt{r: fh, bps: lim.BytesPerSec, start: time.Now()}, info.Size())
	if err != nil {
		if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "encrypt") || strings.Contains(err.Error(), "distribution") {
			return result("암호가 걸린 문서")
		}
		return result("내용을 읽지 못함")
	}
	finding.PII, finding.Keywords = det.Count(text)
	if len(finding.PII) == 0 && len(finding.Keywords) == 0 && !stale {
		return nil, false
	}
	return finding, false
}

// throttledReaderAt 은 초당 읽는 양을 제한한다(디스크·CPU 부담을 낮게).
type throttledReaderAt struct {
	r     io.ReaderAt
	bps   int64
	start time.Time
	read  int64
}

func (t *throttledReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := t.r.ReadAt(p, off)
	t.read += int64(n)
	if t.bps > 0 {
		want := time.Duration(float64(t.read) / float64(t.bps) * float64(time.Second))
		if el := time.Since(t.start); want > el {
			time.Sleep(want - el)
		}
	}
	return n, err
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Roots 는 정책의 폴더 이름을 각 사용자 폴더(usersDir 아래) 기준 경로로 바꾸고, 추가 경로를 더한다. 없는 폴더는 뺀다.
func Roots(p Policy, usersDir string) []string {
	var out []string
	add := func(path string) {
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			for _, o := range out {
				if strings.EqualFold(o, path) {
					return
				}
			}
			out = append(out, path)
		}
	}
	users, _ := os.ReadDir(usersDir)
	for _, u := range users {
		name := strings.ToLower(u.Name())
		if !u.IsDir() || name == "default" || name == "default user" || name == "all users" || name == "defaultapppool" {
			continue
		}
		home := filepath.Join(usersDir, u.Name())
		for _, f := range p.Folders {
			if f = strings.TrimSpace(f); f == "" || strings.Contains(f, "..") {
				continue
			}
			add(filepath.Join(home, f))
			// OneDrive 로 옮겨진 바탕 화면·문서(OneDrive, OneDrive - 회사명)
			if more, _ := filepath.Glob(filepath.Join(home, "OneDrive*", f)); len(more) > 0 {
				for _, m := range more {
					add(m)
				}
			}
		}
	}
	for _, p := range p.ExtraPaths {
		if p = strings.TrimSpace(p); filepath.IsAbs(p) && !strings.Contains(p, "..") {
			add(p)
		}
	}
	return out
}
