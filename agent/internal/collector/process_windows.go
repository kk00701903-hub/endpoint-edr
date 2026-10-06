//go:build windows

package collector

// 프로세스 수집 (Process Explorer 역할)
//
// 사용 API (모두 읽기 전용)
//   - CreateToolhelp32Snapshot / Process32First / Process32Next : 프로세스 목록
//   - OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)              : 최소 권한 핸들
//   - QueryFullProcessImageName, GetProcessTimes                 : 경로, 시작 시각
//   - NtQueryInformationProcess(ProcessCommandLineInformation)   : 명령줄 (Win 8.1+)
//     → 대상 프로세스 메모리(PEB)를 읽지 않으므로 PROCESS_VM_READ 권한이 필요 없다.
//       타 보안 제품의 자기보호(self-protection) 기능과 부딪히지 않는 방식이다.
//
// 금지: PROCESS_VM_READ / PROCESS_TERMINATE / PROCESS_ALL_ACCESS, DLL 주입, 후킹.

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/yourorg/endpoint-edr/agent/internal/hasher"
	"github.com/yourorg/endpoint-edr/agent/internal/model"
)

type procKey struct {
	pid        uint32
	createTime int64
}

// ProcessTracker 는 직전 스캔과 비교해 "새로 생긴 프로세스"와 "종료된 프로세스"를 돌려준다.
// PID 는 재사용되므로 (PID, 시작 시각) 쌍을 고유 키로 쓴다.
//
// 성능: 이미 아는 프로세스는 시작 시각만 확인하고(핸들 1회 + GetProcessTimes),
// 경로·사용자·명령줄·해시 같은 무거운 조회는 새 프로세스에만 한다.
// 일반 PC(프로세스 200~300개)에서 주기당 시스템 호출이 약 1/5 로 준다.
type ProcessTracker struct {
	hasher *hasher.Hasher
	seen   map[procKey]struct{}
	// 마지막 스캔 결과(pid → 이름). 네트워크 수집기가 PID 를 이름으로 바꿀 때 쓴다.
	Names map[uint32]string
}

func NewProcessTracker(h *hasher.Hasher) *ProcessTracker {
	return &ProcessTracker{hasher: h, seen: map[procKey]struct{}{}, Names: map[uint32]string{}}
}

// Scan 은 현재 프로세스를 수집한다.
//   - full=true : 전체 목록(서버가 현재 프로세스 표를 통째로 다시 맞춘다)
//   - full=false: 새 프로세스만 + 직전 스캔 이후 종료된 프로세스 목록
func (t *ProcessTracker) Scan(full bool) ([]model.Process, []model.ProcessExit, error) {
	now := time.Now().UTC()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, nil, err
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return nil, nil, err
	}

	current := make(map[procKey]struct{}, len(t.seen)+16)
	names := make(map[uint32]string, len(t.Names)+16)
	var out []model.Process

	for {
		p := model.Process{
			PID:        pe.ProcessID,
			PPID:       pe.ParentProcessID,
			Name:       windows.UTF16ToString(pe.ExeFile[:]),
			ObservedAt: now,
		}
		names[p.PID] = p.Name

		var h windows.Handle
		if p.PID > 4 { // 0: Idle, 4: System 은 핸들을 열지 않는다
			if hh, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.PID); err == nil {
				h = hh
				p.CreateTime = processCreateTime(h)
			}
		}
		key := procKey{pid: p.PID}
		if !p.CreateTime.IsZero() {
			key.createTime = p.CreateTime.UnixNano()
		}
		current[key] = struct{}{}

		if _, known := t.seen[key]; full || !known {
			if h != 0 {
				fillDetails(h, &p)
			}
			if p.Path != "" && t.hasher != nil {
				if sum, err := t.hasher.SHA256(p.Path); err == nil {
					p.SHA256 = sum
				}
			}
			out = append(out, p)
		}
		if h != 0 {
			windows.CloseHandle(h)
		}

		if err := windows.Process32Next(snap, &pe); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return out, nil, err
		}
	}

	var exits []model.ProcessExit
	for k := range t.seen {
		if _, alive := current[k]; !alive {
			e := model.ProcessExit{PID: k.pid, ObservedAt: now}
			if k.createTime != 0 {
				e.CreateTime = time.Unix(0, k.createTime).UTC()
			}
			exits = append(exits, e)
		}
	}
	t.seen = current
	t.Names = names
	return out, exits, nil
}

func processCreateTime(h windows.Handle) time.Time {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return time.Time{}
	}
	return time.Unix(0, creation.Nanoseconds()).UTC()
}

// fillDetails 는 최소 권한 핸들로 경로·사용자·명령줄을 채운다.
// 보호 프로세스(PPL, 타 보안 제품)는 일부 정보가 거부될 수 있으며, 그 경우 조용히 건너뛴다.
func fillDetails(h windows.Handle, p *model.Process) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err == nil {
		p.Path = windows.UTF16ToString(buf[:size])
	}
	p.User = processUser(h)
	p.CommandLine = processCommandLine(h)
}

func processUser(h windows.Handle) string {
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return ""
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	account, domain, _, err := tu.User.Sid.LookupAccount("")
	if err != nil {
		return tu.User.Sid.String()
	}
	return domain + `\` + account
}

func processCommandLine(h windows.Handle) string {
	var need uint32
	// 1차 호출로 필요한 버퍼 크기를 얻는다.
	_ = windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, nil, 0, &need)
	if need == 0 || need > 64*1024 {
		return ""
	}
	buf := make([]byte, need)
	if err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation,
		unsafe.Pointer(&buf[0]), need, &need); err != nil {
		return ""
	}
	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	return us.String()
}
