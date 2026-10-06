//go:build windows

package collector

// 지속성(Persistence) 수집 (Autoruns 역할)
//
// 레지스트리는 KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS 로만 연다(쓰기 권한 요청 자체를 하지 않음).
// 예약 작업은 Task Scheduler COM 대신 %SystemRoot%\System32\Tasks 의 XML 정의 파일을 읽기 전용으로 파싱한다.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows/registry"

	"github.com/yourorg/endpoint-edr/agent/internal/hasher"
	"github.com/yourorg/endpoint-edr/agent/internal/model"
)

const regRead = registry.QUERY_VALUE | registry.ENUMERATE_SUB_KEYS | registry.WOW64_64KEY

var runKeys = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
	`SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
}

type autorunEntry struct {
	Location, Name, Command string
}

func collectAutoruns() []autorunEntry {
	var out []autorunEntry

	// 1) HKLM Run 계열
	for _, k := range runKeys {
		out = append(out, readValues(registry.LOCAL_MACHINE, k, `HKLM\`+k)...)
	}
	// 2) 로드된 사용자 하이브(HKU\<SID>) Run 계열
	if users, err := registry.OpenKey(registry.USERS, "", regRead); err == nil {
		sids, _ := users.ReadSubKeyNames(-1)
		users.Close()
		for _, sid := range sids {
			if strings.HasSuffix(sid, "_Classes") || !strings.HasPrefix(sid, "S-1-5-21-") {
				continue
			}
			for _, k := range runKeys[:2] {
				out = append(out, readValues(registry.USERS, sid+`\`+k, `HKU\`+sid+`\`+k)...)
			}
		}
	}
	// 3) Winlogon Shell / Userinit (변조 시 로그온 때마다 실행)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, regRead); err == nil {
		for _, v := range []string{"Shell", "Userinit"} {
			if s, _, err := k.GetStringValue(v); err == nil {
				out = append(out, autorunEntry{`HKLM\...\Winlogon`, v, s})
			}
		}
		k.Close()
	}
	// 4) IFEO Debugger (디버거 하이재킹)
	ifeo := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, ifeo, regRead); err == nil {
		subs, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, s := range subs {
			if sk, err := registry.OpenKey(registry.LOCAL_MACHINE, ifeo+`\`+s, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
				if d, _, err := sk.GetStringValue("Debugger"); err == nil && d != "" {
					out = append(out, autorunEntry{`HKLM\...\Image File Execution Options`, s, d})
				}
				sk.Close()
			}
		}
	}
	// 5) 자동 시작 서비스 (Start=2) 의 ImagePath
	svcRoot := `SYSTEM\CurrentControlSet\Services`
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, svcRoot, regRead); err == nil {
		subs, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, s := range subs {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, svcRoot+`\`+s, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			start, _, e1 := sk.GetIntegerValue("Start")
			img, _, e2 := sk.GetStringValue("ImagePath")
			sk.Close()
			if e1 == nil && e2 == nil && start == 2 && img != "" {
				out = append(out, autorunEntry{"Service", s, img})
			}
		}
	}
	// 6) 시작프로그램 폴더
	for _, dir := range startupFolders() {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if !e.IsDir() && !strings.EqualFold(e.Name(), "desktop.ini") {
				out = append(out, autorunEntry{"StartupFolder", e.Name(), filepath.Join(dir, e.Name())})
			}
		}
	}
	// 7) 예약 작업 (XML 정의 파일)
	out = append(out, scheduledTasks()...)
	return out
}

func readValues(root registry.Key, path, label string) []autorunEntry {
	k, err := registry.OpenKey(root, path, regRead)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	var out []autorunEntry
	for _, n := range names {
		if s, _, err := k.GetStringValue(n); err == nil {
			out = append(out, autorunEntry{label, n, s})
		}
	}
	return out
}

func startupFolders() []string {
	dirs := []string{filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\StartUp`)}
	if users, err := os.ReadDir(filepath.Join(os.Getenv("SystemDrive")+`\`, "Users")); err == nil {
		for _, u := range users {
			if u.IsDir() {
				dirs = append(dirs, filepath.Join(os.Getenv("SystemDrive")+`\`, "Users", u.Name(),
					`AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`))
			}
		}
	}
	return dirs
}

type taskXML struct {
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func scheduledTasks() []autorunEntry {
	root := filepath.Join(os.Getenv("SystemRoot"), `System32\Tasks`)
	var out []autorunEntry
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil || len(b) > 1<<20 {
			return nil
		}
		var t taskXML
		if xml.Unmarshal(utf16ToUTF8(b), &t) != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		for _, e := range t.Actions.Exec {
			out = append(out, autorunEntry{"ScheduledTask", `\` + rel, strings.TrimSpace(e.Command + " " + e.Arguments)})
		}
		return nil
	})
	return out
}

// 예약 작업 XML 은 보통 UTF-16LE(BOM) 로 저장된다. encoding/xml 은 UTF-8 만 읽으므로 변환한다.
func utf16ToUTF8(b []byte) []byte {
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]uint16, (len(b)-2)/2)
		for i := range u {
			u[i] = uint16(b[2+2*i]) | uint16(b[3+2*i])<<8
		}
		s := string(utf16.Decode(u))
		// 선언부의 encoding="UTF-16" 을 지워야 encoding/xml 이 거부하지 않는다.
		s = strings.Replace(s, `encoding="UTF-16"`, "", 1)
		return []byte(s)
	}
	return b
}

// imagePathOf 는 명령줄에서 실행 파일 경로를 뽑는다(휴리스틱).
func imagePathOf(cmd string) string {
	cmd = strings.TrimSpace(expandEnv(cmd))
	if strings.HasPrefix(cmd, `"`) {
		if i := strings.Index(cmd[1:], `"`); i > 0 {
			return cmd[1 : i+1]
		}
	}
	lower := strings.ToLower(cmd)
	for _, ext := range []string{".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lnk", ".sys"} {
		if i := strings.Index(lower, ext); i > 0 {
			p := cmd[:i+len(ext)]
			p = strings.TrimPrefix(p, `\??\`)
			if strings.HasPrefix(strings.ToLower(p), `\systemroot\`) {
				p = os.Getenv("SystemRoot") + p[len(`\systemroot`):]
			} else if strings.HasPrefix(strings.ToLower(p), `system32\`) {
				p = filepath.Join(os.Getenv("SystemRoot"), p)
			}
			return p
		}
	}
	return ""
}

func expandEnv(s string) string {
	if v, err := registry.ExpandString(s); err == nil {
		return v
	}
	return s
}

// AutorunTracker 는 기준선(baseline)과 비교해 추가/변경/삭제를 낸다.
// 직전 상태를 파일에 저장하므로, 에이전트가 꺼져 있던 동안 생긴 항목도 재시작 후 "added" 로 잡힌다.
type AutorunTracker struct {
	hasher    *hasher.Hasher
	prev      map[string]string // location|name → command 의 해시
	baseline  bool
	statePath string
}

func NewAutorunTracker(h *hasher.Hasher, stateDir string) *AutorunTracker {
	t := &AutorunTracker{hasher: h, prev: map[string]string{}, statePath: filepath.Join(stateDir, "autoruns_state.json")}
	if b, err := os.ReadFile(t.statePath); err == nil && json.Unmarshal(b, &t.prev) == nil && len(t.prev) > 0 {
		t.baseline = true
	}
	return t
}

func (t *AutorunTracker) save() {
	if b, err := json.Marshal(t.prev); err == nil {
		tmp := t.statePath + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, t.statePath)
		}
	}
}

func (t *AutorunTracker) Scan() []model.AutorunChange {
	now := time.Now().UTC()
	cur := map[string]string{}
	var out []model.AutorunChange
	for _, e := range collectAutoruns() {
		key := e.Location + "|" + e.Name
		sum := sha256.Sum256([]byte(e.Command))
		digest := hex.EncodeToString(sum[:])
		cur[key] = digest

		change := ""
		switch old, ok := t.prev[key]; {
		case !t.baseline:
			change = "baseline"
		case !ok:
			change = "added"
		case old != digest:
			change = "modified"
		}
		if change == "" {
			continue
		}
		c := model.AutorunChange{Change: change, Location: e.Location, EntryName: e.Name,
			Command: e.Command, ImagePath: imagePathOf(e.Command), ObservedAt: now}
		if c.ImagePath != "" && t.hasher != nil {
			c.SHA256, _ = t.hasher.SHA256(c.ImagePath)
		}
		out = append(out, c)
	}
	if t.baseline {
		for key := range t.prev {
			if _, ok := cur[key]; !ok {
				loc, name, _ := strings.Cut(key, "|")
				out = append(out, model.AutorunChange{Change: "removed", Location: loc, EntryName: name, ObservedAt: now})
			}
		}
	}
	t.prev = cur
	t.baseline = true
	t.save()
	return out
}
