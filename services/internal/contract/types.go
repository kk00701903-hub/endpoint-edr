// Package contract 는 agent/internal/model/types.go 의 사본이다(서버 측 디코딩용).
// 원본은 contracts/ingest.schema.json — 바꿀 때는 세 곳을 함께 수정한다.
// 필드를 바꾸면 contracts/ingest.schema.json, services/ingest, supabase 마이그레이션을 함께 바꿔야 한다.
package contract

import "time"

// Envelope 는 한 번의 전송 단위(배치)다. device_id 는 서버가 토큰으로 판별하므로 보내지 않는다.
type Envelope struct {
	AgentVersion   string          `json:"agent_version"`
	Hostname       string          `json:"hostname"`
	SentAt         time.Time       `json:"sent_at"`
	Snapshot       bool            `json:"snapshot"` // true 면 차분(diff)이 아닌 전체 스냅샷
	Processes      []Process       `json:"processes,omitempty"`
	ProcessExits   []ProcessExit   `json:"process_exits,omitempty"`
	Connections    []Connection    `json:"connections,omitempty"`
	SecurityEvents []SecurityEvent `json:"security_events,omitempty"`
	Autoruns       []AutorunChange `json:"autoruns,omitempty"`
	Health         *AgentHealth    `json:"health,omitempty"`    // 5분마다 1회
	Inventory      *Inventory      `json:"inventory,omitempty"` // 자산 정보 전체: 바뀌었을 때 또는 24시간마다
	Posture        []PostureCheck  `json:"posture,omitempty"`   // 보안 상태 점검 전체: 바뀌었을 때 또는 6시간마다
	DocScan        *DocScanBatch   `json:"doc_scan,omitempty"`  // 문서 감사 결과(관리자 정책이 켜져 있을 때만)
}

// ProcessExit 는 직전 스캔 이후 사라진 프로세스다. 서버의 "현재 프로세스" 표에서 지운다.
type ProcessExit struct {
	PID        uint32    `json:"pid"`
	CreateTime time.Time `json:"create_time,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// AgentHealth 는 에이전트 자신의 자원 사용량이다. 콘솔에서 "충돌 없이 가볍게 도는지"를 전 PC 에 대해 보여준다.
type AgentHealth struct {
	UptimeSec    int64            `json:"uptime_sec"`
	CPUPercent   float64          `json:"cpu_percent"`    // 직전 보고 이후 평균(전체 코어 대비 %)
	WorkingSetMB float64          `json:"working_set_mb"` // 에이전트 프로세스 실메모리
	Goroutines   int              `json:"goroutines"`
	SpoolFiles   int              `json:"spool_files"`
	SpoolBytes   int64            `json:"spool_bytes"`
	ScanMillis   map[string]int64 `json:"scan_ms"`               // 수집기별 마지막 소요 시간
	LastErrors   []string         `json:"last_errors,omitempty"` // 최근 오류 최대 5개
}

// Process 는 Process Explorer 의 한 행에 해당한다.
type Process struct {
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	Name        string    `json:"name"`
	Path        string    `json:"path,omitempty"`
	CommandLine string    `json:"command_line,omitempty"`
	User        string    `json:"user,omitempty"`
	SHA256      string    `json:"sha256,omitempty"`
	CreateTime  time.Time `json:"create_time"`
	ObservedAt  time.Time `json:"observed_at"`
}

// Connection 은 TCPView 의 한 행에 해당한다.
type Connection struct {
	Proto       string    `json:"proto"`     // tcp4 | tcp6 | udp4 | udp6
	Direction   string    `json:"direction"` // listen | inbound | outbound | bound(udp)
	LocalIP     string    `json:"local_ip"`
	LocalPort   uint16    `json:"local_port"`
	RemoteIP    string    `json:"remote_ip,omitempty"`
	RemotePort  uint16    `json:"remote_port,omitempty"`
	State       string    `json:"state"`
	PID         uint32    `json:"pid"`
	ProcessName string    `json:"process_name,omitempty"`
	IsExternal  bool      `json:"is_external"` // 원격지가 공인 IP 인지
	ObservedAt  time.Time `json:"observed_at"`
}

// SecurityEvent 는 Windows 이벤트 로그에서 정규화한 보안 이벤트다.
type SecurityEvent struct {
	Channel      string            `json:"channel"`
	EventID      uint32            `json:"event_id"`
	RecordID     uint64            `json:"record_id"`
	EventTime    time.Time         `json:"event_time"`
	Provider     string            `json:"provider"`
	TargetUser   string            `json:"target_user,omitempty"`
	TargetDomain string            `json:"target_domain,omitempty"`
	LogonType    int               `json:"logon_type,omitempty"`
	SourceIP     string            `json:"src_ip,omitempty"`
	SourcePort   string            `json:"src_port,omitempty"`
	Workstation  string            `json:"workstation,omitempty"`
	Status       string            `json:"status,omitempty"`
	SubStatus    string            `json:"sub_status,omitempty"`
	ProcessName  string            `json:"process_name,omitempty"`
	Data         map[string]string `json:"data,omitempty"` // 원본 EventData 전체(분석용)
}

// AutorunChange 는 Autoruns 항목의 추가/변경/삭제다.
type AutorunChange struct {
	Change     string    `json:"change"`   // added | modified | removed | baseline
	Location   string    `json:"location"` // 예: HKLM\...\Run, ScheduledTask, Service
	EntryName  string    `json:"entry_name"`
	Command    string    `json:"command,omitempty"`
	ImagePath  string    `json:"image_path,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// Inventory 는 자산 정보(OS·하드웨어·네트워크·설치 프로그램)다. 매번 전체를 보낸다(서버가 이전 목록과 비교).
type Inventory struct {
	CollectedAt  time.Time  `json:"collected_at"`
	OS           OSInfo     `json:"os"`
	Hardware     Hardware   `json:"hardware"`
	Domain       string     `json:"domain,omitempty"`
	DomainJoined bool       `json:"domain_joined"`
	LastUser     string     `json:"last_user,omitempty"`
	Adapters     []Adapter  `json:"adapters,omitempty"`
	Software     []Software `json:"software,omitempty"`
}

type OSInfo struct {
	Name           string    `json:"name,omitempty"`            // ProductName 예: Windows 11 Pro
	Edition        string    `json:"edition,omitempty"`         // EditionID 예: Professional, Enterprise
	DisplayVersion string    `json:"display_version,omitempty"` // 예: 24H2
	Build          int       `json:"build,omitempty"`
	UBR            int       `json:"ubr,omitempty"`
	InstallType    string    `json:"install_type,omitempty"` // Client | Server
	InstalledAt    time.Time `json:"installed_at,omitempty"`
	Arch           string    `json:"arch,omitempty"`
}

type Hardware struct {
	Manufacturer string  `json:"manufacturer,omitempty"`
	Model        string  `json:"model,omitempty"`
	Serial       string  `json:"serial,omitempty"`
	BIOSVersion  string  `json:"bios_version,omitempty"`
	CPU          string  `json:"cpu,omitempty"`
	Cores        int     `json:"cores,omitempty"`
	MemoryMB     int64   `json:"memory_mb,omitempty"`
	DiskTotalGB  float64 `json:"disk_total_gb,omitempty"` // 시스템 드라이브
	DiskFreeGB   float64 `json:"disk_free_gb,omitempty"`
}

type Adapter struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac,omitempty"`
	IPs  []string `json:"ips,omitempty"`
}

// Software 는 설치 프로그램(제어판 "프로그램 제거" 목록과 같은 출처) 한 줄이다.
type Software struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	InstallDate string `json:"install_date,omitempty"` // YYYYMMDD
	Scope       string `json:"scope,omitempty"`        // machine | user
	Arch        string `json:"arch,omitempty"`         // x64 | x86
}

// PostureCheck 는 보안 설정 점검 한 항목의 결과다. ID 는 서버의 posture_checks.check_id 와 같다.
type PostureCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"` // pass | warn | fail | unknown
	Detail string `json:"detail,omitempty"`
}

// DocScanBatch 는 문서 감사 한 번의 결과 묶음이다. 결과가 많으면 여러 배치로 나눠 보내고 마지막 배치에 Final=true.
// 문서 내용·개인정보 값은 담지 않는다 — 파일 위치와 종류별 건수만.
type DocScanBatch struct {
	ScanID       string       `json:"scan_id"`              // 에이전트가 만든 검사 ID(16진수)
	Trigger      string       `json:"trigger"`              // schedule | request
	RequestID    int64        `json:"request_id,omitempty"` // 콘솔 "지금 검사" 요청 번호
	StartedAt    time.Time    `json:"started_at"`
	FinishedAt   time.Time    `json:"finished_at,omitempty"`
	Final        bool         `json:"final"`
	FilesScanned int          `json:"files_scanned"`
	FilesSkipped int          `json:"files_skipped"` // 너무 큼·암호·클라우드 전용·읽기 실패
	Errors       int          `json:"errors"`
	Findings     []DocFinding `json:"findings,omitempty"` // 배치당 최대 200개
}

// DocFinding 은 검사 결과 문서 하나다(개인정보·키워드가 있거나, 오래된 문서).
type DocFinding struct {
	Path       string         `json:"path"`
	Size       int64          `json:"size"`
	ModifiedAt time.Time      `json:"modified_at"`          // 마지막 저장 시각
	PII        map[string]int `json:"pii,omitempty"`        // rrn·frn·passport·driver·card·phone → 건수
	Keywords   map[string]int `json:"keywords,omitempty"`   // 키워드 → 등장 횟수
	Stale      bool           `json:"stale,omitempty"`      // 정책의 기준보다 오래 저장되지 않은 문서
	Unreadable string         `json:"unreadable,omitempty"` // 읽지 못한 이유(암호 등) — 오래된 문서일 때만 함께 보냄
}
