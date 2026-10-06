// Package config 는 C:\ProgramData\EndpointEDR\config.json 을 읽는다.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	d.Duration = v
	return err
}

type Config struct {
	IngestURL     string `json:"ingest_url"`     // 예: https://ingest.example.com
	EnrollmentKey string `json:"enrollment_key"` // 최초 등록 후 파일에서 지워도 된다

	ProcessInterval   Duration `json:"process_interval"`
	NetworkInterval   Duration `json:"network_interval"`
	EventLogInterval  Duration `json:"eventlog_interval"`
	AutorunInterval   Duration `json:"autorun_interval"`
	FullSnapshotEvery Duration `json:"full_snapshot_every"`
	InventoryInterval Duration `json:"inventory_interval"` // 자산 정보 점검 주기(바뀌었을 때·24시간마다만 전송)
	PostureInterval   Duration `json:"posture_interval"`   // 보안 설정 점검 주기(바뀌었을 때·6시간마다만 전송)
	PolicyInterval    Duration `json:"policy_interval"`    // 서버 정책(문서 감사 켜짐·지금 검사 요청) 확인 주기
	DocScanMBPerSec   int64    `json:"docscan_mb_per_sec"` // 문서 감사 때 초당 읽기 상한

	HashMaxFileMB int64    `json:"hash_max_file_mb"`
	HashMBPerSec  int64    `json:"hash_mb_per_sec"`
	MemoryLimitMB uint64   `json:"memory_limit_mb"`
	SpoolMaxMB    int64    `json:"spool_max_mb"`
	EventBackfill Duration `json:"eventlog_backfill"`
	// AVServices 는 실시간 감시 백신으로 인정할 서비스 이름을 더한다(기본 목록: collector.DefaultAVServices).
	// 예: 사내 백신이 AhnLab V3 면 `sc query` 로 확인한 서비스 이름을 넣는다.
	AVServices []string `json:"av_services"`

	DataDir string `json:"-"`
}

func DefaultDataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "EndpointEDR")
}

func Load(dataDir string) (*Config, error) {
	c := &Config{
		ProcessInterval:   Duration{60 * time.Second},
		NetworkInterval:   Duration{15 * time.Second},
		EventLogInterval:  Duration{10 * time.Second},
		AutorunInterval:   Duration{10 * time.Minute},
		FullSnapshotEvery: Duration{1 * time.Hour},
		InventoryInterval: Duration{6 * time.Hour},
		PostureInterval:   Duration{1 * time.Hour},
		PolicyInterval:    Duration{15 * time.Minute},
		DocScanMBPerSec:   8,
		HashMaxFileMB:     200,
		HashMBPerSec:      20,
		MemoryLimitMB:     150,
		SpoolMaxMB:        50,
		EventBackfill:     Duration{24 * time.Hour},
		DataDir:           dataDir,
	}
	b, err := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, os.MkdirAll(filepath.Join(dataDir, "spool"), 0o700)
}
