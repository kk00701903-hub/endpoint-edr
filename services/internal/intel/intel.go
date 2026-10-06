// Package intel 은 파일 해시 평판 조회 공급자들이다.
//
// 원칙
//   - 해시(SHA-256)만 조회한다. 파일 자체는 절대 업로드하지 않는다(사내 문서·프로그램 유출 방지).
//   - 공급자별 속도 제한을 지킨다.
//
// ⚠ 약관 주의 (사내 사용)
//   - VirusTotal Public API 는 분당 4회·하루 500회 제한이 있고 업무용 사용 제한 조항이 있다.
//     사내 사용 전에 약관을 확인하고, 필요하면 유료(Premium) 계약을 검토할 것.
//   - MalwareBazaar(abuse.ch) 는 Auth-Key 가 필요하며 이용 약관을 확인할 것.
package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Result struct {
	Provider   string         `json:"provider"`
	Found      bool           `json:"found"`
	Malicious  int            `json:"malicious,omitempty"`
	Suspicious int            `json:"suspicious,omitempty"`
	Total      int            `json:"total,omitempty"`
	Label      string         `json:"label,omitempty"` // 예: 악성코드 패밀리명
	Raw        map[string]any `json:"raw,omitempty"`
}

type Provider interface {
	Name() string
	Interval() time.Duration // 요청 간 최소 간격
	Lookup(ctx context.Context, sha256 string) (Result, error)
}

var httpClient = &http.Client{Timeout: 20 * time.Second}

// ---------------- VirusTotal v3 ----------------

type VirusTotal struct {
	APIKey         string
	RequestsPerMin int // Public API 기본 4
}

func (v *VirusTotal) Name() string { return "virustotal" }
func (v *VirusTotal) Interval() time.Duration {
	rpm := v.RequestsPerMin
	if rpm <= 0 {
		rpm = 4
	}
	return time.Minute / time.Duration(rpm)
}

func (v *VirusTotal) Lookup(ctx context.Context, sha string) (Result, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.virustotal.com/api/v3/files/"+sha, nil)
	req.Header.Set("x-apikey", v.APIKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	res := Result{Provider: v.Name()}
	switch resp.StatusCode {
	case http.StatusNotFound:
		return res, nil
	case http.StatusOK:
	case http.StatusTooManyRequests:
		return res, fmt.Errorf("virustotal: rate limited")
	default:
		return res, fmt.Errorf("virustotal: %s", resp.Status)
	}
	var body struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
				Threat struct {
					Label string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return res, err
	}
	st := body.Data.Attributes.Stats
	res.Found = true
	res.Malicious, res.Suspicious = st.Malicious, st.Suspicious
	res.Total = st.Malicious + st.Suspicious + st.Undetected + st.Harmless
	res.Label = body.Data.Attributes.Threat.Label
	return res, nil
}

// ---------------- MalwareBazaar (abuse.ch) ----------------

type MalwareBazaar struct{ AuthKey string }

func (m *MalwareBazaar) Name() string            { return "malwarebazaar" }
func (m *MalwareBazaar) Interval() time.Duration { return 2 * time.Second }

func (m *MalwareBazaar) Lookup(ctx context.Context, sha string) (Result, error) {
	form := url.Values{"query": {"get_info"}, "hash": {sha}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://mb-api.abuse.ch/api/v1/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Auth-Key", m.AuthKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("malwarebazaar: %s", resp.Status)
	}
	var body struct {
		Status string `json:"query_status"`
		Data   []struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body); err != nil {
		return Result{}, err
	}
	res := Result{Provider: m.Name()}
	if body.Status == "ok" && len(body.Data) > 0 {
		res.Found, res.Malicious, res.Total, res.Label = true, 1, 1, body.Data[0].Signature
	}
	return res, nil
}

// ---------------- 판정 ----------------

// Verdict 는 여러 공급자 결과를 하나로 합친다. 임계값은 운영하며 조정한다.
func Verdict(results []Result) string {
	found := false
	for _, r := range results {
		if !r.Found {
			continue
		}
		found = true
		switch {
		case r.Provider == "malwarebazaar":
			return "malicious" // 악성 샘플 저장소에 존재
		case r.Malicious >= 5:
			return "malicious"
		case r.Malicious >= 1 || r.Suspicious >= 3:
			return "suspicious"
		}
	}
	if found {
		return "clean"
	}
	return "unknown"
}

// NextCheck 는 판정별 재조회 주기다(새 백신 시그니처가 나오면 판정이 바뀔 수 있음).
func NextCheck(verdict string) time.Duration {
	switch verdict {
	case "unknown":
		return 24 * time.Hour
	case "clean":
		return 30 * 24 * time.Hour
	case "suspicious":
		return 3 * 24 * time.Hour
	case "malicious":
		return 90 * 24 * time.Hour
	default:
		return time.Hour
	}
}
