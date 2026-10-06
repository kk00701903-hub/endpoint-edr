package collector

// 자산 정보·보안 상태 수집의 OS 와 무관한 부분(리눅스에서도 단위 시험 가능).
// 실제 수집(레지스트리·Win32 API 읽기)은 inventory_windows.go, posture_windows.go 에 있다.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// changeGate 는 "바뀌었을 때, 또는 마지막 전송 후 every 가 지났을 때"만 보내게 한다.
// 비교에서 뺄 값(수집 시각 등)은 호출하는 쪽이 지운 뒤 넘긴다.
type changeGate struct {
	every  time.Duration
	last   [32]byte
	sentAt time.Time
}

func (g *changeGate) due(v any, now time.Time) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return true
	}
	h := sha256.Sum256(b)
	return h != g.last || g.sentAt.IsZero() || now.Sub(g.sentAt) >= g.every
}

func (g *changeGate) mark(v any, now time.Time) {
	b, _ := json.Marshal(v)
	g.last = sha256.Sum256(b)
	g.sentAt = now
}

// ---------------- 설치 프로그램 목록 정리 ----------------

var kbName = regexp.MustCompile(`(?i)\bKB\d{6,8}\b`)

// keepSoftware 는 "프로그램 제거" 목록에 보이는 항목만 남긴다(Windows 가 숨기는 구성 요소·업데이트 제외).
func keepSoftware(name string, systemComponent uint64, parentKey, releaseType string) bool {
	if strings.TrimSpace(name) == "" || systemComponent == 1 || parentKey != "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(releaseType)) {
	case "update", "hotfix", "security update", "update rollup", "service pack":
		return false
	}
	return !kbName.MatchString(name) || strings.Contains(strings.ToLower(name), "visual c++")
}

var yyyymmdd = regexp.MustCompile(`^(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])$`)

// normalizeInstallDate 는 레지스트리 InstallDate(보통 YYYYMMDD, 가끔 다른 형식)를 YYYYMMDD 로. 모르면 빈 문자열.
func normalizeInstallDate(s string) string {
	s = strings.TrimSpace(s)
	if yyyymmdd.MatchString(s) {
		return s
	}
	for _, layout := range []string{"2006-01-02", "1/2/2006", "01/02/2006", "2006/01/02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Format("20060102")
		}
	}
	return ""
}

// osProductName 은 레지스트리 ProductName 을 고친다. Windows 11 도 ProductName 이 "Windows 10 ..." 으로 남아 있다.
func osProductName(product string, build int) string {
	if build >= 22000 && strings.HasPrefix(product, "Windows 10") {
		return "Windows 11" + strings.TrimPrefix(product, "Windows 10")
	}
	return product
}

// ---------------- SMBIOS (GetSystemFirmwareTable 'RSMB') ----------------

// smbiosSystem 은 SMBIOS 구조 형식 1(System Information)의 제조사·모델·일련번호와 형식 0(BIOS)의 버전이다.
type smbiosSystem struct {
	Manufacturer, Product, Serial, BIOSVersion string
}

// parseSMBIOS 는 RawSMBIOSData(8바이트 머리 + SMBIOS 구조들)를 읽는다. 잘못된 데이터면 찾은 만큼만 돌려준다(panic 없음).
func parseSMBIOS(raw []byte) smbiosSystem {
	var out smbiosSystem
	if len(raw) < 8 {
		return out
	}
	n := int(binary.LittleEndian.Uint32(raw[4:8]))
	data := raw[8:]
	if n < len(data) {
		data = data[:n]
	}
	for i := 0; i+4 <= len(data); {
		typ, length := data[i], int(data[i+1])
		if length < 4 || i+length > len(data) {
			break
		}
		formatted := data[i : i+length]
		// 문자열 영역: 형식 영역 뒤에 0 으로 끝나는 문자열이 이어지고, 0 두 개로 끝난다(문자열이 없으면 0 0)
		j := i + length
		var strs []string
		if j+1 < len(data) && data[j] == 0 && data[j+1] == 0 {
			j += 2
		} else {
			start := j
			for j < len(data) {
				if data[j] == 0 {
					strs = append(strs, string(data[start:j]))
					if j+1 < len(data) && data[j+1] == 0 {
						j += 2
						break
					}
					start = j + 1
				}
				j++
			}
		}
		str := func(off int) string {
			if off >= len(formatted) {
				return ""
			}
			idx := int(formatted[off])
			if idx == 0 || idx > len(strs) {
				return ""
			}
			return cleanSMBIOS(strs[idx-1])
		}
		switch typ {
		case 0:
			if out.BIOSVersion == "" {
				out.BIOSVersion = str(0x05)
			}
		case 1:
			if out.Manufacturer == "" {
				out.Manufacturer, out.Product, out.Serial = str(0x04), str(0x05), str(0x07)
			}
		case 127: // 끝 표시
			return out
		}
		i = j
	}
	return out
}

// 제조사가 비워 둔 자리 표시 값은 버린다
func cleanSMBIOS(s string) string {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "to be filled by o.e.m.", "default string", "system serial number", "not specified", "none", "0", "0123456789", "n/a":
		return ""
	}
	return s
}
