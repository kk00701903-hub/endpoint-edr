// Package docscan 은 보안 관리자의 PC 문서 감사(개인정보·키워드·오래된 문서)를 한다.
//
// 원칙
//   - 문서를 "읽기만" 한다(공유 모드로 열기, 파일·속성 변경 없음). 클라우드 전용 파일(OneDrive 자리 표시자)은 내려받지 않도록 건너뛴다.
//   - 서버로는 "어느 파일에 무엇이 몇 건"만 보낸다. 주민등록번호 같은 값과 문서 내용은 보내지 않는다.
//   - 이 파일(detect.go)과 추출기는 OS 와 무관해 리눅스에서도 단위 시험한다.
package docscan

import (
	"regexp"
	"strings"
)

// 검출 종류(서버 doc_scan_policies.detect 와 같은 이름)
const (
	KindRRN      = "rrn"      // 주민등록번호
	KindFRN      = "frn"      // 외국인등록번호
	KindPassport = "passport" // 여권번호
	KindDriver   = "driver"   // 운전면허번호
	KindCard     = "card"     // 신용카드 번호
	KindPhone    = "phone"    // 휴대폰 번호
)

// AllKinds 는 지원하는 검출 종류 전체다.
var AllKinds = []string{KindRRN, KindFRN, KindPassport, KindDriver, KindCard, KindPhone}

var (
	// 앞뒤가 숫자가 아닌 13자리(구분자 없음) 또는 6-7자리(하이픈·공백)
	reRegNo    = regexp.MustCompile(`(?:^|[^0-9])(\d{2})(\d{2})(\d{2})([-\s]?)([1-8])(\d{6})(?:[^0-9]|$)`)
	rePassport = regexp.MustCompile(`(?:^|[^0-9A-Za-z])([MSRODG]\d{8}|[MSRODG]\d{3}[A-Z]\d{4})(?:[^0-9A-Za-z]|$)`)
	reDriver   = regexp.MustCompile(`(?:^|[^0-9])(1[1-9]|2[0-8])[-\s](\d{2})[-\s](\d{6})[-\s](\d{2})(?:[^0-9]|$)`)
	reCard     = regexp.MustCompile(`(?:^|[^0-9])(\d{4})([-\s]?)(\d{4})([-\s]?)(\d{4})([-\s]?)(\d{4})(?:[^0-9]|$)`)
	rePhone    = regexp.MustCompile(`(?:^|[^0-9])01[016789][-\s.]?\d{3,4}[-\s.]?\d{4}(?:[^0-9]|$)`)
)

// Detector 는 켜 둔 검출 종류와 키워드로 텍스트를 센다.
type Detector struct {
	kinds    map[string]bool
	keywords []string // 원래 표기(결과 키)
	lowered  []string
}

func NewDetector(kinds, keywords []string) *Detector {
	d := &Detector{kinds: map[string]bool{}}
	for _, k := range kinds {
		d.kinds[k] = true
	}
	seen := map[string]bool{}
	for _, k := range keywords {
		k = strings.TrimSpace(k)
		lk := strings.ToLower(k)
		if k == "" || seen[lk] || len(d.keywords) >= 50 {
			continue
		}
		seen[lk] = true
		d.keywords = append(d.keywords, k)
		d.lowered = append(d.lowered, lk)
	}
	return d
}

// HasContentChecks 는 문서 내용을 읽어야 하는지(검출 종류나 키워드가 하나라도 있는지)다.
func (d *Detector) HasContentChecks() bool { return len(d.kinds) > 0 || len(d.keywords) > 0 }

// Count 는 종류별 개인정보 건수와 키워드별 등장 횟수를 돌려준다(0 건은 넣지 않는다).
func (d *Detector) Count(text string) (pii map[string]int, kw map[string]int) {
	pii = map[string]int{}
	if d.kinds[KindRRN] || d.kinds[KindFRN] {
		for _, m := range allOverlapping(reRegNo, text) {
			if kind := classifyRegNo(m); kind != "" && d.kinds[kind] {
				pii[kind]++
			}
		}
	}
	if d.kinds[KindPassport] {
		if n := len(allOverlapping(rePassport, text)); n > 0 {
			pii[KindPassport] = n
		}
	}
	if d.kinds[KindDriver] {
		if n := len(allOverlapping(reDriver, text)); n > 0 {
			pii[KindDriver] = n
		}
	}
	if d.kinds[KindCard] {
		n := 0
		for _, m := range allOverlapping(reCard, text) {
			// 구분자는 모두 같거나 모두 없어야(1234-5678 9012-3456 같은 우연한 조합 제외), 그리고 Luhn 검사 통과
			if m[2] == m[4] && m[4] == m[6] && luhn(m[1]+m[3]+m[5]+m[7]) {
				n++
			}
		}
		if n > 0 {
			pii[KindCard] = n
		}
	}
	if d.kinds[KindPhone] {
		if n := len(allOverlapping(rePhone, text)); n > 0 {
			pii[KindPhone] = n
		}
	}
	if len(d.keywords) > 0 {
		lt := strings.ToLower(text)
		for i, k := range d.lowered {
			if n := strings.Count(lt, k); n > 0 {
				if kw == nil {
					kw = map[string]int{}
				}
				kw[d.keywords[i]] = n
			}
		}
	}
	if len(pii) == 0 {
		pii = nil
	}
	return pii, kw
}

// allOverlapping 은 앞뒤 경계 문자를 공유하는 연속 일치(예: "a,b" 두 번호)도 놓치지 않도록 한 글자씩 겹쳐 찾는다.
func allOverlapping(re *regexp.Regexp, s string) [][]string {
	var out [][]string
	for start := 0; start < len(s); {
		loc := re.FindStringSubmatchIndex(s[start:])
		if loc == nil {
			break
		}
		m := make([]string, len(loc)/2)
		for i := range m {
			if loc[2*i] >= 0 {
				m[i] = s[start+loc[2*i] : start+loc[2*i+1]]
			}
		}
		out = append(out, m)
		// 다음 검색은 일치 끝 바로 앞 글자부터(뒤 경계 문자를 다음 일치의 앞 경계로 다시 쓸 수 있게)
		next := start + loc[1] - 1
		if next <= start {
			next = start + 1
		}
		start = next
	}
	return out
}

// classifyRegNo 는 주민·외국인등록번호 후보를 판정한다. 아니면 "".
//   - 생년월일이 실제 날짜여야 한다.
//   - 구분자(하이픈·공백) 없이 13자리가 붙어 있으면 다른 숫자(주문번호 등)와 헷갈리므로 검증 숫자까지 맞아야 한다.
//     (2020년 10월 이후 새로 받은 번호는 검증 숫자 규칙이 없어, 구분자가 있는 표기는 검증 숫자를 보지 않는다)
func classifyRegNo(m []string) string {
	yy, mm, dd, sep, g, rest := m[1], m[2], m[3], m[4], m[5], m[6]
	month := atoi2(mm)
	day := atoi2(dd)
	if month < 1 || month > 12 || day < 1 || day > daysIn(month) {
		return ""
	}
	if sep == "" && !regNoChecksum(yy+mm+dd+g+rest) {
		return ""
	}
	if g >= "5" {
		return KindFRN
	}
	return KindRRN
}

func atoi2(s string) int { return int(s[0]-'0')*10 + int(s[1]-'0') }

func daysIn(month int) int {
	switch month {
	case 2:
		return 29
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

func regNoChecksum(d string) bool {
	if len(d) != 13 {
		return false
	}
	w := []int{2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5}
	sum := 0
	for i, x := range w {
		sum += int(d[i]-'0') * x
	}
	return (11-sum%11)%10 == int(d[12]-'0')
}

func luhn(d string) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0 && strings.Trim(d, "0") != ""
}
