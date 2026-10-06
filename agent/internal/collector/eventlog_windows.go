//go:build windows

package collector

// Windows 이벤트 로그 수집
//
// 사용 API: wevtapi!EvtQuery / EvtNext / EvtRender / EvtClose (읽기 전용)
//   - 실시간 구독(EvtSubscribe 콜백) 대신 "마지막 EventRecordID 이후" 를 주기적으로 조회한다.
//     → 콜백 스레드·이벤트 로그 서비스 부하가 없고, 재시작 시 상태 파일로 이어서 읽는다.
//   - 감사 정책(auditpol)을 에이전트가 바꾸지 않는다. 필요한 감사 정책은 GPO 로 설정하도록 문서화한다.
//
// 주요 이벤트
//   Security 4625 로그온 실패(무차별 대입), 4624 로그온 성공(LogonType 3/10만), 4648 명시적 자격증명 로그온,
//            4720 계정 생성, 4728/4732/4756 그룹 구성원 추가, 4698/4702 예약 작업 생성/변경, 1102 감사 로그 삭제
//   System   7045 서비스 설치, 104 로그 삭제

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/yourorg/endpoint-edr/agent/internal/model"
)

var (
	modWevtapi    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modWevtapi.NewProc("EvtQuery")
	procEvtNext   = modWevtapi.NewProc("EvtNext")
	procEvtRender = modWevtapi.NewProc("EvtRender")
	procEvtClose  = modWevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryForwardDirection = 0x100
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1
	errNoMoreItems           = 259
	errTimeout               = 1460
	batchSize                = 64
	maxEventsPerPoll         = 2000 // 한 주기에 너무 많이 읽지 않도록 상한
)

// ChannelQuery 는 채널 하나와 그 채널에서 볼 XPath 조건들이다.
// XPath 안의 %d 자리에 마지막 EventRecordID 가 들어간다.
type ChannelQuery struct {
	Channel string
	Selects []string
}

// DefaultQueries 는 기본 탐지 대상이다. 4624 는 양이 많으므로 원격 로그온(3, 10)만 받는다.
var DefaultQueries = []ChannelQuery{
	{
		Channel: "Security",
		Selects: []string{
			"*[System[(EventID=4625 or EventID=4648 or EventID=4720 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4698 or EventID=4702 or EventID=1102) and EventRecordID > %d]]",
			"*[System[EventID=4624 and EventRecordID > %d] and EventData[Data[@Name='LogonType']='10' or Data[@Name='LogonType']='3']]",
		},
	},
	{
		Channel: "System",
		Selects: []string{"*[System[(EventID=7045 or EventID=104) and EventRecordID > %d]]"},
	},
}

// EventLogReader 는 채널별 마지막 RecordID 를 상태 파일에 저장한다.
type EventLogReader struct {
	queries   []ChannelQuery
	statePath string
	last      map[string]uint64
	backfill  time.Duration // 최초 실행 시 과거 몇 시간치를 읽을지
}

func NewEventLogReader(stateDir string, queries []ChannelQuery, backfill time.Duration) *EventLogReader {
	r := &EventLogReader{queries: queries, statePath: filepath.Join(stateDir, "eventlog_state.json"),
		last: map[string]uint64{}, backfill: backfill}
	if b, err := os.ReadFile(r.statePath); err == nil {
		_ = json.Unmarshal(b, &r.last)
	}
	return r
}

// Commit 은 전송이 성공한 뒤에 호출해 상태를 저장한다. (전송 실패 시 다음 주기에 다시 읽는다)
func (r *EventLogReader) Commit(events []model.SecurityEvent) error {
	for _, e := range events {
		if e.RecordID > r.last[e.Channel] {
			r.last[e.Channel] = e.RecordID
		}
	}
	b, _ := json.Marshal(r.last)
	tmp := r.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.statePath)
}

// Poll 은 새 이벤트를 읽는다. 상태 저장은 Commit 에서 한다.
func (r *EventLogReader) Poll() ([]model.SecurityEvent, error) {
	var all []model.SecurityEvent
	var errs []error
	for _, q := range r.queries {
		last, known := r.last[q.Channel]
		if known {
			// 로그가 삭제(clear)되어 RecordID 가 되감긴 경우 처음부터 다시 읽는다.
			if newest, err := newestRecordID(q.Channel); err == nil && newest < last {
				last, known = 0, false
			}
		}
		xpaths := make([]string, len(q.Selects))
		for i, s := range q.Selects {
			x := fmt.Sprintf(s, last)
			if !known && r.backfill > 0 {
				// 최초 실행: 최근 backfill 시간치만 읽는다.
				x = strings.Replace(x, "*[System[", fmt.Sprintf("*[System[TimeCreated[timediff(@SystemTime) <= %d] and ", r.backfill.Milliseconds()), 1)
			}
			xpaths[i] = x
		}
		evs, err := queryChannel(q.Channel, buildQueryList(q.Channel, xpaths))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", q.Channel, err))
		}
		all = append(all, evs...)
	}
	return all, errors.Join(errs...)
}

func buildQueryList(channel string, selects []string) string {
	var sb strings.Builder
	sb.WriteString(`<QueryList><Query Id="0" Path="` + xmlEscape(channel) + `">`)
	for _, s := range selects {
		sb.WriteString(`<Select Path="` + xmlEscape(channel) + `">` + xmlEscape(s) + `</Select>`)
	}
	sb.WriteString(`</Query></QueryList>`)
	return sb.String()
}

func xmlEscape(s string) string {
	var sb strings.Builder
	_ = xml.EscapeText(&sb, []byte(s))
	return sb.String()
}

func evtClose(h uintptr) { procEvtClose.Call(h) }

func queryChannel(channel, structuredQuery string) ([]model.SecurityEvent, error) {
	q, err := windows.UTF16PtrFromString(structuredQuery)
	if err != nil {
		return nil, err
	}
	// 구조화(XML) 쿼리는 Path 인자를 NULL 로 넘긴다.
	rs, _, callErr := procEvtQuery.Call(0, 0, uintptr(unsafe.Pointer(q)), evtQueryChannelPath|evtQueryForwardDirection)
	if rs == 0 {
		return nil, fmt.Errorf("EvtQuery: %w", callErr)
	}
	defer evtClose(rs)

	var out []model.SecurityEvent
	handles := make([]uintptr, batchSize)
	for len(out) < maxEventsPerPoll {
		var returned uint32
		ok, _, callErr := procEvtNext.Call(rs, batchSize, uintptr(unsafe.Pointer(&handles[0])), 1000, 0,
			uintptr(unsafe.Pointer(&returned)))
		if ok == 0 {
			if en, isErrno := callErr.(windows.Errno); isErrno && (en == errNoMoreItems || en == errTimeout) {
				break
			}
			return out, fmt.Errorf("EvtNext: %w", callErr)
		}
		for i := uint32(0); i < returned; i++ {
			if x, err := renderXML(handles[i]); err == nil {
				if e, err := parseEventXML(channel, x); err == nil && keepEvent(e) {
					out = append(out, e)
				}
			}
			evtClose(handles[i])
		}
	}
	return out, nil
}

func newestRecordID(channel string) (uint64, error) {
	path, _ := windows.UTF16PtrFromString(channel)
	query, _ := windows.UTF16PtrFromString("*")
	rs, _, callErr := procEvtQuery.Call(0, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(query)),
		evtQueryChannelPath|evtQueryReverseDirection)
	if rs == 0 {
		return 0, callErr
	}
	defer evtClose(rs)
	var h uintptr
	var returned uint32
	ok, _, callErr := procEvtNext.Call(rs, 1, uintptr(unsafe.Pointer(&h)), 1000, 0, uintptr(unsafe.Pointer(&returned)))
	if ok == 0 || returned == 0 {
		return 0, callErr
	}
	defer evtClose(h)
	x, err := renderXML(h)
	if err != nil {
		return 0, err
	}
	e, err := parseEventXML(channel, x)
	return e.RecordID, err
}

func renderXML(h uintptr) (string, error) {
	var used, props uint32
	procEvtRender.Call(0, h, evtRenderEventXML, 0, 0, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if used == 0 {
		return "", errors.New("EvtRender: empty")
	}
	buf := make([]uint16, used/2+1)
	ok, _, callErr := procEvtRender.Call(0, h, evtRenderEventXML, uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if ok == 0 {
		return "", callErr
	}
	return windows.UTF16ToString(buf), nil
}

// ---- XML 파싱 ----

type xmlEvent struct {
	Provider struct {
		Name string `xml:"Name,attr"`
	} `xml:"System>Provider"`
	EventID     uint32 `xml:"System>EventID"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"System>TimeCreated"`
	RecordID uint64 `xml:"System>EventRecordID"`
	Data     []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

func parseEventXML(channel, x string) (model.SecurityEvent, error) {
	var ev xmlEvent
	if err := xml.Unmarshal([]byte(x), &ev); err != nil {
		return model.SecurityEvent{}, err
	}
	t, _ := time.Parse(time.RFC3339Nano, ev.TimeCreated.SystemTime)
	e := model.SecurityEvent{
		Channel: channel, EventID: ev.EventID, RecordID: ev.RecordID,
		EventTime: t.UTC(), Provider: ev.Provider.Name, Data: map[string]string{},
	}
	for _, d := range ev.Data {
		if d.Name != "" {
			e.Data[d.Name] = strings.TrimSpace(d.Value)
		}
	}
	e.TargetUser = e.Data["TargetUserName"]
	e.TargetDomain = e.Data["TargetDomainName"]
	e.LogonType, _ = strconv.Atoi(e.Data["LogonType"])
	e.SourceIP = cleanDash(e.Data["IpAddress"])
	e.SourcePort = cleanDash(e.Data["IpPort"])
	e.Workstation = cleanDash(e.Data["WorkstationName"])
	e.Status = e.Data["Status"]
	e.SubStatus = e.Data["SubStatus"]
	e.ProcessName = cleanDash(e.Data["ProcessName"])
	if e.EventID == 7045 { // 서비스 설치: 서비스명/경로를 정규 필드로
		e.TargetUser = e.Data["AccountName"]
		e.ProcessName = e.Data["ImagePath"]
	}
	return e, nil
}

func cleanDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// keepEvent 는 노이즈를 줄인다: 로컬 루프백에서 온 네트워크 로그온(4624 type 3)은 버린다.
func keepEvent(e model.SecurityEvent) bool {
	if e.EventID == 4624 && e.LogonType == 3 {
		switch e.SourceIP {
		case "", "127.0.0.1", "::1":
			return false
		}
	}
	return true
}
