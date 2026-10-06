//go:build windows

package collector

// 네트워크 연결 수집 (TCPView 역할)
//
// 사용 API: iphlpapi!GetExtendedTcpTable / GetExtendedUdpTable (TABLE_OWNER_PID)
//   - netstat -ano 와 같은 정보원. 패킷 캡처·WFP 필터·드라이버를 쓰지 않는다.
//   - 폴링 방식이라 아주 짧게 열렸다 닫힌 연결은 놓칠 수 있다(수동형 설계의 한계, 문서화됨).

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/yourorg/endpoint-edr/agent/internal/model"
)

var (
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	afInet               = 2
	afInet6              = 23
	tcpTableOwnerPidAll  = 5
	udpTableOwnerPid     = 1
	errInsufficientBuf   = 122
	tcpStateListen       = 2
	tcpStateEstablished  = 5
	sizeTCP4Row          = 24 // MIB_TCPROW_OWNER_PID
	sizeTCP6Row          = 56 // MIB_TCP6ROW_OWNER_PID
	sizeUDP4Row          = 12 // MIB_UDPROW_OWNER_PID
	sizeUDP6Row          = 28 // MIB_UDP6ROW_OWNER_PID
	maxTableFetchRetries = 4
)

var tcpStates = map[uint32]string{
	1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
	6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
	11: "TIME_WAIT", 12: "DELETE_TCB",
}

// fetchTable 은 테이블 크기가 호출 사이에 바뀌는 경우를 대비해 몇 번 재시도한다.
func fetchTable(proc *windows.LazyProc, af, class uintptr) ([]byte, error) {
	var size uint32
	var buf []byte
	for i := 0; i < maxTableFetchRetries; i++ {
		var ptr uintptr
		if len(buf) > 0 {
			ptr = uintptr(unsafe.Pointer(&buf[0]))
		}
		r, _, _ := proc.Call(ptr, uintptr(unsafe.Pointer(&size)), 0, af, class, 0)
		switch r {
		case 0:
			return buf[:size], nil
		case errInsufficientBuf:
			buf = make([]byte, size+4096) // 여유분
			size = uint32(len(buf))
		default:
			return nil, fmt.Errorf("%s failed: %d", proc.Name, r)
		}
	}
	return nil, fmt.Errorf("%s: table kept growing", proc.Name)
}

// port 는 DWORD 의 하위 2바이트에 네트워크 바이트 순서로 들어 있다.
func port(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func ip4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}) }

func ip6(b []byte) netip.Addr {
	var a [16]byte
	copy(a[:], b[:16])
	return netip.AddrFrom16(a).Unmap()
}

func isExternal(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsPrivate() &&
		!a.IsLinkLocalUnicast() && !a.IsMulticast()
}

// ScanConnections 는 TCP/UDP(IPv4/IPv6) 소켓 전체를 수집한다.
// names 는 PID → 프로세스명 (ProcessTracker.Names).
func ScanConnections(names map[uint32]string) ([]model.Connection, error) {
	now := time.Now().UTC()
	var out []model.Connection

	type raw struct {
		proto        string
		lip, rip     netip.Addr
		lport, rport uint16
		state, pid   uint32
	}
	var rows []raw

	if b, err := fetchTable(procGetExtendedTcpTable, afInet, tcpTableOwnerPidAll); err == nil && len(b) >= 4 {
		n := int(binary.LittleEndian.Uint32(b))
		for i := 0; i < n && 4+(i+1)*sizeTCP4Row <= len(b); i++ {
			r := b[4+i*sizeTCP4Row:]
			rows = append(rows, raw{
				proto: "tcp4",
				state: binary.LittleEndian.Uint32(r[0:]),
				lip:   ip4(r[4:]), lport: port(r[8:]),
				rip: ip4(r[12:]), rport: port(r[16:]),
				pid: binary.LittleEndian.Uint32(r[20:]),
			})
		}
	} else if err != nil {
		return nil, err
	}

	if b, err := fetchTable(procGetExtendedTcpTable, afInet6, tcpTableOwnerPidAll); err == nil && len(b) >= 4 {
		n := int(binary.LittleEndian.Uint32(b))
		for i := 0; i < n && 4+(i+1)*sizeTCP6Row <= len(b); i++ {
			r := b[4+i*sizeTCP6Row:]
			rows = append(rows, raw{
				proto: "tcp6",
				lip:   ip6(r[0:]), lport: port(r[20:]),
				rip: ip6(r[24:]), rport: port(r[44:]),
				state: binary.LittleEndian.Uint32(r[48:]),
				pid:   binary.LittleEndian.Uint32(r[52:]),
			})
		}
	}

	// 같은 PID 가 LISTEN 중인 로컬 포트로 들어온 연결 = 인바운드
	listening := map[string]bool{}
	for _, r := range rows {
		if r.state == tcpStateListen {
			listening[fmt.Sprintf("%d/%d", r.pid, r.lport)] = true
		}
	}

	for _, r := range rows {
		c := model.Connection{
			Proto: r.proto, LocalIP: r.lip.String(), LocalPort: r.lport,
			State: tcpStates[r.state], PID: r.pid, ProcessName: names[r.pid], ObservedAt: now,
		}
		switch {
		case r.state == tcpStateListen:
			c.Direction = "listen"
		case listening[fmt.Sprintf("%d/%d", r.pid, r.lport)]:
			c.Direction = "inbound"
		default:
			c.Direction = "outbound"
		}
		if r.state != tcpStateListen {
			c.RemoteIP, c.RemotePort = r.rip.String(), r.rport
			c.IsExternal = isExternal(r.rip)
		}
		out = append(out, c)
	}

	// UDP 는 연결 개념이 없으므로 바인딩된 포트만 기록한다.
	if b, err := fetchTable(procGetExtendedUdpTable, afInet, udpTableOwnerPid); err == nil && len(b) >= 4 {
		n := int(binary.LittleEndian.Uint32(b))
		for i := 0; i < n && 4+(i+1)*sizeUDP4Row <= len(b); i++ {
			r := b[4+i*sizeUDP4Row:]
			pid := binary.LittleEndian.Uint32(r[8:])
			out = append(out, model.Connection{Proto: "udp4", Direction: "bound", State: "BOUND",
				LocalIP: ip4(r[0:]).String(), LocalPort: port(r[4:]), PID: pid, ProcessName: names[pid], ObservedAt: now})
		}
	}
	if b, err := fetchTable(procGetExtendedUdpTable, afInet6, udpTableOwnerPid); err == nil && len(b) >= 4 {
		n := int(binary.LittleEndian.Uint32(b))
		for i := 0; i < n && 4+(i+1)*sizeUDP6Row <= len(b); i++ {
			r := b[4+i*sizeUDP6Row:]
			pid := binary.LittleEndian.Uint32(r[24:])
			out = append(out, model.Connection{Proto: "udp6", Direction: "bound", State: "BOUND",
				LocalIP: ip6(r[0:]).String(), LocalPort: port(r[20:]), PID: pid, ProcessName: names[pid], ObservedAt: now})
		}
	}
	return out, nil
}

// ConnectionTracker 는 새로 나타난 연결만 보내 전송량을 줄인다.
// TIME_WAIT 등 수명이 짧은 상태 변화는 무시하고 (proto, 로컬, 원격, PID) 조합이 처음 보일 때만 보낸다.
type ConnectionTracker struct{ seen map[string]struct{} }

func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{seen: map[string]struct{}{}}
}

func (t *ConnectionTracker) Diff(all []model.Connection, full bool) []model.Connection {
	cur := make(map[string]struct{}, len(all))
	var out []model.Connection
	for _, c := range all {
		if c.State == "TIME_WAIT" || c.State == "CLOSED" || c.State == "DELETE_TCB" {
			continue
		}
		k := fmt.Sprintf("%s|%s|%d|%s|%d|%d|%s", c.Proto, c.LocalIP, c.LocalPort, c.RemoteIP, c.RemotePort, c.PID, c.Direction)
		cur[k] = struct{}{}
		if _, ok := t.seen[k]; full || !ok {
			out = append(out, c)
		}
	}
	t.seen = cur
	return out
}
