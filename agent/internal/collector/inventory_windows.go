//go:build windows

package collector

// 자산 정보 수집 (Falcon Discover · Genian 단말 정보 수집에 해당)
//
// 모두 읽기 전용이다.
//   - 레지스트리: QUERY_VALUE | ENUMERATE_SUB_KEYS 로만 연다(regRead).
//   - Win32: GetSystemFirmwareTable(SMBIOS 읽기), GlobalMemoryStatusEx, GetDiskFreeSpaceEx, NetGetJoinInformation,
//     GetAdaptersAddresses — 모두 조회 API 다. 설정을 바꾸는 호출은 없다.
//   - 설치 프로그램은 제어판 "프로그램 제거" 목록과 같은 출처(Uninstall 레지스트리 키)를 읽는다. 프로그램을 실행하지 않는다.

import (
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/yourorg/endpoint-edr/agent/internal/model"
)

const maxSoftware = 5000

var (
	modkernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemFirmwareTable = modkernel32.NewProc("GetSystemFirmwareTable")
	procGlobalMemoryStatusEx   = modkernel32.NewProc("GlobalMemoryStatusEx")
)

// InventoryTracker 는 자산 정보를 모아 "바뀌었을 때 또는 24시간마다"만 돌려준다.
type InventoryTracker struct {
	gate changeGate
}

func NewInventoryTracker() *InventoryTracker {
	return &InventoryTracker{gate: changeGate{every: 24 * time.Hour}}
}

// Scan 은 보낼 차례면 자산 정보를, 아니면 nil 을 돌려준다. 실패한 항목은 비워 둔다(panic 없음).
func (t *InventoryTracker) Scan() *model.Inventory {
	inv := CollectInventory()
	// 남은 디스크 용량은 조금씩 계속 바뀌므로 비교에서는 1GB 단위로만 본다
	cmp := *inv
	cmp.CollectedAt = time.Time{}
	cmp.Hardware.DiskFreeGB = float64(int(cmp.Hardware.DiskFreeGB))
	now := time.Now()
	if !t.gate.due(cmp, now) {
		return nil
	}
	t.gate.mark(cmp, now)
	return inv
}

// CollectInventory 는 지금 상태를 한 번 모은다(설치 전 점검 `edr-agent.exe console` 에서도 쓴다).
func CollectInventory() *model.Inventory {
	inv := &model.Inventory{CollectedAt: time.Now().UTC()}
	inv.OS = readOSInfo()
	inv.Hardware = readHardware()
	inv.Domain, inv.DomainJoined = readJoinInfo()
	inv.LastUser = regString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI`, "LastLoggedOnUser")
	inv.Adapters = readAdapters()
	inv.Software = readSoftware()
	return inv
}

// ---------------- OS ----------------

func readOSInfo() model.OSInfo {
	var o model.OSInfo
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, regRead)
	if err != nil {
		return o
	}
	defer k.Close()
	str := func(n string) string { s, _, _ := k.GetStringValue(n); return strings.TrimSpace(s) }
	o.Build, _ = strconv.Atoi(str("CurrentBuildNumber"))
	if o.Build == 0 {
		o.Build, _ = strconv.Atoi(str("CurrentBuild"))
	}
	if v, _, err := k.GetIntegerValue("UBR"); err == nil {
		o.UBR = int(v)
	}
	o.Name = osProductName(str("ProductName"), o.Build)
	o.Edition = str("EditionID")
	o.DisplayVersion = str("DisplayVersion")
	if o.DisplayVersion == "" {
		o.DisplayVersion = str("ReleaseId")
	}
	o.InstallType = str("InstallationType")
	if v, _, err := k.GetIntegerValue("InstallDate"); err == nil && v > 0 {
		o.InstalledAt = time.Unix(int64(v), 0).UTC()
	}
	o.Arch = strings.ToLower(regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, "PROCESSOR_ARCHITECTURE"))
	return o
}

// ---------------- 하드웨어 ----------------

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func readHardware() model.Hardware {
	var h model.Hardware
	bios := `HARDWARE\DESCRIPTION\System\BIOS`
	h.Manufacturer = regString(registry.LOCAL_MACHINE, bios, "SystemManufacturer")
	h.Model = regString(registry.LOCAL_MACHINE, bios, "SystemProductName")
	h.BIOSVersion = regString(registry.LOCAL_MACHINE, bios, "BIOSVersion")
	if s := readSMBIOS(); s != (smbiosSystem{}) {
		h.Serial = s.Serial
		if h.Manufacturer == "" {
			h.Manufacturer = s.Manufacturer
		}
		if h.Model == "" {
			h.Model = s.Product
		}
		if h.BIOSVersion == "" {
			h.BIOSVersion = s.BIOSVersion
		}
	}
	h.Manufacturer, h.Model = cleanSMBIOS(h.Manufacturer), cleanSMBIOS(h.Model)
	h.CPU = regString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString")
	h.Cores = runtime.NumCPU() // 논리 프로세서 수

	ms := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r != 0 {
		h.MemoryMB = int64(ms.TotalPhys >> 20)
	}

	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	if p, err := windows.UTF16PtrFromString(drive + `\`); err == nil {
		var free, total, totalFree uint64
		if windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree) == nil && total > 0 {
			h.DiskTotalGB = roundGB(total)
			h.DiskFreeGB = roundGB(totalFree)
		}
	}
	return h
}

func roundGB(b uint64) float64 { return float64(b*10/(1<<30)) / 10 }

// readSMBIOS 는 펌웨어 SMBIOS 표를 읽는다(일련번호는 레지스트리에 없다). 실패하면 빈 값.
func readSMBIOS() smbiosSystem {
	const rsmb = 'R'<<24 | 'S'<<16 | 'M'<<8 | 'B'
	if procGetSystemFirmwareTable.Find() != nil {
		return smbiosSystem{}
	}
	n, _, _ := procGetSystemFirmwareTable.Call(rsmb, 0, 0, 0)
	if n == 0 || n > 1<<20 {
		return smbiosSystem{}
	}
	buf := make([]byte, n)
	got, _, _ := procGetSystemFirmwareTable.Call(rsmb, 0, uintptr(unsafe.Pointer(&buf[0])), n)
	if got == 0 || got > n {
		return smbiosSystem{}
	}
	return parseSMBIOS(buf[:got])
}

// ---------------- 도메인 · 네트워크 ----------------

func readJoinInfo() (string, bool) {
	var name *uint16
	var typ uint32
	if err := windows.NetGetJoinInformation(nil, &name, &typ); err != nil || name == nil {
		return "", false
	}
	defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(name)))
	return windows.UTF16PtrToString(name), typ == windows.NetSetupDomainName
}

func readAdapters() []model.Adapter {
	size := uint32(16 << 10)
	var buf []byte
	for i := 0; i < 3; i++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil
		}
		if i == 2 {
			return nil
		}
	}
	var out []model.Adapter
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil && len(out) < 16; a = a.Next {
		if a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || a.OperStatus != windows.IfOperStatusUp {
			continue
		}
		ad := model.Adapter{Name: windows.UTF16PtrToString(a.FriendlyName)}
		if a.PhysicalAddressLength > 0 && a.PhysicalAddressLength <= 8 {
			parts := make([]string, a.PhysicalAddressLength)
			for i := 0; i < int(a.PhysicalAddressLength); i++ {
				parts[i] = strconv.FormatUint(uint64(a.PhysicalAddress[i])|0x100, 16)[1:]
			}
			ad.MAC = strings.ToUpper(strings.Join(parts, ":"))
		}
		for u := a.FirstUnicastAddress; u != nil && len(ad.IPs) < 16; u = u.Next {
			if ip := u.Address.IP(); ip != nil && !ip.IsLinkLocalUnicast() {
				ad.IPs = append(ad.IPs, ip.String())
			}
		}
		out = append(out, ad)
	}
	return out
}

// ---------------- 설치 프로그램 ----------------

func readSoftware() []model.Software {
	type src struct {
		root  registry.Key
		path  string
		scope string
		arch  string
	}
	srcs := []src{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "machine", nativeArch()},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "machine", "x86"},
	}
	for _, sid := range loadedUserSIDs() {
		srcs = append(srcs, src{registry.USERS, sid + `\Software\Microsoft\Windows\CurrentVersion\Uninstall`, "user", ""})
	}
	seen := map[string]bool{}
	var out []model.Software
	for _, s := range srcs {
		k, err := registry.OpenKey(s.root, s.path, regRead)
		if err != nil {
			continue
		}
		subs, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, sub := range subs {
			if len(out) >= maxSoftware {
				break
			}
			sk, err := registry.OpenKey(s.root, s.path+`\`+sub, registry.QUERY_VALUE|registry.WOW64_64KEY)
			if err != nil {
				continue
			}
			str := func(n string) string { v, _, _ := sk.GetStringValue(n); return strings.TrimSpace(v) }
			sys, _, _ := sk.GetIntegerValue("SystemComponent")
			name := str("DisplayName")
			if keepSoftware(name, sys, str("ParentKeyName"), str("ReleaseType")) {
				sw := model.Software{Name: name, Version: str("DisplayVersion"), Publisher: str("Publisher"),
					InstallDate: normalizeInstallDate(str("InstallDate")), Scope: s.scope, Arch: s.arch}
				if key := strings.ToLower(sw.Name + "\x00" + sw.Version); !seen[key] {
					seen[key] = true
					out = append(out, sw)
				}
			}
			sk.Close()
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func nativeArch() string {
	switch strings.ToUpper(regString(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, "PROCESSOR_ARCHITECTURE")) {
	case "X86":
		return "x86"
	case "AMD64", "ARM64":
		return "x64"
	}
	return ""
}

// loadedUserSIDs 는 지금 로드된(로그온한) 사용자 하이브의 SID 목록이다. 로그오프한 사용자의 하이브는 열지 않는다.
func loadedUserSIDs() []string {
	k, err := registry.OpenKey(registry.USERS, "", regRead)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, "S-1-5-21-") && !strings.HasSuffix(n, "_Classes") {
			out = append(out, n)
		}
	}
	return out
}

// ---------------- 레지스트리 읽기 도우미 ----------------

func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// regDWORD 는 정수 값을 읽는다. 키나 값이 없으면 ok=false.
func regDWORD(root registry.Key, path, name string) (uint64, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		// 문자열로 저장된 숫자(예: AutoAdminLogon="1")도 받아 준다
		if s, _, err2 := k.GetStringValue(name); err2 == nil {
			if n, err3 := strconv.ParseUint(strings.TrimSpace(s), 10, 64); err3 == nil {
				return n, true
			}
		}
		return 0, false
	}
	return v, true
}

// regHasValue 는 값 이름이 있는지만 본다(내용은 읽지 않는다 — 예: 저장된 자동 로그온 비밀번호).
func regHasValue(root registry.Key, path, name string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return false
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}
