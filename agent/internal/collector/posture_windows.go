//go:build windows

package collector

// 보안 상태 점검 (Falcon Zero Trust Assessment · Genian 정책 준수 점검에 해당)
//
// 설정 값을 "읽기만" 한다. 꺼져 있어도 켜지 않는다(수동형 원칙) — 결과는 콘솔의 보안 상태 화면과 경보(EDR-POS-001)로 알린다.
//   - 레지스트리: QUERY_VALUE 로만 연다. 자동 로그온 비밀번호처럼 민감한 값은 이름이 있는지만 보고 내용은 읽지 않는다.
//   - 서비스 상태: OpenSCManager(SC_MANAGER_CONNECT) + OpenService(SERVICE_QUERY_STATUS) — 상태 조회 권한만 요청한다.
// 항목 ID 는 서버 supabase posture_checks.check_id 와 같아야 한다(os_supported 는 서버가 자산 정보로 판단).

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/yourorg/endpoint-edr/agent/internal/model"
)

// DefaultAVServices 는 실시간 감시를 하는 백신 서비스 이름(서비스 키 이름) → 제품 이름이다.
// 회사 백신이 목록에 없으면 config.json 의 av_services 에 서비스 이름을 더한다(`sc query` 로 확인).
var DefaultAVServices = map[string]string{
	"CSFalconService":  "CrowdStrike Falcon",
	"SentinelAgent":    "SentinelOne",
	"SepMasterService": "Symantec Endpoint Protection",
	"ekrn":             "ESET",
	"mfemms":           "Trellix(McAfee)",
	"ntrtscan":         "Trend Micro Apex One",
	"SAVService":       "Sophos",
	"CylanceSvc":       "Cylance",
	"CbDefense":        "Carbon Black",
	"cyserver":         "Cortex XDR",
}

// PostureTracker 는 점검 결과를 "바뀌었을 때 또는 6시간마다"만 돌려준다.
type PostureTracker struct {
	gate       changeGate
	avServices map[string]string
}

func NewPostureTracker(extraAV []string) *PostureTracker {
	av := map[string]string{}
	for k, v := range DefaultAVServices {
		av[k] = v
	}
	for _, s := range extraAV {
		if s = strings.TrimSpace(s); s != "" {
			av[s] = s
		}
	}
	return &PostureTracker{gate: changeGate{every: 6 * time.Hour}, avServices: av}
}

// Scan 은 보낼 차례면 전체 점검 결과를, 아니면 nil 을 돌려준다.
func (t *PostureTracker) Scan() []model.PostureCheck {
	checks := t.Collect()
	now := time.Now()
	if !t.gate.due(checks, now) {
		return nil
	}
	t.gate.mark(checks, now)
	return checks
}

// Collect 는 지금 상태를 한 번 점검한다.
func (t *PostureTracker) Collect() []model.PostureCheck {
	return []model.PostureCheck{
		t.checkAV(),
		checkFirewall(),
		checkAutoUpdate(),
		checkUAC(),
		checkWDigest(),
		checkSMB1(),
		checkRDP(),
		checkAutoLogon(),
		checkScreenLock(),
		checkLSA(),
		checkPSLogging(),
	}
}

func pass(id, detail string) model.PostureCheck {
	return model.PostureCheck{ID: id, Status: "pass", Detail: detail}
}
func fail(id, detail string) model.PostureCheck {
	return model.PostureCheck{ID: id, Status: "fail", Detail: detail}
}
func warn(id, detail string) model.PostureCheck {
	return model.PostureCheck{ID: id, Status: "warn", Detail: detail}
}
func unknown(id, detail string) model.PostureCheck {
	return model.PostureCheck{ID: id, Status: "unknown", Detail: detail}
}

const hklm = registry.LOCAL_MACHINE

// serviceRunning 은 서비스가 있는지, 실행 중인지 본다(상태 조회 권한만).
func serviceRunning(name string) (exists, running bool) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(scm)
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, false
	}
	h, err := windows.OpenService(scm, p, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(h)
	var st windows.SERVICE_STATUS
	if windows.QueryServiceStatus(h, &st) != nil {
		return true, false
	}
	return true, st.CurrentState == windows.SERVICE_RUNNING
}

// 정책 값이 있으면 정책을, 없으면 로컬 설정을 쓴다
func policyOr(policyPath, localPath, name string) (uint64, bool) {
	if v, ok := regDWORD(hklm, policyPath, name); ok {
		return v, true
	}
	return regDWORD(hklm, localPath, name)
}

// ---------------- 항목별 점검 ----------------

func (t *PostureTracker) checkAV() model.PostureCheck {
	const id = "av_realtime"
	var active []string
	// Microsoft Defender: 서비스 실행 + 실시간 보호 켜짐 + 수동(passive) 모드 아님
	if _, running := serviceRunning("WinDefend"); running {
		off, _ := policyOr(`SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`,
			`SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring")
		disabled, _ := regDWORD(hklm, `SOFTWARE\Policies\Microsoft\Windows Defender`, "DisableAntiSpyware")
		passive, _ := regDWORD(hklm, `SOFTWARE\Microsoft\Windows Defender`, "PassiveMode")
		forcePassive, _ := regDWORD(hklm, `SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection`, "ForceDefenderPassiveMode")
		if off != 1 && disabled != 1 && passive != 1 && forcePassive != 1 {
			active = append(active, "Microsoft Defender")
		}
	}
	for svc, product := range t.avServices {
		if _, running := serviceRunning(svc); running {
			active = append(active, product)
		}
	}
	if len(active) > 0 {
		return pass(id, strings.Join(dedupSorted(active), ", ")+" 실시간 감시 동작")
	}
	if _, running := serviceRunning("WinDefend"); running {
		return fail(id, "Microsoft Defender 실시간 보호 꺼짐(또는 수동 모드), 실행 중인 다른 백신 없음")
	}
	return fail(id, "실시간 감시 중인 백신을 찾지 못함(Defender 서비스 중지, 알려진 백신 서비스 없음)")
}

func checkFirewall() model.PostureCheck {
	const id = "firewall"
	profiles := []struct{ label, policy, local string }{
		{"도메인", "DomainProfile", "DomainProfile"},
		{"개인", "PrivateProfile", "StandardProfile"},
		{"공용", "PublicProfile", "PublicProfile"},
	}
	var off []string
	known := 0
	for _, p := range profiles {
		v, ok := policyOr(`SOFTWARE\Policies\Microsoft\WindowsFirewall\`+p.policy,
			`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`+p.local, "EnableFirewall")
		if !ok {
			continue
		}
		known++
		if v == 0 {
			off = append(off, p.label)
		}
	}
	exists, running := serviceRunning("MpsSvc")
	switch {
	case known == 0 && !exists:
		return unknown(id, "방화벽 설정을 읽지 못함")
	case exists && !running:
		return fail(id, "Windows 방화벽 서비스(MpsSvc) 중지")
	case len(off) > 0:
		return fail(id, strings.Join(off, "·")+" 프로필 꺼짐")
	}
	return pass(id, "세 프로필 모두 켜짐")
}

func checkAutoUpdate() model.PostureCheck {
	const id = "auto_update"
	if v, ok := regDWORD(hklm, `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, "NoAutoUpdate"); ok && v == 1 {
		return fail(id, "그룹 정책으로 자동 업데이트 꺼짐(NoAutoUpdate=1)")
	}
	if v, ok := regDWORD(hklm, `SYSTEM\CurrentControlSet\Services\wuauserv`, "Start"); ok && v == 4 {
		return fail(id, "Windows Update 서비스 사용 안 함")
	}
	return pass(id, "자동 업데이트 막혀 있지 않음")
}

func checkUAC() model.PostureCheck {
	const id = "uac"
	if v, ok := regDWORD(hklm, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA"); ok && v == 0 {
		return fail(id, "UAC 꺼짐(EnableLUA=0)")
	}
	return pass(id, "켜짐")
}

func checkWDigest() model.PostureCheck {
	const id = "wdigest"
	if v, ok := regDWORD(hklm, `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, "UseLogonCredential"); ok && v == 1 {
		return fail(id, "WDigest 평문 자격 증명 저장 켜짐(UseLogonCredential=1)")
	}
	return pass(id, "꺼짐")
}

func checkSMB1() model.PostureCheck {
	const id = "smb1"
	var on []string
	server := `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
	if v, ok := regDWORD(hklm, server, "SMB1"); ok {
		if v != 0 {
			on = append(on, "서버(SMB1=1)")
		}
	} else if start, ok := regDWORD(hklm, `SYSTEM\CurrentControlSet\Services\srv`, "Start"); ok && start != 4 {
		on = append(on, "서버(SMB1 기능 설치됨)")
	}
	if start, ok := regDWORD(hklm, `SYSTEM\CurrentControlSet\Services\mrxsmb10`, "Start"); ok && start != 4 {
		on = append(on, "클라이언트(mrxsmb10)")
	}
	if len(on) > 0 {
		return fail(id, "SMBv1 켜짐: "+strings.Join(on, ", "))
	}
	return pass(id, "꺼짐")
}

func checkRDP() model.PostureCheck {
	const id = "rdp_nla"
	deny, ok := policyOr(`SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`,
		`SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections")
	if !ok || deny == 1 {
		return pass(id, "원격 데스크톱 꺼짐")
	}
	nla, ok := policyOr(`SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`,
		`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication")
	if ok && nla == 1 {
		return pass(id, "원격 데스크톱 켜짐, 네트워크 수준 인증(NLA) 사용")
	}
	return fail(id, "원격 데스크톱 켜짐, 네트워크 수준 인증(NLA) 꺼짐")
}

func checkAutoLogon() model.PostureCheck {
	const id = "autologon"
	winlogon := `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	auto, _ := regDWORD(hklm, winlogon, "AutoAdminLogon")
	if auto != 1 {
		return pass(id, "자동 로그온 꺼짐")
	}
	if regHasValue(hklm, winlogon, "DefaultPassword") {
		return fail(id, "자동 로그온 켜짐, 비밀번호가 레지스트리에 저장됨(DefaultPassword)")
	}
	return warn(id, "자동 로그온 켜짐(비밀번호는 레지스트리에 없음)")
}

func checkScreenLock() model.PostureCheck {
	const id = "screen_lock"
	if v, ok := regDWORD(hklm, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "InactivityTimeoutSecs"); ok && v > 0 && v <= 900 {
		return pass(id, fmt.Sprintf("컴퓨터 비활성 한도 %d초", v))
	}
	sids := loadedUserSIDs()
	if len(sids) == 0 {
		return unknown(id, "로그온한 사용자가 없어 화면 보호기 설정을 확인하지 못함")
	}
	bad := 0
	for _, sid := range sids {
		if !userScreenLock(sid) {
			bad++
		}
	}
	if bad > 0 {
		return fail(id, fmt.Sprintf("로그온 사용자 %d명 중 %d명이 15분 안에 화면이 잠기지 않음", len(sids), bad))
	}
	return pass(id, "로그온 사용자 모두 15분 이내 암호 보호 화면 보호기")
}

// 사용자 하이브: 정책(Software\Policies\...)이 있으면 정책, 없으면 사용자 설정
func userScreenLock(sid string) bool {
	read := func(name string) (uint64, bool) {
		if v, ok := regDWORD(registry.USERS, sid+`\Software\Policies\Microsoft\Windows\Control Panel\Desktop`, name); ok {
			return v, true
		}
		return regDWORD(registry.USERS, sid+`\Control Panel\Desktop`, name)
	}
	active, ok1 := read("ScreenSaveActive")
	secure, ok2 := read("ScreenSaverIsSecure")
	timeout, ok3 := read("ScreenSaveTimeOut")
	return ok1 && ok2 && ok3 && active == 1 && secure == 1 && timeout > 0 && timeout <= 900
}

func checkLSA() model.PostureCheck {
	const id = "lsa_protection"
	if v, ok := regDWORD(hklm, `SYSTEM\CurrentControlSet\Control\Lsa`, "RunAsPPL"); ok && (v == 1 || v == 2) {
		return pass(id, "LSA 보호 켜짐")
	}
	return fail(id, "LSA 보호 꺼짐(RunAsPPL 없음)")
}

func checkPSLogging() model.PostureCheck {
	const id = "ps_logging"
	if v, ok := regDWORD(hklm, `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`, "EnableScriptBlockLogging"); ok && v == 1 {
		return pass(id, "스크립트 블록 기록 켜짐")
	}
	return fail(id, "스크립트 블록 기록 꺼짐")
}

func dedupSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
