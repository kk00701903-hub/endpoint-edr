// ---------------------------------------------------------------------------
// ATT&CK 매트릭스에 보여줄 Windows 엔드포인트 기법 목록(엔터프라이즈 매트릭스 중 자주 쓰이는 것).
//   covered  : 탐지 규칙이 있다(detection_rules 와 기법 ID 로 연결)
//   huntable : 규칙은 없지만 수집 데이터로 헌팅 쿼리를 돌려 확인할 수 있다
//   gap      : 수동형(드라이버 없는) 수집으로는 보기 어렵다 — 다른 보안 솔루션·Sysmon 이 필요
// ---------------------------------------------------------------------------
export type Visibility = "huntable" | "gap";
export interface Technique { id: string; name: string; ko: string; tactic: string; visibility: Visibility; query?: string; note?: string }

export const CATALOG: Technique[] = [
  { id: "T1133", name: "External Remote Services", ko: "외부 원격 서비스", tactic: "Initial Access", visibility: "huntable", query: "event.id = 4624 and event.logon_type = 10" },
  { id: "T1078", name: "Valid Accounts", ko: "정상 계정 악용", tactic: "Initial Access", visibility: "huntable", query: "event.id = 4624 and event.logon_type = 10" },
  { id: "T1566", name: "Phishing", ko: "피싱", tactic: "Initial Access", visibility: "huntable", query: 'process.path ~ "\\downloads\\"', note: "메일 첨부 실행 흔적으로 간접 확인" },
  { id: "T1190", name: "Exploit Public-Facing Application", ko: "공개 서비스 취약점", tactic: "Initial Access", visibility: "huntable", query: "process.name = cmd.exe and process.user ~ apppool", note: "웹 서버 프로세스가 셸을 띄웠는지" },
  { id: "T1059.001", name: "PowerShell", ko: "PowerShell", tactic: "Execution", visibility: "huntable", query: 'process.name = powershell.exe and process.cmdline ~ "-enc"' },
  { id: "T1059.003", name: "Windows Command Shell", ko: "명령 프롬프트", tactic: "Execution", visibility: "huntable", query: "process.name = cmd.exe and process.cmdline ~ /c" },
  { id: "T1204.002", name: "User Execution: Malicious File", ko: "악성 파일 실행", tactic: "Execution", visibility: "huntable" },
  { id: "T1047", name: "Windows Management Instrumentation", ko: "WMI 실행", tactic: "Execution", visibility: "huntable", query: "process.name = wmic.exe" },
  { id: "T1569.002", name: "Service Execution", ko: "서비스로 실행", tactic: "Execution", visibility: "huntable", query: "process.name = psexesvc.exe" },
  { id: "T1547.001", name: "Registry Run Keys / Startup Folder", ko: "Run 키·시작프로그램", tactic: "Persistence", visibility: "huntable" },
  { id: "T1543.003", name: "Windows Service", ko: "서비스 등록", tactic: "Persistence", visibility: "huntable" },
  { id: "T1053.005", name: "Scheduled Task", ko: "예약 작업", tactic: "Persistence", visibility: "huntable" },
  { id: "T1136.001", name: "Create Account: Local Account", ko: "로컬 계정 생성", tactic: "Persistence", visibility: "huntable" },
  { id: "T1098", name: "Account Manipulation", ko: "계정 조작", tactic: "Persistence", visibility: "huntable" },
  { id: "T1546.012", name: "Image File Execution Options Injection", ko: "IFEO 하이재킹", tactic: "Persistence", visibility: "huntable", query: 'autorun.location ~ "image file execution"' },
  { id: "T1505.003", name: "Web Shell", ko: "웹셸", tactic: "Persistence", visibility: "huntable", query: "process.name = cmd.exe and process.user ~ apppool" },
  { id: "T1548.002", name: "Bypass User Account Control", ko: "UAC 우회", tactic: "Privilege Escalation", visibility: "gap", note: "레지스트리 쓰기·토큰 변화 감시 필요(Sysmon)" },
  { id: "T1068", name: "Exploitation for Privilege Escalation", ko: "권한 상승 취약점", tactic: "Privilege Escalation", visibility: "gap", note: "메모리·커널 수준 관찰 필요" },
  { id: "T1134", name: "Access Token Manipulation", ko: "토큰 조작", tactic: "Privilege Escalation", visibility: "gap", note: "API 호출 관찰 필요" },
  { id: "T1070.001", name: "Clear Windows Event Logs", ko: "이벤트 로그 삭제", tactic: "Defense Evasion", visibility: "huntable" },
  { id: "T1562.001", name: "Disable or Modify Tools", ko: "보안 도구 무력화", tactic: "Defense Evasion", visibility: "huntable", query: 'process.cmdline ~ "set-mppreference"' },
  { id: "T1027", name: "Obfuscated Files or Information", ko: "난독화", tactic: "Defense Evasion", visibility: "huntable", query: 'process.cmdline ~ "frombase64string"' },
  { id: "T1036", name: "Masquerading", ko: "정상 파일 위장", tactic: "Defense Evasion", visibility: "huntable", query: 'process.name = svchost.exe and process.path !~ "\\windows\\system32\\"' },
  { id: "T1218", name: "System Binary Proxy Execution", ko: "시스템 도구 악용", tactic: "Defense Evasion", visibility: "huntable", query: "process.name = rundll32.exe" },
  { id: "T1110", name: "Brute Force", ko: "무차별 대입", tactic: "Credential Access", visibility: "huntable" },
  { id: "T1003.001", name: "OS Credential Dumping: LSASS Memory", ko: "LSASS 메모리 덤프", tactic: "Credential Access", visibility: "gap", note: "프로세스 메모리 접근 감시 필요 — 수동형 설계상 의도적으로 보지 않음" },
  { id: "T1555", name: "Credentials from Password Stores", ko: "저장된 비밀번호 탈취", tactic: "Credential Access", visibility: "gap", note: "파일 접근 감사 필요" },
  { id: "T1558.003", name: "Kerberoasting", ko: "커버로스팅", tactic: "Credential Access", visibility: "gap", note: "도메인 컨트롤러 4769 이벤트 수집 필요" },
  { id: "T1087", name: "Account Discovery", ko: "계정 탐색", tactic: "Discovery", visibility: "huntable", query: 'process.name = net.exe and process.cmdline ~ "user"' },
  { id: "T1018", name: "Remote System Discovery", ko: "원격 시스템 탐색", tactic: "Discovery", visibility: "huntable", query: 'process.name = net.exe and process.cmdline ~ "view"' },
  { id: "T1082", name: "System Information Discovery", ko: "시스템 정보 수집", tactic: "Discovery", visibility: "huntable", query: "process.name = systeminfo.exe" },
  { id: "T1046", name: "Network Service Discovery", ko: "네트워크 스캔", tactic: "Discovery", visibility: "huntable", query: "net.direction = outbound and net.remote_port = 445" },
  { id: "T1021.001", name: "Remote Desktop Protocol", ko: "원격 데스크톱", tactic: "Lateral Movement", visibility: "huntable" },
  { id: "T1021.002", name: "SMB/Windows Admin Shares", ko: "관리 공유", tactic: "Lateral Movement", visibility: "huntable", query: "event.id = 4624 and event.logon_type = 3" },
  { id: "T1570", name: "Lateral Tool Transfer", ko: "도구 내부 전파", tactic: "Lateral Movement", visibility: "huntable", query: 'process.path ~ "\\admin$\\"' },
  { id: "T1005", name: "Data from Local System", ko: "로컬 데이터 수집", tactic: "Collection", visibility: "gap", note: "파일 접근 감사 필요" },
  { id: "T1560", name: "Archive Collected Data", ko: "압축해 모으기", tactic: "Collection", visibility: "huntable", query: 'process.name ~ "7z" and process.cmdline ~ " a "' },
  { id: "T1071", name: "Application Layer Protocol", ko: "응용 프로토콜 C2", tactic: "Command and Control", visibility: "huntable", query: "net.external = true and net.remote_port = 443" },
  { id: "T1071.001", name: "Web Protocols", ko: "웹 프로토콜 C2", tactic: "Command and Control", visibility: "huntable", query: "net.external = true and net.process = powershell.exe" },
  { id: "T1219", name: "Remote Access Software", ko: "원격 제어 프로그램", tactic: "Command and Control", visibility: "huntable", query: "process.name ~ anydesk" },
  { id: "T1105", name: "Ingress Tool Transfer", ko: "도구 내려받기", tactic: "Command and Control", visibility: "huntable", query: 'process.cmdline ~ "downloadstring"' },
  { id: "T1041", name: "Exfiltration Over C2 Channel", ko: "C2 로 유출", tactic: "Exfiltration", visibility: "gap", note: "전송량 관찰 필요(네트워크 장비)" },
  { id: "T1567", name: "Exfiltration Over Web Service", ko: "웹 서비스로 유출", tactic: "Exfiltration", visibility: "huntable", query: "net.external = true and net.process = rclone.exe" },
  { id: "T1486", name: "Data Encrypted for Impact", ko: "랜섬웨어 암호화", tactic: "Impact", visibility: "gap", note: "파일 변경 감시 필요 — 기존 백신·EDR 영역" },
  { id: "T1490", name: "Inhibit System Recovery", ko: "복구 방해", tactic: "Impact", visibility: "huntable", query: 'process.cmdline ~ "delete shadows"' },
  { id: "T1489", name: "Service Stop", ko: "서비스 중지", tactic: "Impact", visibility: "huntable", query: 'process.cmdline ~ "stop"' },
];
