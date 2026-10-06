#!/usr/bin/env bash
# 에이전트 코드에 "시스템 개입(Active Response)" API 가 들어오는 것을 막는 가드레일.
# CI 와 pre-commit 에서 실행한다. 하나라도 걸리면 실패(exit 1).
set -euo pipefail
cd "$(dirname "$0")/../agent"

FORBIDDEN=(
  # 프로세스 개입
  'TerminateProcess' 'PROCESS_TERMINATE' 'PROCESS_ALL_ACCESS' 'PROCESS_VM_WRITE' 'PROCESS_VM_OPERATION'
  'PROCESS_VM_READ' 'PROCESS_CREATE_THREAD' 'PROCESS_SUSPEND_RESUME' 'NtSuspendProcess' 'DebugActiveProcess'
  'WriteProcessMemory' 'ReadProcessMemory' 'CreateRemoteThread' 'VirtualAllocEx' 'SetWindowsHookEx'
  'QueueUserAPC' 'NtQueueApcThread'
  # 파일·레지스트리 변경 (자기 데이터 폴더 제외는 코드 리뷰로 확인)
  'DeleteFile' 'MoveFileEx' 'SetFileAttributes' 'RegSetValue' 'RegDeleteKey' 'RegDeleteValue'
  'registry.SET_VALUE' 'registry.ALL_ACCESS' 'registry.WRITE' 'CreateKey\(' '.SetStringValue' '.DeleteValue'
  # 네트워크·방화벽 개입
  'SetTcpEntry' 'FwpmFilterAdd' 'INetFwPolicy' 'netsh'
  # 커널·드라이버
  'NtLoadDriver' 'CreateService\(.*SERVICE_KERNEL_DRIVER' 'DeviceIoControl'
  # 시스템 설정 변경
  'auditpol' 'wevtutil' 'EvtClearLog' 'AdjustTokenPrivileges' 'ShellExecute' 'exec.Command'
)

fail=0
for pat in "${FORBIDDEN[@]}"; do
  if grep -rnE --include='*.go' -- "$pat" . | grep -v '^./.*_test.go' | grep -v '// passive-ok' | grep -vE '^[^:]+:[0-9]+:\s*//' ; then
    echo "❌ 금지 API 사용: $pat"
    fail=1
  fi
done

if [[ $fail -eq 0 ]]; then
  echo "✅ passive check passed: 에이전트에 시스템 개입 API 없음"
fi
exit $fail
