//go:build windows

// Package sysutil 은 에이전트 자신이 시스템 자원을 덜 쓰도록 스스로를 제한한다.
// (다른 프로세스에는 아무 것도 하지 않는다)
package sysutil

import (
	"runtime"
	"runtime/debug"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ApplyLowFootprint 는
//   - 프로세스를 백그라운드 모드(CPU·I/O·메모리 우선순위 낮춤)로 전환하고
//   - Job Object 로 메모리 상한을 걸고
//   - Go 런타임의 스레드·힙 목표를 낮춘다.
func ApplyLowFootprint(memLimitBytes uint64) []error {
	var errs []error
	runtime.GOMAXPROCS(2)
	debug.SetMemoryLimit(int64(memLimitBytes) / 2) // GC 목표: 하드 상한의 절반

	if err := windows.SetPriorityClass(windows.CurrentProcess(), windows.PROCESS_MODE_BACKGROUND_BEGIN); err != nil {
		// 백그라운드 모드가 거부되면 일반 BELOW_NORMAL 로 대체
		_ = windows.SetPriorityClass(windows.CurrentProcess(), windows.BELOW_NORMAL_PRIORITY_CLASS)
		errs = append(errs, err)
	}

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return append(errs, err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
	info.ProcessMemoryLimit = uintptr(memLimitBytes)
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		errs = append(errs, err)
	}
	if err := windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		errs = append(errs, err)
	}
	// job 핸들은 프로세스 수명 동안 유지한다(닫지 않음).
	return errs
}
