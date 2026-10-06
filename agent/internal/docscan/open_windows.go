//go:build windows

package docscan

import (
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// 파일 속성: 연결 지점·바로 가기(재분석 지점), 클라우드 전용(OneDrive 자리 표시자 — 열면 내려받기가 시작된다)
const (
	attrReparsePoint       = 0x400
	attrOffline            = 0x1000
	attrRecallOnOpen       = 0x40000
	attrRecallOnDataAccess = 0x400000
)

func attributes(info fs.FileInfo) uint32 {
	if a, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		return a.FileAttributes
	}
	return 0
}

func isCloudOnly(info fs.FileInfo) bool {
	return attributes(info)&(attrOffline|attrRecallOnOpen|attrRecallOnDataAccess) != 0
}

func isLinkOrCloud(d fs.DirEntry) bool {
	if d.Type()&fs.ModeSymlink != 0 {
		return true
	}
	info, err := d.Info()
	if err != nil {
		return true
	}
	return attributes(info)&(attrReparsePoint|attrOffline|attrRecallOnOpen|attrRecallOnDataAccess) != 0
}

// openShared 는 다른 프로그램이 쓰고 있는 문서도 방해하지 않도록 공유 모드(읽기·쓰기·삭제 허용)로, 읽기 전용으로 연다.
func openShared(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// UsersDir 는 사용자 폴더들이 있는 곳(보통 C:\Users)이다.
func UsersDir() string {
	if d := os.Getenv("SystemDrive"); d != "" {
		return d + `\Users`
	}
	return `C:\Users`
}
