//go:build !windows

package docscan

// Windows 가 아닌 곳(단위 시험·개발용): 속성 판별 없이 일반 파일로 연다.

import (
	"io/fs"
	"os"
)

func isCloudOnly(fs.FileInfo) bool { return false }

func isLinkOrCloud(d fs.DirEntry) bool { return d.Type()&fs.ModeSymlink != 0 }

func openShared(path string) (*os.File, error) { return os.Open(path) }

func UsersDir() string { return "/home" }
