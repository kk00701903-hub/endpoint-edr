//go:build windows

// Package hasher 는 실행 파일의 SHA-256 을 "다른 프로그램을 방해하지 않고" 계산한다.
//
// 충돌 방지 원칙
//   - FILE_SHARE_READ|WRITE|DELETE 로 열어 다른 프로세스(백신·업데이트)의 쓰기/삭제를 막지 않는다.
//   - 경로+크기+수정시각 캐시로 같은 파일을 반복해서 읽지 않는다.
//   - 초당 읽기량을 제한(throttle)해 디스크 I/O 를 독점하지 않는다.
//   - 파일 내용은 서버로 보내지 않는다. 해시만 보낸다.
package hasher

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

var ErrTooLarge = errors.New("file too large to hash")

type cacheKey struct {
	path  string
	size  int64
	mtime int64
}

type Hasher struct {
	mu          sync.Mutex
	cache       map[cacheKey]string
	maxEntries  int
	maxFileSize int64
	bytesPerSec int64
}

func New(maxFileSize, bytesPerSec int64) *Hasher {
	return &Hasher{
		cache:       make(map[cacheKey]string, 4096),
		maxEntries:  20000,
		maxFileSize: maxFileSize,
		bytesPerSec: bytesPerSec,
	}
}

// SHA256 은 path 파일의 해시를 반환한다. 열 수 없거나 너무 크면 에러를 반환하며, 호출자는 해시 없이 진행한다.
func (h *Hasher) SHA256(path string) (string, error) {
	if path == "" || strings.HasPrefix(path, `\\?\GLOBALROOT`) {
		return "", fmt.Errorf("unsupported path: %q", path)
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	fh, err := windows.CreateFile(p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_SEQUENTIAL_SCAN,
		0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fh), path)
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if fi.Size() > h.maxFileSize {
		return "", ErrTooLarge
	}
	key := cacheKey{strings.ToLower(path), fi.Size(), fi.ModTime().UnixNano()}

	h.mu.Lock()
	if v, ok := h.cache[key]; ok {
		h.mu.Unlock()
		return v, nil
	}
	h.mu.Unlock()

	sum := sha256.New()
	if _, err := io.Copy(sum, &throttledReader{r: f, bps: h.bytesPerSec}); err != nil {
		return "", err
	}
	digest := hex.EncodeToString(sum.Sum(nil))

	h.mu.Lock()
	if len(h.cache) >= h.maxEntries {
		h.cache = make(map[cacheKey]string, 4096) // 단순 초기화: 메모리 상한 보장
	}
	h.cache[key] = digest
	h.mu.Unlock()
	return digest, nil
}

// throttledReader 는 1초당 bps 바이트 이상 읽지 않도록 잠깐씩 쉰다.
type throttledReader struct {
	r       io.Reader
	bps     int64
	start   time.Time
	readSum int64
}

func (t *throttledReader) Read(p []byte) (int, error) {
	if t.start.IsZero() {
		t.start = time.Now()
	}
	if len(p) > 256*1024 {
		p = p[:256*1024]
	}
	n, err := t.r.Read(p)
	t.readSum += int64(n)
	if t.bps > 0 {
		expected := time.Duration(float64(t.readSum) / float64(t.bps) * float64(time.Second))
		if elapsed := time.Since(t.start); expected > elapsed {
			time.Sleep(expected - elapsed)
		}
	}
	return n, err
}
