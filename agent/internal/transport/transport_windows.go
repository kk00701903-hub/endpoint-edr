//go:build windows

// Package transport 는 Ingest API 와 통신한다.
//   - 최초 1회: 등록키(enrollment key)로 /v1/enroll → 장치 토큰 발급
//   - 장치 토큰은 DPAPI(머신 범위)로 암호화해 디스크에 저장
//   - 배치는 gzip JSON 으로 /v1/ingest 에 전송, 실패 시 디스크 스풀(용량 상한)에 저장 후 재전송
//
// 에이전트는 Supabase/DB 에 직접 접속하지 않는다. (서비스 키가 PC 에 남지 않도록)
package transport

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/yourorg/endpoint-edr/agent/internal/model"
)

type Client struct {
	baseURL   string
	token     string
	http      *http.Client
	spoolDir  string
	spoolMax  int64
	userAgent string
}

func New(baseURL, dataDir, agentVersion string, spoolMaxBytes int64) *Client {
	return &Client{
		baseURL:   baseURL,
		http:      &http.Client{Timeout: 30 * time.Second},
		spoolDir:  filepath.Join(dataDir, "spool"),
		spoolMax:  spoolMaxBytes,
		userAgent: "endpoint-edr-agent/" + agentVersion,
	}
}

// ---------- 등록 / 토큰 ----------

type enrollReq struct {
	EnrollmentKey string `json:"enrollment_key"`
	Hostname      string `json:"hostname"`
	OSVersion     string `json:"os_version"`
	AgentVersion  string `json:"agent_version"`
}
type enrollResp struct {
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"`
}

// EnsureToken 은 저장된 토큰을 읽고, 없으면 등록한다.
func (c *Client) EnsureToken(dataDir, enrollmentKey, hostname, osVersion, agentVersion string) error {
	tokPath := filepath.Join(dataDir, "device.token")
	if enc, err := os.ReadFile(tokPath); err == nil {
		if plain, err := dpapiDecrypt(enc); err == nil {
			c.token = string(plain)
			return nil
		}
	}
	if enrollmentKey == "" {
		return errors.New("no device token and no enrollment_key in config")
	}
	body, _ := json.Marshal(enrollReq{enrollmentKey, hostname, osVersion, agentVersion})
	req, _ := http.NewRequest(http.MethodPost, c.baseURL+"/v1/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("enroll failed: %s %s", resp.Status, b)
	}
	var er enrollResp
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return err
	}
	enc, err := dpapiEncrypt([]byte(er.DeviceToken))
	if err != nil {
		return err
	}
	if err := os.WriteFile(tokPath, enc, 0o600); err != nil {
		return err
	}
	c.token = er.DeviceToken
	return nil
}

func dpapiEncrypt(plain []byte) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return bytes.Clone(unsafe.Slice(out.Data, out.Size)), nil
}

func dpapiDecrypt(enc []byte) ([]byte, error) {
	if len(enc) == 0 {
		return nil, errors.New("empty")
	}
	in := windows.DataBlob{Size: uint32(len(enc)), Data: &enc[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return bytes.Clone(unsafe.Slice(out.Data, out.Size)), nil
}

// ---------- 전송 ----------

// Send 는 배치를 전송한다. 실패하면 스풀에 저장하고 nil 을 반환한다(데이터 유실 방지).
// 반환값 delivered 는 "서버가 받았는지"이며, 이벤트 로그 상태 커밋 여부 판단에 쓴다.
func (c *Client) Send(env *model.Envelope) (delivered bool, err error) {
	payload, err := encode(env)
	if err != nil {
		return false, err
	}
	if err := c.post(payload); err != nil {
		return false, c.spool(payload)
	}
	c.FlushSpool()
	return true, nil
}

func encode(env *model.Envelope) ([]byte, error) {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err := json.NewEncoder(zw).Encode(env); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Client) post(gz []byte) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			// 지수 백오프 + 지터: 여러 PC 가 동시에 재시도해 서버를 몰아치지 않도록
			time.Sleep(time.Duration(1<<attempt)*time.Second + time.Duration(rand.IntN(1000))*time.Millisecond)
		}
		req, _ := http.NewRequest(http.MethodPost, c.baseURL+"/v1/ingest", bytes.NewReader(gz))
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("User-Agent", c.userAgent)
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		switch {
		case resp.StatusCode/100 == 2:
			return nil
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return fmt.Errorf("auth rejected: %s", resp.Status) // 재시도 무의미
		default:
			lastErr = fmt.Errorf("server: %s", resp.Status)
		}
	}
	return lastErr
}

// GetPolicy 는 서버가 이 장치에 주는 정책(문서 감사 등)을 받는다. 응답 본문(JSON) 그대로 돌려준다.
func (c *Client) GetPolicy() ([]byte, error) {
	req, _ := http.NewRequest(http.MethodGet, c.baseURL+"/v1/policy", nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<10))
}

func (c *Client) spool(gz []byte) error {
	name := filepath.Join(c.spoolDir, fmt.Sprintf("%d.json.gz", time.Now().UnixNano()))
	if err := os.WriteFile(name, gz, 0o600); err != nil {
		return err
	}
	c.trimSpool()
	return nil
}

// trimSpool 은 용량 상한을 넘으면 가장 오래된 파일부터 버린다(디스크 고갈 방지).
func (c *Client) trimSpool() {
	files := c.spoolFiles()
	var total int64
	for i := len(files) - 1; i >= 0; i-- {
		total += files[i].size
		if total > c.spoolMax {
			os.Remove(files[i].path)
		}
	}
}

type spoolFile struct {
	path string
	size int64
}

func (c *Client) spoolFiles() []spoolFile {
	entries, _ := os.ReadDir(c.spoolDir)
	var out []spoolFile
	for _, e := range entries {
		if info, err := e.Info(); err == nil && !e.IsDir() {
			out = append(out, spoolFile{filepath.Join(c.spoolDir, e.Name()), info.Size()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// SpoolStats 는 전송 대기 중인 배치 수와 크기다(에이전트 상태 보고용).
func (c *Client) SpoolStats() (files int, bytes int64) {
	for _, f := range c.spoolFiles() {
		files++
		bytes += f.size
	}
	return
}

// FlushSpool 은 쌓인 배치를 오래된 순서로 재전송한다. 한 번에 최대 20개.
func (c *Client) FlushSpool() {
	for i, f := range c.spoolFiles() {
		if i >= 20 {
			return
		}
		b, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		if c.post(b) != nil {
			return
		}
		os.Remove(f.path)
	}
}
