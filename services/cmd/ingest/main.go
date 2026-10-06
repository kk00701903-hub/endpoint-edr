// ingest : 에이전트 → DB 수집 게이트웨이
//
//	POST /v1/enroll   등록키로 장치 등록, 장치 토큰 발급(평문은 응답에서만 1회)
//	POST /v1/ingest   장치 토큰 인증 후 배치 저장 (gzip JSON)
//	GET  /v1/policy   장치 토큰 인증 후 관리자 정책(문서 감사) 전달
//	GET  /healthz
//
// 에이전트가 Supabase 에 직접 쓰지 않게 하는 이유
//   - 서비스 키/DB 비밀번호가 수천 대 PC 에 퍼지지 않는다.
//   - 입력 검증·크기 제한·장치별 속도 제한을 한 곳에서 건다.
//   - COPY 로 대량 적재 → PostgREST 개별 INSERT 보다 훨씬 가볍다.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yourorg/endpoint-edr/services/internal/contract"
)

const (
	maxCompressedBody   = 5 << 20  // 5MB
	maxDecompressedBody = 40 << 20 // 압축 폭탄 방지
	maxRowsPerKind      = 20000
	maxStr              = 4096
)

const (
	maxSoftware      = 5000 // 자산 정보 1건의 설치 프로그램 수
	maxPostureChecks = 50
	maxDocFindings   = 500 // 문서 감사 배치 1건의 결과 수
	maxDocKeywords   = 50
)

var (
	sha256re           = regexp.MustCompile(`^[0-9a-f]{64}$`)
	checkIDre          = regexp.MustCompile(`^[a-z0-9_]{2,40}$`)
	validPostureStatus = map[string]bool{"pass": true, "warn": true, "fail": true, "unknown": true}
	scanIDre           = regexp.MustCompile(`^[0-9a-f]{8,32}$`)
	validDocTrigger    = map[string]bool{"schedule": true, "request": true, "manual": true}
	validPIIKind       = map[string]bool{"rrn": true, "frn": true, "passport": true, "driver": true, "card": true, "phone": true}
)

type server struct {
	db      *pgxpool.Pool
	log     *slog.Logger
	devices sync.Map // tokenHash(hex) → cachedDevice
	limiter *rateLimiter
	// Wazuh 연동(선택): 둘 다 설정돼야 /v1/wazuh 웹훅이 열린다
	wazuhSecret string // 공유 비밀(Authorization: Bearer)
	wazuhTenant string // 경보를 넣을 조직 id
}

const maxWazuhAlerts = 500 // 한 번에 받을 Wazuh 경보 수 상한

type cachedDevice struct {
	id, tenantID string
	active       bool
	until        time.Time
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, mustEnv("DATABASE_URL"))
	if err != nil {
		log.Error("db", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	s := &server{db: pool, log: log, limiter: newRateLimiter(30, time.Minute), // 장치당 분당 30회
		wazuhSecret: os.Getenv("WAZUH_WEBHOOK_SECRET"), wazuhTenant: os.Getenv("WAZUH_TENANT_ID")}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.enroll)
	mux.HandleFunc("POST /v1/ingest", s.ingest)
	mux.HandleFunc("GET /v1/policy", s.policy)
	if s.wazuhSecret != "" && s.wazuhTenant != "" {
		mux.HandleFunc("POST /v1/wazuh", s.wazuh)
		log.Info("Wazuh 경보 웹훅 켜짐", "path", "/v1/wazuh", "tenant", s.wazuhTenant)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := pool.Ping(r.Context()); err != nil {
			http.Error(w, "db down", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})

	addr := envOr("LISTEN_ADDR", ":8080")
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	log.Info("ingest listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}

// ---------------- 등록 ----------------

type enrollReq struct {
	EnrollmentKey string `json:"enrollment_key"`
	Hostname      string `json:"hostname"`
	OSVersion     string `json:"os_version"`
	AgentVersion  string `json:"agent_version"`
}

func (s *server) enroll(w http.ResponseWriter, r *http.Request) {
	var req enrollReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil || req.EnrollmentKey == "" || req.Hostname == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.limiter.allow("enroll:" + clientIP(r)) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	keyHash := sha256.Sum256([]byte(req.EnrollmentKey))
	token := "edr_dev_" + randomHex(32)
	tokHash := sha256.Sum256([]byte(token))

	var deviceID string
	err := pgx.BeginFunc(r.Context(), s.db, func(tx pgx.Tx) error {
		var keyID, tenantID string
		err := tx.QueryRow(r.Context(), `
			select id, tenant_id from enrollment_keys
			where key_hash = $1 and not revoked and expires_at > now() and used_count < max_uses
			for update`, keyHash[:]).Scan(&keyID, &tenantID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `update enrollment_keys set used_count = used_count + 1 where id = $1`, keyID); err != nil {
			return err
		}
		return tx.QueryRow(r.Context(), `
			insert into devices (tenant_id, hostname, os_version, agent_version, token_hash, last_ip)
			values ($1, $2, $3, $4, $5, $6) returning id`,
			tenantID, clip(req.Hostname, 255), clip(req.OSVersion, 255), clip(req.AgentVersion, 64),
			tokHash[:], ipOrNil(clientIP(r))).Scan(&deviceID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "invalid enrollment key", http.StatusForbidden)
		return
	}
	if err != nil {
		s.log.Error("enroll", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.log.Info("device enrolled", "device_id", deviceID, "hostname", req.Hostname)
	writeJSON(w, map[string]string{"device_id": deviceID, "device_token": token})
}

// ---------------- 수집 ----------------

func (s *server) ingest(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.authDevice(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !dev.active {
		http.Error(w, "device disabled", http.StatusForbidden)
		return
	}
	if !s.limiter.allow(dev.id) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	var body io.Reader = http.MaxBytesReader(w, r.Body, maxCompressedBody)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		defer zr.Close()
		body = io.LimitReader(zr, maxDecompressedBody)
	}
	var env contract.Envelope
	if err := json.NewDecoder(body).Decode(&env); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if len(env.Processes) > maxRowsPerKind || len(env.Connections) > maxRowsPerKind || len(env.ProcessExits) > maxRowsPerKind ||
		len(env.SecurityEvents) > maxRowsPerKind || len(env.Autoruns) > maxRowsPerKind ||
		len(env.Posture) > maxPostureChecks || (env.Inventory != nil && (len(env.Inventory.Software) > maxSoftware || len(env.Inventory.Adapters) > 64)) {
		http.Error(w, "batch too large", http.StatusRequestEntityTooLarge)
		return
	}
	for _, c := range env.Posture {
		if !checkIDre.MatchString(c.ID) || !validPostureStatus[c.Status] {
			http.Error(w, "bad posture check", http.StatusBadRequest)
			return
		}
	}
	if env.DocScan != nil {
		if msg := validDocScan(env.DocScan); msg != "" {
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
	}

	if err := s.store(r.Context(), dev, &env, clientIP(r)); err != nil {
		s.log.Error("store", "device_id", dev.id, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError) // 에이전트는 스풀 후 재전송
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// validDocScan 은 문서 감사 배치를 검사한다. 문제가 있으면 이유를 돌려준다.
// 결과에는 위치와 건수만 온다(문서 내용·개인정보 값은 계약에 없다).
func validDocScan(d *contract.DocScanBatch) string {
	if !scanIDre.MatchString(d.ScanID) || !validDocTrigger[d.Trigger] {
		return "bad doc scan header"
	}
	if len(d.Findings) > maxDocFindings {
		return "doc scan batch too large"
	}
	if d.FilesScanned < 0 || d.FilesSkipped < 0 || d.Errors < 0 || d.RequestID < 0 {
		return "bad doc scan counters"
	}
	for _, f := range d.Findings {
		if f.Path == "" || len(f.Path) > maxStr || len(f.Keywords) > maxDocKeywords || len(f.Unreadable) > 200 {
			return "bad doc finding"
		}
		for k, n := range f.PII {
			if !validPIIKind[k] || n < 0 {
				return "bad doc finding pii"
			}
		}
		for k, n := range f.Keywords {
			if k == "" || len(k) > 1024 || n < 0 {
				return "bad doc finding keyword"
			}
		}
	}
	return ""
}

// policy 는 장치가 주기적으로 받아 가는 관리자 정책이다(지금은 문서 감사만).
// "지금 검사" 요청이 있으면 request_id 가 함께 간다. DB 오류면 503 → 에이전트는 이전 정책을 유지한다.
func (s *server) policy(w http.ResponseWriter, r *http.Request) {
	dev, ok := s.authDevice(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !dev.active {
		http.Error(w, "device disabled", http.StatusForbidden)
		return
	}
	if !s.limiter.allow("policy:" + dev.id) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	var body []byte
	if err := s.db.QueryRow(r.Context(), `select public.edr_device_policy($1)::text`, dev.id).Scan(&body); err != nil {
		s.log.Error("policy", "device_id", dev.id, "err", err)
		http.Error(w, "policy unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}

// ---------------- Wazuh 경보 수집 ----------------
// Wazuh integrator 가 경보(JSON)를 보낸다. 공유 비밀로 인증하고, 받은 경보를 alerts 에 source='wazuh' 로 넣는다.
// 받기만 한다 — Wazuh 나 PC 를 제어하지 않는다. 몸체는 경보 1건(객체) 또는 여러 건(배열) 모두 받는다.
func (s *server) wazuh(w http.ResponseWriter, r *http.Request) {
	tok, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || subtle.ConstantTimeCompare([]byte(tok), []byte(s.wazuhSecret)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.limiter.allow("wazuh") { // 공유 출처라 하나의 버킷으로 제한
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	var body io.Reader = http.MaxBytesReader(w, r.Body, maxCompressedBody)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "bad gzip", http.StatusBadRequest)
			return
		}
		defer zr.Close()
		body = io.LimitReader(zr, maxDecompressedBody)
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	// 객체 1건 또는 배열 — Wazuh 설정에 따라 다르다. 둘 다 받는다.
	var alerts []json.RawMessage
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &alerts); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
	} else {
		alerts = []json.RawMessage{json.RawMessage(trimmed)}
	}
	if len(alerts) > maxWazuhAlerts {
		http.Error(w, "too many alerts", http.StatusRequestEntityTooLarge)
		return
	}

	stored := 0
	for _, a := range alerts {
		if len(bytes.TrimSpace(a)) == 0 {
			continue
		}
		var id *int64
		if err := s.db.QueryRow(r.Context(), `select public.edr_ingest_wazuh_alert($1, $2::jsonb)`,
			s.wazuhTenant, stripNUL(a)).Scan(&id); err != nil {
			s.log.Error("wazuh ingest", "err", err)
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		if id != nil {
			stored++
		}
	}
	writeJSON(w, map[string]int{"received": len(alerts), "stored": stored})
}

func (s *server) authDevice(r *http.Request) (cachedDevice, bool) {
	tok, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || !strings.HasPrefix(tok, "edr_dev_") {
		return cachedDevice{}, false
	}
	h := sha256.Sum256([]byte(tok))
	key := hex.EncodeToString(h[:])
	if v, ok := s.devices.Load(key); ok && time.Now().Before(v.(cachedDevice).until) {
		return v.(cachedDevice), true
	}
	var d cachedDevice
	var status string
	err := s.db.QueryRow(r.Context(), `select id, tenant_id, status from devices where token_hash = $1`, h[:]).
		Scan(&d.id, &d.tenantID, &status)
	if err != nil {
		return cachedDevice{}, false
	}
	d.active = status == "active"
	d.until = time.Now().Add(5 * time.Minute) // 비활성화 반영까지 최대 5분
	s.devices.Store(key, d)
	return d, true
}

func (s *server) store(ctx context.Context, dev cachedDevice, env *contract.Envelope, ip string) error {
	// 해시 등록은 본 트랜잭션 밖에서 먼저, 짧게 처리한다.
	// 여러 PC 가 같은 파일(chrome.exe 등) 해시를 동시에 기록하므로, 긴 트랜잭션 안에서 순서 없이 잠그면 교착 상태가 난다.
	if err := s.registerHashes(ctx, dev, env); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			update devices set last_seen_at = now(), last_ip = $2,
			       agent_version = coalesce(nullif($3, ''), agent_version),
			       hostname = coalesce(nullif($4, ''), hostname)
			where id = $1`, dev.id, ipOrNil(ip), clip(env.AgentVersion, 64), clip(env.Hostname, 255)); err != nil {
			return err
		}

		// --- 장치 상태(에이전트 자원 사용량) ---
		if env.Health != nil {
			h, _ := json.Marshal(env.Health)
			if _, err := tx.Exec(ctx, `update devices set health = $2, health_at = now() where id = $1`, dev.id, h); err != nil {
				return err
			}
		}

		// --- 현재 프로세스 표 갱신 (전체 스냅샷이면 통째로 교체, 아니면 시작·종료 반영) ---
		if env.Snapshot && len(env.Processes) > 0 {
			if _, err := tx.Exec(ctx, `delete from processes_current where device_id = $1`, dev.id); err != nil {
				return err
			}
		}
		if len(env.ProcessExits) > 0 {
			pids := make([]int32, 0, len(env.ProcessExits))
			cts := make([]*string, 0, len(env.ProcessExits))
			for _, e := range env.ProcessExits {
				pids = append(pids, int32(e.PID))
				cts = append(cts, str(tsOrNil(e.CreateTime)))
			}
			if _, err := tx.Exec(ctx, `
				delete from processes_current pc using unnest($2::int[], $3::text[]) as x(pid, ct)
				where pc.device_id = $1 and pc.pid = x.pid
				  and pc.create_time = coalesce(x.ct::timestamptz, '-infinity')`, dev.id, pids, cts); err != nil {
				return err
			}
		}
		if len(env.Processes) > 0 {
			rows := make([][]*string, 0, len(env.Processes))
			for _, p := range env.Processes {
				rows = append(rows, []*string{str(dev.tenantID), str(dev.id), str(p.PID), str(tsOrNil(p.CreateTime)),
					str(p.PPID), str(clip(p.Name, 260)), str(nz(clip(p.Path, 1024))), str(nz(clip(p.CommandLine, maxStr))),
					str(nz(clip(p.User, 256))), str(shaOrNil(p.SHA256))})
			}
			cols := []string{"tenant_id", "device_id", "pid", "create_time", "ppid", "name", "path", "command_line", "username", "sha256"}
			args := make([]any, len(cols))
			for i := range cols {
				col := make([]*string, len(rows))
				for r := range rows {
					col[r] = rows[r][i]
				}
				args[i] = col
			}
			if _, err := tx.Exec(ctx, `
				insert into processes_current (tenant_id, device_id, pid, create_time, ppid, name, path, command_line, username, sha256)
				select c0::uuid, c1::uuid, c2::int, coalesce(c3::timestamptz, '-infinity'), c4::int, c5, c6, c7, c8, c9
				from unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[])
				  as u(c0, c1, c2, c3, c4, c5, c6, c7, c8, c9)
				on conflict (device_id, pid, create_time) do update
				set name = excluded.name, path = coalesce(excluded.path, processes_current.path),
				    command_line = coalesce(excluded.command_line, processes_current.command_line),
				    username = coalesce(excluded.username, processes_current.username),
				    sha256 = coalesce(excluded.sha256, processes_current.sha256)`, args...); err != nil {
				return err
			}
		}

		// --- 프로세스 / 네트워크: unnest 다중행 INSERT ---
		// (COPY FROM 은 RLS 가 켜진 테이블에 쓸 수 없으므로, 배열 파라미터 1회 왕복 INSERT 를 쓴다)
		if len(env.Processes) > 0 {
			rows := make([][]*string, 0, len(env.Processes))
			for _, p := range env.Processes {
				rows = append(rows, []*string{str(dev.tenantID), str(dev.id), str(ts(p.ObservedAt)), str(p.PID), str(p.PPID),
					str(tsOrNil(p.CreateTime)), str(clip(p.Name, 260)), str(nz(clip(p.Path, 1024))),
					str(nz(clip(p.CommandLine, maxStr))), str(nz(clip(p.User, 256))), str(shaOrNil(p.SHA256)), str(env.Snapshot)})
			}
			if err := insertUnnest(ctx, tx, "process_events",
				[]string{"tenant_id", "device_id", "observed_at", "pid", "ppid", "create_time", "name", "path",
					"command_line", "username", "sha256", "is_snapshot"},
				[]string{"uuid", "uuid", "timestamptz", "int", "int", "timestamptz", "text", "text", "text", "text", "text", "boolean"},
				rows); err != nil {
				return err
			}
		}
		if len(env.Connections) > 0 {
			rows := make([][]*string, 0, len(env.Connections))
			for _, c := range env.Connections {
				rows = append(rows, []*string{str(dev.tenantID), str(dev.id), str(ts(c.ObservedAt)), str(clip(c.Proto, 8)),
					str(clip(c.Direction, 16)), str(addrOrNil(c.LocalIP)), str(c.LocalPort), str(addrOrNil(c.RemoteIP)),
					str(c.RemotePort), str(clip(c.State, 16)), str(c.PID), str(nz(clip(c.ProcessName, 260))), str(c.IsExternal)})
			}
			if err := insertUnnest(ctx, tx, "net_connections",
				[]string{"tenant_id", "device_id", "observed_at", "proto", "direction", "local_ip", "local_port",
					"remote_ip", "remote_port", "state", "pid", "process_name", "is_external"},
				[]string{"uuid", "uuid", "timestamptz", "text", "text", "inet", "int", "inet", "int", "text", "int", "text", "boolean"},
				rows); err != nil {
				return err
			}
		}

		// --- 보안 이벤트 (재전송 중복은 무시: ON CONFLICT DO NOTHING) ---
		if len(env.SecurityEvents) > 0 {
			b := &pgx.Batch{}
			for _, e := range env.SecurityEvents {
				data, _ := json.Marshal(e.Data)
				srcPort, _ := strconv.Atoi(e.SourcePort)
				b.Queue(`insert into security_events (tenant_id, device_id, channel, record_id, event_id, event_time,
				           provider, target_user, target_domain, logon_type, src_ip, src_port, workstation, status,
				           sub_status, process_name, data)
				         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
				         on conflict do nothing`,
					dev.tenantID, dev.id, clip(e.Channel, 128), int64(e.RecordID), int32(e.EventID), ts(e.EventTime),
					nz(clip(e.Provider, 256)), nz(clip(e.TargetUser, 256)), nz(clip(e.TargetDomain, 256)),
					intOrNil(e.LogonType), addrOrNil(e.SourceIP), intOrNil(srcPort), nz(clip(e.Workstation, 256)),
					nz(clip(e.Status, 32)), nz(clip(e.SubStatus, 32)), nz(clip(e.ProcessName, 1024)), data)
			}
			if err := tx.SendBatch(ctx, b).Close(); err != nil {
				return err
			}
		}

		// --- 지속성: 변경 이력 + 현재 상태 ---
		if len(env.Autoruns) > 0 {
			b := &pgx.Batch{}
			for _, a := range env.Autoruns {
				loc, name := clip(a.Location, 512), clip(a.EntryName, 512)
				b.Queue(`insert into autorun_changes (tenant_id, device_id, change, location, entry_name, command, image_path, sha256, observed_at)
				         values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
					dev.tenantID, dev.id, a.Change, loc, name, nz(clip(a.Command, maxStr)), nz(clip(a.ImagePath, 1024)),
					shaOrNil(a.SHA256), ts(a.ObservedAt))
				if a.Change == "removed" {
					b.Queue(`update autoruns set removed_at = now() where device_id = $1 and location = $2 and entry_name = $3`,
						dev.id, loc, name)
				} else {
					b.Queue(`insert into autoruns (tenant_id, device_id, location, entry_name, command, image_path, sha256)
					         values ($1,$2,$3,$4,$5,$6,$7)
					         on conflict (device_id, location, entry_name) do update
					         set command = excluded.command, image_path = excluded.image_path, sha256 = excluded.sha256,
					             last_seen_at = now(), removed_at = null`,
						dev.tenantID, dev.id, loc, name, nz(clip(a.Command, maxStr)), nz(clip(a.ImagePath, 1024)), shaOrNil(a.SHA256))
				}
			}
			if err := tx.SendBatch(ctx, b).Close(); err != nil {
				return err
			}
		}

		// --- 자산 정보 · 보안 상태: 비교·이력·점수 판단은 DB 함수가 한다(security definer, 이 장치의 조직인지 다시 확인) ---
		if env.Inventory != nil {
			inv := *env.Inventory
			inv.CollectedAt = ts(inv.CollectedAt)
			b, err := json.Marshal(inv)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `select public.edr_apply_inventory($1, $2, $3::jsonb)`, dev.tenantID, dev.id, stripNUL(b)); err != nil {
				return err
			}
		}
		if len(env.Posture) > 0 {
			b, err := json.Marshal(env.Posture)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `select public.edr_apply_posture($1, $2, $3::jsonb)`, dev.tenantID, dev.id, stripNUL(b)); err != nil {
				return err
			}
		}
		// --- 문서 감사: 배치 합산·마지막 배치에서 사라진 결과 정리는 DB 함수가 한다 ---
		if env.DocScan != nil {
			b, err := json.Marshal(env.DocScan)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `select public.edr_apply_doc_scan($1, $2, $3::jsonb)`, dev.tenantID, dev.id, stripNUL(b)); err != nil {
				return err
			}
		}
		return nil
	})
}

// stripNUL 은 JSON 문자열 안의 NUL(\u0000 이스케이프)을 지운다. PostgreSQL jsonb 는 NUL 문자를 받지 않는다
// (레지스트리 문자열 끝에 가끔 섞여 온다). 이스케이프 쌍(\\ 등)을 차례로 건너뛰어 "\\u0000"(역슬래시 + 글자)은 건드리지 않는다.
func stripNUL(b []byte) string {
	if !bytes.Contains(b, []byte(`\u0000`)) {
		return string(b)
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\\' && i+1 < len(b) {
			if i+5 < len(b) && string(b[i+1:i+6]) == "u0000" {
				i += 5
				continue
			}
			out = append(out, b[i], b[i+1])
			i++
			continue
		}
		out = append(out, b[i])
	}
	return string(out)
}

// registerHashes 는 해시 평판 캐시(file_hashes)와 조직이 본 해시(tenant_file_hashes)를 기록한다.
//   - 해시를 정렬해 한 문장으로 넣는다 → 모든 요청이 같은 순서로 행을 잠가 교착 상태가 생기지 않는다.
//   - 본 트랜잭션과 분리된 짧은 자동 커밋 문장이라 잠금을 오래 쥐지 않는다(멱등이라 본 저장이 실패해도 무해).
//   - 1시간 안에 이미 본 해시는 last_seen_at 을 다시 쓰지 않는다(인기 해시 행에 쓰기가 몰리지 않게).
func (s *server) registerHashes(ctx context.Context, dev cachedDevice, env *contract.Envelope) error {
	hashes := map[string]string{} // sha → sample path
	for _, p := range env.Processes {
		if sha256re.MatchString(p.SHA256) {
			hashes[p.SHA256] = p.Path
		}
	}
	for _, a := range env.Autoruns {
		if sha256re.MatchString(a.SHA256) {
			hashes[a.SHA256] = a.ImagePath
		}
	}
	if len(hashes) == 0 {
		return nil
	}
	shas := make([]string, 0, len(hashes))
	for h := range hashes {
		shas = append(shas, h)
	}
	sort.Strings(shas)
	paths := make([]string, len(shas))
	for i, h := range shas {
		paths[i] = clip(hashes[h], 1024)
	}
	if _, err := s.db.Exec(ctx, `
		insert into file_hashes (sha256)
		select h from unnest($1::text[]) as u(h) order by h
		on conflict do nothing`, shas); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `
		insert into tenant_file_hashes (tenant_id, sha256, sample_path)
		select $1::uuid, h, nullif(p, '') from unnest($2::text[], $3::text[]) as u(h, p) order by h
		on conflict (tenant_id, sha256) do update set last_seen_at = now()
		where tenant_file_hashes.last_seen_at < now() - interval '1 hour'`, dev.tenantID, shas, paths)
	return err
}

// ---------------- 유틸 ----------------

// insertUnnest 는 행 단위 값을 열 단위 text[] 배열로 바꿔 한 번의 INSERT ... SELECT FROM unnest(...) 로 넣는다.
func insertUnnest(ctx context.Context, tx pgx.Tx, table string, cols, types []string, rows [][]*string) error {
	args := make([]any, len(cols))
	sel := make([]string, len(cols))
	params := make([]string, len(cols))
	for i := range cols {
		col := make([]*string, len(rows))
		for r := range rows {
			col[r] = rows[r][i]
		}
		args[i] = col
		params[i] = "$" + strconv.Itoa(i+1) + "::text[]"
		sel[i] = "c" + strconv.Itoa(i) + "::" + types[i]
	}
	names := make([]string, len(cols))
	for i := range cols {
		names[i] = "c" + strconv.Itoa(i)
	}
	sql := "insert into " + pgx.Identifier{table}.Sanitize() + " (" + strings.Join(cols, ", ") + ") select " +
		strings.Join(sel, ", ") + " from unnest(" + strings.Join(params, ", ") + ") as u(" + strings.Join(names, ", ") + ")"
	_, err := tx.Exec(ctx, sql, args...)
	return err
}

// str 은 값을 PostgreSQL 텍스트 표현으로 바꾼다(nil → NULL).
func str(v any) *string {
	var s string
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		s = x
	case time.Time:
		s = x.UTC().Format(time.RFC3339Nano)
	case netip.Addr:
		s = x.String()
	case bool:
		s = strconv.FormatBool(x)
	case uint32:
		s = strconv.FormatUint(uint64(x), 10)
	case uint16:
		s = strconv.FormatUint(uint64(x), 10)
	default:
		return nil
	}
	return &s
}

type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	h := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < l.window {
			h = append(h, t)
		}
	}
	if len(h) >= l.limit {
		l.hits[key] = h
		return false
	}
	l.hits[key] = append(h, now)
	if len(l.hits) > 100000 { // 메모리 상한
		l.hits = map[string][]time.Time{}
	}
	return true
}

func clientIP(r *http.Request) string {
	// 리버스 프록시(Caddy/Nginx) 뒤에 둘 때만 TRUST_PROXY=1 로 X-Forwarded-For 를 신뢰한다.
	if os.Getenv("TRUST_PROXY") == "1" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// UTF-8 경계를 깨지 않도록 자른다
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

func nz(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func addrOrNil(s string) any {
	if a, err := netip.ParseAddr(s); err == nil {
		return a
	}
	return nil
}

func ipOrNil(s string) any { return addrOrNil(s) }

func shaOrNil(s string) any {
	if sha256re.MatchString(s) {
		return s
	}
	return nil
}

func intOrNil(v int) any {
	if v == 0 {
		return nil
	}
	return int32(v)
}

// ts 는 에이전트 시계가 크게 틀린 경우(미래 1일 초과 / 과거 1년 초과)를 서버 시각으로 보정한다.
func ts(t time.Time) time.Time {
	now := time.Now().UTC()
	if t.IsZero() || t.After(now.Add(24*time.Hour)) || t.Before(now.AddDate(-1, 0, 0)) {
		return now
	}
	return t.UTC()
}

func tsOrNil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		slog.Error("missing env", "key", k)
		os.Exit(1)
	}
	return v
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
