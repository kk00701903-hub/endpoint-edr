// enricher : 해시 평판 조회 워커 (+ pg_cron 이 없을 때 탐지 규칙·파티션 유지보수 주기 실행)
//
// 동작
//  1. file_hashes 에서 조회할 해시를 "임대(lease)" 방식으로 가져온다 (여러 인스턴스가 떠도 중복 조회 없음)
//  2. 공급자별 속도 제한을 지키며 조회
//  3. verdict 갱신 → DB 트리거(edr_on_hash_verdict)가 악성 판정 시 경보 생성
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yourorg/endpoint-edr/services/internal/intel"
	"github.com/yourorg/endpoint-edr/services/internal/notify"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Error("db", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	var providers []intel.Provider
	if k := os.Getenv("MALWAREBAZAAR_AUTH_KEY"); k != "" {
		providers = append(providers, &intel.MalwareBazaar{AuthKey: k})
	}
	if k := os.Getenv("VT_API_KEY"); k != "" {
		rpm, _ := strconv.Atoi(os.Getenv("VT_REQUESTS_PER_MIN"))
		providers = append(providers, &intel.VirusTotal{APIKey: k, RequestsPerMin: rpm})
	}
	if len(providers) == 0 {
		log.Warn("평판 공급자 키가 없습니다. 해시 조회 없이 탐지 실행만 합니다.")
	}

	if os.Getenv("RUN_DETECTIONS") == "1" {
		go detectionLoop(ctx, pool, log)
	}

	// 알림 발송 루프: outbox 대기 행을 가져가 슬랙·이메일·SIEM 으로 보낸다(기본 켜짐, RUN_NOTIFIER=0 으로 끔).
	if os.Getenv("RUN_NOTIFIER") != "0" {
		go notifierLoop(ctx, pool, log)
	}

	// 공급자별 마지막 요청 시각 — 가장 느린 공급자(VT 무료 4회/분)가 전체 처리 속도를 결정한다.
	last := map[string]time.Time{}

	for ctx.Err() == nil {
		if len(providers) == 0 {
			sleep(ctx, time.Minute)
			continue
		}
		sha, ok, err := lease(ctx, pool)
		if err != nil {
			log.Error("lease", "err", err)
			sleep(ctx, 30*time.Second)
			continue
		}
		if !ok {
			sleep(ctx, 15*time.Second)
			continue
		}

		var results []intel.Result
		failed := false
		for _, p := range providers {
			if wait := p.Interval() - time.Since(last[p.Name()]); wait > 0 {
				sleep(ctx, wait)
			}
			last[p.Name()] = time.Now()
			r, err := p.Lookup(ctx, sha)
			if err != nil {
				log.Warn("lookup", "provider", p.Name(), "sha256", sha, "err", err)
				failed = true
				continue
			}
			results = append(results, r)
			if intel.Verdict(results) == "malicious" {
				break // 이미 악성 확정: 다른 공급자 쿼터 아끼기
			}
		}

		verdict := intel.Verdict(results)
		if failed && verdict == "unknown" {
			verdict = "error"
		}
		if err := save(ctx, pool, sha, verdict, results); err != nil {
			log.Error("save", "sha256", sha, "err", err)
		} else if verdict == "malicious" || verdict == "suspicious" {
			log.Info("reputation hit", "sha256", sha, "verdict", verdict)
		}
	}
}

// lease 는 조회 대상 1건을 골라 next_check_at 을 10분 뒤로 밀어 "선점"한다(SKIP LOCKED).
func lease(ctx context.Context, db *pgxpool.Pool) (string, bool, error) {
	var sha string
	err := db.QueryRow(ctx, `
		update file_hashes set next_check_at = now() + interval '10 minutes'
		where sha256 = (
			select sha256 from file_hashes
			where next_check_at <= now() and verdict in ('pending','unknown','clean','suspicious','error')
			order by (verdict = 'pending') desc, first_seen_at
			limit 1 for update skip locked)
		returning sha256`).Scan(&sha)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return sha, true, nil
}

func save(ctx context.Context, db *pgxpool.Pool, sha, verdict string, results []intel.Result) error {
	src := map[string]intel.Result{}
	var vtMal, vtSus, vtTotal *int
	for _, r := range results {
		src[r.Provider] = r
		if r.Provider == "virustotal" && r.Found {
			m, s, t := r.Malicious, r.Suspicious, r.Total
			vtMal, vtSus, vtTotal = &m, &s, &t
		}
	}
	srcJSON, _ := json.Marshal(src)
	_, err := db.Exec(ctx, `
		update file_hashes
		set verdict = $2, vt_malicious = coalesce($3, vt_malicious), vt_suspicious = coalesce($4, vt_suspicious),
		    vt_total = coalesce($5, vt_total), sources = sources || $6::jsonb,
		    checked_at = now(), next_check_at = now() + make_interval(secs => $7)
		where sha256 = $1`,
		sha, verdict, vtMal, vtSus, vtTotal, srcJSON, intel.NextCheck(verdict).Seconds())
	return err
}

func detectionLoop(ctx context.Context, db *pgxpool.Pool, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	var lastMaint time.Time
	for {
		// 파티션 미리 만들기 + 보존 기간 정리(pg_cron 의 edr-maintenance 대신). 시작 시 1회, 이후 6시간마다.
		// 이게 멈추면 미리 만든 파티션이 끝나는 달부터 수집 저장이 실패하므로 탐지와 같은 루프에서 챙긴다.
		if time.Since(lastMaint) > 6*time.Hour {
			if _, err := db.Exec(ctx, `select public.edr_maintenance()`); err != nil && ctx.Err() == nil {
				log.Error("maintenance", "err", err)
			} else {
				lastMaint = time.Now()
			}
		}
		var n int
		if err := db.QueryRow(ctx, `select public.edr_run_detections()`).Scan(&n); err != nil && ctx.Err() == nil {
			log.Error("detections", "err", err)
		} else if n > 0 {
			log.Info("alerts created", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// notifierLoop : notification_outbox 를 비운다. 대기 행을 임대 → 채널 종류에 맞게 전송 → sent/failed 표시.
func notifierLoop(ctx context.Context, db *pgxpool.Pool, log *slog.Logger) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	var lastPrune time.Time
	for {
		if time.Since(lastPrune) > 6*time.Hour {
			if _, err := db.Exec(ctx, `select public.edr_prune_notifications()`); err != nil && ctx.Err() == nil {
				log.Error("notify prune", "err", err)
			} else {
				lastPrune = time.Now()
			}
		}
		if err := drainNotifications(ctx, db, log); err != nil && ctx.Err() == nil {
			log.Error("notify drain", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func drainNotifications(ctx context.Context, db *pgxpool.Pool, log *slog.Logger) error {
	rows, err := db.Query(ctx, `select o.id, o.channel_id, c.kind, c.target, c.secret_ref, o.payload
		from public.edr_lease_notifications(20) o
		join public.notification_channels c on c.id = o.channel_id`)
	if err != nil {
		return err
	}
	type job struct {
		id  int64
		ch  notify.Channel
		msg notify.Message
	}
	var jobs []job
	for rows.Next() {
		var j job
		var payload []byte
		if err := rows.Scan(&j.id, &j.ch.ID, &j.ch.Kind, &j.ch.Target, &j.ch.SecretRef, &payload); err != nil {
			rows.Close()
			return err
		}
		_ = json.Unmarshal(payload, &j.msg)
		jobs = append(jobs, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for _, j := range jobs {
		sendErr := notify.Send(ctx, j.ch, j.msg)
		ok := sendErr == nil
		var emsg *string
		if !ok {
			s := sendErr.Error()
			emsg = &s
			log.Warn("notify send failed", "channel", j.ch.ID, "kind", j.ch.Kind, "err", s)
		}
		if _, err := db.Exec(ctx, `select public.edr_mark_notification($1, $2, $3)`, j.id, ok, emsg); err != nil && ctx.Err() == nil {
			log.Error("notify mark", "err", err)
		}
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
