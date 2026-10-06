//go:build windows

// edr-agent : 수동형(Passive) 엔드포인트 모니터링 에이전트
//
//	edr-agent.exe install     서비스 등록(지연된 자동 시작)
//	edr-agent.exe uninstall   서비스 제거
//	edr-agent.exe console     콘솔에서 1회 수집 후 JSON 출력(전송 안 함) — 설치 전 점검용
//	edr-agent.exe docscan <폴더> [키워드...]  문서 감사를 그 폴더에만 1회 실행해 결과 JSON 출력(전송 안 함) — 시험용
//	(인자 없음)               서비스 컨트롤러가 실행
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/yourorg/endpoint-edr/agent/internal/collector"
	"github.com/yourorg/endpoint-edr/agent/internal/config"
	"github.com/yourorg/endpoint-edr/agent/internal/docscan"
	"github.com/yourorg/endpoint-edr/agent/internal/hasher"
	"github.com/yourorg/endpoint-edr/agent/internal/model"
	"github.com/yourorg/endpoint-edr/agent/internal/sysutil"
	"github.com/yourorg/endpoint-edr/agent/internal/transport"
)

const serviceName = "EndpointEDRAgent"

var version = "0.1.0-dev" // 빌드 시 -ldflags "-X main.version=..." 로 주입

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			must(install())
			return
		case "uninstall":
			must(uninstall())
			return
		case "console":
			must(consoleOnce())
			return
		case "docscan":
			must(docscanOnce(os.Args[2:]))
			return
		}
	}
	isSvc, err := svc.IsWindowsService()
	must(err)
	if !isSvc {
		fmt.Println("usage: edr-agent.exe [install|uninstall|console]")
		return
	}
	must(svc.Run(serviceName, &service{}))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// ---------------- 서비스 ----------------

type service struct{}

func (s *service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	elog, _ := eventlog.Open(serviceName)
	logf := func(f string, a ...any) {
		if elog != nil {
			_ = elog.Info(1, fmt.Sprintf(f, a...))
		}
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := run(stop, logf); err != nil {
			logf("agent stopped with error: %v", err)
		}
	}()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			close(stop)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
			}
			return false, 0
		}
	}
	return false, 0
}

// run 은 수집 주기를 돌린다. 각 수집기는 서로 다른 주기 + 시작 지터로 CPU 스파이크를 분산한다.
func run(stop <-chan struct{}, logf func(string, ...any)) error {
	dataDir := config.DefaultDataDir()
	cfg, err := config.Load(dataDir)
	if err != nil {
		return err
	}
	for _, e := range sysutil.ApplyLowFootprint(cfg.MemoryLimitMB << 20) {
		logf("low-footprint: %v", e)
	}

	hostname, _ := os.Hostname()
	client := transport.New(cfg.IngestURL, dataDir, version, cfg.SpoolMaxMB<<20)
	for {
		if err := client.EnsureToken(dataDir, cfg.EnrollmentKey, hostname, osVersion(), version); err == nil {
			break
		} else {
			logf("enroll: %v (retry in 5m)", err)
		}
		select {
		case <-stop:
			return nil
		case <-time.After(5 * time.Minute):
		}
	}

	hm := sysutil.NewHealthMonitor()
	errf := func(f string, a ...any) { logf(f, a...); hm.Error(f, a...) }

	h := hasher.New(cfg.HashMaxFileMB<<20, cfg.HashMBPerSec<<20)
	procs := collector.NewProcessTracker(h)
	conns := collector.NewConnectionTracker()
	autoruns := collector.NewAutorunTracker(h, dataDir)
	events := collector.NewEventLogReader(dataDir, collector.DefaultQueries, cfg.EventBackfill.Duration)
	inventory := collector.NewInventoryTracker()
	posture := collector.NewPostureTracker(cfg.AVServices)
	docRunner := docscan.NewRunner(dataDir)
	docOut := make(chan *model.DocScanBatch, 2)

	newEnv := func(snapshot bool) *model.Envelope {
		return &model.Envelope{AgentVersion: version, Hostname: hostname, SentAt: time.Now().UTC(), Snapshot: snapshot}
	}
	send := func(env *model.Envelope) error {
		_, err := client.Send(env) // 실패 시 스풀에 저장되므로 err 는 디스크 오류일 때만
		return err
	}

	// 시작 직후 한꺼번에 몰리지 않도록 0~30초 지터
	time.Sleep(time.Duration(rand.IntN(30)) * time.Second)

	tProc := time.NewTicker(cfg.ProcessInterval.Duration)
	tNet := time.NewTicker(cfg.NetworkInterval.Duration)
	tEvt := time.NewTicker(cfg.EventLogInterval.Duration)
	tAuto := time.NewTicker(cfg.AutorunInterval.Duration)
	tFull := time.NewTicker(cfg.FullSnapshotEvery.Duration)
	tHealth := time.NewTicker(5 * time.Minute)
	tInv := time.NewTicker(cfg.InventoryInterval.Duration)
	tPosture := time.NewTicker(cfg.PostureInterval.Duration)
	tPolicy := time.NewTicker(cfg.PolicyInterval.Duration)
	defer func() {
		tProc.Stop()
		tNet.Stop()
		tEvt.Stop()
		tAuto.Stop()
		tFull.Stop()
		tHealth.Stop()
		tInv.Stop()
		tPosture.Stop()
		tPolicy.Stop()
	}()

	full := true // 첫 주기는 전체 스냅샷
	scanProcs := func() {
		defer hm.Time("process")()
		ps, exits, err := procs.Scan(full)
		if err != nil {
			errf("process scan: %v", err)
		}
		if len(ps) > 0 || len(exits) > 0 {
			env := newEnv(full)
			env.Processes = ps
			if !full {
				env.ProcessExits = exits
			}
			_ = send(env)
		}
	}
	scanNet := func() {
		defer hm.Time("network")()
		all, err := collector.ScanConnections(procs.Names)
		if err != nil {
			errf("network scan: %v", err)
			return
		}
		if cs := conns.Diff(all, full); len(cs) > 0 {
			env := newEnv(full)
			env.Connections = cs
			_ = send(env)
		}
	}
	scanEvents := func() {
		defer hm.Time("eventlog")()
		evs, err := events.Poll()
		if err != nil {
			errf("eventlog: %v", err)
		}
		if len(evs) == 0 {
			return
		}
		env := newEnv(false)
		env.SecurityEvents = evs
		if send(env) == nil { // 전송 또는 스풀 저장 성공 시에만 위치 저장
			_ = events.Commit(evs)
		}
	}
	scanAutoruns := func() {
		defer hm.Time("autoruns")()
		if ch := autoruns.Scan(); len(ch) > 0 {
			env := newEnv(false)
			env.Autoruns = ch
			_ = send(env)
		}
	}

	// 자산 정보·보안 설정: 바뀌었을 때(또는 24시간/6시간마다)만 보낸다
	scanInventory := func() {
		defer hm.Time("inventory")()
		if inv := inventory.Scan(); inv != nil {
			env := newEnv(false)
			env.Inventory = inv
			_ = send(env)
		}
	}
	scanPosture := func() {
		defer hm.Time("posture")()
		if checks := posture.Scan(); checks != nil {
			env := newEnv(false)
			env.Posture = checks
			_ = send(env)
		}
	}

	// 문서 감사: 관리자가 정책을 켰을 때만. 정해진 간격이나 콘솔의 "지금 검사" 요청이 오면 백그라운드에서 한 번 돈다.
	checkPolicy := func() {
		body, err := client.GetPolicy()
		if err != nil {
			return // 서버가 정책을 모르는 옛 버전이거나 연결 실패 — 다음 주기에
		}
		p, err := docscan.ParsePolicy(body)
		if err != nil {
			errf("policy: %v", err)
			return
		}
		if trigger, ok := docRunner.Due(p, time.Now()); ok {
			lim := docscan.DefaultLimits()
			lim.BytesPerSec = cfg.DocScanMBPerSec << 20
			docRunner.Start(p, docscan.Roots(p, docscan.UsersDir()), trigger, lim, docOut, stop)
		}
	}

	reportHealth := func() {
		env := newEnv(false)
		env.Health = hm.Snapshot(client.SpoolStats())
		_ = send(env)
	}

	scanProcs()
	scanNet()
	scanEvents()
	scanAutoruns()
	full = false
	scanInventory()
	scanPosture()
	reportHealth()
	checkPolicy()

	for {
		select {
		case <-stop:
			return nil
		case <-tProc.C:
			scanProcs()
		case <-tNet.C:
			scanNet()
		case <-tEvt.C:
			scanEvents()
		case <-tAuto.C:
			scanAutoruns()
		case <-tHealth.C:
			reportHealth()
		case <-tInv.C:
			scanInventory()
		case <-tPosture.C:
			scanPosture()
		case <-tPolicy.C:
			checkPolicy()
		case b := <-docOut:
			env := newEnv(false)
			env.DocScan = b
			_ = send(env)
		case <-tFull.C:
			full = true
			scanProcs()
			scanNet()
			full = false
		}
	}
}

func osVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("Windows %d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

// consoleOnce 는 설치 전 점검용: 1회 수집해 표준출력으로 JSON 을 보여준다(서버 전송 없음).
func consoleOnce() error {
	dir, _ := os.MkdirTemp("", "edr-console")
	defer os.RemoveAll(dir)
	h := hasher.New(200<<20, 50<<20)
	pt := collector.NewProcessTracker(h)
	ps, _, err := pt.Scan(true)
	if err != nil {
		return err
	}
	cs, err := collector.ScanConnections(pt.Names)
	if err != nil {
		return err
	}
	evs, evErr := collector.NewEventLogReader(dir, collector.DefaultQueries, time.Hour).Poll()
	ar := collector.NewAutorunTracker(h, dir).Scan()
	host, _ := os.Hostname()
	env := model.Envelope{AgentVersion: version, Hostname: host, SentAt: time.Now().UTC(), Snapshot: true,
		Processes: ps, Connections: cs, SecurityEvents: evs, Autoruns: ar,
		Inventory: collector.CollectInventory(), Posture: collector.NewPostureTracker(nil).Collect()}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if evErr != nil {
		log.Printf("eventlog (관리자 권한 필요할 수 있음): %v", evErr)
	}
	return enc.Encode(env)
}

// docscanOnce 는 지정한 폴더에서 문서 감사를 한 번 돌려 결과를 출력한다(서버 전송 없음). 개인정보 값은 출력하지 않고 건수만.
func docscanOnce(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: edr-agent.exe docscan <폴더> [키워드...]")
	}
	p := docscan.Policy{Enabled: true, Extensions: docscan.Extensions, Detect: docscan.AllKinds, Keywords: args[1:], StaleDays: 1095, MaxFileMB: 20}
	lim := docscan.DefaultLimits()
	lim.PausePerFile = 0
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	var err error
	docscan.Run(p, []string{args[0]}, "manual", lim, func(b *model.DocScanBatch) bool {
		if e := enc.Encode(b); e != nil {
			err = e
		}
		return true
	}, make(chan struct{}))
	return err
}

// ---------------- 설치 / 제거 ----------------

func install() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:      "Endpoint EDR Agent (Passive)",
		Description:      "Read-only endpoint telemetry agent. No kernel driver, no active response.",
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true, // 부팅 직후 다른 보안 제품과 자원 경합을 피한다
	})
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Minute},
		{Type: mgr.NoAction},
	}, 86400)
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	return os.MkdirAll(filepath.Join(config.DefaultDataDir(), "spool"), 0o700)
}

func uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = eventlog.Remove(serviceName)
	return s.Delete()
}
