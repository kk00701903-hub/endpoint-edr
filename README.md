# Endpoint EDR (Passive)

커널 드라이버 없이 Windows API 를 **읽기 전용**으로만 쓰는 수동형 엔드포인트 모니터링 시스템. **회사 내부 전용.**
기존 보안 에이전트가 설치된 PC 에서도 개입·충돌 없이 24시간 동작하는 것을 목표로 한다.

| 기능 | 대응 도구 | 구현 |
|---|---|---|
| 프로세스 목록 + 해시 평판(VirusTotal 등) | Process Explorer | `agent/internal/collector/process_windows.go`, `services/cmd/enricher` |
| TCP/UDP 연결·포트 | TCPView | `agent/internal/collector/network_windows.go` |
| 보안 이벤트(4625/4624 등) | 이벤트 뷰어 | `agent/internal/collector/eventlog_windows.go` |
| 시작프로그램·서비스·예약작업 | Autoruns | `agent/internal/collector/autoruns_windows.go` |
| 탐지 규칙 10종 → 경보 | — | `supabase/migrations/*_detection.sql` |
| 관리 콘솔 | Defender XDR·Falcon 류 | `apps/web` — 인시던트(자동 묶음·요약·공격 그래프), ATT&CK 매트릭스, 엔터티 프로필, 쿼리 헌팅, 프로세스 트리 |
| 장기 추이·외부 알림 | — | `deploy/grafana` |

시스템 개입(Active Response) 기능은 없으며 `scripts/check-passive.sh` 가 이를 강제한다.

## 문서
- [아키텍처 설계](docs/ARCHITECTURE.md) — 흐름도, 충돌 제로 원칙, DB/RLS, 사내 운영 구조·도입 순서
- [개발·운영 가이드](docs/DEV_GUIDE.md) — 개발은 Claude, Cursor 에서는 확인·빌드·커밋·푸시
- [Claude 개발 규칙](CLAUDE.md)
- [작업 기록](docs/work-log.md)

## 빠른 시작
- 개발: Claude 에게 요청 (규칙은 `CLAUDE.md`)
- 화면 미리보기: `cd apps/web && pnpm install && EDR_DEMO=1 pnpm dev` (예시 데이터)
- 빌드: Cursor 터미널에서 `.\scripts\build.ps1` (처음 1회는 `-Tidy`)
- 커밋·푸시: Cursor

```bash
npx supabase link --project-ref <ref> && npx supabase db push       # DB
cd deploy && cp .env.example .env && docker compose up -d --build   # 서버
```
