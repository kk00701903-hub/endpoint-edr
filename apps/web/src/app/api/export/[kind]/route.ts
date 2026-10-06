import { canAdmin, getContext } from "@/lib/context";
import { PII_LABEL } from "@/lib/data/doc-defaults";
import { REMEDIATION_KIND, REMEDIATION_STATUS } from "@/lib/remediation-labels";
import type { DocPiiKind, Page, RemediationView } from "@/lib/data/types";
import { POSTURE_LABEL_TEXT } from "./labels";

// 목록 화면의 CSV 내려받기 (Excel 에서 한글이 깨지지 않도록 UTF-8 BOM).
// 권한은 화면과 같다: 사용자 세션으로 조회하므로 RLS 가 판단한다.
//   /api/export/assets · software · software-changes · posture · iocs
//   /api/export/remediation  (화면과 같은 조건)
//   /api/export/documents-pii · documents-keyword · documents-stale  (소유자·관리자만, 내보내기는 감사 기록에 남음)

const MAX_ROWS = 50_000;

/** 셀 값: 따옴표 처리 + 수식 주입 방지(=, +, -, @ 로 시작하면 앞에 ' ) */
function cell(v: unknown): string {
  if (v == null) return "";
  let s = Array.isArray(v) ? v.join(" | ") : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

function csv(header: string[], rows: unknown[][]): string {
  return "﻿" + [header, ...rows].map((r) => r.map(cell).join(",")).join("\r\n") + "\r\n";
}

/** 페이지를 끝까지(최대 MAX_ROWS) 모은다 */
async function all<T>(load: (page: number) => Promise<Page<T>>): Promise<T[]> {
  const out: T[] = [];
  for (let page = 1; out.length < MAX_ROWS; page++) {
    const p = await load(page);
    out.push(...p.rows);
    if (p.rows.length === 0 || page * p.pageSize >= p.total) break;
  }
  return out.slice(0, MAX_ROWS);
}

export async function GET(req: Request, { params }: { params: Promise<{ kind: string }> }) {
  const { kind } = await params;
  const { source, tenant, viewer } = await getContext();
  let body: string;
  switch (kind) {
    case "assets": {
      const rows = await all((page) => source.assets(tenant, { page, pageSize: 500 }));
      body = csv(
        ["장치", "Windows", "에디션", "버전", "빌드", "지원 종료일", "제조사", "모델", "일련번호", "BIOS", "CPU", "스레드", "메모리(GB)",
          "디스크 전체(GB)", "디스크 남음(GB)", "도메인", "도메인 가입", "마지막 로그온", "IP", "MAC", "설치 프로그램 수", "확인 시각"],
        rows.map((a) => [a.hostname, a.os_name, a.os_edition, a.os_display_version, a.os_build && `${a.os_build}${a.os_ubr ? `.${a.os_ubr}` : ""}`,
          a.os_end_of_support, a.manufacturer, a.model, a.serial_number, a.bios_version, a.cpu, a.cpu_cores,
          a.memory_mb && Math.round(a.memory_mb / 1024), a.disk_total_gb, a.disk_free_gb, a.domain, a.domain_joined == null ? "" : a.domain_joined ? "예" : "아니요",
          a.last_user, a.adapters.flatMap((x) => x.ips ?? []), a.adapters.map((x) => x.mac).filter(Boolean), a.software_count, a.collected_at]),
      );
      break;
    }
    case "software": {
      const rows = await all((page) => source.softwareCatalog(tenant, { page, pageSize: 200 }));
      body = csv(["프로그램", "게시자", "버전", "설치 장치 수", "처음 본 때"], rows.map((s) => [s.name, s.publisher, s.versions, s.devices, s.first_seen_at]));
      break;
    }
    case "software-changes": {
      const rows = await all((page) => source.softwareChanges(tenant, { days: 30, page, pageSize: 500 }));
      body = csv(["시각", "장치", "변화", "프로그램", "이전 버전", "버전", "게시자"],
        rows.map((c) => [c.observed_at, c.hostname, { installed: "설치", removed: "삭제", updated: "업데이트" }[c.change], c.name, c.prev_version, c.version, c.publisher]));
      break;
    }
    case "posture": {
      const [rows, ov] = await Promise.all([all((page) => source.postureDevices(tenant, { page, pageSize: 200 })), source.postureOverview(tenant)]);
      body = csv(["장치", "보안 점수", "실패 항목"], rows.map((r) => [r.hostname, r.score, r.fails]));
      // 항목별 요약을 아래에 덧붙인다
      body += "\r\n" + csv(["점검 항목", "분류", "가중치", "점수 반영", ...Object.values(POSTURE_LABEL_TEXT)],
        ov.checks.map((c) => [c.title, c.category, c.weight, c.enabled ? "예" : "아니요", c.pass, c.warn, c.fail, c.unknown])).slice(1);
      break;
    }
    case "iocs": {
      const rows = await source.iocs(tenant);
      body = csv(["종류", "값", "심각도", "설명", "출처", "사용", "만료", "발견 건수", "마지막 발견", "등록자", "등록 시각"],
        rows.map((i) => [i.type === "sha256" ? "SHA-256" : "IP", i.value, i.severity, i.description, i.source, i.enabled ? "예" : "아니요",
          i.expires_at, i.hit_count, i.last_hit_at, i.created_by_email, i.created_at]));
      break;
    }
    case "documents-pii":
    case "documents-keyword":
    case "documents-stale": {
      if (!canAdmin(viewer.tenant.role)) return new Response("문서 감사 결과는 소유자·관리자만 내려받을 수 있습니다", { status: 403 });
      const docKind = kind.slice("documents-".length) as "pii" | "keyword" | "stale";
      const sp = new URL(req.url).searchParams;
      // 한 번에 받아 감사 기록이 한 줄만 남게 한다(DB 함수가 doc_scan.export 로 기록)
      const { rows } = await source.docFindings(tenant, {
        kind: docKind, q: sp.get("q") || undefined, device: sp.get("device") || undefined,
        keyword: docKind === "keyword" ? sp.get("keyword") || undefined : undefined, page: 1, pageSize: MAX_ROWS, purpose: "export",
      });
      const counts = (o: Record<string, number | undefined>, label?: (k: string) => string) =>
        Object.entries(o).map(([k, n]) => `${label ? label(k) : k} ${n ?? 0}`).join(" | ");
      body = csv(["장치", "파일 경로", "개인정보(종류별 건수)", "개인정보 합계", "키워드(횟수)", "오래된 문서", "읽지 못한 이유", "마지막 저장", "크기(바이트)", "확인 시각"],
        rows.map((r) => [r.hostname, r.path, counts(r.pii, (k) => PII_LABEL[k as DocPiiKind] ?? k), r.pii_total, counts(r.keywords), r.stale ? "예" : "",
          r.unreadable, r.modified_at, r.size, r.last_seen_at]));
      break;
    }
    case "remediation": {
      const sp = new URL(req.url).searchParams;
      const view = (["active", "open", "in_progress", "done", "exception", "resolved", "all"].includes(sp.get("view") ?? "") ? sp.get("view") : "active") as RemediationView;
      const kind = (["posture", "software", "docs"].includes(sp.get("kind") ?? "") ? sp.get("kind") : undefined) as "posture" | "software" | "docs" | undefined;
      const rows = await all((page) => source.remediation(tenant, {
        view, kind, q: sp.get("q") || undefined, device: sp.get("device") || undefined,
        assignee: sp.get("mine") === "1" ? viewer.userId : undefined, page, pageSize: 1000,
      }));
      body = csv(["장치", "종류", "할 일", "내용", "심각도", "발견", "상태", "담당자", "기한", "메모", "고치는 방법", "마지막 처리"],
        rows.map((r) => [r.hostname, REMEDIATION_KIND[r.kind], r.title, r.detail, r.severity, r.since, r.present ? REMEDIATION_STATUS[r.status] : "해결 확인됨",
          r.assignee_email, r.due_date, r.note, r.guidance, r.updated_at]));
      break;
    }
    default:
      return new Response("알 수 없는 내보내기 종류입니다", { status: 404 });
  }
  const date = new Date().toISOString().slice(0, 10);
  return new Response(body, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="edr-${kind}-${date}.csv"`,
      "Cache-Control": "no-store",
    },
  });
}
