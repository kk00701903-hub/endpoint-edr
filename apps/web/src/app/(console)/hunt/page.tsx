import Link from "next/link";
import { QueryConsole } from "@/components/query-console";
import { Empty, Mono, PageHeader } from "@/components/ui";
import { canTriage, getContext } from "@/lib/context";
import { DATASET_LABEL, normalizeQuery, parseQuery, type Dataset } from "@/lib/hunt/query";
import { ago, num, stamp } from "@/lib/format";

export const metadata = { title: "위협 헌팅" };

const LOGON: Record<number, string> = { 2: "콘솔", 3: "네트워크", 4: "배치", 5: "서비스", 7: "잠금 해제", 10: "원격 데스크톱", 11: "캐시" };
const EVENT: Record<number, string> = { 4624: "로그온 성공", 4625: "로그온 실패", 4648: "명시적 자격 증명", 4720: "계정 생성", 4732: "그룹 추가", 4698: "예약 작업 생성", 1102: "감사 로그 삭제", 7045: "서비스 설치" };
const v = (r: Record<string, unknown>, k: string) => (r[k] == null ? "" : String(r[k]));

export default async function HuntPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  const raw = (sp.q ?? "").slice(0, 2000);
  const query = normalizeQuery(raw);
  const hours = [24, 168, 720, 2160].includes(Number(sp.h)) ? Number(sp.h) : 168;
  const { source, viewer, tenant } = await getContext();
  const parsed = query ? parseQuery(query) : null;
  const [saved, result] = await Promise.all([
    source.savedQueries(tenant),
    parsed?.ok ? source.runQuery(tenant, parsed.query, hours) : Promise.resolve(null),
  ]);
  const byDevice = new Map<string, { id: string; host: string; n: number }>();
  result?.rows.forEach((r) => {
    const id = v(r, "device_id"), cur = byDevice.get(id) ?? { id, host: v(r, "hostname") || id.slice(0, 8), n: 0 };
    cur.n++; byDevice.set(id, cur);
  });

  return (
    <>
      <PageHeader title="위협 헌팅" description="전체 PC 의 프로세스·네트워크·로그온·자동 실행 기록을 조건으로 찾습니다. 값만 넣어도(IP, 해시, 프로그램 이름) 알아서 찾습니다." />
      <QueryConsole key={query} initial={query} hours={hours} saved={saved} canSave={canTriage(viewer.tenant.role)}>

      {parsed && !parsed.ok && (
        <p className="mt-4 rounded-md border border-warn/40 bg-surface px-4 py-3 text-[13px] text-warn" role="alert">{parsed.error}</p>
      )}

      {result && (
        <section className="mt-5" aria-label="결과">
          <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
            <p className="text-ink-2">
              <strong className="text-ink">{DATASET_LABEL[result.dataset as Dataset]}</strong> {num(result.rows.length)}건{result.truncated && "(앞 500건만)"},
              장치 {num(byDevice.size)}대, {result.ms}ms
            </p>
            {byDevice.size > 0 && (
              <p className="flex flex-wrap gap-x-3 text-[13px] text-ink-2">
                {[...byDevice.values()].sort((a, b) => b.n - a.n).slice(0, 6).map((d) => (
                  <Link key={d.id} href={`/devices/${d.id}`} className="hover:text-accent">{d.host} <span className="tabular-nums text-muted">{d.n}</span></Link>
                ))}
              </p>
            )}
          </div>
          <div className="overflow-x-auto rounded-lg border border-line bg-surface">
            {result.rows.length === 0 ? <Empty title="조건에 맞는 기록이 없습니다">기간을 늘리거나 조건을 줄여 보세요. ~ (포함)는 일부만 맞아도 찾습니다.</Empty> : (
              <ResultTable dataset={result.dataset as Dataset} rows={result.rows} />
            )}
          </div>
        </section>
      )}
      </QueryConsole>
    </>
  );
}

function ResultTable({ dataset, rows }: { dataset: Dataset; rows: Record<string, unknown>[] }) {
  const head = (cols: string[]) => (
    <thead className="border-b border-line bg-surface-2 text-xs text-muted"><tr>{cols.map((c, i) => <th key={c} className={i === 0 ? "px-4 py-2 font-medium" : "px-3 py-2 font-medium"}>{c}</th>)}</tr></thead>
  );
  const when = (r: Record<string, unknown>) => <td className="px-4 py-2 whitespace-nowrap text-ink-2" title={stamp(v(r, "ts"))}>{ago(v(r, "ts"))}</td>;
  const dev = (r: Record<string, unknown>) => <td className="px-3 py-2 whitespace-nowrap"><Link href={`/devices/${v(r, "device_id")}`} className="font-medium hover:text-accent">{v(r, "hostname")}</Link></td>;
  return (
    <table className="w-full min-w-[960px] text-left text-[13px]">
      {dataset === "process" && head(["시각", "장치", "프로세스", "명령줄", "계정", "해시"])}
      {dataset === "net" && head(["시각", "장치", "프로세스", "방향", "원격지", "로컬 포트"])}
      {dataset === "event" && head(["시각", "장치", "이벤트", "계정", "출발지", "로그온 유형"])}
      {dataset === "autorun" && head(["마지막 확인", "장치", "이름", "위치", "명령"])}
      <tbody className="divide-y divide-line">
        {rows.map((r, i) => (
          <tr key={i} className="align-top hover:bg-surface-2">
            {when(r)}{dev(r)}
            {dataset === "process" && <>
              <td className="px-3 py-2 font-medium">{v(r, "name")} <span className="text-xs text-muted">{v(r, "pid")}</span></td>
              <td className="max-w-[28rem] px-3 py-2"><Mono className="line-clamp-2 break-all text-ink-2">{v(r, "command_line") || v(r, "path")}</Mono></td>
              <td className="px-3 py-2 text-ink-2">{v(r, "username")}</td>
              <td className="px-3 py-2">{v(r, "sha256") ? <Link href={`/entities/hash/${v(r, "sha256")}`} className="font-mono text-[12px] text-accent hover:underline">{v(r, "sha256").slice(0, 12)}…</Link> : "—"}</td>
            </>}
            {dataset === "net" && <>
              <td className="px-3 py-2">{v(r, "process_name")} <span className="text-xs text-muted">{v(r, "pid")}</span></td>
              <td className="px-3 py-2 text-ink-2">{{ inbound: "들어옴", outbound: "나감", listen: "대기", bound: "UDP" }[v(r, "direction")] ?? v(r, "direction")}</td>
              <td className="px-3 py-2">{v(r, "remote_ip") ? <Link href={`/entities/ip/${encodeURIComponent(v(r, "remote_ip"))}`} className="font-mono text-[12.5px] hover:text-accent">{v(r, "remote_ip")}:{v(r, "remote_port")}</Link> : "—"}{r.is_external === true && <span className="ml-2 text-xs text-ink-2">외부</span>}</td>
              <td className="px-3 py-2 font-mono text-[12.5px]">{v(r, "local_port")}</td>
            </>}
            {dataset === "event" && <>
              <td className="px-3 py-2">{v(r, "event_id")} <span className="text-ink-2">{EVENT[Number(v(r, "event_id"))] ?? ""}</span></td>
              <td className="px-3 py-2">{v(r, "target_user") ? <Link href={`/entities/user/${encodeURIComponent(v(r, "target_user"))}`} className="hover:text-accent">{v(r, "target_user")}</Link> : "—"}</td>
              <td className="px-3 py-2">{v(r, "src_ip") ? <Link href={`/entities/ip/${encodeURIComponent(v(r, "src_ip"))}`} className="font-mono text-[12.5px] hover:text-accent">{v(r, "src_ip")}</Link> : "—"}</td>
              <td className="px-3 py-2 text-ink-2">{LOGON[Number(v(r, "logon_type"))] ?? (v(r, "logon_type") || "—")}</td>
            </>}
            {dataset === "autorun" && <>
              <td className="px-3 py-2 font-medium">{v(r, "entry_name")}</td>
              <td className="px-3 py-2 text-ink-2">{v(r, "location")}</td>
              <td className="max-w-[30rem] px-3 py-2"><Mono className="line-clamp-2 break-all text-ink-2">{v(r, "command")}</Mono></td>
            </>}
          </tr>
        ))}
      </tbody>
    </table>
  );
}
