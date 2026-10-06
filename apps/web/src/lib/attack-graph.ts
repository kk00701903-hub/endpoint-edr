// ---------------------------------------------------------------------------
// 공격 그래프 — 인시던트의 경보·프로세스·연결로 "누가(IP·계정) → 어디(장치) → 무엇을(프로세스) → 어떻게 남겼나(자동 실행·외부 통신)"를
// 왼쪽에서 오른쪽으로 흐르는 그래프로 만든다. 서버·클라이언트 어디서나 쓰는 순수 함수.
// ---------------------------------------------------------------------------
import type { Alert, ConnectionRow, Device, ProcessRow, Severity } from "./data/types";

export type NodeKind = "ip" | "user" | "device" | "process" | "persistence" | "remote";

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  sub?: string;
  severity?: Severity;
  alertIds: number[];
  href?: string;
  detail: Record<string, string | number | null>;
  layer: number;
  row: number;
}

export interface GraphEdge { from: string; to: string; label: string; hot: boolean }
export interface AttackGraph { nodes: GraphNode[]; edges: GraphEdge[]; layers: number; rows: number }

const RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const worse = (a?: Severity, b?: Severity) => (!a ? b : !b ? a : RANK[a] >= RANK[b] ? a : b);
const STOP = new Set(["services.exe", "explorer.exe", "wininit.exe", "smss.exe", "system"]);
const str = (v: unknown) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : "");

export function buildGraph(alerts: Alert[], devices: Device[], processes: Record<string, ProcessRow[]>, connections: Record<string, ConnectionRow[]>): AttackGraph {
  const nodes = new Map<string, Omit<GraphNode, "layer" | "row"> & { layer?: number }>();
  const edges = new Map<string, GraphEdge>();
  const add = (n: Omit<GraphNode, "layer" | "row" | "alertIds"> & { alertIds?: number[]; layer?: number }) => {
    const cur = nodes.get(n.id);
    if (cur) {
      cur.severity = worse(cur.severity, n.severity);
      cur.alertIds = [...new Set([...cur.alertIds, ...(n.alertIds ?? [])])];
      return cur;
    }
    const v = { ...n, alertIds: n.alertIds ?? [] };
    nodes.set(n.id, v);
    return v;
  };
  const link = (from: string, to: string, label: string, hot = false) => {
    const k = `${from}>${to}`;
    const e = edges.get(k);
    if (e) e.hot ||= hot; else edges.set(k, { from, to, label, hot });
  };

  const devById = new Map(devices.map((d) => [d.id, d]));
  for (const a of alerts) {
    const dev = a.device_id ? devById.get(a.device_id) : undefined;
    const devId = dev ? `dev:${dev.id}` : null;
    if (dev) add({ id: devId!, kind: "device", label: dev.hostname, sub: dev.last_ip ?? undefined, href: `/devices/${dev.id}`, severity: a.severity, alertIds: [a.id], detail: { "IP": dev.last_ip, "운영체제": dev.os_version } });
    const d = a.details;
    const src = str(d.src_ip) || (a.rule_id === "EDR-NET-001" ? str(d.remote_ip) : "");
    const user = str(d.user) || (Array.isArray(d.users) ? str(d.users[0]) : "");
    if (src) add({ id: `ip:${src}`, kind: "ip", label: src, sub: "출발지", href: `/entities/ip/${encodeURIComponent(src)}`, severity: a.severity, alertIds: [a.id], detail: { "역할": "접속 출발지" } });
    if (user) add({ id: `user:${user.toLowerCase()}`, kind: "user", label: user, sub: "계정", href: `/entities/user/${encodeURIComponent(user)}`, severity: a.severity, alertIds: [a.id], detail: {} });
    if (src && user) {
      link(`ip:${src}`, `user:${user.toLowerCase()}`, a.rule_id === "EDR-AUTH-001" ? "로그온 시도" : "로그온", a.rule_id !== "EDR-AUTH-001");
      if (devId) link(`user:${user.toLowerCase()}`, devId, a.rule_id === "EDR-AUTH-001" ? "실패" : "로그온 성공", a.rule_id !== "EDR-AUTH-001");
    } else if (src && devId) link(`ip:${src}`, devId, a.rule_id === "EDR-NET-001" ? "RDP 연결" : "접속", true);

    if (devId && (a.rule_id.startsWith("EDR-PERSIST") || a.rule_id.startsWith("EDR-ACCT") || a.rule_id === "EDR-LOG-001")) {
      const name = str(d.entry) || a.title.split(":").pop()?.trim() || a.rule_id;
      const id = `per:${a.device_id}:${a.rule_id}:${name}`;
      const label = a.rule_id === "EDR-LOG-001" ? "로그 삭제" : a.rule_id.startsWith("EDR-ACCT") ? name : name;
      const sub = { "EDR-PERSIST-001": "서비스", "EDR-PERSIST-002": "자동 실행", "EDR-PERSIST-003": "예약 작업", "EDR-ACCT-001": "새 계정", "EDR-ACCT-002": "그룹 추가", "EDR-LOG-001": "흔적 삭제" }[a.rule_id];
      add({ id, kind: "persistence", label, sub, severity: a.severity, alertIds: [a.id], detail: { "명령": str(d.command) || null, "위치": str(d.location) || null } });
      link(devId, id, sub ?? "변경", true);
    }

    // 프로세스: 해시·경로가 경보에 있으면 해당 프로세스와 조상 체인을 그린다
    const sha = str(d.sha256), path = str(d.path) || str(d.image_path);
    if (devId && a.device_id && (sha || path)) {
      const procs = processes[a.device_id] ?? [];
      const byPid = new Map(procs.map((p) => [p.pid, p]));
      const hits = procs.filter((p) => (sha && p.sha256 === sha) || (path && p.path?.toLowerCase() === path.toLowerCase()));
      for (const hit of hits) {
        const chain: ProcessRow[] = [hit];
        let cur = hit;
        for (let i = 0; i < 6; i++) {
          const parent = cur.ppid != null ? byPid.get(cur.ppid) : undefined;
          if (!parent || parent.create_time > cur.create_time) break;
          chain.unshift(parent);
          if (STOP.has(parent.name.toLowerCase())) break;
          cur = parent;
        }
        // 의심 프로세스가 띄운 자식(예: powershell)도 포함
        procs.filter((p) => p.ppid === hit.pid).forEach((c) => chain.push(c));
        let prevId = devId;
        chain.forEach((p) => {
          const id = `proc:${a.device_id}:${p.pid}:${p.create_time}`;
          const isHit = p === hit || p.verdict === "malicious" || /-enc\b|-w(indowstyle)?\s+hidden/i.test(p.command_line ?? "");
          add({ id, kind: "process", label: p.name, sub: `PID ${p.pid}`, severity: isHit ? a.severity : undefined, alertIds: p === hit ? [a.id] : [],
            href: p.sha256 ? `/entities/hash/${p.sha256}` : undefined,
            detail: { "명령줄": p.command_line, "경로": p.path, "계정": p.username, "SHA-256": p.sha256 } });
          link(prevId, id, prevId === devId ? "실행" : "자식 프로세스", isHit);
          prevId = id;
        });
        // 이 체인의 프로세스가 외부와 통신했으면 원격지를 붙인다
        const pids = new Set(chain.map((p) => p.pid));
        for (const c of connections[a.device_id] ?? []) {
          if (c.pid != null && pids.has(c.pid) && c.is_external && c.remote_ip && c.direction === "outbound") {
            const rid = `remote:${c.remote_ip}`;
            add({ id: rid, kind: "remote", label: c.remote_ip, sub: `:${c.remote_port} 외부 통신`, severity: "high", href: `/entities/ip/${encodeURIComponent(c.remote_ip)}`, detail: { "프로세스": c.process_name, "포트": c.remote_port } });
            const p = chain.find((x) => x.pid === c.pid)!;
            link(`proc:${a.device_id}:${p.pid}:${p.create_time}`, rid, "외부 통신", true);
          }
        }
      }
    }
  }

  // ---- 층(열) 배치: 들어오는 쪽 → 장치 → 프로세스 깊이 → 남긴 것 ----
  const base: Record<NodeKind, number> = { ip: 0, user: 1, device: 2, process: 3, persistence: 9, remote: 9 };
  const layerOf = new Map<string, number>();
  for (const n of nodes.values()) if (n.kind !== "process") layerOf.set(n.id, base[n.kind]);
  // 프로세스는 장치로부터 거리만큼 오른쪽으로
  const out = new Map<string, string[]>();
  edges.forEach((e) => out.set(e.from, [...(out.get(e.from) ?? []), e.to]));
  const queue = [...nodes.values()].filter((n) => n.kind === "device").map((n) => n.id);
  while (queue.length) {
    const id = queue.shift()!;
    for (const to of out.get(id) ?? []) {
      const n = nodes.get(to)!;
      if (n.kind !== "process") continue;
      const l = (layerOf.get(id) ?? 2) + 1;
      if ((layerOf.get(to) ?? 0) < l) { layerOf.set(to, l); queue.push(to); }
    }
  }
  const maxProc = Math.max(2, ...[...nodes.values()].filter((n) => n.kind === "process").map((n) => layerOf.get(n.id) ?? 3));
  for (const n of nodes.values()) if (n.kind === "persistence" || n.kind === "remote") layerOf.set(n.id, maxProc + 1);
  // 빈 열을 없애 촘촘하게
  const used = [...new Set(layerOf.values())].sort((a, b) => a - b);
  const compact = new Map(used.map((l, i) => [l, i]));
  const rowsPer = new Map<number, number>();
  const placed: GraphNode[] = [...nodes.values()].map((n) => {
    const layer = compact.get(layerOf.get(n.id) ?? 0) ?? 0;
    const row = rowsPer.get(layer) ?? 0;
    rowsPer.set(layer, row + 1);
    return { ...n, layer, row } as GraphNode;
  });
  return { nodes: placed, edges: [...edges.values()], layers: used.length, rows: Math.max(1, ...rowsPer.values()) };
}
