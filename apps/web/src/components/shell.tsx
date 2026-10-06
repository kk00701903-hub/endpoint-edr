"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState, useTransition } from "react";
import { Command } from "cmdk";
import * as Dialog from "@radix-ui/react-dialog";
import {
  BadgeCheck, Bell, Boxes, FileSearch, Crosshair, Fingerprint, Gauge, Grid3x3, Layers, ListChecks, LogOut, Monitor, Moon, Network, ScanSearch, Search, Settings, ShieldCheck, Sun, User,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/cn";
import { setTheme, signOut, switchTenant } from "@/lib/actions";
import type { Viewer } from "@/lib/data/types";
import { ROLE_LABEL } from "@/lib/format";
import { createClient } from "@/lib/supabase/client";
import { Kbd } from "./ui";

type NavItem = { href: string; label: string; icon: typeof Gauge };
const GROUPS: { label: string; items: NavItem[] }[] = [
  { label: "탐지와 대응", items: [
    { href: "/", label: "현황", icon: Gauge },
    { href: "/incidents", label: "인시던트", icon: Layers },
    { href: "/alerts", label: "경보", icon: Bell },
  ] },
  { label: "조사", items: [
    { href: "/hunt", label: "위협 헌팅", icon: Crosshair },
    { href: "/attack", label: "ATT&CK 매트릭스", icon: Grid3x3 },
  ] },
  { label: "자산", items: [
    { href: "/devices", label: "장치", icon: Monitor },
    { href: "/assets", label: "자산·소프트웨어", icon: Boxes },
    { href: "/posture", label: "보안 상태", icon: BadgeCheck },
    { href: "/documents", label: "문서 감사", icon: FileSearch },
    { href: "/remediation", label: "PC 조치 목록", icon: ListChecks },
  ] },
  { label: "관리", items: [
    { href: "/rules", label: "탐지 규칙", icon: ShieldCheck },
    { href: "/iocs", label: "위협 지표", icon: ScanSearch },
    { href: "/settings", label: "설정", icon: Settings },
  ] },
];
const NAV: NavItem[] = GROUPS.flatMap((g) => g.items);
const MOBILE = ["/", "/incidents", "/alerts", "/hunt", "/devices"];

/** 관측 렌즈 모양의 제품 표식 */
function Mark() {
  return (
    <svg viewBox="0 0 24 24" className="size-6" aria-hidden>
      <circle cx="12" cy="12" r="10.25" fill="none" stroke="currentColor" strokeWidth="1.5" opacity=".45" />
      <circle cx="12" cy="12" r="6" fill="none" stroke="currentColor" strokeWidth="1.5" opacity=".75" />
      <circle cx="12" cy="12" r="2.2" fill="currentColor" />
      <path d="M12 1.75v4M12 18.25v4M1.75 12h4M18.25 12h4" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

export function Sidebar({ viewer, openCount, incidentCount }: { viewer: Viewer; openCount: number; incidentCount: number }) {
  const path = usePathname();
  const active = (href: string) => (href === "/" ? path === "/" : path.startsWith(href));
  const badge = (href: string) => (href === "/incidents" ? incidentCount : href === "/alerts" ? openCount : 0);
  return (
    <aside className="sticky top-0 hidden h-dvh w-[232px] shrink-0 flex-col border-r border-white/5 bg-nav text-nav-ink md:flex">
      <div className="flex items-center gap-2.5 px-5 pt-5 pb-5 text-white">
        <Mark />
        <div className="leading-tight">
          <div className="text-[15px] font-semibold">엔드포인트 관제</div>
          <div className="text-xs text-nav-ink">{viewer.tenant.name}</div>
        </div>
      </div>
      <nav className="flex flex-1 flex-col gap-4 overflow-y-auto px-3 pb-4" aria-label="주 메뉴">
        {GROUPS.map((g) => (
          <div key={g.label}>
            <div className="px-3 pb-1 text-xs text-nav-ink/70">{g.label}</div>
            <div className="flex flex-col gap-0.5">
              {g.items.map(({ href, label, icon: Icon }) => {
                const n = badge(href);
                return (
                  <Link key={href} href={href} aria-current={active(href) ? "page" : undefined}
                    className={cn("flex items-center gap-3 rounded-md px-3 py-[7px] text-[14px] transition-colors hover:bg-nav-2 hover:text-white",
                      active(href) && "bg-nav-2 font-medium text-white shadow-[inset_2px_0_0_var(--accent)]")}>
                    <Icon className="size-[17px]" strokeWidth={1.75} aria-hidden />
                    <span className="flex-1">{label}</span>
                    {n > 0 && <span className={cn("rounded px-1.5 text-xs tabular-nums", href === "/incidents" ? "bg-sev-high/20 text-[#ffd3cd]" : "bg-white/10 text-white")}>{n > 999 ? "999+" : n}</span>}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>
      <div className="border-t border-white/10 px-5 py-4 text-xs">
        <div className="truncate text-white">{viewer.email}</div>
        <div className="mt-0.5 flex items-center justify-between">
          <span>{ROLE_LABEL[viewer.tenant.role]}</span>
          <button onClick={() => signOut()} className="inline-flex items-center gap-1 hover:text-white">
            <LogOut className="size-3.5" aria-hidden /> 로그아웃
          </button>
        </div>
      </div>
    </aside>
  );
}

export function MobileNav() {
  const path = usePathname();
  return (
    <nav className="sticky bottom-0 z-20 grid grid-cols-5 border-t border-line bg-surface md:hidden" aria-label="주 메뉴">
      {NAV.filter((n) => MOBILE.includes(n.href)).map(({ href, label, icon: Icon }) => {
        const on = href === "/" ? path === "/" : path.startsWith(href);
        return (
          <Link key={href} href={href} className={cn("flex flex-col items-center gap-0.5 py-2 text-[11px] text-ink-2", on && "text-accent font-medium")}>
            <Icon className="size-5" strokeWidth={1.75} aria-hidden />
            {label}
          </Link>
        );
      })}
    </nav>
  );
}

// ---------------------------------------------------------------------------
// 상단 바: 검색(⌘K), 실시간 연결 상태, 조직 전환, 테마
// ---------------------------------------------------------------------------
export function Topbar({ viewer, hostnames, theme }: { viewer: Viewer; hostnames: { id: string; hostname: string }[]; theme: string }) {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.key === "k" && (e.metaKey || e.ctrlKey)) || (e.key === "/" && !isTyping(e))) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-line bg-canvas/90 px-4 backdrop-blur md:px-6">
      <button
        onClick={() => setOpen(true)}
        className="flex h-9 w-full max-w-md items-center gap-2 rounded-md border border-line-strong bg-surface px-3 text-left text-ink-2 hover:border-accent/60"
      >
        <Search className="size-4" aria-hidden />
        <span className="flex-1 truncate">장치, 해시, IP, 경보 검색</span>
        <span className="hidden gap-1 sm:flex"><Kbd>Ctrl</Kbd><Kbd>K</Kbd></span>
      </button>
      <div className="ml-auto flex items-center gap-3">
        <LiveIndicator demo={viewer.demo} tenant={viewer.tenant.id} />
        {viewer.tenants.length > 1 && (
          <select
            aria-label="조직 선택"
            defaultValue={viewer.tenant.id}
            onChange={(e) => switchTenant(e.target.value)}
            className="h-8 rounded-md border border-line-strong bg-surface px-2 text-[13px]"
          >
            {viewer.tenants.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
        )}
        <ThemeButton theme={theme} />
      </div>
      <CommandPalette open={open} onOpenChange={setOpen} hostnames={hostnames} />
    </div>
  );
}

function isTyping(e: KeyboardEvent) {
  const t = e.target as HTMLElement | null;
  return !!t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
}

function ThemeButton({ theme }: { theme: string }) {
  const dark = theme !== "light";
  return (
    <button
      onClick={() => setTheme(dark ? "light" : "dark")}
      className="inline-flex size-8 items-center justify-center rounded-md text-ink-2 hover:bg-surface-3 hover:text-ink"
      title={dark ? "밝은 화면으로" : "어두운 화면으로"}
      aria-label={dark ? "밝은 화면으로 바꾸기" : "어두운 화면으로 바꾸기"}
    >
      {dark ? <Sun className="size-[18px]" strokeWidth={1.75} /> : <Moon className="size-[18px]" strokeWidth={1.75} />}
    </button>
  );
}

/** 새 경보가 들어오면 알림을 띄우고 화면을 새로 고친다(Supabase Realtime). */
function LiveIndicator({ demo, tenant }: { demo: boolean; tenant: string }) {
  const router = useRouter();
  const [live, setLive] = useState<"connecting" | "live" | "off">(demo ? "off" : "connecting");
  useEffect(() => {
    if (demo) return;
    const sb = createClient();
    const ch = sb
      .channel(`alerts:${tenant}`)
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "alerts", filter: `tenant_id=eq.${tenant}` }, (msg) => {
        const a = msg.new as { title?: string; severity?: string; id?: number; status?: string };
        if (a.status === "closed") return; // 예외 규칙으로 자동 종결된 경보는 알리지 않음
        const urgent = a.severity === "critical" || a.severity === "high";
        toast(urgent ? "새 경보 (긴급·높음)" : "새 경보", {
          description: a.title,
          action: { label: "열기", onClick: () => router.push(`/alerts?id=${a.id}`) },
          duration: urgent ? 15000 : 6000,
        });
        router.refresh();
      })
      .subscribe((s) => setLive(s === "SUBSCRIBED" ? "live" : s === "CLOSED" || s === "CHANNEL_ERROR" ? "off" : "connecting"));
    return () => { sb.removeChannel(ch); };
  }, [demo, tenant, router]);

  if (demo) return <span className="rounded border border-warn/50 px-2 py-0.5 text-xs text-warn" title="EDR_DEMO=1 또는 Supabase 미설정">예시 데이터</span>;
  return (
    <span className="hidden items-center gap-2 text-[13px] text-ink-2 sm:inline-flex" title="새 경보 실시간 수신 상태">
      <span className={cn("size-2 rounded-full", live === "live" ? "bg-ok beacon" : live === "off" ? "bg-off" : "bg-warn")} aria-hidden />
      {live === "live" ? "실시간" : live === "off" ? "실시간 끊김" : "연결 중"}
    </span>
  );
}

// ---------------------------------------------------------------------------
// 명령 팔레트
// ---------------------------------------------------------------------------
const SHA = /^[0-9a-f]{64}$/i;
const IP = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f]*:[0-9a-f:]+$/i;

function CommandPalette({ open, onOpenChange, hostnames }: { open: boolean; onOpenChange: (o: boolean) => void; hostnames: { id: string; hostname: string }[] }) {
  const router = useRouter();
  const [q, setQ] = useState("");
  const [, start] = useTransition();
  const go = (href: string) => {
    onOpenChange(false);
    setQ("");
    start(() => router.push(href));
  };
  const term = q.trim();
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-[#0a111b]/40" />
        <Dialog.Content className="fixed top-[12vh] left-1/2 z-50 w-[min(640px,92vw)] -translate-x-1/2 overflow-hidden rounded-lg border border-line bg-surface shadow-2xl">
          <Dialog.Title className="sr-only">검색과 이동</Dialog.Title>
          <Command label="검색과 이동" shouldFilter={!SHA.test(term) && !IP.test(term)}>
            <div className="flex items-center gap-2 border-b border-line px-4">
              <Search className="size-4 text-muted" aria-hidden />
              <Command.Input value={q} onValueChange={setQ} placeholder="장치 이름, 해시(SHA-256), IP, 경보 내용" className="h-12 flex-1 bg-transparent outline-none placeholder:text-muted" />
              <Kbd>Esc</Kbd>
            </div>
            <Command.List className="max-h-[56vh] overflow-y-auto p-2">
              <Command.Empty className="px-3 py-6 text-center text-ink-2">일치하는 항목이 없습니다. Enter 를 누르면 전체 데이터에서 찾습니다.</Command.Empty>
              {term && (SHA.test(term) || IP.test(term) || /^[\w.$-]{2,40}$/.test(term)) && (
                <Command.Group heading="프로필 열기" className={GROUP}>
                  {SHA.test(term) ? (
                    <Item onSelect={() => go(`/entities/hash/${term.toLowerCase()}`)} value={`hash ${term}`}><Fingerprint className="size-4" aria-hidden /> 파일 해시 프로필</Item>
                  ) : IP.test(term) ? (
                    <Item onSelect={() => go(`/entities/ip/${encodeURIComponent(term)}`)} value={`ip ${term}`}><Network className="size-4" aria-hidden /> IP 주소 {term} 프로필</Item>
                  ) : (
                    <Item onSelect={() => go(`/entities/user/${encodeURIComponent(term)}`)} value={`user ${term}`}><User className="size-4" aria-hidden /> 계정 &lsquo;{term}&rsquo; 프로필</Item>
                  )}
                </Command.Group>
              )}
              {term && (
                <Command.Group heading="검색" className={GROUP}>
                  <Item onSelect={() => go(`/hunt?q=${encodeURIComponent(term)}`)} value={`hunt ${term}`}>
                    <Crosshair className="size-4" aria-hidden /> 전체 PC 에서 &lsquo;{term}&rsquo; 찾기 (프로세스·연결·자동실행)
                  </Item>
                  <Item onSelect={() => go(`/alerts?q=${encodeURIComponent(term)}&status=all`)} value={`alerts ${term}`}>
                    <Bell className="size-4" aria-hidden /> 경보 제목·장치에서 &lsquo;{term}&rsquo; 찾기
                  </Item>
                </Command.Group>
              )}
              <Command.Group heading="이동" className={GROUP}>
                {NAV.map((n) => (
                  <Item key={n.href} onSelect={() => go(n.href)} value={`이동 ${n.label}`}>
                    <n.icon className="size-4" aria-hidden /> {n.label}
                  </Item>
                ))}
                <Item onSelect={() => go("/incidents?severity=critical,high")} value="긴급 높음 인시던트">
                  <Layers className="size-4" aria-hidden /> 미처리 긴급·높음 인시던트
                </Item>
                <Item onSelect={() => go("/devices?state=offline")} value="연결 끊긴 장치">
                  <Monitor className="size-4" aria-hidden /> 연결 끊긴 장치
                </Item>
              </Command.Group>
              {hostnames.length > 0 && (
                <Command.Group heading="장치" className={GROUP}>
                  {hostnames.map((h) => (
                    <Item key={h.id} onSelect={() => go(`/devices/${h.id}`)} value={`장치 ${h.hostname}`}>
                      <Monitor className="size-4" aria-hidden /> {h.hostname}
                    </Item>
                  ))}
                </Command.Group>
              )}
            </Command.List>
          </Command>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
const GROUP = "[&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:pt-2 [&_[cmdk-group-heading]]:pb-1 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:text-muted";

function Item({ children, onSelect, value }: { children: React.ReactNode; onSelect: () => void; value: string }) {
  return (
    <Command.Item value={value} onSelect={onSelect} className="flex cursor-pointer items-center gap-2.5 rounded-md px-3 py-2 text-[14px] text-ink data-[selected=true]:bg-accent-soft data-[selected=true]:text-accent">
      {children}
    </Command.Item>
  );
}

export function useActionToast() {
  return (r: { ok: boolean; message?: string; error?: string }) => {
    if (r.ok) { if (r.message) toast.success(r.message); }
    else toast.error(r.error ?? "처리하지 못했습니다");
  };
}
