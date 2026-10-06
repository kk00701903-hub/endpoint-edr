import { cookies } from "next/headers";
import { Toaster } from "sonner";
import { MobileNav, Sidebar, Topbar } from "@/components/shell";
import { getContext } from "@/lib/context";

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const { source, viewer, tenant } = await getContext();
  const [ov, devs, incs] = await Promise.all([
    source.overview(tenant), source.devices(tenant, { page: 1 }), source.incidents(tenant, { status: "active", days: 90 }),
  ]);
  const openCount = Object.values(ov.open_alerts).reduce((s, n) => s + (n ?? 0), 0);
  const theme = (await cookies()).get("edr_theme")?.value === "dark" ? "dark" : "light";
  return (
    <div className="flex min-h-dvh">
      <Sidebar viewer={viewer} openCount={openCount} incidentCount={incs.total} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar viewer={viewer} theme={theme} hostnames={devs.rows.map((d) => ({ id: d.id, hostname: d.hostname }))} />
        <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-6 md:px-7">{children}</main>
        <MobileNav />
      </div>
      <Toaster position="bottom-right" richColors={false} toastOptions={{ className: "!bg-surface !text-ink !border-line" }} />
    </div>
  );
}
