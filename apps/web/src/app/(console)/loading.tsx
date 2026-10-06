export default function Loading() {
  return (
    <div className="animate-pulse space-y-4" aria-busy="true" aria-label="불러오는 중">
      <div className="h-8 w-48 rounded bg-surface-3" />
      <div className="h-24 rounded-lg bg-surface-3/70" />
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="h-64 rounded-lg bg-surface-3/70 lg:col-span-2" />
        <div className="h-64 rounded-lg bg-surface-3/70" />
      </div>
    </div>
  );
}
