"use client";

import { Button } from "@/components/ui";

export default function ConsoleError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <div className="mx-auto mt-16 max-w-lg rounded-lg border border-line bg-surface p-6">
      <h1 className="text-lg font-semibold">이 화면을 불러오지 못했습니다</h1>
      <p className="mt-2 text-ink-2">
        데이터베이스 연결이나 권한 문제일 수 있습니다. 다시 시도해도 같으면 아래 내용을 관리자에게 전달하세요.
      </p>
      <pre className="mt-3 overflow-x-auto rounded bg-surface-2 p-3 font-mono text-xs text-ink-2">{error.message}{error.digest ? `\n(digest ${error.digest})` : ""}</pre>
      <Button variant="primary" className="mt-4" onClick={reset}>다시 시도</Button>
    </div>
  );
}
