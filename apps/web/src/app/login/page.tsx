"use client";

import { useActionState, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";
import { Building2 } from "lucide-react";
import { signIn, signOut } from "@/lib/actions";
import { createClient } from "@/lib/supabase/client";

// 회사 계정(SSO) 로그인 버튼은 공급자가 설정된 경우에만 보인다 (예: NEXT_PUBLIC_SSO_PROVIDER=keycloak)
const SSO_PROVIDER = process.env.NEXT_PUBLIC_SSO_PROVIDER;
const SSO_LABEL = process.env.NEXT_PUBLIC_SSO_LABEL || "회사 계정으로 로그인";

function SsoButton({ next }: { next: string }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <>
      <button
        type="button"
        disabled={pending}
        onClick={async () => {
          setPending(true);
          setError(null);
          const redirectTo = `${window.location.origin}/auth/callback?next=${encodeURIComponent(next)}`;
          // Keycloak 사용자 정보(userinfo)를 받으려면 openid 범위가 필요하다
          const { error } = await createClient().auth.signInWithOAuth({
            provider: SSO_PROVIDER as "keycloak",
            options: { redirectTo, scopes: "openid" },
          });
          if (error) { setError("회사 계정 로그인을 시작하지 못했습니다. 잠시 후 다시 시도하세요."); setPending(false); }
        }}
        className="mt-5 flex h-10 w-full items-center justify-center gap-2 rounded-md bg-accent font-medium text-accent-ink hover:bg-accent-hover disabled:opacity-60"
      >
        <Building2 className="size-4" aria-hidden />
        {pending ? "회사 로그인 화면으로 이동 중" : SSO_LABEL}
      </button>
      {error && <p className="mt-2 text-[13px] text-sev-high" role="alert">{error}</p>}
    </>
  );
}

function LoginForm() {
  const params = useSearchParams();
  const next = params.get("next") ?? "/";
  const reason = params.get("reason");
  const [state, action, pending] = useActionState(signIn, null);
  // React 19 는 액션 후 폼을 초기화하므로, 로그인 실패 시 이메일이 지워지지 않게 상태로 유지한다
  const [email, setEmail] = useState("");
  const sso = !!SSO_PROVIDER;
  return (
    <div className="w-full max-w-sm rounded-lg border border-line bg-surface p-6">
      <div className="flex items-center gap-2.5 text-ink">
        <svg viewBox="0 0 24 24" className="size-7 text-accent" aria-hidden>
          <circle cx="12" cy="12" r="10.25" fill="none" stroke="currentColor" strokeWidth="1.5" opacity=".45" />
          <circle cx="12" cy="12" r="6" fill="none" stroke="currentColor" strokeWidth="1.5" opacity=".75" />
          <circle cx="12" cy="12" r="2.2" fill="currentColor" />
          <path d="M12 1.75v4M12 18.25v4M1.75 12h4M18.25 12h4" stroke="currentColor" strokeWidth="1.5" />
        </svg>
        <h1 className="text-[18px] font-semibold">엔드포인트 관제</h1>
      </div>

      {reason === "no-access" ? (
        <div className="mt-4 rounded-md border border-line bg-surface-2 p-3 text-[13px]" role="alert">
          <p className="font-medium">로그인은 되었지만 이 콘솔을 쓸 권한이 없습니다.</p>
          <p className="mt-1 text-ink-2">
            {sso ? "회사 계정이면 콘솔 권한 그룹(EDR-Admins·EDR-Analysts·EDR-Viewers) 가입을 보안 관리자에게 요청하세요. 그룹에 들어간 뒤 다시 로그인하면 됩니다." : "보안 관리자에게 조직 구성원 등록을 요청하세요."}
          </p>
          <form action={signOut}>
            <button className="mt-3 h-8 rounded-md border border-line-strong bg-surface px-3 text-[13px] hover:bg-surface-3">다른 계정으로 로그인</button>
          </form>
        </div>
      ) : (
        <p className="mt-1 text-[13px] text-ink-2">{sso ? "회사 계정(Windows 로그인 계정)으로 로그인하세요." : "보안 담당자 계정으로 로그인하세요."}</p>
      )}
      {reason === "sso-error" && (
        <p className="mt-3 rounded-md border border-line bg-surface-2 p-3 text-[13px] text-sev-high" role="alert">
          회사 계정 로그인이 완료되지 않았습니다{params.get("msg") ? `: ${params.get("msg")}` : ""}. 다시 시도하거나 보안 관리자에게 문의하세요.
        </p>
      )}

      {sso && <SsoButton next={next} />}

      <form action={action}>
        {sso && (
          <div className="mt-5 flex items-center gap-3 text-xs text-muted" aria-hidden>
            <span className="h-px flex-1 bg-line" />관리자용 이메일 로그인<span className="h-px flex-1 bg-line" />
          </div>
        )}
        <input type="hidden" name="next" value={next} />
        <label className={sso ? "mt-3 block text-[13px]" : "mt-5 block text-[13px]"}>
          <span className="mb-1 block font-medium">이메일</span>
          <input name="email" type="email" required autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} className="h-9 w-full rounded-md border border-line-strong bg-surface px-3 outline-none focus:border-accent" />
        </label>
        <label className="mt-3 block text-[13px]">
          <span className="mb-1 block font-medium">비밀번호</span>
          <input name="password" type="password" required autoComplete="current-password" className="h-9 w-full rounded-md border border-line-strong bg-surface px-3 outline-none focus:border-accent" />
        </label>
        {state && !state.ok && <p className="mt-3 text-[13px] text-sev-high" role="alert">{state.error}</p>}
        <button
          disabled={pending}
          className={sso
            ? "mt-5 h-9 w-full rounded-md border border-line-strong bg-surface font-medium text-ink hover:bg-surface-3 disabled:opacity-60"
            : "mt-5 h-9 w-full rounded-md bg-accent font-medium text-accent-ink hover:bg-accent-hover disabled:opacity-60"}
        >
          {pending ? "로그인 중" : "로그인"}
        </button>
        <p className="mt-4 text-xs text-muted">계정이 없으면 보안 관리자에게 요청하세요.</p>
      </form>
    </div>
  );
}

export default function LoginPage() {
  return (
    <main className="flex min-h-dvh items-center justify-center bg-nav px-4">
      <Suspense>
        <LoginForm />
      </Suspense>
    </main>
  );
}
