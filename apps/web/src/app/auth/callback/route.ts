import { NextResponse, type NextRequest } from "next/server";
import { createClient } from "@/lib/supabase/server";

/**
 * 회사 계정(SSO) 로그인 복귀 지점.
 * Keycloak → Supabase Auth 를 거쳐 ?code= 로 돌아오면, 브라우저에 남겨 둔 PKCE 검증값(쿠키)으로 세션을 만든다.
 * 역할은 DB 트리거(edr_sync_sso_membership)가 AD 그룹으로 이미 정해 두었다.
 */
export async function GET(request: NextRequest) {
  const url = request.nextUrl;
  const raw = url.searchParams.get("next") ?? "/";
  const next = raw.startsWith("/") && !raw.startsWith("//") ? raw : "/";
  const back = (reason: string, msg?: string) => {
    const to = new URL("/login", url.origin);
    to.searchParams.set("reason", reason);
    if (msg) to.searchParams.set("msg", msg.slice(0, 200));
    return NextResponse.redirect(to);
  };

  // Keycloak 또는 Supabase Auth 가 오류를 돌려준 경우(취소, 잠긴 계정 등)
  const err = url.searchParams.get("error_description") ?? url.searchParams.get("error");
  if (err) return back("sso-error", err);

  const code = url.searchParams.get("code");
  if (!code) return back("sso-error", "인증 코드가 없습니다");

  const supabase = await createClient();
  const { error } = await supabase.auth.exchangeCodeForSession(code);
  if (error) return back("sso-error", error.message);
  return NextResponse.redirect(new URL(next, url.origin));
}
