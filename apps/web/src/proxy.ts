import { NextResponse, type NextRequest } from "next/server";
import { createServerClient } from "@supabase/ssr";

// 모든 요청 전에 Supabase 세션 쿠키를 갱신하고, 로그인하지 않았으면 /login 으로 보낸다.
// 데모 모드(EDR_DEMO=1 또는 Supabase 미설정)에서는 아무것도 하지 않는다.
export async function proxy(request: NextRequest) {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  if (process.env.EDR_DEMO === "1" || !url) return NextResponse.next();

  let response = NextResponse.next({ request });
  const supabase = createServerClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: {
      getAll: () => request.cookies.getAll(),
      setAll: (list) => {
        list.forEach(({ name, value }) => request.cookies.set(name, value));
        response = NextResponse.next({ request });
        list.forEach(({ name, value, options }) => response.cookies.set(name, value, options));
      },
    },
  });

  const { data } = await supabase.auth.getUser();
  const path = request.nextUrl.pathname;
  // /auth/callback 은 SSO 로그인 복귀 지점이라 세션이 없어도 통과
  if (!data.user && !path.startsWith("/login") && !path.startsWith("/auth/")) {
    const to = request.nextUrl.clone();
    to.pathname = "/login";
    to.searchParams.set("next", path);
    return NextResponse.redirect(to);
  }
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|icon.svg).*)"],
};
