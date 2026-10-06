import "server-only";
import { cookies } from "next/headers";
import { createServerClient } from "@supabase/ssr";

/** 서버 컴포넌트·Server Action 용. 사용자 세션(쿠키)으로 동작하므로 권한은 RLS 가 판단한다. */
export async function createClient() {
  const store = await cookies();
  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll: () => store.getAll(),
        setAll: (list) => {
          try {
            list.forEach(({ name, value, options }) => store.set(name, value, options));
          } catch {
            // 서버 컴포넌트에서는 쿠키를 쓸 수 없다. 세션 갱신은 proxy.ts 가 담당한다.
          }
        },
      },
    },
  );
}
