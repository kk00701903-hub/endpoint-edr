"use client";
import { createBrowserClient } from "@supabase/ssr";

/** 브라우저용(실시간 경보 구독). anon 키 + 사용자 세션만 쓴다. */
export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
  );
}
