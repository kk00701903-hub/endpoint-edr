import "server-only";
import { cache } from "react";
import { redirect } from "next/navigation";
import { getSource } from "./data/source";

/** 페이지·액션 공통: 데이터 소스 + 로그인 사용자 + 현재 조직. 요청당 1회만 계산한다. */
export const getContext = cache(async () => {
  const source = await getSource();
  const viewer = await source.viewer();
  // proxy.ts 가 로그인하지 않은 요청은 이미 /login 으로 보낸다 → 여기 오는 경우는 "로그인은 했지만 조직 구성원이 아님"
  // (예: 회사 계정으로 로그인했는데 콘솔 권한 AD 그룹에 없음)
  if (!viewer) redirect("/login?reason=no-access");
  return { source, viewer, tenant: viewer.tenant.id };
});

export const canTriage = (role: string) => role === "owner" || role === "admin" || role === "analyst";
export const canAdmin = (role: string) => role === "owner" || role === "admin";
