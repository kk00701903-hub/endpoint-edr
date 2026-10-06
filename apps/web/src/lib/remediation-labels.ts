import type { RemediationKind, RemediationStatus } from "./data/types";

// PC 조치 목록 표시 이름(서버·클라이언트 컴포넌트 공용)
export const REMEDIATION_STATUS: Record<RemediationStatus, string> = { open: "대기", in_progress: "진행 중", done: "완료 표시", exception: "예외" };
export const REMEDIATION_KIND: Record<RemediationKind, string> = { posture: "보안 점검", software: "프로그램", doc_pii: "개인정보 문서", doc_stale: "오래된 문서" };
