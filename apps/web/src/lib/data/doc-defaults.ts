import type { DocPiiKind, DocScanPolicy } from "./types";

// 문서 감사 정책 기본값·표시 이름. DB(0009) 의 기본값과 같다.

export const DOC_POLICY_DEFAULT: DocScanPolicy = {
  enabled: false,
  interval_hours: 168,
  folders: ["Desktop", "Documents", "Downloads"],
  extra_paths: [],
  extensions: ["txt", "csv", "log", "docx", "xlsx", "pptx", "hwp", "hwpx", "pdf", "doc", "xls", "ppt"],
  detect: ["rrn", "frn", "passport", "driver", "card"],
  keywords: [],
  stale_days: 1095,
  max_file_mb: 20,
  notice_confirmed_at: null,
  notice_confirmed_by: null,
  notice_confirmed_by_email: null,
  updated_at: null,
};

export const PII_KINDS: { value: DocPiiKind; label: string; hint: string }[] = [
  { value: "rrn", label: "주민등록번호", hint: "생년월일·성별 자리 확인" },
  { value: "frn", label: "외국인등록번호", hint: "성별 자리 5~8" },
  { value: "passport", label: "여권번호", hint: "영문 1자 + 숫자 8자리 등" },
  { value: "driver", label: "운전면허번호", hint: "지역 번호(11~28)로 시작하는 12자리" },
  { value: "card", label: "카드번호", hint: "검증 숫자(Luhn) 확인" },
  { value: "phone", label: "휴대전화번호", hint: "010 등 — 업무 문서에 흔해 기본 꺼짐" },
];

export const PII_LABEL: Record<DocPiiKind, string> = Object.fromEntries(PII_KINDS.map((k) => [k.value, k.label])) as Record<DocPiiKind, string>;

export const DOC_FOLDERS = [
  { value: "Desktop", label: "바탕 화면" },
  { value: "Documents", label: "문서" },
  { value: "Downloads", label: "다운로드" },
];

export const DOC_EXT_GROUPS: { label: string; exts: string[] }[] = [
  { label: "한글", exts: ["hwp", "hwpx"] },
  { label: "Office", exts: ["docx", "xlsx", "pptx", "doc", "xls", "ppt"] },
  { label: "PDF", exts: ["pdf"] },
  { label: "텍스트", exts: ["txt", "csv", "log", "tsv", "md"] },
];

export const DOC_INTERVALS = [
  { value: 24, label: "매일" },
  { value: 168, label: "매주" },
  { value: 720, label: "매월(30일)" },
  { value: 2160, label: "분기(90일)" },
];
