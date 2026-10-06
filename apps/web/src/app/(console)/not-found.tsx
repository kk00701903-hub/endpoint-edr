import Link from "next/link";

export default function NotFound() {
  return (
    <div className="mx-auto mt-16 max-w-md text-center">
      <h1 className="text-lg font-semibold">찾는 항목이 없습니다</h1>
      <p className="mt-2 text-ink-2">삭제되었거나 다른 조직의 항목일 수 있습니다.</p>
      <Link href="/" className="mt-4 inline-block text-accent hover:underline">현황으로 가기</Link>
    </div>
  );
}
