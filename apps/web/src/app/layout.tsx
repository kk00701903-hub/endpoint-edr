import type { Metadata, Viewport } from "next";
import { cookies } from "next/headers";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "엔드포인트 관제", template: "%s · 엔드포인트 관제" },
  description: "사내 PC 보안 모니터링 콘솔",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: [
    { color: "#090e19" },
  ],
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const theme = (await cookies()).get("edr_theme")?.value;
  return (
    <html lang="ko" className={theme === "dark" ? "dark" : "light"}>
      <body className="min-h-dvh">{children}</body>
    </html>
  );
}
