import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Docker 이미지에서만 standalone 산출물을 만든다(Windows 로컬 빌드는 심볼릭 링크 권한 문제를 피하려고 기본 모드)
  output: process.env.NEXT_OUTPUT === "standalone" ? "standalone" : undefined,
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "same-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },
};

export default nextConfig;
