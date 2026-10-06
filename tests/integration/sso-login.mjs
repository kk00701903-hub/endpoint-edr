// 회사 계정(SSO) 로그인 도우미 — 실제 Keycloak 과 시험용 흉내(fake-supabase.mjs)에서 똑같이 동작한다.
// Keycloak 로그인 화면의 입력칸 id(username·password·kc-login, OTP 등록 totp·saveTOTPBtn, OTP 입력 otp)를 쓴다.
import crypto from "node:crypto";

/** RFC 6238 TOTP — Keycloak 기본값(HmacSHA1·6자리·30초), 비밀값은 OTP 등록 화면의 totpSecret 문자열 그대로 */
export function totpCode(secret, t = Date.now()) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const h = crypto.createHmac("sha1", Buffer.from(secret, "utf8")).update(counter).digest();
  const o = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

/**
 * 콘솔 로그인 화면 → "회사 계정으로 로그인" → Keycloak 아이디·비밀번호(→ 관리자는 OTP) → 콘솔로 복귀
 * @returns {{ ok: boolean, url: string, message?: string, otp?: "setup" | "used" }}
 */
export async function ssoLogin(page, consoleUrl, username, password, otpSecrets) {
  await page.goto(consoleUrl + "/login", { waitUntil: "load" });
  await page.waitForTimeout(600); // 하이드레이션
  await page.getByRole("button", { name: /회사 계정/ }).click();
  await page.locator("#username").waitFor({ timeout: 20000 });
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(password);
  await page.locator("#kc-login").click();
  let otp;
  for (let step = 0; step < 4; step++) {
    await page.waitForLoadState("load");
    await page.waitForTimeout(500);
    if (page.url().startsWith(consoleUrl)) return { ok: true, url: page.url(), otp };
    if (await page.locator("input[name=totpSecret]").count()) {             // 처음: 인증 앱 등록
      const secret = await page.locator("input[name=totpSecret]").inputValue();
      otpSecrets[username] = secret;
      await page.locator("#totp").fill(totpCode(secret));
      if (await page.locator("#userLabel").count()) await page.locator("#userLabel").fill("실험 PC");
      await page.locator("#saveTOTPBtn").click();
      otp = "setup";
      continue;
    }
    if (await page.locator("#otp").count()) {                               // 다음부터: OTP 입력
      if (!otpSecrets[username]) return { ok: false, url: page.url(), message: "OTP 비밀값을 모릅니다(이전에 등록한 기록 없음)" };
      await page.locator("#otp").fill(totpCode(otpSecrets[username]));
      await page.locator("#kc-login").click();
      otp = "used";
      continue;
    }
    break;
  }
  const message = (await page.locator("body").innerText()).replace(/\s+/g, " ").slice(0, 200);
  return { ok: page.url().startsWith(consoleUrl), url: page.url(), message, otp };
}
