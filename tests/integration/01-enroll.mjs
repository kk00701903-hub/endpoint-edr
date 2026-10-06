// 1단계: 콘솔 로그인 → 설정 화면에서 등록키 발급(평문 키는 화면에 한 번만 보임) → 로그인 상태 저장
import fs from "node:fs";
import { CONSOLE, PASSWORD, STATE_DIR, USER_EMAIL, browser, done, expect } from "./lib.mjs";

fs.mkdirSync(STATE_DIR, { recursive: true });
const b = await browser();
const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, locale: "ko-KR", timezoneId: "Asia/Seoul" });
const p = await ctx.newPage();
const errs = [];
p.on("pageerror", (e) => errs.push(String(e).slice(0, 200)));

try {
  // 로그인하지 않으면 로그인 화면으로
  await p.goto(CONSOLE + "/incidents", { waitUntil: "load" });
  expect("로그인 전 보호", p.url().includes("/login"), p.url());

  // 틀린 비밀번호 → 안내 문구, 이메일은 남아 있음
  await p.getByLabel("이메일").fill(USER_EMAIL);
  await p.getByLabel("비밀번호").fill("wrong-password");
  await p.getByRole("button", { name: "로그인", exact: true }).click();
  // (Next.js 의 화면 전환 안내도 role=alert 라서 문구로 찾는다)
  const msg = p.getByRole("alert").filter({ hasText: /비밀번호/ });
  await msg.first().waitFor({ timeout: 10000 }).catch(() => {});
  expect("틀린 비밀번호 안내", /맞지 않습니다/.test(await msg.first().innerText().catch(() => "")));
  expect("실패 후 이메일 유지", (await p.getByLabel("이메일").inputValue()) === USER_EMAIL);

  await p.getByLabel("비밀번호").fill(PASSWORD);
  await p.getByRole("button", { name: "로그인", exact: true }).click();
  // 처음 열려던 화면(/incidents)으로 돌아가야 함
  await p.waitForURL((u) => u.pathname === "/incidents", { timeout: 20000 });
  expect("로그인 → 원래 가려던 화면", (await p.locator("h1").first().innerText()).includes("인시던트"));

  // 장치가 없을 때 등록 방법 안내
  await p.goto(CONSOLE + "/devices", { waitUntil: "load" });
  expect("빈 장치 화면 안내", (await p.locator("main").innerText()).includes("등록키"));

  // 등록키 발급
  await p.goto(CONSOLE + "/settings", { waitUntil: "load" });
  await p.waitForTimeout(800); // 하이드레이션
  await p.getByRole("button", { name: "등록키 만들기" }).click();
  await p.getByPlaceholder(/재무팀/).fill("통합 테스트");
  await p.getByRole("dialog").getByRole("button", { name: "만들기" }).click();
  await p.getByText("등록키가 만들어졌습니다").waitFor({ timeout: 10000 });
  const key = (await p.getByRole("dialog").locator("code").first().innerText()).trim();
  expect("등록키 발급", /^edr_enr_[0-9a-f]{48}$/.test(key), key.slice(0, 12) + "…");
  fs.writeFileSync(`${STATE_DIR}/enroll-key.txt`, key);
  await ctx.storageState({ path: `${STATE_DIR}/state.json` });
  expect("브라우저 오류 없음", errs.length === 0, errs.join(" | "));
} catch (e) {
  expect("단계 완료", false, String(e).split("\n")[0]);
} finally {
  await b.close();
  done("01 콘솔 로그인·등록키");
}
