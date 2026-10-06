// 테스트 전용 Supabase 흉내 — 운영에 쓰지 말 것.
//   /rest/v1  → PostgREST 로 그대로 전달(콘솔 → PostgREST → RLS 경로는 실제와 같음)
//   /auth/v1  → 비밀번호 로그인, 세션 갱신, 사용자 조회, 그리고 회사 계정(SSO) PKCE 로그인 흉내
//   /fake-kc  → Keycloak 로그인 화면 흉내(같은 입력칸 id: username·password·kc-login·totp·otp).
//               로그인에 성공하면 실제 Supabase Auth 처럼 auth.users 에 메타데이터(custom_claims.groups)를 써서
//               DB 트리거(edr_sync_sso_membership)가 AD 그룹 → 역할을 맞추게 한다.
import http from "node:http";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

const PORT = Number(process.env.FAKE_SUPABASE_PORT ?? 54321);
const PGRST_PORT = Number(process.env.PGRST_PORT ?? 3301);
export const SECRET = process.env.JWT_SECRET ?? "super-secret-jwt-token-with-at-least-32-characters";
const PASSWORD = process.env.EDR_IT_PASSWORD ?? "correct-horse";
const DB = process.env.EDR_IT_DB ?? "edr_it";
const now = () => new Date().toISOString();
const PW_USER = { id: "33333333-3333-3333-3333-333333333333", email: "secops@corp.example", aud: "authenticated", role: "authenticated", app_metadata: { provider: "email", providers: ["email"] }, user_metadata: {}, created_at: now() };

// 테스트용 AD 디렉터리(deploy/sso-lab/samba/entrypoint.sh 의 사용자와 같음)
const AD_PASSWORD = process.env.LAB_USER_PASSWORD ?? "Passw0rd!Lab";
const DIRECTORY = {
  "kim.admin": { name: "김관리", groups: ["EDR-Admins"] },
  "lee.analyst": { name: "이분석", groups: ["EDR-Analysts"] },
  "park.viewer": { name: "박열람", groups: ["EDR-Viewers"] },
  "choi.none": { name: "최무권한", groups: [] },
  "jung.locked": { name: "정잠김", groups: ["EDR-Analysts"], disabled: true },
};
const users = new Map([[PW_USER.id, PW_USER]]);           // id → Supabase 사용자
const flows = new Map();                                     // Keycloak 로그인 흐름 → { redirectTo, challenge, user? }
const codes = new Map();                                     // PKCE 코드 → { userId, challenge }
const totp = new Map();                                      // AD 아이디 → OTP 비밀값 (관리자만)

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
export function jwt(claims) {
  const h = b64({ alg: "HS256", typ: "JWT" }), p = b64(claims);
  return `${h}.${p}.${crypto.createHmac("sha256", SECRET).update(`${h}.${p}`).digest("base64url")}`;
}
const exp = () => Math.floor(Date.now() / 1000) + 3600;
const session = (u) => ({
  access_token: jwt({ sub: u.id, role: "authenticated", aud: "authenticated", email: u.email, exp: exp(), app_metadata: u.app_metadata }),
  token_type: "bearer", expires_in: 3600, expires_at: exp(), refresh_token: `r-${u.id}`, user: u,
});
const userFromAuth = (h) => {
  try { return users.get(JSON.parse(Buffer.from(String(h).split(".")[1], "base64url")).sub) ?? null; } catch { return null; }
};
// RFC 6238 TOTP (Keycloak 기본: HmacSHA1, 6자리, 30초, 비밀값은 문자열 그대로)
export function totpCode(secret, t = Date.now()) {
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const h = crypto.createHmac("sha1", Buffer.from(secret, "utf8")).update(counter).digest();
  const o = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
// 실제 Supabase Auth 가 Keycloak 로그인 때 하는 일: 사용자를 만들거나 메타데이터를 다시 쓴다
function upsertAuthUser(username) {
  const d = DIRECTORY[username];
  const id = crypto.createHash("sha256").update("kc:" + username).digest("hex").replace(/^(.{8})(.{4})(.{3})(.{3})(.{12}).*/, "$1-$2-4$3-8$4-$5");
  const email = `${username}@bing.test`;
  const app = { provider: "keycloak", providers: ["keycloak"] };
  const meta = { iss: "http://host.docker.internal:8080/realms/bing", sub: id, email, email_verified: true, name: d.name, full_name: d.name,
    custom_claims: { groups: ["default-roles-bing", "offline_access", ...d.groups], preferred_username: username } };
  const lit = (v) => `'${JSON.stringify(v).replace(/'/g, "''")}'`;
  execFileSync("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", DB, "-c",
    `insert into auth.users (id, email, raw_app_meta_data, raw_user_meta_data) values ('${id}', '${email}', ${lit(app)}::jsonb, ${lit(meta)}::jsonb)
     on conflict (id) do update set raw_user_meta_data = excluded.raw_user_meta_data, raw_app_meta_data = excluded.raw_app_meta_data`]);
  const u = { id, email, aud: "authenticated", role: "authenticated", app_metadata: app, user_metadata: meta, created_at: now() };
  users.set(id, u);
  return u;
}
// 그룹을 바꿔 다시 로그인하는 시험용(테스트 스크립트가 호출)
function setGroups(username, groups) { if (DIRECTORY[username]) DIRECTORY[username].groups = groups; }

const page = (title, body) => `<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>${title}</title></head>
<body style="font-family:sans-serif;max-width:420px;margin:60px auto"><h1 id="kc-page-title">${title}</h1>${body}</body></html>`;
const loginForm = (flow, error = "") => page("BING 사내 계정 (실험)에 로그인", `
  ${error ? `<div class="alert-error" role="alert"><span id="input-error">${error}</span></div>` : ""}
  <form id="kc-form-login" method="post" action="/fake-kc/login?flow=${flow}">
    <label for="username">사용자 이름</label><input id="username" name="username" autofocus>
    <label for="password">비밀번호</label><input id="password" name="password" type="password">
    <button id="kc-login" name="login" type="submit">로그인</button>
  </form>`);

function finish(res, f, u) {
  const code = crypto.randomBytes(16).toString("hex");
  codes.set(code, { userId: u.id, challenge: f.challenge });
  const to = new URL(f.redirectTo);
  to.searchParams.set("code", code);
  res.writeHead(302, { location: to.toString() }).end();
}

// `node fake-supabase.mjs anon-key` → anon 키만 출력하고 끝
if (process.argv[2] === "anon-key") {
  console.log(jwt({ role: "anon", iss: "edr-it", exp: Math.floor(Date.now() / 1000) + 86400 * 365 }));
  process.exit(0);
}

http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  if (url.pathname.startsWith("/rest/v1")) {
    const opts = { host: "127.0.0.1", port: PGRST_PORT, path: req.url.replace("/rest/v1", "") || "/", method: req.method, headers: { ...req.headers } };
    delete opts.headers.host;
    const auth = req.headers.authorization;
    if (!auth || auth.split(".").length !== 3 || !userFromAuth(auth.replace(/^Bearer /, ""))) opts.headers.authorization = `Bearer ${jwt({ role: "anon", exp: exp() })}`;
    const up = http.request(opts, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
    up.on("error", () => { res.statusCode = 502; res.end("{}"); });
    req.pipe(up);
    return;
  }
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const json = (v, status = 200) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(v)); };
    const html = (h, status = 200) => { res.writeHead(status, { "content-type": "text/html; charset=utf-8" }); res.end(h); };
    const form = Object.fromEntries(new URLSearchParams(body));

    // ---- Supabase Auth ----
    if (url.pathname === "/auth/v1/authorize") {          // signInWithOAuth 가 브라우저를 보내는 곳
      const flow = crypto.randomBytes(8).toString("hex");
      flows.set(flow, { redirectTo: url.searchParams.get("redirect_to"), challenge: url.searchParams.get("code_challenge") });
      res.writeHead(302, { location: `/fake-kc/login?flow=${flow}` }).end();
      return;
    }
    if (url.pathname === "/auth/v1/token") {
      const b = body ? JSON.parse(body) : {};
      const grant = url.searchParams.get("grant_type");
      if (grant === "password") {
        if (b.password !== PASSWORD) return json({ error: "invalid_grant", error_description: "Invalid login credentials", code: "invalid_credentials" }, 400);
        return json(session(PW_USER));
      }
      if (grant === "pkce") {                               // exchangeCodeForSession
        const c = codes.get(b.auth_code);
        codes.delete(b.auth_code);
        const ok = c && crypto.createHash("sha256").update(b.code_verifier ?? "").digest("base64url") === c.challenge;
        if (!ok) return json({ error: "invalid_grant", error_description: "invalid flow state", code: "flow_state_not_found" }, 400);
        return json(session(users.get(c.userId)));
      }
      if (grant === "refresh_token") {
        const u = users.get(String(b.refresh_token ?? "").replace(/^r-/, ""));
        return u ? json(session(u)) : json({ error: "invalid_grant", code: "refresh_token_not_found" }, 400);
      }
      return json({ error: "unsupported_grant_type" }, 400);
    }
    if (url.pathname === "/auth/v1/user") {
      const u = userFromAuth((req.headers.authorization ?? "").replace(/^Bearer /, ""));
      return u ? json(u) : json({ code: "bad_jwt", message: "invalid JWT" }, 401);
    }
    if (url.pathname === "/auth/v1/logout") { res.statusCode = 204; return res.end(); }

    // ---- Keycloak 로그인 화면 흉내 ----
    if (url.pathname === "/fake-kc/login") {
      const fid = url.searchParams.get("flow"), f = flows.get(fid);
      if (!f) return html(page("세션이 만료되었습니다", ""), 400);
      if (req.method === "GET") return html(loginForm(fid));
      const d = DIRECTORY[form.username];
      if (!d || form.password !== AD_PASSWORD) return html(loginForm(fid, "잘못된 사용자 이름 또는 비밀번호입니다."));
      if (d.disabled) return html(loginForm(fid, "계정이 비활성화되었습니다. 관리자에게 문의하세요."));
      f.user = form.username;
      if (d.groups.includes("EDR-Admins")) {                // 관리자는 OTP (처음이면 등록 화면)
        if (!totp.has(form.username)) {
          const secret = crypto.randomBytes(10).toString("base64url");
          f.pendingSecret = secret;
          return html(page("모바일 인증 설정", `<form id="kc-totp-settings-form" method="post" action="/fake-kc/otp?flow=${fid}">
            <span id="kc-totp-secret-key">${secret}</span><input type="hidden" name="totpSecret" value="${secret}">
            <label for="totp">일회용 코드</label><input id="totp" name="totp"><input id="userLabel" name="userLabel">
            <button id="saveTOTPBtn" type="submit">제출</button></form>`));
        }
        return html(page("BING 사내 계정 (실험)에 로그인", `<form id="kc-otp-login-form" method="post" action="/fake-kc/otp?flow=${fid}">
          <label for="otp">일회용 코드</label><input id="otp" name="otp"><button id="kc-login" type="submit">로그인</button></form>`));
      }
      return finish(res, f, upsertAuthUser(form.username));
    }
    if (url.pathname === "/fake-kc/otp" && req.method === "POST") {
      const fid = url.searchParams.get("flow"), f = flows.get(fid);
      if (!f?.user) return html(page("세션이 만료되었습니다", ""), 400);
      const secret = totp.get(f.user) ?? f.pendingSecret;
      const given = form.otp ?? form.totp;
      if (!secret || ![-1, 0, 1].some((w) => totpCode(secret, Date.now() + w * 30000) === given)) return html(page("잘못된 인증 코드입니다", ""), 400);
      if (!totp.has(f.user)) totp.set(f.user, secret);
      return finish(res, f, upsertAuthUser(f.user));
    }
    // 시험용: AD 그룹 바꾸기 (POST /fake-kc/groups {username, groups})
    if (url.pathname === "/fake-kc/groups" && req.method === "POST") {
      const b = JSON.parse(body || "{}");
      setGroups(b.username, b.groups);
      return json({ ok: true });
    }
    json({}, 404);
  });
}).listen(PORT, () => console.log(`fake supabase on ${PORT} → postgrest ${PGRST_PORT}`));

