# Authentication

> **Disclaimer.** Educational learning writeup. Every technique below was
> practised against the [PortSwigger Web Security Academy](https://portswigger.net/web-security)
> labs — deliberately vulnerable targets, in my own environment. Where I used the
> official lab solutions, what follows is my explanation of the *mechanism, the
> exploitation path, and the fix* — not a claim of independent discovery. Nothing
> here is aimed at systems I don't own or have permission to test.

The theme that ties this whole chapter together: **authentication is a chain,
not a single check.** It runs
`identify the user → verify the secret → verify the second factor → keep the
session`. Each link can be attacked on its own, and a break anywhere lets you
skip the rest. Most of these labs aren't "guess the password" — they're
"notice that one link trusts something it shouldn't."

---

## 1. Username enumeration

The goal is to learn *which usernames exist* before spending any effort on
passwords. Anything the server does differently for a valid vs. an invalid
username is a side channel: response wording, response length, status code, or
time taken.

### 1.1 Via different responses

- **What it is.** The login form returns a *different* error for a bad username
  than for a good username with a bad password.
- **Steps.** Intruder over a username list, watching the **response length**
  column — the tell is invisible in the rendered page, you only catch it by
  sorting on Length. The valid username stood out as `Length: 3354` against the
  `3352` of every other request. Then a second pass brute-forcing the password
  for that one username.
- **Fix.** Identical, generic responses for every failure (*"Invalid username or
  password."*), same length, same status.

### 1.2 Via subtly different responses

- **What it is.** Same idea, but the difference is buried — a stray character or
  inconsistent wording rather than a clean length delta.
- **Steps.** A **Grep – Match** rule on the exact string
  `Invalid username or password.`: every invalid username *matched* the string;
  the valid one **did not** (its message was subtly different), so the odd row
  out is the hit. Then password brute-force, **status 302 = success**.
- **Fix.** Byte-for-byte identical failure responses; no per-branch wording.

### 1.3 Via response timing

- **What it is.** The server *checks the password* only when the username is
  valid, so a valid username takes measurably longer — a timing oracle.
- **Steps.** A very long password amplifies the time difference so it clears the
  noise. IP-based lockout was dodged by spoofing **`X-Forwarded-For`**, driven as
  a second payload in an Intruder **Pitchfork** attack (one payload = username,
  the other = a changing XFF value), sorting on the **Response received** column.
- **Fix.** Constant-time work regardless of whether the username exists (e.g.
  always hash against a dummy); don't let control flow leak timing.

### (skipped on purpose) Broken brute-force protection — IP block

Skipped the lab itself but noted the idea: when lockout is counted per IP and
**resets on any successful login**, you interleave a known-good credential pair
into the wordlist to keep resetting the counter, so the block never trips.

---

## 2. Two-factor authentication (2FA)

2FA is only as strong as the assumption that *the second factor is bound to the
authenticated user and can't be skipped*. Both labs break that assumption in a
different link of the chain.

### 2.1 Simple bypass

- **What it is.** The 2FA step is a *page you're sent to*, not a *gate you must
  pass* — a UI state, not an authorization state.
- **Steps.** Logged in as carlos (I had the password), then instead of completing
  the OTP page navigated straight to `/my-account?id=carlos`. The account was
  already served — the second factor was never actually enforced server-side.
- **Fix.** The server must refuse every post-login resource until the second
  factor is verified *for this session*. No factor = not authenticated, full stop.

### 2.2 Broken logic

- **What it is.** The server decides *whose* 2FA code to generate and check based
  on a **client-controlled cookie**, not the logged-in session.
- **Steps.**
  1. Logged in as wiener (my own account, my own OTP delivery).
  2. On the `GET /login2` request, changed the cookie `account=wiener` →
     `account=carlos`. That made the server generate and expect **carlos's** code.
  3. Brute-forced the 4-digit code in Intruder (Numbers `0000–9999`, leading
     zeros on), **status 302 = success**.
- **The thread.** Two separate failures chained: (a) the server *trusted the
  `account` cookie* to decide identity, and (b) *no rate limiting* on a 4-digit
  code — 10,000 guesses is nothing.
- **Fix.** Bind the second factor to the server-side session, never to a client
  value; rate-limit and lock the code after a few tries; make codes longer /
  single-use / short-lived.

---

## 3. Brute-forcing a stay-logged-in cookie

- **What it is.** A "remember me" cookie that is **derived deterministically from
  the password** instead of being an opaque random token:
  `stay-logged-in = base64( username + ":" + md5(password) )`.
  New primitives for me here: **base64** (reversible *encoding*, not encryption),
  **MD5** (one-way 32-hex hash), and **Intruder payload processing**.
- **Steps.**
  1. Logged in with *Stay logged in* checked, took the cookie, decoded it in Burp
     Decoder → `wiener:51dc30ddc473d43a6011e9ebba6ca770`, which is `wiener:` +
     `md5("peter")`. Formula confirmed *from the inside*, not assumed.
  2. Sent `GET /my-account` to Intruder, position on the `stay-logged-in` value,
     payload = password wordlist, with **payload processing in this order**:
     `Hash: MD5` → `Add prefix: carlos:` → `Base64-encode`. Each rule feeds the
     next: `password → md5-hex → carlos:md5 → base64`.
  3. Changed `id=wiener` → `id=carlos` in the URL and the prefix to `carlos:`.
     Success signal is a **Grep – Match on `Update email`** (a valid cookie serves
     the 200 account page), *not* a 302.
- **Where I actually got stuck.** This was the one lab that genuinely caught me
  out. You have to **log out first** — otherwise your live `session` cookie keeps
  authenticating you, the server never falls back to `stay-logged-in`, and every
  response is just your own account, so there's no signal to distinguish the
  right guess. Once logged out, `stay-logged-in` becomes the only thing deciding
  identity, which is exactly the mechanism the lab is testing. It also flips my
  reflex from the earlier labs: here a **302 means *failed*** (bounced to login),
  not success.
- **The kicker — offline password recovery.** Because the hash is **unsalted
  MD5**, cracking carlos's cookie doesn't just hand over his *session* — decode it
  to `carlos:<md5>` and the hash is directly reversible offline (wordlist /
  rainbow table), recovering the *plaintext password* without ever touching the
  server again. That's the jump from "I have his session" to "I own the account."
- **Fix.** A remember-me token must be **random, opaque, and stored server-side**
  (selector + validator pattern), never a pure function of the password. If you
  must store a secret's hash, salt it and use a slow KDF — never bare MD5.

---

## Recurring themes

- **Authentication ≠ authorization, and both are a chain.** Breaking any single
  link (identify → verify → second factor → session) skips everything after it.
- **Client-controlled data is never trustworthy for security decisions.**
  Cookies (`account`, `stay-logged-in`), headers (`X-Forwarded-For`), and params
  are all forgeable. Only server-side checks count.
- **Any observable difference is a side channel.** Response wording, length,
  status, and *time* all leak — enumeration doesn't need an error that says
  "user exists," just one that behaves differently.
- **Deriving a token from a secret weaponises the secret.** The stay-logged-in
  cookie turned a rate-limited, online-only secret (the password) into an
  offline-attackable one, and leaked the hash on top.
- **Rate limiting has to be un-bypassable.** Per-IP counters fall to
  `X-Forwarded-For`; unthrottled 4-digit codes fall in seconds.

## Defensive summary

- Generic, identical failure responses; constant-time verification.
- Robust rate limiting / lockout that can't be reset or spoofed away.
- Second factor enforced server-side and bound to the session, not a cookie.
- Session and remember-me tokens: random, opaque, server-side; no
  password-derived tokens; salted slow hashing for any stored secret.

## Tools

Burp Suite — Proxy, Repeater, Intruder (Sniper & Pitchfork, payload processing,
Grep-Match), Decoder, Inspector.
