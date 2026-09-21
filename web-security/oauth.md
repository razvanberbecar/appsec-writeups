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

> Currently covers one lab (implicit-flow auth bypass). `redirect_uri` and
> `state` attacks (practitioner) slot in as new sections later.

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
flow** (token straight to the browser — the flow in this lab).

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

## Where I got tripped up

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

## Why no session-cookie theft was needed

Stealing a session cookie attacks the *end* of the auth chain — the session
Carlos already has. You'd need him online and a way to exfiltrate his cookie
(e.g. XSS). Here I attacked the *start* of the chain — the step that **decides**
identity — so the server minted me a brand-new, valid session *as Carlos*, of
its own accord. No victim online, no second bug, and it's repeatable for any
account by swapping the email. The rule: don't steal the token at the end if you
can corrupt the decision at the beginning.

## Fix

- The backend must never trust an `email` supplied in the request body. It should
  take the token and call `/userinfo` **server-side itself** to establish
  identity — never let the client assert who it is.
- Better: use **authorization code flow** (`response_type=code`). The token is
  obtained by a server-to-server exchange (`code` + `client_secret`) that the
  browser can't touch, so there's no forgeable identity field in the first place.

## Recurring theme

Same defect as 2FA broken logic (the `account` cookie) and the stay-logged-in
cookie: **the server trusts client-controlled data for an identity decision.**
Only the setting changed — from a form/cookie to an OAuth flow.

## Tools

Burp Suite — Proxy (HTTP history), intercept, Repeater.
