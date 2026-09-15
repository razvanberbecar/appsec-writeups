# Broken Access Control — When the Server Trusts the Wrong Thing

> **Educational writeup.** Done against deliberately vulnerable lab targets
> (PortSwigger Web Security Academy) in a controlled environment, to learn the
> vulnerability class and how to defend against it. No real or third-party
> systems were involved. No lab flags are reproduced — this is method and
> reasoning only.

## What it is

Broken Access Control is #1 in the OWASP Top 10, and after working through it the
reason is obvious: there are a dozen different-looking bugs that are all the same
underlying mistake. The application knows **who you are** (authentication), but
fails to correctly check **what you're allowed to do** (authorization).

The single thread running through every case below: **the server either doesn't
check permission, checks it in a place that can be bypassed, or trusts something
the client controls.** Authentication is not authorization.

Access control splits into two directions:

- **Vertical** — accessing a *higher* privilege level (normal user → admin).
- **Horizontal** — accessing another user's resources *at the same level*
  (my account → someone else's account).

## Vertical: escalating to admin

Every one of these is "the admin check is missing, or in the wrong place, or
based on client-controlled data."

**No access control at all.** The admin panel was reachable just by browsing to
`/admin` — the check simply wasn't there. Even when the admin URL was
"unpredictable," it was disclosed in a JavaScript file, so obscurity wasn't
protection.

**Role controlled by a forgeable cookie.** The server decided admin status from a
cookie like `Admin=false`. Since cookies are client-side, editing it to
`Admin=true` (in DevTools or Burp) made me admin. The server trusted a value I
fully control.

**Role set via mass assignment.** The "change email" request sent
`{"email":"..."}`. The server also accepted a `roleid` field that the UI never
exposes — adding `"roleid":2` to the request promoted me. The server blindly
accepted fields it should have rejected.

**URL-based bypass (`X-Original-URL`).** A front-end proxy blocked `/admin`, but
the back-end honored the `X-Original-URL` header. Requesting `/` (which the proxy
allows) with `X-Original-URL: /admin` made the two layers disagree about what I
was asking for — the proxy saw `/`, the back-end served `/admin`. The access
check was enforced in a layer that could be sidestepped.

**Method-based bypass.** The admin check applied to `POST` but not other methods.
Sending the same action as a `GET` skipped the check entirely.

**Multi-step process, check on only one step.** Promotion was a two-step flow
(submit → confirm). The admin check was on step 1; step 2 (`confirmed=true`)
assumed you'd already passed step 1. Sending the step-2 request directly, as a
normal user, skipped the guarded step. You are never obligated to follow the
application's intended flow.

**Referer-based access control.** The server allowed admin actions if the
`Referer` header pointed at `/admin`. `Referer` is a client-controlled header, so
forging it bypassed the check — same class as the forgeable cookie.

## Horizontal: accessing other users' data (IDOR)

The common move: find an identifier you can change, swap it for someone else's,
and see whether the server checks that you're allowed the resource — or just
hands it over.

**Predictable ID in a parameter.** `GET /my-account?id=wiener` → change to
`id=carlos` → their account. No ownership check.

**Unpredictable ID (GUID).** The ID was a GUID, so it couldn't be guessed. But it
didn't need to be guessed — carlos's GUID was **leaked** in a public place (an
author link on a blog post). A "secret" identifier that the app displays publicly
isn't secret.

**Data leakage in a redirect.** Requesting another user's account returned a
redirect ("you're not allowed") — but the server had already put the sensitive
data in the response body *before* redirecting. In Burp you see the raw response,
not the redirect the browser would follow, so the data was right there. A
redirect is not a security control.

**Password disclosure → escalation.** Accessing another user's account page
exposed their password (pre-filled in a field). Horizontal access became a
foothold: get the credential, then log in as them. IDOR isn't only "I can see
data" — it can hand you the keys.

## What I actually learned

- **Authentication ≠ authorization.** Every app here knew who I was. They just
  didn't check that *this* user was allowed *this* action or *this* resource.
  Verifying identity is easy and gets done; verifying permission per-resource,
  per-step, per-method is what gets forgotten.
- **The check has to be where it can't be bypassed.** Not on a front-end proxy
  (X-Original-URL), not tied to one HTTP method (GET vs POST), not on only one
  step of a multi-step flow. Attackers hit whatever path the check doesn't cover.
- **Never trust client-controlled data for security decisions.** Cookies,
  headers (`Referer`, `X-Original-URL`), request parameters, hidden form fields —
  all fully controllable by the attacker. A role in a cookie is a suggestion, not
  a fact.
- **Obscurity is not access control.** Unpredictable admin URLs and GUIDs feel
  safe but get disclosed by the app itself (JS files, author links). If the only
  thing stopping access is "you probably don't know the identifier," it's already
  broken.
- **You don't have to follow the intended flow.** With Burp you send any request
  directly — skip steps, change methods, swap IDs. The app's assumptions about
  how users "should" move through it are not constraints on an attacker.

## The fix

- **Enforce authorization on the server, on every request** that touches a
  protected resource or action — independent of method, step, headers, or how the
  user got there. Deny by default.
- **Determine identity and role server-side** (from the session), never from
  client-supplied cookies, parameters, or headers.
- **Check ownership** on every object access ("does this user own this record?"),
  not just that the user is logged in.
- **Use an allowlist for accepted fields** so requests can't set properties like
  `roleid` that the user should never control (prevents mass assignment).
- **Don't rely on obscurity** (unguessable URLs/IDs) as a substitute for an
  actual permission check.
