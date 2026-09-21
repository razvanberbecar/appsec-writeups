# Security Learning — Writeups

Hands-on notes from working through binary exploitation and web security,
written to understand *how* each vulnerability class works and *how to defend
against it* — not just to complete labs.

> **Educational only.** Everything here was done on my own machine (a local VM I
> control) or against deliberately vulnerable lab targets
> ([PortSwigger Web Security Academy](https://portswigger.net/web-security)),
> purely to learn. No real or third-party systems were ever involved, and no lab
> flags are reproduced — each writeup describes method and reasoning, not
> answers.

## About

I'm a computer science student working toward application security. These
writeups are how I consolidate what I learn: for each topic I document the
mechanism, the exploitation steps, the mistakes I made along the way (the most
useful part), and — always — how the bug is actually fixed. The through-line
across all of them is the same: **user-controlled data must never be allowed to
cross into the code/trust channel**, whether that's SQL, JavaScript, machine
code, or an authorization decision.

## Writeups

### Binary exploitation
- **[ret2libc](binary-exploitation/ret2libc.md)** — turning a stack buffer
  overflow into a shell by chaining existing libc functions
  (`system("/bin/sh")`), bypassing NX without injecting any code. Covers offset
  discovery, the `pop rdi; ret` gadget, and the classic `movaps` stack-alignment
  crash and its fix.

### Web security
- **[SQL Injection (blind)](web-security/blind-sqli.md)** — extracting a full
  password through a one-bit ("Welcome back" / absent) side channel, automated in
  Python. Includes the gotchas: orphaned quotes, charset assumptions, and
  rate-limiting.
- **[Cross-Site Scripting (XSS)](web-security/xss.md)** — reflected, stored, and
  DOM-based, across multiple injection contexts (HTML body, attribute,
  `<select>`, `href`, `eval`/JSON). Emphasis on reading the context to choose the
  payload, and on how a *broken* sanitizer (not a missing one) is the real bug.
- **[Broken Access Control](web-security/access-control.md)** — vertical
  (privilege escalation) and horizontal (IDOR), covering forgeable cookies, mass
  assignment, header/method/multi-step bypasses, and identifier leakage. The core
  lesson: authentication is not authorization.
- **[Authentication](web-security/authentication.md)** — username enumeration
  (via differing responses and response timing), two 2FA logic bypasses, and
  brute-forcing a password-derived "stay logged in" cookie. The thread:
  authentication is a chain of links, and the server must never trust a
  client-supplied identity.
- **[OAuth](web-security/oauth.md)** — logging in as another user by editing the
  email in the client app's `/authenticate` call during the OAuth implicit flow.
  A protocol-flow bug, not an input bug: the app trusts an identity the browser
  asserts instead of verifying the token server-side.

## Recurring themes

A few ideas show up in every topic, which is the point of documenting them
together:

- **Data vs. code.** Injection of every kind (SQL, XSS, format string) is
  user input being interpreted as code instead of data. The fix is always the
  same shape: keep them separate (parameterized queries, `textContent`,
  `printf("%s", x)`).
- **Client-controlled data is not trustworthy.** Cookies, headers, hidden fields,
  and validation that runs in the browser can all be forged or bypassed — only
  server-side checks count.
- **Attack the mechanism, then verify.** Find the sink/source, the offset, the
  trust boundary — then confirm it precisely rather than assuming.

## Tools

`gdb` + `pwndbg`, `ROPgadget`, `Valgrind` (binary exploitation);
Burp Suite, Python `requests` (web security).
