# Cross-Site Scripting (XSS) — Reading Context to Break Out of It

> **Educational writeup.** Done against deliberately vulnerable lab targets
> (PortSwigger Web Security Academy) in a controlled environment, to learn the
> vulnerability class and how to defend against it. No real or third-party
> systems were involved. No lab flags are reproduced — this is method and
> reasoning only.

## What XSS is

XSS is the same root cause as SQL injection and format-string bugs, in a
different context: **user input ends up interpreted as code** — here, as
HTML/JavaScript running in the victim's browser — instead of as data. If I can
get my input to execute as script in someone else's session, I can act as them
(steal their session cookie, perform actions on their behalf).

In labs the proof is a harmless `alert(1)` — if the popup fires, my code ran. In
a real attack that `alert(1)` is replaced with cookie theft or actions in the
victim's name.

## The three types (and how I told them apart)

- **Reflected** — the server takes something from my request and echoes it back
  into the HTML it returns. The vulnerability is server-side.
- **Stored** — my payload is *saved* on the server (e.g. in a comment) and runs
  for anyone who views the page. More dangerous — no need to trick a victim into
  clicking a crafted link.
- **DOM-based** — the vulnerability is in the page's JavaScript. The server sends
  a clean page; the JS itself reads attacker-controlled data (from the URL, etc.)
  and writes it into the page. Client-side.

**How I distinguish reflected from DOM in practice:** inject a unique marker and
look for it in two places. `Ctrl+U` (View Source) shows what the *server* sent;
`F12 → Elements` shows the live DOM after JS ran. If the marker is in View Source
→ server put it there → reflected/stored. If it's only in Elements → JavaScript
put it there → DOM-based. Shortcut: a payload after `#` in the URL never reaches
the server at all, so it's always DOM-based.

## My methodology

The workflow I settled into for every lab:

1. Inject a unique test string (e.g. `zzztest`) and see where it lands.
2. Watch the request/response in **Burp Repeater** to see what the server does
   with it.
3. Read the page source / JS to decide whether the bug is server-side or
   client-side.
4. For DOM XSS, `Ctrl+Shift+F` across all JS files for dangerous **sinks**
   (`document.write`, `innerHTML`, `eval`), then trace back from the sink to the
   **source** to confirm attacker-controlled data reaches it uncleaned.

The single most important reflex: **read the context before choosing a payload.**
Where the input lands decides everything.

## Context decides the payload

The same idea (break out of wherever the input is embedded, then inject) took a
different shape every time — exactly like escaping a string with `'` in SQLi:

| Context input lands in | How to break out |
|---|---|
| Plain HTML body | nothing needed — `<script>` runs directly |
| `<img src="...HERE...">` attribute | `">` closes the attribute and tag first |
| Inside a `<select>` element | `</select>` to close it first |
| `href="...HERE..."` attribute | `javascript:alert(1)` scheme |

## Sinks decide the payload too

A key "aha": the sink function matters as much as the surrounding HTML.

- **`document.write`** executes `<script>` written through it — so
  `<script>alert(1)</script>` works.
- **`innerHTML` does NOT execute `<script>`** (a browser security rule for
  dynamically-added scripts). So I had to use an event handler instead:
  `<img src=x onerror=alert(1)>` — the image fails to load, `onerror` fires, and
  the code runs. `innerHTML` accepts it because it isn't a `<script>` tag.
- **`eval`** runs its argument as raw JavaScript — so the payload is JS that
  breaks out of the surrounding string/JSON, e.g. `\"-alert(1)}//`.

Safe sinks exist too: `innerText` / `textContent` insert input as *text*, so a
payload shows up literally instead of executing. Recognizing safe vs dangerous
sinks is what stops you wasting time on code that only *looks* vulnerable.

## The most instructive lab: a stored DOM XSS

This one taught me the most because the obvious path was a dead end, and the data
told me so.

Reading the comment-rendering JS, I found an `escapeHTML()` applied to `author`
and `body`, and one field — `website` — put straight into an `<a href>` with no
escaping. So I tried the `href` route: `javascript:alert(1)` in the website field.

- The **client-side** validation rejected it ("please match the requested
  format") — bypassed easily by editing the request in Burp, since client
  validation is only in *my* page and I control that.
- But then the **server** rejected it too ("invalid website"). I tested
  systematically in Repeater: `http://foo` passed, anything starting with
  `javascript:` failed. The server required the value to start with `http://` /
  `https://`. And a `href` only executes `javascript:` if the scheme is at the
  *start* — so `https://.../javascript:alert(1)` passes the server but is just a
  normal link at click time. **The two requirements were mutually exclusive.**

The data was telling me the `website` field was a dead end. Instead of forcing
it, I went back to the code — and looked harder at the escaping function:

```javascript
function escapeHTML(html) {
    return html.replace('<', '&lt;').replace('>', '&gt;');
}
```

`.replace('<', ...)` with a plain string replaces only the **first** occurrence.
So a field with *two* `<` gets the first escaped and the second one through
untouched. And `comment.body` — supposedly "protected" — goes into `innerHTML`.

Payload in the comment body:

```
<a><img src=x onerror=alert(1)>
```

The first `<` and `>` (from `<a>`) are sacrificed to the broken `replace`; the
second `<img ...>` survives unescaped and executes via `innerHTML`.

## What I actually learned

- **Read the context, then pick the payload.** Attribute, `<select>`, `href`,
  `eval`-string — each needs a different break-out. Memorizing payloads is
  useless; reading where you are is the skill.
- **The sink matters as much as the HTML context.** `document.write` vs
  `innerHTML` vs `innerText` accept completely different things.
- **Client-side validation is not security.** It lives in the page I control, so
  Burp walks right past it. Only server-side checks count.
- **Let the data redirect you.** When systematic testing showed the `website`
  field couldn't satisfy both the server and the browser, that was the signal to
  pivot — not to push harder. The real bug was a *broken* sanitizer elsewhere,
  not a missing one.
- **"Escaped" is not the same as "escaped correctly."** `.replace('<', ...)`
  only catches the first match. The most common real-world XSS isn't "they forgot
  to escape" — it's "they escaped wrong."

## The fix

Same principle as every injection bug — keep data out of the code channel:

- **Don't build HTML from raw input.** Use safe sinks (`textContent` instead of
  `innerHTML`/`document.write`) when inserting user data.
- **Escape correctly and completely** — replace *all* occurrences, in the right
  context (HTML body vs attribute vs URL vs JS have different rules), ideally with
  a vetted library rather than hand-rolled `.replace` calls.
- **Never trust `javascript:` and similar schemes** in URLs that come from users.
- **Validate on the server**, not just the client — the client check is a
  convenience for honest users, not a barrier for attackers.
