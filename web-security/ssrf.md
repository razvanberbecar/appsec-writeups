# SSRF (Server-Side Request Forgery)

> **Disclaimer.** Educational learning writeup. Practised against the
> [PortSwigger Web Security Academy](https://portswigger.net/web-security) SSRF
> labs — deliberately vulnerable targets, in my own environment. What follows is
> my explanation of the *mechanism, the exploitation path, and the fix*. Nothing
> here is aimed at systems I don't own or have permission to test.

Every other class I'd done attacks the *user* or their *session*. SSRF attacks
the **server itself** — you make it issue requests on your behalf, to places you
can't reach directly. The server is a trusted messenger inside a network; you're
outside it. So you don't hit the internal target yourself — you send the server
to hit it for you.

The recurring thread still holds, with a twist: client-supplied data the server
trusts — but here that data is a **URL**, and the trust turns it into *the
destination of a network action the server takes*. The input doesn't become code
(like injection); it becomes an address the server acts on.

These four labs are a progression: reach the server itself → scan its internal
network → beat a blacklist filter → beat an allowlist by chaining a second bug.

---

## Lab 1: SSRF against the local server

- **What it is.** A stock-check feature takes a full URL in a `stockApi`
  parameter and fetches it server-side, returning the response. Whatever URL you
  put there, the server requests.
- **Steps.** The admin panel at `http://localhost/admin` is blocked when accessed
  directly (not an admin / not from loopback). Set:
  ```
  stockApi=http://localhost/admin
  ```
  The server fetches it *from loopback* — i.e. as itself — so the check passes and
  the admin HTML comes back.
- **The key move.** To actually delete the user, the *action* has to go through
  SSRF too. Reading the panel in the browser then clicking "delete" fails —
  that click comes from my browser, not loopback. So the delete URL goes in
  `stockApi` as well:
  ```
  stockApi=http://localhost/admin/delete?username=carlos
  ```
- **What tripped me up.** I saw the panel and assumed I now "had admin access."
  I don't. SSRF gives me a messenger, not a session — every action is one more
  request I hand to the server. Reading is one request; deleting is another.
- **Why it works.** `localhost`/`127.0.0.1` means "me" *from the perspective of
  whoever makes the request*. From my browser that's my machine; from the server
  it's the server. The app trusts loopback requests, and the server's own
  requests are loopback.
- **Fix.** Don't let user input decide the fetch destination; use an allowlist of
  exact permitted URLs, and never grant loopback requests implicit trust.

## Lab 2: SSRF against another back-end system

- **What it is.** Same `stockApi` sink, but the target is an admin panel on a
  *different* internal host, somewhere in `192.168.0.0/24` on port `8080`. I don't
  know which IP — I have to find it.
- **Steps.** Sent the request to **Intruder**, put the payload position on the
  last octet:
  ```
  stockApi=http://192.168.0.§1§:8080/admin
  ```
  Payload type Numbers, 0–255, Sniper. Started the attack and sorted by **status
  code**: dead IPs all returned the same error/length; the one hosting the panel
  stood out (200, different length). Then the delete URL through `stockApi` as in
  lab 1.
- **The lesson.** SSRF isn't just "read localhost" — it turns the public server
  into a scanner for an entire internal network you can't otherwise touch. This is
  real internal recon: map hidden services through one public entry point.
- **Fix.** Same as lab 1 — an allowlist. The server should never be able to reach
  arbitrary internal hosts on user command.

## Lab 3: SSRF with blacklist-based input filter

- **What it is.** The filter now *blocks* `localhost` and `127.0.0.1`. A blacklist.
- **Steps.** Two defences, in a chain, each beaten separately:
  1. **Host blacklist** → bypassed with an alternative representation of
     `127.0.0.1`: `http://127.1/` (a valid shorthand). Returned 200.
  2. **String blacklist on `admin`** → the path `/admin` was still blocked. Beat
     it with URL-encoding: `a` → `%61`, so `/%61dmin`. The filter checks the raw
     string (no "admin" literal), the back-end decodes `%61` → `a` and routes to
     `/admin`.
  Final:
  ```
  stockApi=http://127.1/%61dmin/delete?username=carlos
  ```
- **What tripped me up.** I first tried *double*-encoding (`%2561dmin`) and got
  **404** — not "blocked". That 404 was the tell: the filter was already beaten
  (it wasn't a block message), but I'd over-encoded. The back-end here decodes
  once, so `%2561dmin` reached it as the literal `%61dmin` → no such path. Single
  encoding was right. Testing `http://127.1/` alone (200) vs `/%61dmin` is how I
  isolated which filter fired.
- **The lesson.** **Blacklists always lose.** The defender has to predict every
  equivalent representation (`127.1`, decimal, `%61`); the attacker needs one that
  slipped through. An allowlist would have held.
- **Fix.** Allowlist permitted hosts/paths; never blacklist strings.

## Lab 4: SSRF with filter bypass via open redirection

- **What it is.** Now the filter is *good* — `stockApi` only accepts URLs on the
  application's own stock system (effectively an allowlist). No host trick beats
  it. The weakness is elsewhere: an **open redirect** in a `nextProduct` feature.
- **Steps.**
  1. Found the open redirect:
     ```
     GET /product/nextProduct?currentProductId=1&path=/product?productId=2
     ```
     Its `path` accepts a full URL and 302-redirects to it — confirmed by setting
     `path=http://192.168.0.12:8080/admin` and seeing
     `Location: http://192.168.0.12:8080/admin`.
  2. Chained it. `stockApi` points at the *allowed* endpoint (`nextProduct`),
     whose redirect sends the server onward to the internal target:
     ```
     stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin/delete?username=carlos
     ```
- **What tripped me up.** Two things.
  - Testing the redirect in the *browser* gave "Failed to connect to
    192.168.0.12" after a timeout. I thought it failed — actually it *worked*: the
    redirect pointed at the internal host, and my browser (outside the network)
    can't reach it. That failure was the confirmation, and the reason SSRF is
    needed at all.
  - I then sent `nextProduct` *directly* in Repeater and only got the 302 back —
    nobody followed it. The redirect has to sit *inside* `stockApi` so the
    **stock-check request** (which follows redirects server-side) is the client
    that follows it. Browser follows from my position (blocked); server follows
    from its position (allowed). The whole attack is moving who follows the
    redirect from me to the server.
- **Why it works.** The allowlist validates only the *first* address. It doesn't
  re-check where a redirect leads. Open redirect (usually low severity alone) +
  strict SSRF allowlist (usually safe alone) = admin account takeover. Two small
  flaws, harmless apart, chained into a critical one.
- **Fix.** Don't follow redirects on server-side fetches, or re-validate every hop
  against the allowlist. And fix the open redirect (validate the redirect target).

---

## Recurring themes

- **The server is a trusted messenger you aim.** It can reach what you can't —
  loopback, internal hosts, admin panels bound to the internal network. You send
  it, you don't go yourself.
- **`localhost` is relative to who asks.** The whole first lab hinges on this.
- **Every action is a separate request.** SSRF is not a session; reading and
  deleting are two requests you hand the server one at a time.
- **Blacklists lose, allowlists win — but an allowlist that follows redirects is
  an illusion.** Validate every hop, or don't redirect.
- **Critical bugs are chains of small ones.** Lab 4 is an open redirect (minor) +
  a strict SSRF filter (safe), chained into full compromise.

## Tools

Burp Suite — Proxy, Repeater, Intruder (Sniper, Numbers payload, sort by
status/length).
