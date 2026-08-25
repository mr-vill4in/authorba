# Authorba — Broken Access Control Tester (Burp Suite Extension)
#
# Author: Mr_Vill4in

A Jython Burp Suite extension for hunting **BOLA** (object-level), **BFLA**
(function-level), and **BOPLA** (property-level) broken access control by
replaying captured requests under multiple user identities and roles.

## Install

1. Download the [Jython 2.7.x Standalone JAR](https://www.jython.org/download).
2. Burp → **Extender → Options → Python Environment** → select the Jython JAR.
3. **Extender → Add** → Extension Type: *Python* → select `Authorba.py`.

## Workflow

1. **Browse the app through Burp Proxy.** Requests are auto-captured as
   endpoints (deduped by method + path + host; static assets like images,
   CSS, JS, fonts are skipped by default). You can also right-click any
   request → **Add to Authorba**.
2. **Add users** — one dialog per user:
   - `name`, `role` (new roles are created inline),
   - **Cookies** (`name=value` per line — replaces the whole Cookie header),
   - **Headers** (`Name: value` per line, e.g. `Authorization: Bearer eyJ...`,
     `X-API-Key: ...`, `X-CSRF-Token: ...`),
   - optional **session refresh**: a raw login request plus regexes that
     extract a new cookie / token from the response. Refresh runs
     automatically at the start of each test run, or via *Run Refresh Now*.
3. **Role Permissions** — a checkbox matrix of endpoint × role marking which
     roles *should* be allowed. Endpoints are auto-tagged with a heuristic
     category (BOLA / BFLA / BOPLA / GraphQL).
4. **Run All Tests.** Each endpoint is replayed as the original identity
   (baseline) and then once per enabled user. CSRF-ish tokens
   (`csrf`, `xsrf`, `authenticity_token`, `nonce`, ...) are detected in the
   captured request and replaced with the user's `X-CSRF-Token` if provided.
5. Read the **matrix**: cells are colored by verdict (click any cell to view
   the exact request/response in the viewers below):

| Color | Verdict | Meaning |
|---|---|---|
| 🟢 green | BLOCKED | 401/403 — access denied |
| 🔵 blue-gray | ALLOWED | 2xx and the role is permitted |
| 🔴 red | FINDING | 2xx but the role is explicitly denied — likely BOLA/BFLA/BOPLA |
| 🟠 amber | UNVERIFIED | 2xx but no permission policy defined for that role |
| 🔴 red | FINDING | 2xx but role explicitly denied, or canary leak |
| 🩸 crimson | BOLA | object-swap confirmed cross-user access |
| 🔷 light blue | PUBLIC | responds identically with no auth |
| 🟣 purple | ERROR / violet WAF-RL | request failed / infrastructure block |
| ⚪ gray | SKIPPED | other/uninteresting status |

6. **Export JSON / HTML** — full results plus detailed request/response for
   each FINDING.

## Test modes

- **Role-swap (BFLA/BOPLA):** every endpoint is replayed under each user's
  session; 2xx on an endpoint the role isn't allowed to use is a FINDING.
- **Object-swap (BOLA):** for same-role user pairs, the endpoint captured
  against user A's object is replayed with A's session but B's object ID
  (configured per user as *Owned objects*, e.g. `orders=1001`). A 2xx shows
  as a crimson **BOLA** column (`alice->bob`). 401/403 or a body matching
  the denial-marker regex counts as blocked.

## Three-state model (public endpoint filtering)

Every endpoint is probed three ways: as captured (baseline), per user, and
**with all auth stripped** (`(no-auth)` column). An endpoint where the
unauthenticated response matches the baseline is simply **PUBLIC** (light
blue) — those cells don't count as bypasses, killing a whole class of false
positives.

## Canary markers

Give each user a *canary* — a string unique to them (email, username,
tenant slug). If user B's response contains user A's canary, the cell turns
red with a `canary leak` note even if the status code looked fine. On the
test server: set alice's canary to `alice@corp.local` and replay
`GET /api/users/2` as eve.

## Risk score column

Each endpoint gets a deterministic 0–100 BOLA/IDOR likelihood score
(inspired by authz-hunter): object refs in path (+30) / query (+15),
state-changing method (+20), GraphQL (+10), BOLA/BFLA/BOPLA category
(+10–15), auth-bearing request (+10). Sort your manual testing by it.

## WAF / rate-limit guard

HTTP 429/502/503, or a 403 whose body matches WAF phrases (rate limit,
cloudflare, captcha, akamai...), is classified violet **WAF/RL** — an
infrastructure block, not an application authz result — so it never gets
mistaken for ENFORCED.

## GraphQL safety

GraphQL *queries* are safe reads and are replayed even in write-safe mode;
*mutations* still require the explicit *Allow Write Replay* opt-in.

## Passive auto-testing (Autorize-style)

Enable **Auto-test new endpoints** and just browse as the privileged user —
every newly captured endpoint is immediately tested in the background
(baseline / each user / unauthenticated, with canary + WAF guards) and the
matrix fills in live. No need to press Run All Tests. Combine with
**Capture Repeater traffic** to auto-test manually crafted requests from
Repeater too.

## Safety

- **Safe mode (default ON):** only GET/HEAD/OPTIONS are replayed. POST/PUT/
  PATCH/DELETE endpoints are skipped unless you select the endpoint and press
  *Allow Write Replay* (the endpoint list then shows `[write-OK]`).
- Every finding should be manually verified before reporting.

## Endpoint normalization

REST paths are templated (`/api/orders/1001` → `/api/orders/{id}`), so
`/orders/1001` and `/orders/1002` collapse into one endpoint instead of
polluting the matrix. UUIDs and long hex IDs are treated the same way.
GraphQL requests are keyed by operation (`mutation:deleteUser` vs
`query:GetUser`), so distinct operations are distinct endpoints.

## Content-based verdicts

A configurable **denial-marker regex** (default
`forbidden|unauthorized|access denied|...`) is matched against the response
body: a "200 OK" whose body says *forbidden* is classified BLOCKED, not
allowed — this catches apps that return 200 with an error payload.

## Length-diff signal (AutoRepeater-style)

Matrix cells show `status / length d±delta`, where delta is the response
length difference against the original-identity baseline. **Same status
code + delta 0 is a strong indicator the tested identity really got
access** (hover a cell to see the interpretation). Large deltas usually
mean the response changed shape — check the diff in the viewers.

## Capture controls

- **Live capture from Proxy: ON/OFF** — toggle anytime; a status line under
  it shows the current state. When OFF, nothing is captured.
- **Pull Endpoints from History (scope filter applies)** — one-click bulk
  import of everything already in Burp's HTTP history. Combine with *Only
  capture in-scope* to pull just your target scope; the log line reports
  how many out-of-scope items were skipped. Static-asset skipping,
  auth-only filtering and normalization dedupe all apply, so re-pulls
  never create duplicates. Useful when you browsed before loading the
  extension or had capture turned off.
- Right-click → **Add to Authorba** for individual requests.

## Context menu

Right-click any request in Proxy/Repeater/Target to:
- **Add to Authorba** — register as endpoint
- **Create User from this Request's Auth** — extracts Cookie / Authorization
  headers into a new user
- **Set as Session-Refresh Request for User...** — uses the request as that
  user's re-login template and runs it immediately

## Operational safety (Authz-ExeC-inspired)

- **Delay between replays (ms)** — rate limiting; default 250ms between any
  two requests the engine sends.
- **Dry run** — build the test plan and mark cells `dry run - not sent`
  without sending anything. Good for reviewing scope before firing.
- **Check Sessions** — probes each user's credentials with a harmless GET
  and reports ALIVE / DEAD per identity, so stale sessions don't masquerade
  as ENFORCED.
- **Only capture requests carrying auth** — skips public noise (login
  pages, docs, assets) at capture time.
- **Empty-result guard** — a 200 with an empty body/collection (`[]`,
  `{}`, `{"data":null}`...) is treated as row-level filtering (BLOCKED),
  not as granted access.

## Exports

JSON (full results + request/response evidence for findings), HTML
(color-coded client-ready matrix + findings), and CSV (spreadsheet triage:
verdict, status, length-diff vs baseline, similarity per identity).

## Smart diffing

Before comparing a replayed response against the baseline, volatile values
are masked: timestamps (ISO + epoch), UUIDs/long hex tokens, and long numeric
IDs. This keeps verdicts quiet when only ephemeral values differ.

## JWT inspection

*Inspect JWT* button decodes header + payload and flags: `alg:none` /
unsigned tokens, empty signatures, injectable key headers (`jku`, `jwk`,
`x5u`, `x5c`, `kid`), missing `exp`, and expired tokens (with how long ago —
stale tokens that still authenticate are themselves a finding).

## GraphQL

Endpoints under `/graphql` (or whose body contains `query`/`mutation`
operations) are detected and tagged; each distinct GraphQL request captured
counts as its own endpoint, so per-operation BFLA testing works naturally.

## Notes / limitations

- Config (users, permissions) persists to `~/authorba_config.json (legacy auth_matrix_config.json is auto-migrated)`. Note
  that saved permission keys now use the *normalized* path template
  (`/api/users/{id}`), so permissions saved by older versions against
  concrete paths need re-marking once.
- Capture can be restricted to Burp's Target scope via *Only capture
  in-scope*.
- The replay engine strips `Accept-Encoding` so responses are comparable.
- Session refresh uses the `Host` header of the raw refresh request; target
  it at the same host you browse.
- Only Burp's legacy (pre-Montoya) extension API / Jython is supported, since
  the request was for a Python extension.

## Legal

For use on systems you are authorized to test only.

## Local test server

`vuln_server.py` is a deliberately vulnerable Flask app for exercising the
extension end-to-end. Start it, point Burp's browser at it, and confirm the
matrix lights up red exactly where it should:

```bash
python3 vuln_server.py 5000     # listens on 127.0.0.1:5000
```

Logins: `admin/admin123` (admin), `alice/alice123` and `bob/bob123` (user),
`eve/eve123` (viewer).

Expected findings when you replay as a non-admin user:

| Endpoint | Class | Expected matrix result |
|---|---|---|
| `GET /api/orders/<id>` | BOLA | 🔴 200 for any user on others' orders |
| `DELETE /api/orders/<id>` | BOLA | 🔴 200 for any user |
| `POST /api/admin/delete-user` | BFLA | 🔴 200 for user/viewer roles |
| `GET /api/admin/stats` | BFLA | 🔴 200 for user/viewer roles |
| `GET /api/users/<id>` | BOPLA | 🔴 200, leaks `password_hash` + `salary` |
| `POST /graphql` (mutation) | BFLA | 🔴 200 for non-admins |
| `GET /api/admin/export-audit` | safe | 🟢 403 for user/viewer |
| `GET /api/orders` | safe | 🔵 200, own orders only |
| `GET /api/users/<id>/profile` | safe | 🔵 200, safe fields only |
| `GET /api/public/health` | public | 🔷 identical with no auth (three-state test) |
| `GET /api/admin/soft-denied` | content-verdict | 🟢 200 + "forbidden" body → BLOCKED for non-admins |
| `GET /api/reports` | WAF sim | 🟣 403 with WAF/rate-limit body → WAF/RL verdict |
| `/static/*`, `/favicon.ico` | noise | skipped by capture |

Test flows:

1. Log in as each user in Burp's browser (through the Proxy) so all requests
   get captured. `/api/login` sets a `session` cookie; `GET /api/token`
   returns a JWT — configure one extension user with the cookie and another
   with `Authorization: Bearer <jwt>` to test both auth styles.
2. Add extension users `admin`, `alice`, `bob`, `eve` with their cookies /
   tokens and the roles above.
3. In *Role Permissions*, allow `admin` on the `/api/admin/*` and
   `/api/users/*` endpoints, deny `user`/`viewer` there, etc.
4. Run All Tests — the vulnerable endpoints should show red for roles that
   should be denied; the safe ones green/blue. Note `server_time` in
   `/api/orders` responses exercises the dynamic-value masking.
5. Session refresh test: set a user's refresh request to the raw
   `POST /api/login` with JSON body and regex `"session":"([0-9a-f]{32})"`.

