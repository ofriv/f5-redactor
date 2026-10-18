# redactor

[![ci](https://github.com/ofriv/f5-redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/ofriv/f5-redactor/actions/workflows/ci.yml)

Redacts sensitive data from NDJSON API traffic logs, line by line, as a CLI
or as an HTTP service. What to hide and how is set in `rules.yaml`.

```
redactor [--rules rules.yaml] [input-file]          # stdin if no file
redactor --serve --addr :8080 --rules /etc/redactor/rules.yaml
```

**One line in, one line out** (real output of the tool):

```jsonc
// in
{"method":"POST","path":"/v1/login?token=abc123","headers":{"Authorization":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"},"body":{"email":"alice@example.com","password":"hunter2","note":"card 4111 1111 1111 1111 on file"}}
// out
{"method":"POST","path":"/v1/login?token=****","headers":{"Authorization":"Bearer ****"},"body":{"email":"sha256:ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976","password":"****","note":"card ***************1111 on file"}}
```

The secrets are hidden; the auth scheme and the last 4 card digits stay as
signals, and the email is hashed so one user can still be followed across
requests.

| | |
|---|---|
| **Streaming** | memory stays flat: 256 MiB in 23.5 s with 28 MiB peak RSS |
| **Fails closed** | rules that do not load stop the process before it reads or listens; a line that cannot be parsed becomes an error record |
| **Idempotent** | a second run changes nothing, checked by fuzzing |
| **Tested** | 424 tests, a 1,819-line generated leak corpus, fuzzing, `-race`, CI on every push |
| **Bonuses** | worker pool in input order, Prometheus `/metrics`, rules reload on `SIGHUP` |

Contents: [How I worked](#how-i-worked) ·
[1. Build, run, test](#1-build-run-test) ·
[2. Design](#2-design-and-trade-offs) ·
[3. JWT report](#3-the-jwt-report) ·
[4. Deployment](#4-deployment) ·
[5. Limitations](#5-known-limitations-and-what-i-would-do-with-more-time) ·
[6. Live traffic](#6-inline-on-live-traffic-under-a-millisecond-per-request)

## How I worked

Most of this was new to me: I had not written Go before, and most of the
tools in this project were new to me as well. I really enjoyed this
assignment, and learning so many new things along the way was the best part
of it. I used Claude Code throughout, as the brief allows, and worked with
it like a senior teammate I could ask anything. Before each part I asked it
to lay out the options and what each one costs, and then I chose; those
choices are the ones in section 2. I read and approved every commit, and
whatever I did not understand I asked about until I could explain it
myself.

Once it worked, I spent most of my time trying to break it:

1. I went over it against the brief and outside sources. That is how I
   found that unexpected top-level fields got no rules at all, and that a
   plain SHA-256 of an email can be reversed by guessing, so I added HMAC.
2. I attacked the rules with my own inputs: names like `accessToken`, more
   kinds of credential headers, XML and multipart bodies, and a client that
   connects and stalls the service.
3. I gave the repo to four independent AI reviewers, each in a different
   role (hiring manager, security, Go code review, and a grading suite
   written only from the brief). They found real bugs I had missed, for
   example a curl upload over 1 MiB that lost its whole body.
4. I fixed what they found and ran them again. The second round found, among
   other things, a password in a URL that was hashed instead of masked.

Every bug I found became a test, so it cannot come back. Fixes to my own
earlier commits are separate commits, so the history shows what each round
found. The first round's eight fixes were committed together after I
approved them as a set, so they share a timestamp.

## 1. Build, run, test

Requires Go 1.27 (Docker and kind only for deployment).

```bash
go build -o redactor ./cmd/redactor
./redactor --rules rules.yaml input.ndjson > redacted.ndjson   # summary on stderr
./redactor --rules rules.yaml --check-config                    # validate rules only

./redactor --serve --addr :8080 --rules rules.yaml
curl --data-binary @input.ndjson localhost:8080/redact

go test ./...            # -short skips the 64 MiB memory test
go test -race ./...
go test ./internal/redact -run '^$' -fuzz FuzzRedactLine -fuzztime 60s
```

| Flag | Default | |
|---|---|---|
| `--max-line-bytes` | 10 MiB | longer lines are rejected without being read into memory |
| `--workers` | CPU count | lines redacted in parallel, output in input order |
| `--summary-format` | `text` | or `json` |
| `--max-concurrent` | 64 | service: more requests get `503` + `Retry-After` |
| `--idle-timeout` | 1m | service: cut off a request with no full line in or out |
| `--shutdown-delay` | 5s | service: time between failing `/readyz` and closing the listener |

`REDACTOR_HASH_KEY` (at least 32 bytes) switches `hash` to HMAC-SHA256.
Exit codes: `0` done (rejected lines are reported, not fatal), `1` I/O
error, `2` bad usage or rules that do not load.

**Service endpoints.** `POST /redact` streams NDJSON both ways; its summary
comes in the `X-Redactor-Summary` trailer and the log. `GET /healthz` is
liveness, `GET /readyz` turns `503` once shutdown starts, `GET /metrics`
has Prometheus counters (requests, lines, rejections by reason, redactions
by rule; never input data). `kill -HUP` reloads `rules.yaml`: rules that do
not load are logged and the current ones stay, and a running request keeps
the rules it started with.

**Tests that matter most:** `TestNoSecretLeaks` (all 68 secrets in the
sample are absent from stdout and stderr), `TestGeneratedLeakCorpus` (58
spellings of secret names × every place a secret can sit × every value
shape; its first run found 6 kinds of leaks), `TestExpectedOutput` (golden
output I reviewed line by line), `TestRedactStreamsLineByLine` (a buffering
server would deadlock), `TestMemoryStaysFlat`, `TestProcessWorkersKeepOrder`
(1, 2 and 8 workers give byte-identical output), and
`TestManyConcurrentClients` (60 clients under `-race`, some hanging up).

## 2. Design and trade-offs

**Pipeline per line:** read, parse into a JSON tree, apply key rules and
value rules by scope, write back compact.

**Streaming.** Lines are read with `bufio.Reader.ReadSlice`, so a line over
the limit is dropped piece by piece and never held (`bufio.Scanner` fails
over 64 KiB). Memory is bounded by the longest line plus one 1 MiB batch;
time is linear, since Go's RE2 regexes cannot backtrack. Batches hold only
lines already waiting, are redacted in parallel and written in order, and
output is flushed whenever no full line is waiting, so `tail -f | redactor`
and a client sending line by line get each line back at once.

**Parsing and recursion.** A small tree of my own built from
`encoding/json` tokens, not `map[string]any`: a map drops duplicate keys
(line 25), loses key order and turns `12345678901234567890` into a float.
The tree writes untouched lines back exactly. Nesting is limited to 1,000
levels and 3 levels of JSON inside a string.

**Rule matching.**
- Key rules: `headers` scope for header names, `body` for every other JSON
  field, including unexpected top-level ones; a line that is not an object
  gets every rule. Header lists of `{"name","value"}` (HAR) work too.
- Under a matching key, numbers and booleans are redacted through their
  text and become strings, objects and arrays keep their structure, and
  `null` and `""` stay.
- Value rules run on every string, on object keys and on integer numbers (a
  card can arrive as a number). Overlapping matches merge into one region
  with the strongest action (mask, then hash, then partial), so a password
  inside an email-shaped match is masked, not hashed.
- When Luhn rejects a match, the engine searches inside it: in
  `qty 2 4111 1111 1111 1111` the 17-digit run fails, but the card inside
  it must not leak.
- String bodies are tried as JSON, then as a form (by `Content-Type` or
  shape), then as text. Query strings in `path` are forms.

**Failure handling.** A line that is not JSON, too deep, too big or too long
becomes `{"_redactor":{"error":"invalid_json","line":20}}`: the reason and
line number, no input data. I do not redact it as text: some secrets are
found only by their field name, and a broken line has none. stderr never
gets the decoder's message, which quotes the input. Empty lines are kept,
so output line N is input line N. Rules are validated strictly (typos,
bad regexes, duplicate names, a pattern that matches `****` itself), all
errors at once.

**Idempotency.** Hashes are written `sha256:<hex>` (or `hmac-sha256:`), and
a value already in that form is not hashed again: without the prefix a
hashed field changes on every run, and treating any 64-hex string as a hash
would pass real hex API keys. This is the one place I add to "replace with
the SHA-256". Text is re-scanned until nothing changes, because the fuzzer
found masking that created a new match. A card inside a run of digit groups
masks the whole run, because masking each card can leave digits that form
a new card.

**For threat detection** the signal stays: `Bearer ****` keeps the auth
scheme (`preserve_scheme`, known schemes only), emails and API keys are
hashed so a user stays visible across requests, and HMAC (required in
Kubernetes) stops reversing a hash by guessing candidates.

**Config changes** (allowed if documented): `preserve_scheme` on key rules
and `group: N` on value rules, to mask only the value in `password=****`.
The rules now match secret names with any prefix or plural (`newPassword`,
`AWS_SECRET_ACCESS_KEY`, `user[password]`, but not `max_tokens`), more
credential headers, known key formats (GitHub, Slack, AWS, Stripe,
OpenAI), PEM keys, credentials in URLs, and named secrets inside text,
broken JSON, XML and multipart.

## 3. The JWT report

**Cause.** The `jwt` pattern used the standard base64 alphabet
`[A-Za-z0-9+/=]`. JWTs are base64url (RFC 7515), which uses `-` and `_`.

**Effect in the sample**, worse than missed tokens: lines 11 and 16 have
`_` in the payload and were not matched at all; line 15 has `_` only in the
signature, so the output read `****_adQssw5c`, a partial leak that looks
redacted.

**Fix** (commit `Fix JWT pattern missing base64url tokens`): the base64url
alphabet plus `=`, 2 to 5 segments (5 is an encrypted JWE), and
`access_token`, `refresh_token`, `id_token` as secret field names. The
regression tests were written first and failed on the original rules. A
review later showed that also accepting `/` made a token in a URL path
swallow the rest of the path, so standard base64 is out again.

**Same kind of bug, found along the way:** the card pattern
`\b\d{13,19}\b` missed cards with spaces or dashes (lines 1, 6, 36, 44).

## 4. Deployment

```bash
docker build -t redactor:0.1.0 .
kind create cluster && kind load docker-image redactor:0.1.0
kubectl apply -k deploy/k8s
kubectl -n redactor create secret generic redactor-hash-key --from-literal=key="$(openssl rand -hex 32)"
kubectl -n redactor port-forward service/redactor 8080:80
```

- **Image:** static Go binary on `distroless/static`, non-root, about 16 MB,
  base images pinned by digest.
- **Pods:** 2 replicas spread over nodes, rolling updates with
  `maxUnavailable: 0`, readiness and liveness probes, read-only root
  filesystem, all capabilities dropped, under the `restricted` Pod Security
  Standard.
- **Memory:** 1Gi limit, lines up to 1 MiB and 4 requests at once. The
  worst line I found (dense short emails, which grow 10x when hashed) peaks
  at 397 MiB for 4 requests. `GOMEMLIMIT` sits below the limit; no CPU limit,
  which would throttle the pod even on an idle node.
- **Rules:** a ConfigMap whose name carries a hash of its content, so a
  rules change rolls the pods. Broken rules on kind left the new pod in
  CrashLoopBackOff while the old pods kept serving.
- **Shutdown:** on SIGTERM `/readyz` fails first, then running requests get
  20 s inside the 30 s grace period.
- **HMAC key** comes from a Secret, never git; without it the pods do not
  start.

## 5. Known limitations, and what I would do with more time

- **Luhn false positives:** about 1 in 10 random 13–19 digit numbers pass,
  so some 64-bit IDs and millisecond timestamps get masked. I kept it: a
  corrupted ID is better than a leaked card. Next: an optional
  network-prefix validator.
- **Cards glued to letters** (`card4111…`) are missed: the provided pattern
  needs a word boundary, and without it about 1 hex ID in 400 would be
  corrupted.
- **Over-masking:** two cards separated only by a space keep the last 4
  digits of the second only; any header containing `auth` is masked,
  including `:authority`.
- **Not understood:** base64 or compressed bodies, header pairs as arrays,
  XML `CDATA`, cut-off JSON inside a string (only text rules run there).
- **Throughput:** 3.4 MB/s per core; secret names with any prefix cost about
  a third. Next: a cheap prefilter per rule (no `@`, no email search).
- **Service:** no authentication (meant to sit behind a NetworkPolicy);
  metrics count a request when it ends.

## 6. Inline on live traffic, under a millisecond per request

I would stop treating it as log processing. Run it in the proxy (an Envoy or
NGINX filter, or a library call in the data plane) instead of an HTTP hop,
and redact per request, not per NDJSON line. Skip the JSON tree: scan the raw
bytes once, with all value patterns compiled into a single automaton
(Hyperscan or an RE2 set) and a literal prefilter so most bodies are rejected
without running a regex, and keep header rules as a hash lookup. Allocate
nothing per request (reused buffers), drop the re-scan loop by validating at
load time that rules cannot create new matches, and cap the work per request:
over budget, mask the whole body and flag it rather than pass it through.
Then measure p99 latency on real traffic, not averages.
