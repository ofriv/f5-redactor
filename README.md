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

**The service.** `POST /redact` takes NDJSON and streams the redacted lines
back while it is still reading. A summary of each request goes into the
`X-Redactor-Summary` trailer and the log. `GET /healthz` and `GET /readyz`
are for Kubernetes (readiness turns `503` once shutdown starts), and
`GET /metrics` has Prometheus counters: requests, lines, rejected lines by
reason and redactions by rule, never input data. `kill -HUP` reloads
`rules.yaml` without a restart. If the new file is broken, I keep the old
rules and log the error, and a request that is already running finishes
with the rules it started with.

**The tests I rely on most:**

- `TestNoSecretLeaks`: all 68 secrets in the sample are gone from stdout
  and stderr.
- `TestGeneratedLeakCorpus`: 1,819 generated lines that hide secrets under
  58 spellings of secret names, in every place I could think of (nested
  JSON, JSON inside strings, forms, URLs, XML, multipart, free text,
  headers). Its first run found 6 kinds of leaks.
- `TestExpectedOutput`: the full output for the sample, which I checked
  line by line.
- `TestRedactStreamsLineByLine`: the client reads line 1 before it sends
  line 2, so a server that buffers would hang.
- `TestMemoryStaysFlat`, `TestProcessWorkersKeepOrder` (1, 2 and 8 workers
  give exactly the same output) and `TestManyConcurrentClients` (60 clients
  under `-race`, some of them hanging up halfway).

## 2. Design and trade-offs

Each line goes through the same steps: read it, parse it into a JSON tree,
apply the rules, write it back.

**Streaming.** I read lines with `bufio.Reader.ReadSlice` rather than
`bufio.Scanner`, which fails on lines over 64 KiB. A line over the limit is
skipped piece by piece, so it is never held in memory. Memory is bounded by
the longest line plus one 1 MiB batch, whatever the size of the input, and
time grows linearly because Go's regex engine (RE2) never backtracks. Lines
that are already waiting are redacted in parallel and written back in their
original order. The output is flushed whenever no full line is waiting, so
`tail -f access.log | redactor`, or a client sending one line at a time,
gets each line back right away.

**Parsing and recursion.** I parse each line into a small tree of my own
instead of `map[string]any`. A map would drop duplicate keys (line 25 has
two `email` keys), lose the key order and turn `12345678901234567890` into
a float. The tree writes an untouched line back exactly as it came.
Nesting is capped at 1,000 levels, and at 3 levels of JSON inside a string,
so a crafted line cannot exhaust the stack.

**Rule matching.**
- Key rules look at names. Header names get the `headers` rules, and every
  other JSON field gets the `body` rules, including unexpected top-level
  fields. A line that is valid JSON but not an object gets all the rules,
  because I cannot tell what it is. Headers logged as a list of
  `{"name": ..., "value": ...}` objects (HAR files) work too.
- Under a matching key, numbers and booleans are redacted and become
  strings, objects and arrays keep their shape, and `null` and `""` stay as
  they are, since there is nothing to hide.
- Value rules look at content: every string, every object key, and integer
  numbers, because a card can arrive as a number. When two matches overlap,
  they merge and the strongest action wins (mask, then hash, then partial).
  That way a password that happens to look like part of an email is masked,
  not hashed.
- When Luhn rejects a match, I look for a valid card inside it. In
  `qty 2 4111 1111 1111 1111` the regex first grabs 17 digits, which fail
  Luhn, and without this step the real card would leak.
- A body that is a string is tried as JSON, then as a form, then as plain
  text. The query string in `path` is treated as a form.

**When something goes wrong.** A line that is not valid JSON, or is too
deep, too big or too long, is replaced by
`{"_redactor":{"error":"invalid_json","line":20}}`: only the reason and the
line number, no input data. I chose not to redact it as text instead,
because some secrets can only be found by their field name, and a broken
line has no structure to find names in. Errors on stderr never include the
JSON parser's message, since that message quotes the input. Empty lines
stay, so output line N is always input line N. A broken rules file stops
everything, with all its errors listed at once.

**Running twice changes nothing.** A hash is written as `sha256:<hex>`, and
a value already in that form is not hashed again. Without the prefix, a
hashed field would change on every run, and treating any 64-character hex
string as "already hashed" would let real hex API keys through. This is the
one place where I add to the brief's "replace with the SHA-256". The fuzzer
also showed that masking can create a new match, so text is scanned again
until nothing changes. For the same reason, a card inside a run of digit
groups masks the whole run.

**Keeping the signal for threat detection.** These logs are used to detect
attacks, so I tried to hide the secret but keep what is useful.
`Bearer ****` keeps the auth scheme (`preserve_scheme`, for known schemes
only). Emails and API keys are hashed instead of masked, so you can still
see the same user across requests. Because a plain SHA-256 of an email can
be reversed by guessing, the tool uses HMAC with a secret key when one is
set, and in Kubernetes it is required.

**Changes to the config** (the brief allows them if documented): I added
`preserve_scheme` for key rules and `group: N` for value rules, so
`password=hunter2` becomes `password=****` and not `****`. I also extended
the rules: secret names with any prefix or plural (`newPassword`,
`AWS_SECRET_ACCESS_KEY`, `user[password]`, but not `max_tokens`), more
credential headers, known key formats (GitHub, Slack, AWS, Stripe, OpenAI),
private keys, passwords in URLs, and named secrets inside free text, broken
JSON, XML and multipart bodies.

## 3. The JWT report

**What was wrong.** The `jwt` pattern used the standard base64 alphabet,
`[A-Za-z0-9+/=]`. JWTs use base64url (RFC 7515), where `-` and `_` take
the place of `+` and `/`.

**What it did in the sample** was worse than just missing tokens. Lines 11
and 16 have `_` in the payload, so they were not matched at all. Line 15
has `_` only in the signature, so the match stopped there and the output
read `****_adQssw5c`: a partial leak that looks redacted, which is the
dangerous kind.

**What I did** (commit `Fix JWT pattern missing base64url tokens`): I wrote
the regression tests first and checked that they failed on the original
rules. Then I changed the pattern to base64url plus `=`, with 2 to 5
segments (an encrypted JWT has 5), and added `access_token`,
`refresh_token` and `id_token` to the secret field names. At first I also
accepted `/`, but a review showed that a token inside a URL path then
swallowed the rest of the path, so I took it out again.

**A similar bug I found along the way:** the card pattern `\b\d{13,19}\b`
missed cards written with spaces or dashes (lines 1, 6, 36 and 44).

## 4. Deployment

```bash
docker build -t redactor:0.1.0 .
kind create cluster && kind load docker-image redactor:0.1.0
kubectl apply -k deploy/k8s
kubectl -n redactor create secret generic redactor-hash-key --from-literal=key="$(openssl rand -hex 32)"
kubectl -n redactor port-forward service/redactor 8080:80
```

I tested all of this on a local kind cluster.

- **Image:** a static Go binary on `distroless/static`, running as non-root.
  It has no shell and no package manager, it is about 16 MB, and the base
  images are pinned by digest.
- **Pods:** 2 replicas spread across nodes, and updates that start a new pod
  before stopping an old one. The pods run with a read-only filesystem and
  no extra permissions, and the namespace enforces the `restricted` Pod
  Security Standard.
- **Memory:** a 1Gi limit, lines up to 1 MiB and 4 requests at a time. The
  worst line I could find (lots of short emails, which grow 10x when
  hashed) used 397 MiB for 4 requests. I did not set a CPU limit, because
  it slows the pod down even when the node has CPU to spare.
- **Rules:** a ConfigMap whose name includes a hash of its content, so
  changing the rules rolls out new pods. When I deployed a broken rules
  file on purpose, the new pod failed to start and the old pods kept
  serving.
- **Shutdown:** on SIGTERM the pod first stops receiving new traffic, then
  gives running requests 20 seconds to finish.
- **HMAC key:** it comes from a Secret and is never in git. Without it the
  pods do not start, instead of quietly falling back to plain SHA-256.

## 5. Known limitations, and what I would do with more time

- **Luhn false positives.** About 1 in 10 random 13 to 19 digit numbers
  pass Luhn, so some long IDs and millisecond timestamps get masked. I
  decided a broken ID is better than a leaked card. Next step: an optional
  check of card network prefixes.
- **Cards glued to letters** (`card4111…`) are missed, because the provided
  pattern needs a word boundary. Removing it would corrupt about 1 hex ID
  in 400, so I left it.
- **Hiding a bit too much:** two cards separated by just a space keep only
  the last 4 digits of the second, and any header with `auth` in its name
  is masked, including `:authority`.
- **Formats I do not handle:** base64 or compressed bodies, headers as
  arrays of pairs, XML `CDATA`, and JSON inside a string that was cut off,
  where only the text rules run.
- **Speed:** 3.4 MB/s per core. About a third of that goes to catching
  secret names with a prefix (`newPassword`). Next step: a cheap check
  before each rule, for example skipping the email regex when there is no
  `@`.
- **The service** has no authentication (it is meant to run behind a
  NetworkPolicy), and metrics count a request only when it ends.

## 6. Inline on live traffic, under a millisecond per request

I would stop treating it as log processing. It would run inside the proxy
(an Envoy or NGINX filter, or a library call) instead of as a separate HTTP
hop, and work on each request instead of on NDJSON lines. I would skip
building a JSON tree and scan the raw bytes once, with all the value
patterns compiled together (Hyperscan or an RE2 set) and a quick literal
check so most bodies never reach a regex, and keep header rules as a simple
lookup. I would allocate nothing per request, check when the rules are
loaded that they cannot create new matches, so the second scan is not
needed, and set a time budget per request: over budget, the whole body is
masked and flagged rather than passed through. Then I would measure p99
latency on real traffic, not the average.
