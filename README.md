# redactor

Redacts sensitive data from NDJSON API traffic logs, line by line, as a CLI
or as an HTTP service. Rules come from `rules.yaml`.

```
redactor [--rules rules.yaml] [input-file]          # stdin if no file
redactor --serve --addr :8080 --rules /etc/redactor/rules.yaml
```

## 1. Build, run, test

Requires Go 1.27 (Docker and kind only for the deployment part).

```bash
go build -o redactor ./cmd/redactor

./redactor --rules rules.yaml input.ndjson > redacted.ndjson   # summary on stderr
cat input.ndjson | ./redactor --rules rules.yaml                # stdin
./redactor --rules rules.yaml --check-config                    # validate rules and exit
```

| Flag | Default | Meaning |
|---|---|---|
| `--rules` | `rules.yaml` | rules file |
| `--max-line-bytes` | 10 MiB | longer lines are rejected without being read into memory |
| `--summary-format` | `text` | `json` prints the summary as one JSON line |
| `--check-config` | | validate the rules and exit |
| `--serve`, `--addr` | `:8080` | run the HTTP service |
| `--max-concurrent` | 64 | `/redact` requests at once; more get `503` + `Retry-After` |
| `--idle-timeout` | 1m | close a request with no full line in or out for this long |
| `--shutdown-delay` | 5s | time between failing `/readyz` and closing the listener on SIGTERM |

`REDACTOR_HASH_KEY` (env, at least 32 bytes): if set, `hash` uses
HMAC-SHA256 with this key instead of plain SHA-256 (see 2.6).

Exit codes: `0` processed (rejected lines are reported, not fatal), `1` I/O
error, `2` bad usage or rules that do not load.

**Service**

```bash
./redactor --serve --addr :8080 --rules rules.yaml
curl --data-binary @input.ndjson localhost:8080/redact
```

| Endpoint | |
|---|---|
| `POST /redact` | NDJSON in, redacted NDJSON out, streamed. The per-request summary comes as the `X-Redactor-Summary` trailer and in the server log. Works with `Expect: 100-continue`, which curl sends for bodies over 1 MiB. |
| `GET /healthz` | liveness: `200` while the process answers |
| `GET /readyz` | readiness: `200` with rules loaded, `503` once shutdown has started |

The server is built from rules that already loaded. If `rules.yaml` is
missing or invalid the process exits (code 2) before it listens, so traffic
is never passed through unredacted.

**Tests**

```bash
go test ./...            # 417 tests; -short skips the 64 MiB memory test
go test -race ./...
go test ./internal/redact -run '^$' -fuzz FuzzRedactLine -fuzztime 60s
go test ./internal/stream -run '^$' -bench . -benchtime 5s
```

The tests that matter most:

- `TestNoSecretLeaks`: every secret in `input.ndjson` (68 values) is
  absent from stdout and stderr. `TestNoLeaksInHardCases` does the same
  for cases found in the reviews (see "How I worked").
- `TestGeneratedLeakCorpus`: 1,802 generated lines hide secrets in every
  combination of field-name spelling (58, from `password` to
  `AWS_SECRET_ACCESS_KEY`),
  place (JSON at any depth, JSON inside strings up to 5 levels, forms, query
  strings, URLs, XML, multipart, free text, headers) and value shape (cards,
  emails, JWTs, API keys). None may survive. Its first run found 6 kinds of
  leaks, now fixed.
- `TestExpectedOutput`: a full run equals `cmd/redactor/testdata/`, which I
  reviewed line by line. Regenerate with `-update` after an intended change.
- `TestRedactLineSampleInput` and the fuzz tests: no panic, valid JSON out,
  and running on its own output changes nothing.
- `TestRedactStreamsLineByLine`: the client reads line 1 before it sends
  line 2, so a buffering server would deadlock.
- `TestMemoryStaysFlat`: 64 MiB through the pipeline, heap stays under
  32 MiB.
- `TestManyConcurrentClients`: 60 clients at once under `-race`, a fifth of
  them hanging up halfway; every full response is correct and no goroutine
  is left behind.

## 2. Design and trade-offs

**Pipeline per line:** read a line, parse it into a JSON tree, walk the tree
applying key rules and value rules by scope, write it back compact. A line
that cannot be parsed becomes an error record.

### 2.1 Streaming

- Lines are read with `bufio.Reader.ReadSlice` in 64 KiB pieces. A line over
  `--max-line-bytes` is dropped piece by piece and never held whole.
  (`bufio.Scanner` would fail on lines over 64 KiB.)
- Memory is O(longest accepted line), independent of input size. Time is
  O(input size × number of rules); Go's RE2 regex engine is linear, so no
  input can make a pattern backtrack.
- Measured on an Apple M5, one core: 3.6 MB/s on the sample; a 256 MiB
  input took 75 s with 20 MiB peak RSS; `TestMemoryStaysFlat` peaks at
  4 MiB of heap. Most of the time is regex matching (see 5).
- The worst line for memory is one full of short values: each becomes a tree
  node and a redacted copy, about 12x the line in total. A line may hold at
  most 200,000 JSON values; more is rejected as `too_many_values`.
- Output is flushed whenever no complete input line is waiting. A client
  streaming lines (or `tail -f | redactor`) gets each line back at once; a
  big upload is still written in large blocks.
- In the service, `EnableFullDuplex` lets HTTP/1.1 read the request while
  writing the response, which a streaming endpoint needs.

### 2.2 Parsing and recursion

- Each line is parsed with `encoding/json`'s token decoder into a small tree
  of my own instead of `map[string]any`. A map would drop duplicate keys
  (line 25), lose key order, and turn numbers into float64, which changes
  `12345678901234567890` and rewrites `1.0` as `1`. The tree writes the line
  back exactly, with `&` and `<` left as is.
- Recursion is limited to 100 levels per document and 3 levels of JSON inside
  a string, so a malicious line cannot exhaust the stack.

### 2.3 Rule matching

- **Scopes.** Key rule scopes separate two kinds of names: `headers` for
  header names (request and response), `body` for JSON field names. Any JSON
  field outside the headers, including unexpected top-level fields like
  `"user"`, gets the body rules. A line that is valid JSON but not an object
  (`42`, an array) gets every rule, since its structure is unknown.
- **Key rules**: first matching rule in file order wins. Exact names match
  case-insensitively (header names are case-insensitive). Under a matching
  key: `null` and `""` stay (nothing to hide, and an empty password is itself
  a signal); numbers and booleans are redacted through their text and become
  strings; inside objects and arrays every value is redacted and the
  structure kept; `remove` drops the key.
- **Value rules** run on every string, on object keys (maps keyed by email
  are common), and on integer JSON numbers (a card can arrive as a number).
  All rules match on the original text; overlapping matches are merged into
  one region that gets the strongest action (mask or remove, then hash, then
  partial; the rule listed first on a tie). Otherwise a password next to a
  host (`https://u:s3cret@db.internal`) would be hashed by the email rule,
  and a plain hash can be reversed by guessing. `partial` becomes `mask`
  when the region came from different rules, since its last 4 characters
  could belong to the other match.
- **Validators.** When Luhn rejects a match, the engine looks for a valid
  match inside it: in `qty 2 4111 1111 1111 1111` the regex first takes the
  17-digit run, which fails Luhn, and the card inside it would leak.
- **Bodies that are strings** are tried as JSON (if they start with `{` or
  `[`), then as a URL-encoded form (by `Content-Type` or by shape), then as
  text. A string that parses but needs no redaction is kept byte for byte.
  The query string in `path` is handled as a form with the body rules. Form
  pairs are decoded before matching (`bob%40example.com`) and only changed
  pairs are re-encoded, so the output stays readable.

### 2.4 Failure handling

- A line that is not JSON, nests too deep, holds too many values or is too
  long is replaced by
  `{"_redactor":{"error":"invalid_json","line":20}}`: no input data, only the
  reason and the original line number. The output stays valid NDJSON and the
  consumer sees that a record was dropped.
- I do not redact such a line as text. Some secrets are found only by their
  field name (`"password":"Summer2024`), and a truncated line has no
  structure to find names in.
- stderr gets `line 20: invalid_json`, never the decoder's message, which
  quotes the input. A test checks this.
- Empty and whitespace-only lines are written back as they are and counted,
  so output line N is always input line N.
- Rules are validated strictly: unknown fields (a typo like `acton`), bad
  regexes, unknown actions or validators, duplicate names, an empty rule set,
  or a pattern that matches `****` itself all stop the load, all reported at
  once.

### 2.5 Idempotency

Running the tool on its own output gives identical output, verified on the
sample, in unit tests and by fuzzing (millions of inputs).

- Hashes are written `sha256:<hex>` (or `hmac-sha256:<hex>`), and a value
  already in that exact form is not hashed again. Without the prefix a field
  whose rule is `hash` would be re-hashed on every run, and treating any
  64-character hex string as "already hashed" would pass real hex API keys
  through. This is the one place I add to "replace with the SHA-256". Only
  the hash itself is skipped: a secret written right next to it is still
  found.
- Text is re-scanned until nothing changes (at most 8 passes): deleting text
  can create a new match. The fuzzer found a case where masking removed the
  only space in a string, which then read as a form on the next run; whole
  body strings and the query string in `path` are re-processed the same way
  now.
- `partial` on a value of 4 characters or less masks all of it, since keeping
  "the last 4" would reveal everything (line 38, `"card_number": "1234"`).
- A card found inside a run of digit groups redacts the whole run. Redacting
  each card separately keeps 4 digits of each, and those 4 plus the next
  group can form a new card-length run that passes Luhn (all zeros do), so
  every run of the tool found one more. The fuzzer found this with a long
  run of zeros.

### 2.6 Choices for threat detection

The logs are used to detect threats, so redaction should hide the secret and
keep the signal.

- `Authorization: Bearer ****`: the auth scheme is kept (`preserve_scheme`
  in `rules.yaml`). Basic auth on an API is itself a signal. Only known
  schemes are kept, so the first word of another value never leaks.
- Emails and API keys are hashed, not masked, so the same user across many
  requests stays visible. Plain SHA-256 of an email can be reversed by
  hashing candidates, so with `REDACTOR_HASH_KEY` set the tool uses
  HMAC-SHA256; in Kubernetes the key comes from a Secret and the pod does not
  start without it.
- Text rules mask only the value: `password=****`, `<password>****</password>`.

### 2.7 Changes to the config format

Allowed by the brief if documented:

- `preserve_scheme: true` on a key rule (2.6).
- `group: N` on a value rule: redact only that capture group, so the name
  next to the value stays.

Rules added or changed:

- `secret-fields` matches any name that ends in a secret word, in any
  spelling: `password`, `newPassword`, `db_password`, `accessToken`,
  `access-token`, `AWS_SECRET_ACCESS_KEY`, `sessionId`, `credentials`,
  plurals (`passwords`, `api_keys`), ...; `tokens` only alone or after a
  credential word (`access_tokens`), so counts like `max_tokens` stay;
  names are matched with surrounding spaces ignored.
- `credential-headers`: any header whose name contains auth, cookie, token,
  secret, session, password, pwd, passphrase, credential, signature, csrf,
  xsrf, private-key or api-key.
- `pii-fields`: ssn, phone, date of birth, hashed.
- `api-key-prefix` also knows GitHub, GitLab, Slack, Google API keys, AWS
  access key ids, Stripe restricted keys and webhook secrets, and OpenAI and
  Anthropic keys.
- New value rules: `url-credentials` (`https://user:****@host`),
  `pem-private-key` (also a key cut off before its END line),
  `bearer-token` (`Bearer <token>` anywhere in text),
  `http-header-dump` (`Authorization:` and `Cookie:`
  written as text, as in a raw request in a log), and `secret-assignment`,
  `json-secret`, `xml-secret`, `multipart-secret` for named secrets in text
  (quoted or not), broken or deeply nested JSON, XML and multipart bodies.
  The four share one list of names with `secret-fields`.
- The email rule also matches `%40` and international domains.

## 3. The JWT report

**Cause.** The `jwt` pattern used the standard base64 alphabet
`[A-Za-z0-9+/=]`. JWTs are base64url (RFC 7515), which uses `-` and `_`.

**Effect in the sample**, worse than missed tokens:

- lines 11 and 16: `_` in the payload, the token was not matched at all;
- line 15: `_` only in the signature, so the token was matched up to the `_`
  and the output read `****_adQssw5c`. That is a partial leak that looks
  redacted.

**Fix** (commit `Fix JWT pattern missing base64url tokens`): the base64url
alphabet plus `=` (some producers pad), 2 to 5 segments (5 is an encrypted JWE, which the old pattern would cut in
the middle), and `access_token`, `refresh_token` and `id_token` added to the
secret field names so opaque tokens are hidden too. The regression tests
were written first and failed on the original rules. My first fix accepted
both alphabets; a later review showed that with `/` a token in a URL path
also swallowed the rest of the path (`/v1/eyJ.../users/42`), so `+` and `/`
are out again.

**Same kind of bug, found along the way.** The card pattern `\b\d{13,19}\b`
missed cards with spaces or dashes (lines 1, 6, 36, 44). Allowing separators
created a new leak, the 17-digit run above, fixed in the next commit.

## 4. Deployment

`Dockerfile`, and Kubernetes manifests in `deploy/k8s`. On a local kind
cluster:

```bash
docker build -t redactor:0.1.0 .
kind create cluster
kind load docker-image redactor:0.1.0
kubectl apply -k deploy/k8s
kubectl -n redactor create secret generic redactor-hash-key --from-literal=key="$(openssl rand -hex 32)"
kubectl -n redactor rollout status deployment/redactor
kubectl -n redactor port-forward service/redactor 8080:80
```

The pods wait for the Secret and start once it exists.

- **Image:** multi-stage. A static Go binary (`CGO_ENABLED=0`) on
  `distroless/static` running as non-root: no shell, no package manager,
  about 16 MB. Base images are pinned by digest. The build stage
  cross-compiles, so `docker buildx build --platform linux/amd64 .` builds
  the x86 image on an ARM laptop without emulation.
- **Deployment:** 2 replicas spread over nodes; rolling updates with
  `maxUnavailable: 0`. Readiness on `/readyz`, liveness on `/healthz`.
  Non-root, read-only root filesystem, all capabilities dropped, seccomp, no
  service account token; the namespace enforces the `restricted` Pod Security
  Standard.
- **Resources:** memory limit 1Gi with `--max-concurrent=8` and
  `--max-line-bytes=4194304`: the worst case is about 8 requests × 4 MiB
  lines × 12 (2.1), about 400 MiB.
  `GOMEMLIMIT=900MiB` so the garbage collector works harder before the limit.
  No CPU limit: it would throttle the pod even with idle CPU on the node.
- **Rules:** a ConfigMap from kustomize's `configMapGenerator`, whose name
  carries a hash of the content. Changing the rules therefore starts a
  rolling update. kustomize reads only files under `deploy/k8s`, so
  `deploy/k8s/rules.yaml` is a copy, and a test checks it equals `rules.yaml`.
- **Shutdown:** on SIGTERM `/readyz` fails, the listener closes after
  `--shutdown-delay` (time for endpoint changes to reach load balancers), and
  running requests get 20 s, inside the 30 s grace period. Kubernetes'
  built-in `preStop: sleep` (on by default since 1.30) would do the first
  part too; doing it in the app
  also works outside Kubernetes and is tested.
- **HMAC key:** `REDACTOR_HASH_KEY` from the Secret `redactor-hash-key`,
  created once (above). It is never in git.
- **Tried on kind:** deployed under the restricted policy; the output through
  the Service equals the expected file; with the Secret missing the pods do
  not start; deploying a broken regex left the new pod in CrashLoopBackOff
  while the two old pods kept serving, and restoring the rules rolled back.
  The test also showed that kustomize does not add selectors to a
  PodDisruptionBudget, so the PDB selector is written out.

## 5. Known limitations, and what I would do with more time

- **Luhn false positives.** About 1 in 10 random 13–19 digit numbers passes
  Luhn, so some 64-bit IDs (Twitter or Discord snowflakes, 18–19 digits) are
  partially masked. I kept Luhn only: checking card network prefixes would
  fix most of it but could miss rare networks (UATP airline cards start with
  1), and in a redactor a corrupted ID is better than a leaked card. The
  same goes for JSON numbers: a 13-digit millisecond timestamp passes Luhn
  1 time in 10 and is then masked and turned into a string. I kept value
  rules on numbers, since a card stored as a number is a real case. Next
  step: an optional `card` validator for users who want the trade the other
  way.
- **Neighbouring digits are over-masked:** a card inside a run of digit
  groups masks the whole run, so two cards separated only by a space keep
  only the last 4 digits of the second.
- **Not decoded:** base64 or compressed bodies, cards written with dots or
  with non-ASCII digits.
  Personal data is found by field name only (no phone numbers in free text,
  no names).
- **Hashes and correlation:** with HMAC, rotating the key changes every
  hash; a key id in the prefix (`hmac-sha256:k2:`) would keep old logs
  comparable.
- **Throughput:** 3.6 MB/s on one core, most of it in regex matching.
  Matching secret names with any prefix (`newPassword`) costs about a third
  of it, since the name list is tried at every letter rather than only at
  word starts. Next: a cheap per-rule prefilter (no `@`, no email search)
  and a worker pool that keeps output order.
- **Not done from the bonus list:** worker pool, Prometheus metrics, hot
  reload of the rules (in Kubernetes a rules change already rolls the pods).
- **Service:** no authentication (meant to run inside the cluster behind a
  NetworkPolicy, not included), no request compression.

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

## How I worked

I built this with Claude Code. Go was new to me. I made the design calls
(listed above, each with what it costs) and reviewed and approved every
commit. After the core worked I reviewed the decisions twice: once against
the brief and outside sources, which found the scope gap for unexpected
fields and led to HMAC, and once by attacking the rules with crafted input,
which found camelCase field names, more credential headers, XML and
multipart bodies, and a stalled-client DoS in the service. Last, four
independent AI reviews of the finished repo, each given only the brief and
the code, found more: a `curl` upload over 1 MiB (`Expect: 100-continue`)
lost its body, a line of many tiny values used far more memory than its
size, a card written right after a hash was skipped, and more name
spellings. Commits are small and each builds and passes its tests; fixes to
my own earlier commits are separate commits, so the history shows what each
review found.
