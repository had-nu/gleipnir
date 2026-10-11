# Verification Playbook

**Purpose**: a standing procedure that has to be applied before and after any change to
this repository, so that a wrong belief cannot survive long enough to be built on.

**Status**: this document exists because the previous four commits each diagnosed the
same failure differently, and three of the four diagnoses were wrong. The failure was
not in the fixes. It was in how the failures were *identified*.

---

## 1. Why this exists — three wrong diagnoses, in order

Each of these is a real claim made in a commit message or a document in this
repository. Each was stated with confidence. Each was falsified by running the code.

### 1.1 `e45dab5` — "consensus runs over `MemoryBus`, so the multi-node path has no empirical basis"

Reasonable inference from reading `engine.go`. But `NewEngineWithPeers` and
`GossipChannel` existed and were tested, so the conclusion "unwired but present"
understated the problem. The actual finding was that `--peers` was discarded with
`_ = peers` and every real process ran single-node — a deployment path that appeared to
honour a flag and did not.

**Lesson**: reading the wiring tells you what is reachable from the entry point. It does
not tell you what a running process does.

### 1.2 `3a94fde` — "Peer formation remains unreliable, and it is now the only thing blocking convergence"

Backed by a real observation — 43 cycles aborting with `incomplete proof set` — and
presented with a careful hedge (`Not diagnosed`, `this is a suspicion, not a finding`).
The hedge was correct and was then dropped: the next commit treated peer formation as
established.

**Lesson**: a stated uncertainty that is not carried forward becomes an assumption
within one commit.

### 1.3 `3a94fde` — "docker-compose.yml still uses mDNS, which discovers nothing in this environment"

Measured on a `/tmp` bootstrap override that is not in the repository. Stated as a
general property of the topology.

Measured on the actual `docker-compose.yml` topology:

```
val-1 connected: 4      val-1 connected: 4
val-2 connected: 4      val-2 connected: 4
val-3 connected: 4      val-3 connected: 4
val-4 connected: 4      val-4 connected: 4
val-5 connected: 4      val-5 connected: 4
```

A complete 4/4 mesh on every node, in about three seconds, on every run. The
environment was the `/tmp` override. The claim was about compose.

This cost a full debugging cycle. `17ef3d5` added per-peer retry throttling to
`redialLoop`, on the theory that dials were being starved. The loop was never running at
all — `NewGossipBus` started it only `if len(cfg.BootstrapPeers) > 0`, and compose
configures no `IPC_PEERS` bootstrap addresses. So the throttle was dead code, and the
symptom it was written to explain had a different cause: `RunPreparePhase` read its VRF
proof set in the same instant it published its own.

**Lesson**: a measurement taken against a local override is a measurement of the
override. Say which configuration was measured, every time.

### 1.4 This session — the same error, a fourth time

Before running anything, the assessment was that peer formation was the blocker and
that `IPC_P2P_BOOTSTRAP` was the fix. That was inherited from `3a94fde` and repeated
without being checked. Running the topology falsified it immediately.

The redial loop was genuinely dead code and genuinely worth fixing, and the fix was
correct — but it was not the blocker, and the write-up would have said so if the
measurement had come first.

**Lesson**: this is a process failure, not an individual one. It recurs because nothing
in the workflow forces a measurement before a diagnosis.

### 1.5 The same failure with the specification in hand — the fifth time

The deadlock in item 3.10 was first diagnosed by reading `engine.go` and reasoning about the
phase order. That reading was wrong: the proposer's quorum check completes, and what fails is
that validators exhaust their wait for the proposal before it is delivered. Both accounts
predict the same symptom, which is why reading code could not distinguish them.

The error was not reading the code carelessly. It was **never opening the specification**.
`docs/IMPLEMENTATION-STATUS.md` §2.2 recorded that 3CP lives in another repository and is
therefore not consultable. That was written on 2026-10-05 and it stopped being true:
`had-nu/3CP` is reachable, and `./scripts/fetch-3cp.sh` now caches it. §6 of the spec
describes the cycle in six steps, and reading it shows immediately that the code's two
`RunPreparePhase` calls are not what the spec describes, and that `waitForProposal` — whose
expiry causes the failure — has no basis in the spec at all.

It then went further, and the sequence is the argument for this rule: once the spec was open,
this file cited the **wrong one of two documents** in that repository, called it normative,
and wrote its reasoning into a code comment as fact. Both documents exist,
`spec/SPEC-3CP-V2.md` and `spec/3CP-v2.md`, and they contradict each other. The claim
recorded in the comment — "the spec departs from RFC 9381, do not correct it toward the RFC"
— was not in either document, and was wrong; checked against RFC 9380 §3, the construction
in the code *is* RFC 9380. No test would ever have caught that, because the code was right.
Only reading the RFC as well as the spec did.

Reading the code was never a substitute for reading the spec. They answer different questions.
The code says what happens; the spec says what should happen. Only the second can tell you the
first is wrong.

**Lesson**: open the specification before diagnosing a protocol defect or proposing a fix for
one. That is Rule 2 below.

---

## 2. The rules

> **Rule 1 — No claim about runtime behaviour may be written down before a named command
> produced it. If the command is not recorded with the claim, it is a hypothesis.**

The named command matters as much as the fact. "The topology converges" is unfalsifiable.
"`grep -c 'peer connected' <logs>` returned 4 on all five nodes" can be re-run.

Three things make a claim checkable:

1. the configuration it was measured under (compose file, override, flags)
2. the command that produced it
3. the observation itself, including what it does *not* show

> **Rule 2 — Every change to protocol behaviour cites the 3CP section that governs it.
> Look the requirement up. Do not infer it from the code.**

The specification is `had-nu/3CP`, `spec/SPEC-3CP-V2.md`. It is cached:

```
./scripts/fetch-3cp.sh            # fetch or refresh into .3cp/
./scripts/fetch-3cp.sh --check    # verify the cache is present
```

`.3cp/` is gitignored. The spec is canon; vendoring a second copy into the repository is
what produces a stale one, and a stale spec is worse than none — a citation drawn from the
wrong version still looks right.

The hierarchy is not flat:

```
3CP RFC                              ← source of truth
  ↓ must be followed structurally
spec/SPEC-3CP-V2.md                  ← normative spec; an implementation *attempt*
  ↓ may exceed, if documented and heavily tested
Gleipnir                             ← this repository
```

Where the **RFC and the spec disagree, the RFC wins.** Where **Gleipnir is more efficient
than the spec anticipated**, that is legitimate — but it must be documented and heavily
tested *before* being reflected into the RFC. A silent divergence is not an improvement,
it is a fork. Correcting the spec is a normative act handled in the 3CP repository, never
from here.

`docs/3CP-CONFORMANCE.md` maps each section to the code and lists the open divergences
(D1–D10). Read it before touching the consensus path.

Three rules of use:

- **Cite `SPEC-3CP-V2.md`, not `3CP-v2.md`.** Both exist in the 3CP repository and they
  contradict each other in §2, §4, §6 and §6.5. The README and CONTRIBUTING name
  `SPEC-3CP-V2.md` as normative. See D10.
- **Verify the quote against the RFCs as well as the spec.** The spec cites RFC 9380 and
  RFC 9381 for the VRF, and its explanation of the construction was wrong. A citation that
  reads plausibly is not a citation that was checked.
- **If a change is not in the spec, say so explicitly** and justify it on measured
  behaviour. Adding a timeout the spec does not define is a protocol change, and "it seemed
  like the right amount" is not a justification.

A reviewer can check every citation against the spec without trusting the author. That is
the point: the claim does not depend on my confidence.

---

## 3. Pre-activity check — before changing anything

Run this before forming or writing down a diagnosis. It is deliberately cheap.

### 3.1 Establish the baseline

```
docker compose up -d
sleep 30
docker compose ps
```

Record, per node: container up, process alive.

### 3.2 Establish what the system is actually doing

```
for i in 1 2 3 4 5; do
  echo "--- val-$i ---"
  docker logs val-$i 2>&1 | tail -20
done
```

Read the logs before theorising. Specifically, answer:

- What is the node **doing**, not failing to do?
- Which node is named in errors? Which node is *silent*?
- Does the error name the same peer on every node, or a different one each time?

That last question distinguishes a transport failure (one peer unreachable everywhere)
from a scheduling race (a different missing peer per node), and it is the question that
would have identified the VRF proof race immediately.

### 3.3 Query state, do not infer it

```
for i in 1 2 3 4 5; do
  echo -n "val-$i: "
  docker exec val-$i wget -qO- --timeout=5 http://localhost:8080/v1/health
done
```

Note: `/v1/health` reports the **consensus graph** (`GetHealth` counts
`state.Nodes` with `Status > 0`), **not** libp2p connections. It can report 5/5 peers
on a node that has never connected to anything. For transport state, read the connection
logs or `GossipBus.ConnectedPeers()`. Conflating the two is how a healthy-looking node was
declared broken.

### 3.4 Record the measurement

Write down, before proceeding:

| Question | Command | Observation |
|---|---|---|
| Are all nodes up? | | |
| What is each node doing? | | |
| What is the mesh? | | |
| What is the block height? | | |
| Which peer is named in errors? | | |

If any cell says "I think", the step is not finished.

---

## 4. Post-activity check — after changing anything

### 4.1 Re-measure the same table

Same commands, same fields. Compare against the baseline. **A change that cannot be
shown to have moved a number in that table is not yet demonstrated to have worked.**

The VRF fix moved `block_height` from 0 to 1. That was real but partial, and the honest
report said so. The temptation is to round "one block appeared" into "convergence
fixed". Don't.

### 4.2 Check the claim survived contact with the topology

```
docker compose -f docker-compose.yml -f docker-compose.test.yml --profile test \
  run --rm conformance-test
```

Baseline is **16/33**. All 17 failures currently trace to one deadlock and are expected
to persist until it is fixed. If that number changes unexpectedly, stop and find out why
before continuing — in either direction.

### 4.3 Check for regressions in the gate

```
go build ./... && go vet ./...
golangci-lint run
gosec -confidence medium ./...
govulncheck ./...
go test ./... -count=1 -timeout=400s
go test -race ./pkg/... -count=1
```

`gofmt -l` on **the files you touched**. Note that 13 files in this repository were
already unformatted before any of this work; compare against `main` before attributing
a formatting failure to your change.

### 4.4 Confirm the negative

For every defect you set out to fix, produce the evidence it is fixed **and** the
evidence the test fails without the fix:

```
git stash push <the fix file> -q
go test ./pkg/consensus/ -run <the test> -count=1   # must FAIL
git stash pop -q
go test ./pkg/consensus/ -run <the test> -count=1   # must PASS
```

A test that has never been seen to fail is not evidence of anything.

### 4.5 Check that you did not break something unrelated

Run the topology before *and* after. If a failure appeared that you cannot explain from
your change, the change is not understood well enough to merge.

---

## 5. Claims that require special care

### 5.1 "The system does X"

Requires a command. If the system does X only under a local override that is not in the
repository, the claim is about the override, and must say so. This is the single most
repeated failure in this repository's history.

### 5.2 "The topology converges" / "the network is healthy"

Never assert this. Assert the specific measurement: block height, mesh completeness,
passing conformance count. "Healthy" has meant three different things in this repository's
history — no errors, 5/5 peers on `/v1/health`, and blocks actually finalising. Only the
third is evidence.

### 5.3 "This is a design gap, not a bug"

Legitimate, and used correctly in `dc76606`. But it requires that the alternative was
considered and rejected for a stated reason. Without that, it is a deferral.

### 5.4 Absence of evidence

`grep -c "func Fuzz"` returning 0 is solid. "There are no other bugs" is not, and has not
been true of this repository on any previous occasion.

---

## 6. Known-inaccurate statements to correct when touching these files

`docs/IMPLEMENTATION-STATUS.md` was written against `7dfd23d` and is accurate about what
it measured. Two statements in it should be read with care:

- It attributes the multi-node problem to `--peers` being discarded. **Correct**, and
  fixed in `dc76606`.
- It predates any measurement of mDNS on the compose topology. Any inference in it about
  peer discovery being absent is unmeasured and should not be relied on. The measurement
  in §1.3 above supersedes it.
- **§2.2's conclusion no longer holds, but its reason was right.** It says the
  specification is not consultable because it lives in another repository. That is still
  why it was never read. It *is* reachable — `./scripts/fetch-3cp.sh` caches it — but note
  that the 3CP repository's own `README.md` and `CONTRIBUTING.md` describe it as **private
  and pre-publication**. It is reachable here only because the authenticated `gh` account
  has access. Do not describe it as public. Use `docs/3CP-CONFORMANCE.md`.

---

## 7. Reviewer checklist

For a change to this repository, in order:

1. Does the commit message name the command that produced each empirical claim?
2. Is the configuration the measurement was taken under named?
3. Is there a test that has been observed to fail without the fix?
4. Does the topology measurement in §4.1 move in the direction claimed?
5. Does the conformance count match what the message claims about it?
6. If the change is a fix, is there a stated residual problem?
7. **If the change touches the consensus path, does it cite the 3CP section it implements —
   and does that quote match `SPEC-3CP-V2.md`, and the RFCs it in turn cites?**
8. **If the change is not described by the spec, is that stated, with the measured
   justification?**

Items 7 and 8 can be checked without trusting the author: open the cited section and read it.
If the citation does not hold, the change is not ready regardless of how well it is tested.

If (1), (3) or (7) cannot be answered, the change is not ready for review regardless of how
good the code is.