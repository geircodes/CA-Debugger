# Clarion QUEUE viewer — design record (as planned, before implementation)

> **This is the AS-PLANNED design, kept for its reasoning — not a status report.**
>
> It was written before any code existed, so it is in the future tense throughout and its checkpoints
> read as intentions. The work is now **done and verified**. For what actually shipped, what was found
> along the way, and what is still open, read **`HANDOVER-queue-viewer.md`** — that file supersedes this
> one on every point of fact.
>
> Kept for the design reasoning it records: why one shared decode core instead of two renderers, why
> rows decode from a `byte[]` while reference fields still read live, why `count` is the only authority,
> and which alternatives were considered and rejected.
>
> Known places where reality differed from this plan:
> - The inline-group storage shape (`code 0x08`) never occurred. Every QUEUE local in Clarion 11.1 came
>   back as `code=0x16` pointing at a HEAP record image — even a 36-byte record — so that discovery
>   branch exists but is unexercised.
> - Three bugs this plan did not anticipate were found and fixed: a write hazard on QUEUE parameters, a
>   pre-existing concurrent-func-eval bug that silently disabled breakpoints, and an infinite recursion
>   in the host's `RECORDS` node graft (caught on first deploy).
> - `moduledata` reading THREADed data at the template was discovered during verification and fixed;
>   it is not mentioned below at all.

## Context

The CA Debugger can show a Clarion `QUEUE` local's **record buffer** — the single row the program
last wrote or `GET()`-ed — but not the queue's **stored rows**. Opening `MYQ` in the Variables panel
today derefs the slot and renders the record image's fields; the rows behind
`ctrl+0x08 → obj+0x79 → order+0x05 → node+0x04` are never touched. Nothing in `src/` walks a node
array and nothing decodes the RLE row format (verified by grep: no `payloadLen`, no `nodeArray`, no
order-object offsets anywhere in the codebase).

The reverse engineering to close that gap is **complete and empirically verified** — see
`docs/clarion-queue-internals.md` (the recipe, all six storage classes, the RLE codec, field decoding
with string references, SORT/ADD/DELETE semantics) and `docs/HANDOVER-queue-viewer.md` (status and
next steps). This plan implements handover step 1: **build the viewer**.

Hard constraint carried over from the reverse engineering: **reads only**. Calling runtime entry
points such as `Cla$GETqueueptr` would overwrite the debuggee's record buffer and bump its cursors and
`numchanges`. The one exception is the pre-existing `THR$GetInstance` func-eval, needed to resolve a
per-thread instance (see Phase C).

Outcome: expanding a queue in the Variables panel shows every row, with fields rendered exactly as
the Locals panel renders them.

## Decisions taken

| Decision | Choice |
|---|---|
| Row field renderer | **Shared decode core + thin wrappers.** Extract the type switch out of `FormatValueAt` into one source-agnostic core; `FormatValueAt(…, va)` becomes a wrapper over it, so all existing call sites compile and behave unchanged. Queue rows feed the same core from a `byte[]`. |
| UI surface | **In-tree**, under a synthetic `RECORDS (n)` child of the queue node. The queue node keeps its current record-buffer expansion; rows are siblings of it, one level down. |
| THREADed queues | **In scope**, reusing the existing `THR$GetInstance` func-eval (Phase C). Needed because QTester's `GlobalQueue` is the only test case with `&CSTRING` + `&STRING` fields. |

Rejected: a dedicated grid panel (much more new host UI); rendering rows as raw hex first (contradicts
"rows render identically to the Locals panel"); pinning the decoded buffer and reading it back through
`ReadProcessMemory` against our own process handle (works, but requires swapping the engine's
`_hProcess` per call — a trick that would mislead the next reader).

## Why a byte[] source is needed at all

A large-record queue stores each row RLE-compressed: `node+0x04` points at
`{ u32 payloadLen; byte payload[] }`, and the decompressed row exists only as a buffer on our side —
there is no address in the debuggee to point a VA-based renderer at. Small-record queues store rows
raw and *could* be read by VA, but routing both through one buffer path keeps a single code path for
rows.

**Reference fields are the exception and must still read the live process.** A `&CSTRING`/`&STRING`
field stores only a pointer plus its allocated-size word; the text lives in the debuggee heap. So the
decode core needs a primary source (buffer or VA) *and* the process reader for the 0x16 deref.

## Architecture

Three pieces, split by whether they need a live process:

**`ClarionDbg.Core` — pure, no process access**
- `ClarionRle.cs` (new): `Decode(byte[] payload, int payloadLen, int destSize) -> byte[]`. Direct port
  of the documented codec (ClaRUN RVA 0x193EB). `payloadLen == 0` means the payload is a raw memcpy.
  All five documented token examples were checked against the pseudocode and agree; the 16-/32-bit
  count forms are implemented but **unexercised** (they need a single run > 12287 bytes) — implement
  them, and don't claim them as verified.

**`ClarionDbg.Cli` — needs `_hProcess`**
- `DebugEngine.ValueFormat.cs` (new partial): the shared decode core, as a `private static` taking
  **two** readers — `primary` (buffer or VA) and `process` (always `ReadBlock`, for the 0x16 deref).
  Keeping it a `DebugEngine` partial in Cli avoids all visibility churn: `DebugEngine` is
  `internal sealed partial`, `ClarionTypeLabel` stays `internal static` for `Json.cs:335`, and
  `CodeForType` stays `private static`. Moving the core to Core is possible via the same injected
  readers, but costs making `ClarionTypeLabel` public and relocating `Cp1252`/`FormatBcd`/`DecimalDigits`.
- `DebugEngine.Queue.cs` (new partial): control-block discovery, the node-array walk, row decode,
  and the `queuerows` handler.
- `DebugEngine.Locals.cs` (edit): `FormatValueAt` becomes the remote wrapper; emit the `RECORDS (n)` node.

**Host (`debugger.html`)**
- One new lazy node kind alongside the existing `ref:true` kind.

### The refactor's sharp edges

A call-site audit found seven `FormatValueAt` callers, all in `ClarionDbg.Cli` — the addin consumes only
rendered JSON. The thin wrapper is safe for all seven **provided it is a literal delegation**: same `len`
table (`Locals.cs:527-535`), same `ReadBlock`, same `got` handling. What must not drift:

- **Buffer-source `got` semantics must mirror `ReadBlock`.** `ReadBlock` returns bytes actually copied
  (0 on failure, never throws, and *can* return a partial count). So the buffer reader returns
  `clamp(len, bufferLength - offset)`, `0` for an out-of-range offset (which yields `"<unreadable>"`,
  the correct analogue of a bad VA), and never throws — an exception here would escape into
  `HandleFrameLocalsCommand` and into hit-time breakpoint evaluation.
- **`got` is not consulted for 0x11/0x12/0x13/0x25** — those `BitConverter` from `buf[0]` regardless, so
  a short read silently renders a zero-filled tail as a valid number. Pre-existing, but queue rows will
  meet it more often than stack locals do.
- **`FormatBcd` indexes `b[size-1]`** (`Locals.cs:614`), so a clamped short read yields a silently wrong
  sign rather than a visible truncation. Have the buffer reader return `0` when it cannot satisfy the
  full length for 0x23/0x24, so the row shows `"<unreadable>"` instead of a plausible wrong number.
- **Do not "fix" the `size == 0` string path.** The comment at `Locals.cs:440-444` claims
  `FormatValueAt` falls back to a bounded 256-byte read when `size <= 0`. It does not — there is no 256
  anywhere; case 0x18 with `size == 0` renders exactly **one** character (`Locals.cs:530`). Implementing
  the documented-but-false behaviour during the refactor would change every `&STRING(?)`-shaped row.
- **Sentinel strings are load-bearing.** Two `val == "(null)"` comparisons steer `&STRING` vs
  `&STRING(?)` (`Locals.cs:252`, `Eval.cs:138`), and `NodeJson` has a second, independent `"(null)"`
  producer at `Locals.cs:228` — keep the spellings identical. Breakpoint conditions also text-compare
  against `"<unreadable>"` (`BpAdvanced.cs:212/216`).
- **`NodeJson`'s deref loop needs the same split** (`Locals.cs:223-225`): for a buffer-sourced row the
  *first* hop reads its u32 from the buffer and only later hops go remote. Simplest is for the queue
  viewer to pre-resolve the pointer before calling `NodeJson`.

### ⚠ The one risk that can write to the debuggee

`NodeJson` emits edit metadata — `"va"` plus `typeCode`/`size`/`places` — for any `IsEditableCode` leaf
(`Locals.cs:257-261`). The UI keys the edit pencil purely on the presence of `va`
(`debugger.html:902`), and `HandleSetValCommand` does **no re-resolution** — it writes straight to the
supplied address (`VarEdit.cs:26-48`).

A queue row has no target address. A buffer-sourced `NodeJson` that forgets to suppress that quartet
would show a working-looking pencil that writes to a bogus address in the live process — turning a
read-only viewer into a memory corrupter. **Row field nodes must never carry `va`.** This is the
highest-severity item in the refactor and deserves an explicit check during Phase B verification: open a
row, confirm no pencil appears on any field.

## The walk (from the verified recipe)

```
recordSize = u32[ctrl + 0x0C]        // authoritative — never sum TSWD member sizes
obj        = u32[ctrl + 0x08]        // NULL => queue never used, 0 records
order      = u32[obj  + 0x79]        // CURRENT sort order
count      = u32[order + 0x01]       // == RECORDS(q)
nodeArray  = u32[order + 0x05]
for i in 0..count-1:
    node    = u32[nodeArray + i*4]
    dataPtr = u32[node + 0x04]       // raw row, OR {u32 len; payload} when compressed
compressed = u32[obj + 0x2D] != 0    // test != 0, never == 2
```

Four invariants from the doc that the implementation must honour (each is an easy, expensive bug):

1. **`count` is the only authority.** `DELETE` compacts the array but leaves a live-looking stale
   pointer in the vacated slot — scanning to NULL renders the last row twice.
2. **Many fields are unaligned** (`order+0x01`, `order+0x05`, `obj+0x2D`, `obj+0x79` are all
   ≡ 1 mod 4). Read the structures into a byte[] and use `BitConverter` at byte offsets; do not build
   aligned dword reads.
3. **The control-block offset is not a constant** — it differs per storage class. Always signature-match.
4. **`recordSize` comes from `u32[ctrl+0x0C]`**, never from summing TSWD field sizes (a string
   reference field occupies 8 bytes while TSWD reports 4).

## Control-block discovery

No TSWD symbol exists for the 16-byte control block, so it is found by signature match — which
doubles as **queue detection**: a `&GROUP` that is not a queue simply has no matching block.

Require **both** conditions (matching size alone produced a false positive 140 bytes away during the
reverse engineering):

```
u32[cand + 0x00] == recordImageVa   &&   u32[cand + 0x0C] == expectedRecordSize
```

`expectedRecordSize` is `ClarionType.Size` of the resolved group — read straight from the type record
(`TswdDebugInfo.cs:1131`), the compiler's own declared total, **not** a member sum, so rule 4 holds.

Per storage class, following the doc's consolidated rule:

| Declaration | How to reach `ctrl` |
|---|---|
| `MyQ QUEUE(MyQType)` (small) | slot holds the record image → scan the frame |
| large record | slot holds a heap record image → scan the frame |
| QUEUE parameter | `ctrl = u32[ebp-4]` directly — disambiguate by `u32[p+0x0C] == recordSize && u32[p+0x08] != 0` |
| `&MyQType` + `NEW` | the slot **is** `ctrl`; self-check `u32[ctrl+0x00] == ctrl + 0x10` |
| global | scan static data around the record image (was 0x4C *below* it) |
| threaded | scan around the resolved per-thread instance (was instance − 0x18) |

Scan windows: read one block and scan it locally, step 4 bytes. Frame: from
`ebp − (max |FrameOff| + 64)` up to `ebp`. Static/threaded: `[image − 0x200, image + 0x40)`.

**Discovery happens where EBP is in hand** — in the `framelocals` path — so the emitted `RECORDS (n)`
node already carries `ctrl` and the live count. The row-fetch command is then stateless: it needs only
`ctrl` + `typeRef`, not a frame.

## Threaded queues: the func-eval seam (Phase C)

Resolving a per-thread instance means reusing the `THR$GetInstance` func-eval — the engine hijacks the
paused thread (EAX = template VA, EBX = .cwtls base, EIP = the helper, a magic return address pushed),
lets the target run the call, catches the AV at `EVAL_TRAP_VA` (`DebugEngine.cs:336-341`), and
`OnEvalComplete` restores the context and re-enters `PausedWait`.

Two reassurances from tracing it: `PausedWait` at `Eval.cs:120` is in **tail position** and `Run()` is
the only event pump, so eval round trips fully unwind — pause loops do **not** accumulate stack. And
queued commands are preserved across the round trip, not dropped, which is why batched threaded watches
already work today.

**The `_eval*` state holds one *watch* payload**, so it must generalise. Use a continuation delegate,
not a discriminator — it is a net *reduction* in fields:

- Delete `_evalName`, `_evalSize`, `_evalTypeCode`, `_evalTemplateVa`, and `_evalTypeName`
  (`DebugEngine.cs:173-177`). `_evalTypeName` is already **dead** — assigned at `Eval.cs:74`, never read.
- Add `private Action<uint> _evalDone;` and `private string _evalWhat;` (the latter for the failure
  message). `HandleWatchCommand` sets a closure that is a straight lift of `Eval.cs:115`.
- Keep the *mechanism* fields singular — `_evalActive`, `_evalTid`, `_evalSavedCtx`, `_evalHadRearm`,
  `_evalSavedRearm`. There is one trap VA, one hijacked thread, one `_evalActive` test. A parallel
  `_queueEval*` set would institutionalise the bug below instead of fixing it.
- Extract the arming code (`Eval.cs:55-96`) into `BeginThreadedEval(..., string what, Action<uint> done)`
  so all guards live in one place, with `HandleWatchCommand` as its first caller.

### ⚠ A pre-existing bug this work would start triggering

`_evalActive` is tested in exactly **one** place and guarded in none. `ContinueDebugEvent` resumes the
whole process, so during the eval window another thread can hit a breakpoint, enter `PausedWait`, and
start a second eval — which unconditionally overwrites `_evalSavedCtx`, `_evalTid`, and the **scalar**
`_evalSavedRearm`.

The breakpoint consequence is the nasty one. `Eval.cs:82-83` removes the pending 0xCC re-plant so the
eval does not consume its single-step, and `Eval.cs:112` restores it. A second eval's
`_rearm.TryGetValue` returns false (entry already removed), so `_evalHadRearm` goes false and the first
eval's saved re-plant is **lost**: the 0xCC is never re-planted while `_armed[va]` still claims it is —
**the user's breakpoint silently stops firing for the rest of the session** while the pane still shows it
set. Because `_rearm` is per-tid but `_evalSavedRearm` is a scalar, a concurrent eval on a *different*
thread is equally destructive.

Fix first, in `BeginThreadedEval`: `if (_evalActive) { EmitError(what + ": eval already in flight"); return false; }`.
Roughly two lines, and it closes both the clobber and the re-plant loss. This is the highest-value change
in the whole plan and it is worth landing on its own merits, independent of the viewer.

Also add an `AbortEval(why)` — `_evalActive` is cleared in exactly one place (`Eval.cs:104`) and nothing
clears it on failure, so a fault at an unexpected address, a hijacked thread blocked in a kernel wait
(reachable: `PickPauseThread` can select a GUI thread sitting in `GetMessage`), or an
`EXIT_THREAD_DEBUG_EVENT` for `_evalTid` all strand it `true` with the thread still hijacked. Recovery is
safe even if the call never ran, since the hijack is pure `SetThreadContext`. A stranded `watch` loses one
pane row; a stranded `queuerows` leaves the viewer with a forever-pending `reqId`.

One aliasing note while in there: `Eval.cs:120` passes `ref _evalSavedCtx` as `PausedWait`'s `ref ctx`, so
inside that nested loop the parameter and the field are the **same storage**. Benign today only because
`Eval.cs:78` assigns a fresh clone. Copy to a local before the call, or comment it.

### Keep the pause reason string `"watch"`

`OnEvalComplete` re-enters `PausedWait` with reason `"watch"`, and the host suppresses that transient
pause by matching the string **literally** — `ClarionDebuggerWebView.cs:795` and
`ClarionDebuggerService.cs:633`. Passing `"queuerows"` instead would make the host treat an eval round
trip as a genuine stop: the editor jumps and steals focus, panes refresh, run-to-cursor one-shots get
torn down, and every watched name is re-issued — some of them threaded, i.e. **more evals launched from
inside a completion path**.

So Phase C keeps the literal `"watch"` reason regardless of consumer. The CLI's own log line
(`DebugEngine.cs:484`) reads slightly oddly; that is the whole cost. Renaming it to `"eval"` and teaching
both host checks to accept either is a clean follow-up, but it needs an addin rebuild and redeploy — and
the addin ships its own copy of `debugger.html` under `bin/Debug/Terminal/`, so a stale deploy would
desync host and engine.

## Command and event shape

Modelled on the existing `expand` / `framelocals` request-response pair (`reqId`-correlated):

```
queuerows <reqId> <module> <typeRef> <ctrlHex> [from] [count]
  -> @JSON {"event":"queuerows","reqId":…,"total":n,"from":i,"items":[ …row nodes… ]}
```

Each row node is a group-shaped node named `[i]` whose children are the decoded fields — the same
node shape `GroupChildrenJson` already produces, so the host renders rows with no new row-level UI.

Non-threaded queues walk and emit synchronously, then `break` — exactly like `expand`. Threaded queues
return the `bool` that leaves the pause loop, like `watch` does at `DebugEngine.cs:581-583`.

**`queuerows` must also be added to the running-mode reject list** (`DebugEngine.cs:643-648`). If
`WaitForDebugEvent` times out, `DrainCommandsWhileRunning` consumes queued commands with the running verb
set; an unlisted verb is reported as "unknown command" and its `reqId` reply never arrives. The host's
callback maps (`_expandCbs` / `_flCbs`, `debugger.html:950-963`) have **no timeout**, so that entry leaks
forever and the row just spins. Better still: have that arm emit a `queuerows` event carrying the `reqId`
and an `error` field, so the pending callback always resolves. Apply the same reasoning to the
`_evalActive` guard's rejection path.

Paging: default window of 200 rows, mirroring the bounded-children approach `ArrayChildrenJson`
already uses (cap 1000) so a 100k-row browse queue cannot blow up the DOM or one JSON line. `total`
is always the true `count`, so the host can show "n more".

Order: the viewer walks the **current** order (`obj+0x79`). Orders are independent index views over
shared nodes and every order is a complete permutation, so this is a complete row set, not a subset.
Walking `[obj+0x39 + k*4]` for k < `[obj+0x7D]` to offer "view in any existing order" is a clean later
extension; note `[obj+0x39]` is MRU-ordered, so slot index does not imply creation order.

## Phases

**Phase A — shared decode core + RLE.** Refactor `FormatValueAt` per the decision above; add
`ClarionRle`. No behaviour change anywhere. Checkpoint: `dotnet build` clean, and the Variables panel
still renders locals/watch/globals identically (the refactor is mechanical, so any diff is a bug).

**Phase B — non-threaded queues, end to end.** Control-block discovery for local small, local large,
parameter, and reference/`NEW`; the walk; row decode; `queuerows`; the `RECORDS (n)` node; the host's
new lazy kind. Checkpoint: QTester's `Test` and `TestLargeQueue` procedures — five storage-class cases
including the compressed 360-byte rows and the `DELETE` stale-pointer trap.

**Phase C — global + threaded.** In order: (1) the `_evalActive` re-entry guard and `AbortEval` — land
these first, with a threaded `watch` re-verified, since they fix a live breakpoint bug and are worth
having regardless; (2) the continuation-delegate refactor of the `_eval*` state plus `BeginThreadedEval`,
again re-verified against a threaded `watch` before adding a second consumer; (3) static-data
control-block discovery; (4) `queuerows` on the threaded path. Checkpoint: `GlobalQueue`, which exercises
`&CSTRING` + `&STRING` reference-field decoding.

Phase C also folds in **handover step 2**, since it already drives `GlobalQueue` live: add
`GlobalSubQ &MyQType` to `GlobalQueue` in `Qtester.clw`, assign `&= MyRefQ`, rebuild with `/t:Rebuild`,
and check the `framelocals` output. This settles the last unverified assumption in the internals doc —
that a `&MyQType` field *inside* a group expands correctly at 2 hops (currently reasoned from the call
chain through `NodeJson`, never tested live). Expect the member row to carry `hops=2` and an `addr` two
derefs from the slot. If it does not, `GroupChildrenJson`'s member path needs the same treatment
`ResolveGroup` gave the top-level path — which would be a genuine finding, not a blocker for the viewer.

Phase B is the natural stopping point if the work is interrupted — it covers five of six storage
classes with a fully synchronous command.

## Verification

Test bed: `<QTesterDir>` (`Qtester.clw`, a local test program), which exercises every storage class in one
program with expected results in comments.

**Build the test bed with `/t:Rebuild`, never `/t:Build`.** The incremental path only relinks, leaving
a stale EXE whose addresses do not match the debug info — a planted INT3 then lands mid-instruction
and the target dies with `0xC0000005`. Confirm the log contains `made Qtester.obj`, and re-resolve
line→RVA after every rebuild (addresses and frame offsets shift when locals change).

Build the debugger with **`dotnet build`** — ClarionDbg is SDK-style; the .NET Framework MSBuild fails
MSB4041. (The Clarion solution still needs that Framework MSBuild — the two build systems differ here.)

Drive it via the CLI at `src\ClarionDbg.Cli\bin\Debug\net48\`:

```
ClarionDbg break <exe> --bp Qtester:101 --interactive --json
  then: stack ; framelocals <reqId> <va> <ebp> ; queuerows <reqId> <module> <typeRef> <ctrl>
```

Expected values to assert against, from the doc and the .clw comments. A breakpoint pauses *before*
its line runs, so these lines are chosen to sit after the operation under test:

| Case | Break at | Expect |
|---|---|---|
| `MyQ` — 3 ADDs + SORT + both workers | 101 (`GET(MyQ,1)`) | 5 rows: `aa0, aaa, abc, def, ghi` (current ascending order) |
| `MyRefQ` (`&MyQType` + `NEW`) | 101 | 1 row, `TEST = '123'`; self-check `u32[ctrl+0x00] == ctrl+0x10` |
| `MyLQ` **declared but never used** in `Test` | 101 | `u32[ctrl+0x08] == 0` → **0 rows**, no error. Exercises the never-added path. |
| `GlobalQueue` (threaded) | 101 | 1 row per thread; `GlobalCstring = 'ab'` (capacity word 32), `GlobalString = 'xy'` (word 20) |
| `MyLQ` after `DELETE` in `TestLargeQueue` | **62** (`RETURN`), not 61 | **2** rows, not 3 — the stale slot must not duplicate the last row |
| `MyLQ` fields (compressed 360-byte rows) | 62 | `TEST` at +0, `NUMBERARR[1..10]` at +320; row 1 = `'1234567890qwertyyuiop'`, 123, …, 456 |
| parameter queue (`internalQ`) | 112 (`CLEAR`) in `QueueWorker` | `ctrl = u32[ebp-4]`; 4 rows. Same in `QueuePtrWorker` at 120 → 5 rows. |

`Test` is a good single-breakpoint target: at line 101 it has a small local queue, a reference queue, an
unused large-record queue, and a threaded global all in scope at once.

`Test` also runs on **two threads** (`th# = START(Test); RESUME(th#); Test()`), so a breakpoint at 101
hits twice and either thread may arrive first. That is the point for the threaded case — each thread has
its own `GlobalQueue` instance, control block, node and row — but it means the per-thread `ctrl` must be
re-resolved on each hit rather than cached across hits.

Note `MyLQ` rows 2 and 3 carry `NumberArr[10] = 456` even though only row 1 assigned it — Clarion does
not clear the record buffer between ADDs. That is faithful data, not a decode bug; display it as stored.

CLI gotchas that cost real time before: do **not** pass `--once` when follow-up commands are needed
(it kills the target at the first hit); drive the CLI with async output draining, not blocking
`ReadLine`; and do the func-eval before interleaved `mem` reads, which can otherwise desync the drain.
Inline PowerShell commands fail above ~965 bytes here — write a `.ps1` and invoke it.

## Free wins the buffer path unlocks (optional, after Phase B)

The same audit found existing code that reads one field at a time by VA where a single bulk read would
do. Once the buffer source exists these become small changes — worth doing, but **not** before the
viewer is verified, so a regression can't be confused with a queue bug:

- `GroupChildrenJson` (`Locals.cs:270-338`) does one process read per member, plus a 4-byte peek per
  unsized `&STRING`. `g.Size` is known, so it could read the group image once and format members from
  it — exactly the queue-row shape, and the natural first consumer.
- `HandleExpandCommand` (`Locals.cs:381-399`) has the same pattern: every expand click costs N+ syscalls.
- `ArrayChildrenJson` (`Locals.cs:345-376`) reads up to 1000 elements individually;
  `Length * ElemSize` is one bulk read.
- `EmitWatchValue` (`Eval.cs:129-141`) is a literal double read — line 134 reads the bytes for the hex
  dump, then line 137 re-reads the same address through `FormatValueAt`. Note line 134 uses unpaged
  `ReadProcessMemory` (returns 0 at a page boundary) while `ReadBlock` returns a partial, so switching
  the formatter to that buffer without also upgrading line 134 changes page-boundary behaviour from
  "partial value" to `"<unreadable>"`.

Leave `BpAdvanced.cs:210/216` alone — it runs at hit time, where correctness beats syscall count.

## Explicitly out of scope

**The pure-read TEB route** (handover step 3) stays out. It is all-new P/Invoke —
`NativeMethods.cs` has no `NtQueryInformationThread`, no `THREAD_BASIC_INFORMATION`, no ntdll import at
all — and the formula needs `tlsIndex = u32[clarunBase + 0x13F12C]`, a hardcoded ClaRUN RVA measured on
one build with no symbolic way to validate it. The internals doc rates the whole route
`confidence: likely` and the handover says to implement it **alongside** the func-eval with fallback,
never as a replacement. So `queuerows` must not be its first consumer. (One thing already lines up for
later: `OpenThreadForContext` requests `THREAD_QUERY_INFORMATION`, which is exactly what the call needs.)

That route is what unlocks an all-threads view and post-mortem inspection, so it is the natural next
project — just not a prerequisite for shipping the viewer.

Also deferred: multi-order views (`[obj+0x39]`), and the runtime field descriptor at `ctrl+0x04` (which
the internals doc establishes is unnecessary, since TSWD carries reference-queue layout after all).

## Open risks

- The ≥2-hop deref rule is verified for exactly one construct (`&MyQType`). A construct encoding 2
  hops that is only one pointer at runtime would take a bogus second deref; the `ptr != 0` guard
  catches nulls, not garbage.
- RLE 16-/32-bit count forms are from disassembly, not observation.
- Rows hold shallow pointer copies, so a reference field can dangle if the program reassigned or
  disposed the target. Treat unreadable targets as dangling rather than assuming the string is live.
- Control-block discovery by signature scan doubles as queue *detection*. A non-queue `&GROUP` whose
  nearby memory happens to satisfy both conditions would be misread as a queue. Both-conditions matching
  makes this unlikely (size alone already produced a false positive during the reverse engineering), and
  the `NEW` case has the extra `ctrl+0x00 == ctrl+0x10` self-check — but a bogus `count` from a false
  match should be sanity-bounded before it drives a loop.
