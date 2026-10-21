# Handover — Clarion QUEUE viewer for the CA Debugger

Written 2026-08-04. Hand this file to whoever (or whatever) picks the work up next.

## Read these first

| Document | What it is |
|---|---|
| `docs/clarion-queue-internals.md` | **The reference.** Complete reverse-engineered QUEUE layout: the read-only enumeration recipe, all six storage classes, RLE row compression, field decoding, SORT/ADD/DELETE semantics, threaded resolution. Includes an "Invariants for an implementation" section (4 rules) and "Known limitations" — read both before touching the walk. |
| `docs/queue-viewer-design.md` | The as-planned design record: why one shared decode core, why rows decode from a buffer, which alternatives were rejected. Future-tense and superseded on facts by THIS file — read it for rationale, not status. |
| `docs/TSWD-format.md` | Pre-existing: the debug-info format the debugger reads. |
| `_notes/debugger-ui-nosource.html` | A mockup of a future GUI (by another agent). Its queue parts are assessed under "For whoever builds the GUI" below. |

The internals doc is generated from the Clarion Assistant knowledge base
(`%APPDATA%\clarionassistant\memory.db`, `knowledge_entries` ids 56–76) by
`export_kb.py`. That DB is in **WAL mode** — if you copy it, take `.db`, `-shm` and `-wal`
together or you will silently lose recent entries.

## Goal

Let the debugger show **every row of a live QUEUE without disturbing the running program**.
Hard constraint: **reads only**. Calling runtime entry points such as `Cla$GETqueueptr` would
overwrite the debuggee's record buffer and bump its cursors and `numchanges`.

## Status

**The viewer is built, deployed, and verified — engine and UI.** Details in the UPDATE section below.
What remains is GUI *presentation* work (a grid / sub-window instead of tree rows), which is a separate
job; see "For whoever builds the GUI".

**Reverse engineering: complete and empirically verified.** Local (large record), global, QUEUE
parameter, reference/`NEW`, and THREADed queues; sorted and multi-order; compressed and raw rows;
multi-field records with `DIM` arrays; `DELETE`. All validated against a live process with
known-correct expected values. (The "local small / inline GROUP" class listed in the internals doc did
NOT reproduce — see open item 4.)

**Earlier shipped change (prior session):** `ClarionType.ResolveGroup(out hops)` added to
`ClarionDbg.Core`; the one-hop reference logic in `DebugEngine.Locals.cs` (`GroupTypeOf`) and
`Program.cs` (CLI `locals`) now follows N hops, and `NodeJson` performs one deref per hop. This fixed
reference queues (`&MyQType`) showing no fields.

Build the engine with **`dotnet build`** — ClarionDbg is SDK-style; the .NET Framework MSBuild fails
MSB4041. The **addin** needs a `ClarionRoot`: `dotnet build src\ClarionDebugger.Addin\ClarionDebugger.Addin.csproj /p:ClarionRoot=<ClarionRoot>`
(the default `C:\Clarion12` does not exist on this machine). `deploy-addin.ps1 -Kill` builds and deploys
both, closing the Clarion IDE.

## UPDATE 2026-08-04 — the viewer is built (engine AND UI verified)

Step 1 is done. `ClarionRle` (Core) ports the codec; `DebugEngine.ValueFormat.cs` holds one
source-agnostic decode core with `FormatValueAt` as its remote wrapper, so rows and locals render
through identical logic; `DebugEngine.Queue.cs` does control-block discovery, the node walk, and the
`queuerows` / `queuerowsname` commands. The host grows a `RECORDS (n)` child on queue nodes.

**Verified live against QTester** (`spikes/drive-queuerows.ps1` chains pause → stack → framelocals →
queuerows; `spikes/test-clarionrle.ps1` checks the codec against the byte-exact captures in the
internals doc — run that one under **32-bit** PowerShell or it silently passes):

| Case | Result |
|---|---|
| `MyQ`, 3 ADDs + SORT + 2 workers | 5 rows `aa0, aaa, abc, def, ghi` |
| `MyRefQ` (`&MyQType` + `NEW`) | 1 row `'123'`; record image at ctrl+0x10 as predicted |
| `MyLQ` declared, never used | `u32[ctrl+0x08] == 0` → 0 rows, no error |
| `MyLQ` after `DELETE` | **2** rows, not 3 — the stale slot does not duplicate |
| `MyLQ` compressed 360-byte rows | `TEST`+0, `NUMBERARR`+320, 123 / 456 byte-exact |
| QUEUE parameter (`internalQ`) | `ctrl = u32[ebp-4]`, 4 rows |
| `MySQ` (new, 36-byte record) | 2 rows, **uncompressed** node class, both fields |
| `GlobalQueue` (THREADed, via func-eval) | 1 row/thread; `'ab'` (cap 32), `'xy'` (len 20) |

`Qtester.clw` gained `MyQSmallType` (36 bytes, to reach the uncompressed node class) and
`GlobalSubQ &MyQType` inside `GlobalQueue`. **`GlobalQueue` is now 24 bytes, not 20** — a `&QUEUE`
reference is pointer-only, with no size word, unlike `&STRING`/`&CSTRING`. Earlier byte captures in the
internals doc predate that.

### Bugs found and fixed on the way

- **QUEUE parameters had an edit-write hazard.** TSWD reports a parameter as ONE reference hop, but the
  slot holds the caller's *control block*, so `NodeJson` landed on ctrl and rendered the 16-byte control
  header as the record's first member — carrying `va` + `typeCode`, i.e. an edit pencil that would write
  over the live queue's control block. Discovery now supplies the real record image.
- **A second concurrent func-eval could silently kill a breakpoint.** `_evalActive` was tested in one
  place and guarded in none, so a second eval (reachable: `ContinueDebugEvent` resumes every thread)
  overwrote the scalar `_evalSavedRearm` and the pending 0xCC re-plant was lost — the breakpoint stopped
  firing for the rest of the session while the UI still showed it set. `BeginThreadedEval` now refuses a
  second eval, and `AbortEval` unwinds a hijack that will never complete.
- **`moduledata` read THREADed data at the TEMPLATE, not the per-thread instance** — so a threaded
  global's reference members all showed `(null)` while the live instance had them populated, and its
  scalar fields were emitted with an editable `va` pointing at the template (an edit would write to the
  template, not the running thread's copy). Now resolved via a chain of `THR$GetInstance` evals. Full
  detail in open item 2 below, since it is also what unblocked the last of the verification.
- **The host grafted `RECORDS` onto `RECORDS`, infinitely** — found on first deploy, presenting as "the
  expand arrow is there but clicking does nothing". Detail in open item 1 below.

### Still open

1. ~~The UI is unverified.~~ **Verified live in the IDE, 2026-08-04.** `RECORDS (n)` expands, rows render
   with fields, the record buffer still shows alongside it, and — the check that mattered — no edit pencil
   appears on any row field (the only pencil present is on the pre-existing, legitimately-editable record
   buffer field). One bug surfaced on the first deploy and was fixed before the second: `recordsChild()`
   copies `queueCtrl` onto the synthetic `RECORDS (n)` node so `requestQueueRows` can read it back off `v`
   — but that same copy made the RECORDS node satisfy `isQueue` itself, and the "direct group" render
   branch grafts a RECORDS child onto any `isQueue` node UNCONDITIONALLY at render time (not gated by
   open/click). Result: RECORDS grafted onto RECORDS, forever, which threw before the click handler for
   that row (and any sibling rendered after it in the same pass) ever got wired — presenting as "the arrow
   is there but clicking does nothing." Fixed in `debugger.html` by excluding `queueRows`-carrying nodes
   from `isQueue` (`const isQueue = !v.queueRows && v.queueCtrl !== undefined && ...`).
2. ~~`moduledata` shows THREADed data at the TEMPLATE, not the per-thread instance.~~ **Fixed 2026-08-04.**
   `HandleModuleDataCommand` now resolves each THREADed symbol via a CHAIN of `THR$GetInstance` func-evals
   (one per symbol — `BeginThreadedEval` resolves exactly one template at a time), collecting into
   `_mdRows` across however many completions the chain needs before emitting a single `moduledata` event.
   `DrainModuleDataPending` opens its OWN thread handle on every call rather than threading one through
   from an earlier frame: the continuation runs from inside a LATER `OnEvalComplete`, so a handle captured
   from an earlier call could be stale by then. `OnEvalComplete` gained an `_evalActive` check after
   running the continuation, so a chained eval's hijack is left armed and `Run()` actually executes it,
   instead of the nested pause loop swallowing the resume. Verified live: `GlobalQueue`'s three reference
   members now resolve to the live instance instead of `(null)`, `GLOBALLONG`'s `va` is the instance
   address (confirmed against `loadBase + RVA`, not equal), exactly one `moduledata` event fires, and the
   session stays healthy afterward (`regs`/`watch` both work with identical restored register state).
3. **Handover step 2 is now fully settled.** With `moduledata` resolving the instance correctly, its
   member-path rendering of `GlobalSubQ` was re-checked and also resolves at 2 hops (`addr = ctrl+0x10`,
   `TEST = '123'`) — the same result the row renderer already gave. `GroupChildrenJson` → `NodeJson`'s
   member expansion is confirmed correct for a `&MyQType` field inside a group.
4. **Two paths remain unexercised.** The non-threaded *global* queue branch (static-data scan) has no test
   case — QTester's only global queue is THREADed. And the inline-group discovery branch (`code 0x08`,
   local IS the record image) never fires: in Clarion 11.1 every QUEUE local came back as `code=0x16`
   pointing at a HEAP record image, even the 36-byte one, so the "local small (inline GROUP)" storage class
   listed below may not exist in this compiler version.
5. RLE 16-/32-bit count forms are implemented and self-consistent with the disassembly, still never
   observed live (they need a single run > 12287 bytes).

## Decided AGAINST: showing Clarion's `POINTER(queue)` in the viewer

Recorded so nobody re-derives it. A future grid UI is sketched in
`_notes/debugger-ui-nosource.html`, and its mockup includes a `POINTER = 47` chip marking "the record
the program is on". **That chip is deliberately not being built**, on the developer's call, for a reason
that is about Clarion semantics rather than difficulty:

`POINTER(queue)` is updated on `ADD`, `GET` and `PUT`, **and only when they succeed**. So it reports
wherever the program's last successful operation happened to land — arbitrary, often stale state, not a
meaningful cursor for someone inspecting a queue. It is also relative to whichever sort order was current
at the time. Not worth the reverse engineering it would need: the 12-byte cursor at `collection+0x04`
(inside the 20-byte collection objects at `obj+0x11/+0x15/+0x19`) is still undecoded.

**Do not reach for `Cla$GETqueueptr` for this.** Despite the name, it is not Clarion's `POINTER()` — the
disassembly in `clarion-queue-internals.md` shows it *consuming* a 1-based index in EBX (`dec ebx`, then
`lea eax,[eax+ebx*4]` in the index→node worker), i.e. it implements `GET(queue, n)` and returns a memory
pointer to record n's data. A function reporting the current cursor would not take an index in. It is
also on the do-not-call list for a concrete reason: its node→buffer worker does `[coll+0x0C] = eax`,
writing into the collection's record-buffer field, which is exactly the debuggee disturbance this whole
design exists to avoid.

### The related feature that IS worth it — and is already free

The mockup's other queue control, a "go to record N" entry field, needs **no new work and no state
tracking**. Rows are NOT a linked list: the order object holds a FLAT ARRAY of node pointers
(`nodeArray = u32[order+0x05]`, `node = u32[nodeArray + i*4]`), which is why ClaRUN's own worker can do
`lea eax,[eax+ebx*4]`. Access is O(1) random-index, so:

- "go to record 47" is just the existing window parameter — `queuerows <reqId> <module> <typeRef> <ctrl> 46 1`
  (`from` is 0-based; row labels are 1-based). Jumping to record 50,000 costs the same as record 1.
- The 200-row window bounds JSON line size, NOT access cost.
- Sort order is self-correcting: every `queuerows` call re-reads `obj+0x79`, so index N always means the
  Nth record of the order the program currently sees. Nothing is cached host-side.

The one place a host DOES have to track something itself is narrower: keeping a *selected row* on the same
record across a re-sort or refetch. An index will not survive that — the NODE POINTER will, and is stable
row identity across orders (see the sort-orders entry in the internals doc).

## For whoever builds the GUI

The current UI is a `RECORDS (n)` child on the queue node, with rows as tree nodes. A
grid or sub-window is sketched in `_notes/debugger-ui-nosource.html`. That transition needs no change to
discovery, the RLE codec, the read-only guarantee or windowing — those carry over as-is. What you need
to know:

### The engine contract you build against

A queue variable node (from `framelocals`) carries three extra fields — that IS the discovery result,
computed while the frame pointer was in hand:

```
"queueCtrl":"0x...",  "records":N,  "queueTypeRef":T
```

Fetching rows needs no frame, so a detached window works fine:

```
queuerows     <reqId> <module> <typeRef> <ctrlHex> [from] [count]   -> locals/parameters/references
queuerowsname <reqId> <NAME> [from]                                -> module-scope (incl. THREADed)
  -> @JSON {"event":"queuerows","reqId":…,"total":N,"from":I,"compressed":bool,"items":[…]}
     or the same event with "error":"…" — it ALWAYS answers (see below)
```

`total` is the true record count regardless of the window, so it sizes a scrollbar. `from` is 0-based;
row labels are 1-based.

### What the mockup needs that does NOT exist yet

1. **Column order is arbitrary.** `ds.Fields` gets offset-sorted (`TswdDebugInfo.cs:935`) but
   `t.Members` never does (`:1149`) — members arrive in TSWD walk order. That is why rows render
   `NUMBERARR` before `TEST` (offsets +320, +0) and `GLOBALCSTRING`(+4) before `GLOBALLONG`(+0).
   Cosmetic in a tree; **wrong in a grid**, where `<thead>` order is the schema. One-line fix, but it
   also changes field order in the existing Locals panel — a visible change, so decide it deliberately.
2. **A column schema emitted once.** A grid needs `<thead>` before rows arrive. Today the schema is
   implicit in each row's nested `children`, repeated per row. Add a `columns` array to the event and a
   flat value-row shape. This is FORMATTING ONLY — `EmitQueueRows` / `RowFieldsJson` in
   `DebugEngine.Queue.cs`; the walk, decode and discovery are untouched. Prefer a second event shape
   over changing the existing one, so the tree keeps working.
3. **Two unanswered design questions.** What is a grid column for a `LONG,DIM(10)` — ten columns, or one
   summary cell? And for a reference field: `&CSTRING`/`&STRING` render as text fine, but
   `GlobalSubQ &MyQType` is a pointer to another queue, meaningless as a flat cell (an affordance that
   opens *its* grid, probably). The mockup's example has only flat scalars and so dodges both.
   `MyQLargeType` (STRING(320) + LONG,DIM(10)) already breaks the first assumption.

### Constraints no layout can remove

| Constraint | Consequence for the UI |
|---|---|
| Both commands are **paused-only** | The mockup's "virtualisert" scroll-to-fetch cannot run while the target is running. Freeze or grey the grid on resume. The reject path already replies with the `reqId` + an `error`, so you get a message, not a hung spinner — that was deliberate. |
| For a **local** queue, `ctrl` is a frame address | A window left open across steps must RE-DISCOVER via `framelocals`; never cache `ctrl`. Globals are durable — `queuerowsname` re-resolves every call. |
| THREADed queues need the func-eval | One eval at a time (enforced), and it briefly resumes the target. No post-mortem until the TEB route lands. |
| Only the **current** order is exposed | "View in order N" needs `obj+0x39` walking added — small, since orders are complete permutations over shared nodes. |
| Reference fields deref live | 200 rows × a `&STRING` column = 200 extra process reads per fetch, bounded by the window size. Not measured. |

Navigation ("go to record N") is already free and needs no host-side state — see the POINTER section
above for why, and for the one case where you *do* have to track something yourself.

## Next steps, highest value first

1. **GUI presentation work** — the grid / sub-window described above.
2. **Pure-read threaded resolution.** The formula is derived and structurally proven (see
   "Threaded data without the func-eval"). Needs one new capability: read a thread's TEB
   (`NtQueryInformationThread(ThreadBasicInformation)` → `TEB+0xE10 + tlsIndex*4` on x86).
   Implement it **alongside** the existing func-eval with fallback, not as a replacement: `watch` on
   threaded data currently resumes the target and emits a second `paused` event with
   `reason:"watch"` — the host filters on that LITERAL string to suppress the transient stop, so keep
   emitting it (`OnEvalComplete` has the full explanation).
3. **Wire global queues into the Variables panel.** `queuerowsname` works from the CLI, but nothing in
   the UI calls it: `HandleModuleDataCommand` does not run queue discovery, so a global queue shows its
   record buffer without a `RECORDS (n)` child. Now unblocked — the reason it was skipped (moduledata
   reading THREADed data at the template) is fixed. Detection for a threaded global has to happen
   lazily on expansion, since it needs a func-eval.
4. **Fill the two coverage gaps** in open items 4 above: a NON-threaded global queue in the test bed
   (nothing exercises the static-data scan), and a decision on whether the inline-group branch is
   reachable at all in this compiler version — if not, simplify it away rather than leave dead code.
5. **Optional / probably unnecessary:** decoding the runtime field descriptor at `u32[ctrl+0x04]`.
   Header is decoded, field records are not. Only worth doing if layout is ever needed with no TSWD
   at all. See "Appendix: partial / unfinished work".

## Test bed

`<QTesterDir>` (`Qtester.clw`, a local test program) exercises every storage class in one program: a local
queue, a large-record queue, a global THREADed queue with `&CSTRING` + `&STRING` fields, a
reference queue via `NEW`, queue parameters (by value and by `*`), two sort orders, and `DELETE`.
Expected results are in comments.

**Two additions were made 2026-08-04**, so byte captures recorded in the internals doc before that date
no longer match:
- `MyQSmallType` (`STRING(32)` + `LONG` = 36 bytes) with a `MySQ` local and two ADDs, to reach the
  **uncompressed** node class (`obj+0x2D == 0`) — nothing else in the test bed did.
- `GlobalSubQ &MyQType` appended to `GlobalQueue`, assigned `&= MyRefQ`, for the 2-hop group-member
  case. **`GlobalQueue` is now 24 bytes, not 20** — a `&QUEUE` reference is pointer-only with no size
  word, unlike `&STRING`/`&CSTRING` which carry one. `GlobalQueue` also moved BELOW the TYPE
  declarations, since a QUEUE member cannot name a type declared further down the file.

Useful breakpoints after those edits (re-resolve after any rebuild): **120** in `Test` has a local
queue, a reference queue, an unused large-record queue and a small-record queue all in scope at once,
plus the threaded global; **71** in `TestLargeQueue` is after the `DELETE`; **131** is inside
`QueueWorker` for the parameter case. `Test` runs on TWO threads, so line 120 hits twice.

**Build it with `/t:Rebuild`, never `/t:Build`.** The incremental path only relinks — it leaves a
stale EXE whose addresses do not match the debug info, so a planted INT3 lands mid-instruction and
the target dies with `0xC0000005`. Confirm the log contains `made Qtester.obj`. Re-resolve
line→RVA after every rebuild; addresses and frame offsets shift when locals are added.

## Tooling

`ClarionDbg.exe` CLI at `src\ClarionDbg.Cli\bin\Debug\net48\`:

- `locals <exe> [--proc NAME]`, `globals <exe> [--name X]`, `lines`, `resolve`, `symbols`,
  `typechain <exe> <typeRefHex>` (prints a resolved reference chain — how the 2-hop discovery was made)
- `break <exe> --bp MODULE:LINE|--rva 0xN --interactive --json`, then `regs`, `mem 0xADDR LEN`,
  `disasm 0xADDR COUNT`, `watch NAME`, `framelocals <reqId> <va> <ebp>`,
  `queuerows <reqId> <module> <typeRef> <ctrlHex> [from] [count]`,
  `queuerowsname <reqId> <NAME> [from]`, `expand <reqId> <module> <typeRef> <addrHex>`, `moduledata`

Gotchas that cost real time:

- Do **not** pass `--once` when you need follow-up commands — it kills the target at the first hit.
- Drive the CLI with **async output draining** (event-based), not blocking `ReadLine`; a blocking
  read deadlocks. Interleaving `mem` reads *before* a `watch` func-eval can desync the drain — do
  the func-eval first.
- Inline PowerShell commands fail above ~965 bytes in this environment: write a `.ps1` and invoke it.

- PowerShell variables are **case-insensitive**: a loop variable named `$line` in a script that also has
  an `[int]$Line` parameter silently assigns a string to the parameter, and every later `.StartsWith()`
  fails on an `Int32`. Cost real time in `drive-queuerows.ps1`.
- `ClarionDbg.Core.dll` is **x86**, so `Add-Type` on it from 64-bit PowerShell throws
  `BadImageFormatException` — and the failure can be QUIET: calls then return `$null` and any
  "expected null" negative test passes anyway. Run such scripts under
  `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`.
- Bash mangles Windows backslash paths (`C:\Clarion11` → `C:Clarion11`). Use the PowerShell tool for
  commands that pass such paths as arguments.

Two reusable scripts now live in `spikes/` (the rest of the reverse-engineering walkers were in a
session-scoped scratchpad and are gone):

- `spikes/drive-queuerows.ps1` — drives the whole chain against a live target: pause → stack →
  framelocals → queuerows for every queue found, with `-Global NAME` for module-scope queues, `-Follow`
  to expand reference fields inside a row **in the same run** (ASLR moves addresses between runs, so a
  two-run check compares stale addresses), and `-Raw` to echo every engine line.
- `spikes/test-clarionrle.ps1` — checks the RLE codec against the byte-exact captures in the internals
  doc. 32-bit PowerShell only, per the gotcha above.

## Method note

The expensive mistakes on this task were all the same shape: concluding a layout from one data
point, or from a code check read in isolation. What worked was reading the runtime's own
walkers/disassembly, and validating every claim against a value the program itself reported
(`RECORDS()`, a `GET()` result, a `watch` address). Two conclusions were wrong and are retracted in
the doc — the appendices are there on purpose, so nobody re-derives a dead end.
