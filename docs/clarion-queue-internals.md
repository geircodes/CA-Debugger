# Clarion QUEUE internals

Reverse-engineered layout of Clarion `QUEUE` internals in `ClaRUN.dll`, so the CA Debugger can
display **every row of a live queue without disturbing the running program**.

## Scope and provenance

- Verified empirically against a local test program, `Qtester.clw` (Clarion **11.1.13855**), driven with
  `ClarionDbg.exe break --rva N --interactive --json` plus its `regs` / `mem` / `disasm` commands.
- All `ClaRUN.dll` addresses below are **RVAs**, which are stable across runs. Virtual addresses shift
  with ASLR, so resolve them live (read the load base from the debugger's `module-loaded` event).
- Every claim here was checked against a running process. Where a conclusion was later found wrong it
  was corrected rather than deleted -- see [Appendix: superseded findings](#appendix-superseded-findings).
- `[[double-bracket]]` names are knowledge-base cross-links; the corresponding material is in this
  document under the section headings.

## Invariants for an implementation

Four rules that are easy to get wrong and expensive to debug later:

1. **`count` is the only authority.** Read exactly `count` entries from the node array. `DELETE`
   compacts the array but leaves a live-looking stale pointer in the vacated slot, so scanning until
   NULL will duplicate a row. The array is also over-allocated, so its size proves nothing.
2. **Many fields are unaligned.** `order+0x01`, `order+0x05`, `obj+0x11`, `obj+0x79` are all at
   offsets `= 1 (mod 4)`. Use byte-wise reads; aligned dword reads silently return shifted garbage.
3. **The control-block offset is not a constant.** It differs per storage class (threaded:
   instance-0x18; global: image-0x4C; local: on the frame). Always signature-match on **both**
   `u32[ctrl+0x00] == recordImage` **and** `u32[ctrl+0x0C] == recordSize`; matching on size alone
   produced a false positive 140 bytes away during testing.
4. **`recordSize` comes from `u32[ctrl+0x0C]`.** Never sum TSWD field sizes: each string/CSTRING
   reference field occupies 8 bytes (pointer + size word) while TSWD reports it as 4. Getting this
   wrong shifts every later field *and* breaks the signature match in rule 3.

## Known limitations

- **THREADed queues still use a func-eval in the shipped code.** Resolving a per-thread instance
  currently calls `THR$GetInstance` in the target — the one place the otherwise-pure-read approach
  executes code. It cannot run on a frozen or post-mortem process, and because it returns the
  *calling* thread's instance, an all-threads view would need one eval per thread (hijacking each).
  A pure-read replacement **has been derived and structurally proven** (see
  [Threaded data without the func-eval](#threaded-data-without-the-func-eval)); it needs one new
  capability — reading a thread's TEB — which the debugger does not have yet.
- **Post-mortem viability.** Once the pure-read route is implemented, a dump works *if it captured
  enough memory*: queue rows always live on the heap (nodes + row data in a small-object pool), so a
  stack-only minidump is insufficient for ANY queue, threaded or not. Threaded additionally needs
  TEBs. A full-memory dump covers both.
- **The globals path does not follow references.** `DataSymbol` decoding tests `Kind == Group` only,
  so a module-level `&MyQType` will not expand in the `globals` dump. Unaffected by the
  `ResolveGroup` fix — a separate code path.
- **The >=2 reference-hop deref rule is verified for exactly one construct** (`&MyQType`:
  slot -> control block -> record image). Sound wherever the TSWD chain mirrors real pointer
  indirection, unverified beyond that.
- **RLE 16-/32-bit count forms are untested.** Only the 14-bit form was exercised (runs up to 12287
  bytes). The wider forms are read from disassembly, not observed.
- **Only `&CSTRING` and `&STRING` reference fields were measured.** Other reference kinds (`ANY`,
  `&GROUP`) are unverified.


## Contents

- [Read-only enumeration recipe](#read-only-enumeration-recipe)
- [The hidden control block](#the-hidden-control-block)
- [Locating the control block, per storage class](#locating-the-control-block-per-storage-class)
- [Row storage and the RLE codec](#row-storage-and-the-rle-codec)
- [Field decoding, including string references](#field-decoding-including-string-references)
- [Operation semantics: orders, ADD, DELETE](#operation-semantics-orders-add-delete)
- [ClaRUN.dll internals reference](#clarundll-internals-reference)
- [Field layout for reference queues (use TSWD, not the runtime descriptor)](#field-layout-for-reference-queues-use-tswd-not-the-runtime-descriptor)
- [Threaded data without the func-eval](#threaded-data-without-the-func-eval)
- [Build and tooling notes](#build-and-tooling-notes)
- [Appendix: partial / unfinished work](#appendix-partial--unfinished-work)
- [Appendix: superseded findings](#appendix-superseded-findings)

---

## Read-only enumeration recipe

The whole point of the exercise: how to list every row of a live QUEUE using only memory reads, so the debuggee's record buffer, cursors and change counter are untouched.

### SOLVED: full read-only recipe to enumerate all Clarion QUEUE records from outside the process

*pattern | confidence: confirmed | knowledge-base entry 60*

Verified end-to-end against Qtester.exe (3 records 'abc','def','ghi', STRING(32)). Supersedes the "not found" conclusions in the earlier record-storage entries — the rows WERE reachable, just via the order object's pointer array which earlier memory sweeps never covered.

Chain (all plain memory reads — NO calls into ClaRUN, so the debuggee's record buffer is never disturbed):
```
recordSize = u32[ctrl + 0x0C]      // 16-byte hidden control block
obj        = u32[ctrl + 0x08]      // queue object; NULL => queue never used, 0 records
order      = u32[obj  + 0x79]      // CURRENT sort order object
count      = u32[order + 0x01]     // identical to RECORDS(q)
nodeArray  = u32[order + 0x05]     // flat array of 4-byte node pointers
for i in 0..count-1:
    node    = u32[nodeArray + i*4] // 8-byte node
    dataPtr = u32[node + 0x04]     // -> recordSize bytes of raw record data
```

Derived from ClaRUN.dll disassembly (RVAs stable; VAs shift with ASLR):
- Cla$RECORDSqueue (export RVA 0x1960C) -> worker RVA 0x1A15C is literally: `mov eax,[eax+79h] / mov eax,[eax+1] / ret`
- Cla$GETqueueptr (export RVA 0x198AC) -> `eax=[edx+79h]; dec ebx; call 0x1AAB0` (index->node) then `eax=[edx+11h]; call 0x1B9FC` (node->buffer)
- index->node worker RVA 0x1AAB0: `edx=[order+1](count); eax=[order+5]; lea eax,[eax+ebx*4]; mov eax,[eax]`
- node->buffer worker RVA 0x1B9FC: in mode `[coll+0x10]==0` it does `eax=[node+4]; [coll+0x0C]=eax` — i.e. node+0x04 IS the record data pointer

CRITICAL GOTCHAS:
1. **Fields are UNALIGNED.** order+0x01, order+0x05, obj+0x11, obj+0x79 etc. are all ≡1 mod 4 (1-byte tag then 4-byte field). Use byte-wise/unaligned reads — aligned dword reads silently return shifted garbage (this cost real time in the investigation).
2. Enumeration order follows the CURRENT order object at [obj+0x79]. For a queue with sort keys, [obj+0x39] is an array of order objects and [obj+0x7D] is how many; pick the right one for a specific SORT order.
3. Row data lives in a small-object pool (0x08xxxxxx-style region), NOT near the queue object (0x01xxxxxx) — never try to find rows by scanning around the object.

Other confirmed queue-object fields: +0x00 vtable (RVA 0x144924), +0x11/+0x15/+0x19 three 20-byte collection objects, +0x1D numchanges (seeded from Cla$CLOCK * 0x189635B, ++ on each ADD), +0x21 recordSize, +0x25 numchanges-at-init minus 1, +0x29 record-image ptr, +0x2D flag (2 when recordSize >= 0x80), +0x7D order count, +0x82 bool. Collection (20 bytes): +0x00 owner obj, +0x04 12-byte cursor, +0x0C record buffer, +0x10 mode (0 = shares the program's record image, 2 = private malloc'd buffer).

**How to apply (locating the hidden control block):** it has no TSWD symbol, so don't look for one. TSWD DOES report the record-image local (e.g. MYQ). Robust trick: the control block is a 16-byte frame slot where u32[+0x00] == the TSWD-reported record-image address AND u32[+0x0C] == its size. Signature-match the frame for that instead of hardcoding a frame offset — the offset moves when other locals are added (it was ebp-0x10 with MYQ at ebp-52, but the layout shifts). See [[clarun-queue-hidden-control-block]] and [[clarun-queue-add-free-disasm]].

`tags: queue,clarun,ca-debugger,record-storage,enumeration,solved,unaligned`

---

## The hidden control block

Every QUEUE is reached through a 16-byte control block that carries no debug symbol. Understanding it is a prerequisite for everything else.

### QUEUE local = hidden 16-byte control block, NOT the record-image group; TSWD deliberately omits it

*gotcha | confidence: confirmed | knowledge-base entry 56*

When a Clarion QUEUE is declared as a local (e.g. `MyQ QUEUE(MyQType) END`), the compiler emits TWO stack objects, not one:
1. The record-image group (e.g. MyQType, 32 bytes for a STRING(32) field) — this is what TSWD's `locals`/GROUP decode reports, and what `MyQ.Test = 'abc'` writes into.
2. A SEPARATE, undocumented 16-byte "queue control block" a few bytes away (in a minimal Test proc, record image at ebp-0x30, control block at ebp-0x10). ADD(queue)/GET/etc. compile to a call passing a pointer to THIS control block, not the record image.

TswdDebugInfo.ReadLocals() (ClarionDbg.Core/TswdDebugInfo.cs ~line 972) explicitly filters out locals whose decorated name starts with '$' or ends with '\'' — comment says this is for "file RELATE/ACCESS managers, record buffers". The QUEUE control block for a plain in-memory queue apparently isn't even given a decorated symbol at all (scanname found no second candidate for MYQ) — it's compiler-synthesized with no TSWD symbol, so it's invisible to static analysis and must be found dynamically (disassemble the ADD/GET call site to see what pointer gets passed).

Confirmed 16-byte control-block layout (offsets from the passed pointer):
- +0x00: pointer to the record-image local (the visible GROUP, e.g. MyQType buffer)
- +0x04: pointer to a compiler-generated static record-descriptor in the EXE's own data section (field layout metadata for generic copy/compare)
- +0x08: pointer to the RUNTIME-ALLOCATED queue storage block (heap) — NULL when the queue is empty/never added to; this is the field Cla$FREEqueue checks/frees/zeroes
- +0x0C: record size in bytes (32 for STRING(32) in the test case)

**Why:** discovered via live disassembly of Qtester.exe — `ADD(MyQ)` on line 29 compiles to `lea ebx,[ebp-10h]; mov eax,ebx; call dword [IAT slot] -> ClaRUN.dll!Cla$ADDqueue`. Confirmed via ClarionDbg.Cli (src\ClarionDbg.Cli) interactive `break --rva --interactive --json` + `mem`/`regs`/`disasm` commands.

**How to apply:** For the CA Debugger's "show all queue records without touching the running program's buffer" feature, resolve the QUEUE local's hidden control-block address by finding the frame offset used in the ADD/GET/PUT call site (disassembly), not from TSWD locals. Then dereference +0x08 to reach the live per-queue heap allocation. See [[clarun-queue-add-free-disasm]] for the ADD/FREE runtime function disassembly and [[clarun-queue-record-storage-todo]] for what's still unresolved about the internal row layout.

`tags: queue,tswd,clarun,ca-debugger,control-block,disassembly`

---

## Locating the control block, per storage class

The walk itself never changes; only *finding* the control block differs by how the queue was declared. The consolidated decision procedure is in the first entry below; the rest give the per-class specifics. All six classes (local small, local large, global, parameter, reference/NEW, threaded) are verified.

### CORRECTION: SORT can add order objects (orders are independent index views); a QUEUE parameter arrives as a pointer to the caller's control block

*gotcha | confidence: confirmed | knowledge-base entry 64*

Corrects the over-strong claim in [[clarun-queue-rle-compressed-rows]] that "SORT does NOT create a new order object". That was observed with only ONE sort spec ever applied — in that case the existing order is re-sorted in place and `[obj+0x7D]` stays 1. Verified now with TWO different sort specs (`SORT(MyQ,-MyQ.Test)` in the caller, then `SORT(internalQ, internalQ.Test)` in a callee): `[obj+0x7D]` became **2**.

**Orders are independent index views over shared nodes.** Each order object has its OWN count (`order+0x01`) and its OWN node-pointer array (`order+0x05`), but they point at the SAME node objects. Verified with 5 records:
- order[0] @0xF693B8 (CURRENT, ascending): aa0, aaa, abc, def, ghi
- order[1] @0xF68FC8 (earlier descending): ghi, def, abc, aaa, aa0
Same five node addresses (0x8000F58/F60/F70/F78/F88), different sequence. So a debugger can offer "view in any existing order" by walking `[obj+0x39 + k*4]` for k < `[obj+0x7D]`, and `[obj+0x79]` identifies which one the program currently sees. The enumeration recipe itself is unchanged per-order.

**QUEUE parameters (verified):** a QUEUE passed to a procedure arrives as a POINTER TO THE CALLER'S 16-byte control block, sitting at `ebp-4` in the callee. So inside a callee this is the EASIEST case — `ctrl = u32[ebp-4]` directly, no frame scanning. Confirmed: the value at ebp-4 dereferenced to a block whose +0x00/+0x04/+0x08/+0x0C matched the caller's control block byte-for-byte, and walking it yielded the correct 4 then 5 rows. `PROCEDURE(MyQType)` and `PROCEDURE(*MyQType)` behave IDENTICALLY at runtime (same mangled name `@F7MYQTYPE`); TSWD does record different target type codes (0x08 vs 0x05) but the mechanism is the same.

**Consolidated rule for locating a queue's control block** (now validated across three shapes — local small, local large, parameter, plus global in static data):
1. TSWD reports the queue local. If `code == 0x08` (inline GROUP) the local IS the record image -> signature-scan the frame.
2. If `code == 0x16` (reference), read `p = u32[ebp + frameOff]`, then DISAMBIGUATE: if `u32[p+0x0C] == recordSize && u32[p+0x08] != 0` then **p is the control block** (parameter case); otherwise p is the record image (local large-record case) -> signature-scan the frame for a 16-byte block with `u32[+0x00] == p`.
3. For a global queue, take the record-image RVA from TSWD `globals` and signature-scan static data the same way.
Always require BOTH signature conditions (`[+0x00] == recordImage` AND `[+0x0C] == recordSize`) — matching size alone produced a false positive 140 bytes away during testing.

`tags: queue,clarun,ca-debugger,sort,orders,parameters,correction,control-block`

### Global QUEUE: control block lives in static data; reference fields (&CSTRING) occupy 8 bytes and TSWD under-reports their size

*pattern | confidence: confirmed | knowledge-base entry 63*

Extends [[clarun-queue-enumerate-readonly]]. Verified in Qtester.exe with a module-level `GlobalQueue QUEUE / GlobalLong LONG() / GlobalCstring &CSTRING / END` plus one ADD.

**Locating a global queue's control block:** the SAME signature match works, just scanned over static data instead of a stack frame. TSWD's `globals` reports the record image as a data symbol (here `GLOBALQUEUE` at RVA 0x20D0, "GROUP size 12"). Scan the module's data region for a 16-byte block where `u32[ctrl+0x00] == loadBase + <that RVA>`; found it at RVA 0x2084 (0x4C bytes BELOW the record image — do not assume it sits adjacent or after). Read the record size from `u32[ctrl+0x0C]` rather than computing it from the field list.

Confirmed values: ctrl+0x00 = record image, +0x04 = static descriptor, +0x08 = queue object, +0x0C = 12 (recordSize). `[obj+0x2D]` = 0 -> uncompressed, and the node vtable was RVA 0x144A44 (uncompressed class) exactly as the size rule predicts. COUNT = 1. The whole walk from [[clarun-queue-enumerate-readonly]] worked unchanged.

**Reference fields inside a queue record (IMPORTANT for field decoding):** a `&CSTRING` field occupies **8 bytes** in the row — pointer at +0, allocated length at +4. The 12-byte record decoded as: `+0` GlobalLong (LONG, 4 bytes) = 0; `+4` pointer = 0x08001F80; `+8` = 0x20 (=32, the allocated CSTRING length). TSWD reported `GLOBALCSTRING` as `type 0x16 size 4` at +4 — the size 4 is the POINTER width, not the field's footprint, which is why the GROUP is 12 bytes and not 8. **Do not lay out fields using TSWD's reported size for reference-typed members.**

To display such a field: read the pointer from the row, then read a NUL-terminated string at that address (cap at the allocated length from +4). Verified: followed 0x08001F80 -> `67 68 69 20 20 ... 20 00` = 'ghi' + 28 spaces + NUL = 31 chars, correct for `CSTRING(32)` assigned from a `STRING(200)` holding 'ghi'.

**Semantic caveat:** the row stores the POINTER, so it is a shallow copy — if the program later reassigns or DISPOSEs the reference, the stored row still points at the old (possibly freed) allocation. A debugger should defensively handle unreadable target addresses rather than assume the string is live.

**Bonus (confirmed via TSWD symbols):** `PROCEDURE(MyQType)` and `PROCEDURE(*MyQType)` produce IDENTICAL mangled signatures (`QUEUEWORKER@F7MYQTYPE` / `QUEUEPTRWORKER@F7MYQTYPE`) — QUEUE parameters are always passed by reference in Clarion, so the `*` adds nothing. This matches the developer's observation that they could see no difference between the two forms.

`tags: queue,clarun,ca-debugger,global-queue,static-data,reference-field,cstring,tswd`

### Reference QUEUE (&MyQType + NEW): reference slot IS the control block, record image inline at ctrl+0x10; TSWD gives NO field layout

*pattern | confidence: confirmed | knowledge-base entry 66*

Completes the storage-class matrix for [[clarun-queue-enumerate-readonly]]. Verified with `MyRefQ &MyQType` / `MyRefQ &= NEW(MyQType)` / `MyRefQ.Test='123'` / `ADD(MyRefQ)` in Qtester.exe (recordSize 200).

**Easiest case to locate.** The TSWD local (`MYREFQ` at ebp-28, `code=0x16 ->0x16`) holds the pointer returned by NEW, which IS the 16-byte control block — no frame scanning, no signature search: `ctrl = u32[ebp + frameOff]`.

**Self-validating signature:** for a NEW'd queue the record image is allocated INLINE right after the header, so `u32[ctrl+0x00] == ctrl + 0x10`. Verified exactly (both 0x1018DA8 with ctrl=0x1018D98), and `u32[obj+0x29]` agreed. This matches Cla$NEWqueue's code (`malloc(recordSize + 0x10)` then `lea eax,[edi+10h]; mov [edi],eax`), so total allocation = 16 + recordSize (216 here). Use this equality as a cheap confidence check that a candidate pointer really is a control block.

Everything else was unchanged: `[ctrl+0x0C]`=200, `[obj+0x2D]`=1 -> compressed, node vtable RVA 0x144A5C (compressed class), COUNT=1, blob `07 00 00 00 | 83 31 32 33 40 C5 20` -> '123' + 197 spaces = 200 bytes.

**GAP — no field layout from TSWD for reference queues.** TSWD reports `MYREFQ` as `code=0x16 ->0x16 size=0` with NO resolved GROUP and no usable typeRef, unlike a direct `MyQ QUEUE(MyQType)` which carries `+0 TEST string/200`. So the row BYTES and record SIZE are obtainable (size from `[ctrl+0x0C]`), but the field breakdown is not available from the local's own debug record. Workarounds for the CA Debugger, in preference order:
1. Reuse the QUEUE,TYPE layout resolved from another local/global of the same type (MyQType is in TSWD via MYQ's typeRef).
2. Decode the runtime field descriptor pointed to by `[ctrl+0x04]` (here 0x006120B0, in the EXE's static data — the same descriptor kind Cla$NEWqueue passes around as a ClassDesc/FieldDesc). This would make field decoding independent of TSWD entirely and is worth investigating — NOT yet reverse-engineered.

Storage classes now VERIFIED end-to-end: local small (inline GROUP), local large (heap image + reference local), global (static-data control block), QUEUE parameter (pointer to caller's control block), reference/NEW'd (this entry). Still untested: THREADed (.cwtls), class-member queue, DELETE(q) compaction, RLE u16/u32 count forms, multi-field records with nested GROUP/DIM.

`tags: queue,clarun,ca-debugger,reference-queue,new,cla-newqueue,tswd,field-layout`

### THREADed QUEUE: resolve the per-thread instance via THR$GetInstance, then signature-scan — control-block offset is NOT constant

*pattern | confidence: confirmed | knowledge-base entry 68*

Verified with `GlobalQueue QUEUE, THREAD` and two threads (`th# = START(Test); RESUME(th#); Test()`), each doing one ADD.

**Detection:** the THREAD attribute moves the queue out of `.data` into `.cwtls`. Same declaration, non-threaded, sat at RVA 0x20D0 in .data; with THREAD it moved to RVA 0x3020 inside .cwtls (section va 0x3000, span 0x200). So: a queue is threaded iff its TSWD data-symbol RVA falls in the owning module's .cwtls range (LoadedModule.CwtlsLo/CwtlsHi already computes this).

**Resolution:** the TSWD RVA is only a TEMPLATE. Get the live per-thread address via the THR$GetInstance func-eval the engine already implements for `watch` (DebugEngine.Eval.cs): EAX = template VA, EBX = loadBase + CwtlsLo, return value in EAX = instance VA. The `watch` text line reports it: `watch GLOBALQUEUE: GROUP size 12 at 0x83EB50 (threaded; template 0x513020)`. NOTE the JSON only carries the instance address as `"va"` when the type is editable — a GROUP is not, so parse the text line rather than the JSON.

**Then signature-scan for the control block — the offset VARIES and must not be hardcoded:**
- threaded instance: control block at instance - 0x18
- non-threaded global (earlier test): control block at record image - 0x4C
Scan a small window around the resolved instance for `u32[+0x00] == instanceVa && u32[+0x0C] == recordSize`, exactly as for the other storage classes.

**Everything downstream is per-thread and needs no special handling.** Measured across the two threads (same template 0x513020):
- thread A: instance 0x83EB50, ctrl 0x83EB38, obj 0x81A700, COUNT 1, &CSTRING -> 0x08001F80
- thread B: instance 0x83BBB8, ctrl 0x83BBA0, obj 0x81AF18, COUNT 1, &CSTRING -> 0x08001F60
Distinct control block, queue object, order, node, row AND a separate NEW(CSTRING(32)) per thread. COUNT=1 each, matching the developer's own MESSAGE-based measurement (with THREAD each thread sees 1 record; without THREAD both threads share one queue and thread 2 saw 2).

The descriptor at `ctrl+0x04` stays SHARED — it points into .data (0x51208C), not .cwtls, since the field layout is identical for all threads. Only the record image and the object are per-thread.

**LIMITATIONS to design around:**
1. Resolving a threaded instance REQUIRES running code in the target (the func-eval). It is the one place the otherwise-pure-read approach must execute something. THR$GetInstance is a benign lookup and the engine saves/restores the thread context, but it cannot be done on a frozen or post-mortem process.
2. THR$GetInstance returns the CALLING thread's instance, so a func-eval on the paused thread only reveals THAT thread's queue. To show every thread's copy (e.g. an "all threads" view) you must either run the eval on each thread or read the Clarion TLS structures directly — the latter is NOT yet reverse-engineered and would remove limitation 1 as well.

`tags: queue,clarun,ca-debugger,threaded,cwtls,thr-getinstance,func-eval`

---

## Row storage and the RLE codec

Rows are stored raw for small records and RLE-compressed for large ones, behind two different node classes. This is the single biggest trap for anyone who tests only with a small record.

### QUEUE rows are RLE-COMPRESSED when the record is large — two node classes, and the decoder format

*gotcha | confidence: confirmed | knowledge-base entry 62*

Extends [[clarun-queue-enumerate-readonly]]. Verified with STRING(200) (recordSize=200) + SORT descending, 3 rows, in Qtester.exe.

There are TWO node storage classes, and `node+0x04` means different things in each:
- **Uncompressed node** (vtable RVA 0x144A44, init RVA 0x1B594): `node+0x04` -> pointer to the raw record bytes. Read recordSize bytes directly. This is the small-record case (verified with STRING(32)).
- **Compressed node** (vtable RVA 0x144A5C, init RVA 0x1B554): `node+0x04` -> pointer to `{ u32 payloadLen; byte payload[] }`. If `payloadLen == 0` the payload is a RAW copy (plain memcpy of recordSize bytes). Otherwise payload is RLE and must be decoded.

**Discriminator — use `[obj+0x2D] != 0` means COMPRESSED.** Verified: recordSize 32 -> [obj+0x2D]==0; recordSize 200 -> [obj+0x2D]==1. Note objinit's size test (`cmp dword [ebx+21h],80h`, i.e. >= 128 bytes) writes 0 or 2, but a fallback path at RVA 0x1A923 writes 1 — we observed 1. So test `!= 0`, never `== 2`. Do NOT key off the vtable RVAs (version-fragile) and do NOT re-derive from recordSize alone.

The dispatcher is the node vtable's `+0x08` slot (RVA 0x1BDA0): reads `[node+4]`, and if `[storage]==0` memcpy from `storage+4`, else calls the RLE decoder at **RVA 0x193EB** with (eax=payloadLen, ebx=payload, edx=dest, ecx=destSize).

RLE format (ported from RVA 0x193EB, validated byte-exactly):
```
token = src[i++]
count = token & 0x3F
if token & 0x40:                       // extended count
    if count == 0x30:  count = u32 at src; i += 4
    elif count > 0x30: count = u16 at src; i += 2
    else:              count = (count << 8) | src[i++]     // 14-bit
if token & 0x80:  copy `count` literal bytes from src
else:             val = src[i++]; emit `count` copies of val
```
Real example: a 200-byte record holding 'ghi' compresses to 12 bytes — `07 00 00 00 | 83 67 68 69 40 C5 20 | 00`. payloadLen=7 = token(0x83) + 3 literals + token(0x40) + count(0xC5=197) + value(0x20=space); output = 3 + 197 = 200 exactly. A Python port decoded all three rows ('ghi','def','abc') byte-exactly to 200 bytes.

CAVEAT: only the 14-bit count form is empirically exercised (counts <= 0x2FFF = 12287). The u16/u32 forms are read from disassembly but untested — they need a single run longer than 12287 bytes (e.g. STRING(20000)) to hit.

**SORT behaviour (verified):** SORT does NOT create a new order object. `[obj+0x7D]` stayed 1 and `[obj+0x39][0] == [obj+0x79]`; SORT reorders the flat node-pointer array at `[order+0x05]` in place. Array went from F88,F78,F70 (insertion) to F70,F78,F88 (descending), and index 1 read back as 'ghi', matching GET(MyQ,1). So the enumeration recipe needs no change for sorted queues.

**Also verified:** for a large record the compiler puts the record image on the HEAP and TSWD reports the local as a REFERENCE (`code=0x16 -> 0x08, &GROUP(size=200)`) at ebp-4, not an inline GROUP. The 16-byte control block was still on the frame (at ebp-20) and was located reliably by matching `u32[ctrl+0x00] == <TSWD reference target>` AND `u32[ctrl+0x0C] == recordSize`. Matching on size ALONE produced a false positive 140 bytes away — always require both.

`tags: queue,clarun,ca-debugger,rle,compression,sort,large-record,node-class`

---

## Field decoding, including string references

Turning a decoded row into named field values. Reference-typed fields are where TSWD's reported sizes cannot be trusted.

### String/CSTRING reference fields in a QUEUE record: pointer + a 4-byte length word AFTER it — record is 4 bytes larger per reference field

*gotcha | confidence: confirmed | knowledge-base entry 69*

Refines the reference-field note in [[clarun-queue-global-static-and-reference-fields]]. Confirmed by the developer (Clarion 11.1) and matched byte-for-byte in the capture: the compiler emits a length variable alongside every string/CSTRING reference, so the record grows by 4 bytes per such field beyond the bare pointer.

Observed layout for `GlobalQueue QUEUE / GlobalLong LONG() / GlobalCstring &CSTRING / END` (recordSize 12):
```
+0  00 00 00 00   GlobalLong    LONG
+4  80 1F 00 08   pointer  -> 0x08001F80 (derefs to 'ghi' + 28 spaces + NUL)
+8  20 00 00 00   length word = 32
```
So the length word comes AFTER the pointer in this compiler version. TSWD reports `GLOBALCSTRING type 0x16 size 4` — the POINTER width only, not the 8-byte footprint. That is exactly why the GROUP is 12 bytes rather than 8.

**RULE: never compute recordSize by summing TSWD field sizes.** Always read it from `u32[ctrl+0x0C]`. A record with N string/CSTRING reference fields is 4N bytes larger than the naive pointer-only sum, and getting this wrong shifts every field after the first reference AND breaks the control-block signature match (which compares `[ctrl+0x0C]` against recordSize).

**UNRESOLVED — which length is it?** The observed 32 is ambiguous: `CSTRING(32)` was assigned a STRING(200) of 'ghi'+spaces, truncated to 31 chars + NUL = exactly 32, so declared capacity and stored length coincide. Both threads showed 32 for the same reason. To settle it, assign a SHORT literal (`GlobalQueue.GlobalCstring = 'ab'`) and re-read +8: stays 32 => capacity; becomes 2/3 => current length. This matters because a debugger wants to know whether the word is a safe read bound for the pointed-to string or merely the allocation size. Until settled, read the target as NUL-terminated and treat the word as an upper bound only.

`tags: queue,clarion,record-layout,reference-field,cstring,tswd,ca-debugger`

### RESOLVED: the 4-byte word after a &CSTRING pointer in a QUEUE record is the ALLOCATED CAPACITY, not the current length

*gotcha | confidence: confirmed | knowledge-base entry 70*

Resolves the open question in [[clarion-queue-string-reference-length-word]]. Controlled A/B test on the same code path (threaded GlobalQueue, `GlobalCstring &CSTRING` pointed at `NEW(CSTRING(32))`), verified in BOTH threads:

- assignment `= MyQ.Test` (STRING(200) of 'ghi'+spaces -> truncated to 31 chars + NUL, filling all 32 bytes): record+8 = 32
- assignment `= 'ab'` (3 bytes used: 'ab' + NUL, rest zero): record+8 = **still 32**

The word is invariant to content, so it is the DECLARED/ALLOCATED capacity of the CSTRING, not the stored length. Target buffer in the short case read `61 62 00 00 00 ...`, i.e. 'ab' + NUL + zeros, while +8 remained 32.

**How to apply:** treat the length word as a SAFE UPPER BOUND on how many bytes of the referenced buffer may be read (useful for clamping a defensive read of a possibly-dangling pointer), but do NOT use it as the string length. For `&CSTRING`, scan to the NUL within that bound.

**Also disproved:** the hypothesis that this word exists because queues internally compact strings. The queue's compaction is a separate RUNTIME mechanism (whole-row RLE, only when recordSize >= 0x80). GlobalQueue's record is 12 bytes, so `[obj+0x2D] == 0`, the node used the UNCOMPRESSED class (vtable RVA 0x144A44) and the row was read raw with no decoding — yet the length word was present. Therefore the word is a COMPILE-TIME record-layout artifact, independent of compaction. (The developer's "queues compact strings" instinct does correspond to a real mechanism — it is exactly the RLE that collapses trailing spaces in fixed-size STRING fields, e.g. STRING(320) 'literal 21' + '299 x 0x20'. But that acts on inline fixed fields, never on referenced buffers: the row stores only the pointer and the queue never copies the pointed-to string.)

**STILL UNTESTED:** only `&CSTRING` was measured. For `&STRING` (no NUL terminator) the accompanying word may well be the meaningful length rather than capacity — a different type, not yet verified. Note TswdDebugInfo.ReadLocals separately special-cases `code == 0x16 && target == 0x18` to read an "&STRING char count", suggesting a length does travel with &STRING references at the debug-info level.

`tags: queue,clarion,cstring,reference-field,record-layout,capacity,resolved`

### RESOLVED for &STRING too: the word after a string-reference pointer is the ALLOCATED BUFFER SIZE — authoritative length for &STRING, upper bound for &CSTRING

*pattern | confidence: confirmed | knowledge-base entry 71*

Completes [[clarion-queue-cstring-length-word-is-capacity]]. Tested a queue with BOTH reference kinds: `GlobalQueue QUEUE,THREAD / GlobalLong LONG() / GlobalCstring &CSTRING / GlobalString &STRING / END`, with `&= NEW(CSTRING(32))` assigned 'ab' and `&= NEW(STRING(20))` assigned 'xy'.

TSWD reported the record as GROUP size **20** with GLOBALLONG +0, GLOBALCSTRING +4, GLOBALSTRING +12 — i.e. 4 + 8 + 8. Confirms the developer's rule (4 extra bytes per string/CSTRING reference) for MULTIPLE reference fields, and confirms each reference field spans 8 bytes (pointer then word). Row bytes (recordSize 20, `[obj+0x2D]`=0 so uncompressed, read raw):
```
00 00 00 00 | 80 1F 00 08 | 20 00 00 00 | 88 2E 00 08 | 14 00 00 00
GlobalLong    cstring ptr   word = 32     string ptr    word = 20 (0x14)
```

**The word is the ALLOCATED SIZE of the referenced buffer in both cases.** How to consume it differs:
- `&STRING`: STRING has no terminator and is fixed-length/space-padded, so allocated size == content length. The word IS the authoritative read length — read exactly N bytes. Verified: target was `78 79` + 18 x 0x20 = exactly 20 bytes ('xy' + 18 spaces), with zeros beyond (i.e. outside the allocation — reading past the word spills into unrelated heap).
- `&CSTRING`: the word is an UPPER BOUND only. Verified: word = 32 while the content was 'ab' with NUL at offset 2.

**Unified rule for the CA Debugger's field decoder:** for a reference-typed field (TSWD `code 0x16`) read `ptr = u32[row + off]` and `size = u32[row + off + 4]`; clamp any read of the target to `size`; then for CSTRING scan to the first NUL within it, for STRING take all `size` bytes. Treat `ptr == 0` and unreadable targets as null/dangling (the row holds only a shallow pointer copy).

Reminder from the same test: TSWD reports each reference field as `size 4` (the pointer width), so recordSize must always come from `u32[ctrl+0x0C]` (20 here), never from summing TSWD field sizes (which would give 12).

`tags: queue,clarion,string-reference,cstring,record-layout,field-decoding,ca-debugger,resolved`

---

## Operation semantics: orders, ADD, DELETE

What SORT, ADD and DELETE actually do to the internal structures. The DELETE finding is an invariant the reader must honour, not a curiosity. (SORT's order-creation behaviour is corrected in the first entry of 'Locating the control block' above.)

### QUEUE sort orders: separate pointer arrays over SHARED nodes; ADD maintains every order; [obj+0x39] is MRU-ordered

*pattern | confidence: confirmed | knowledge-base entry 65*

Refines [[clarun-queue-sort-orders-and-parameters]] with the storage-ownership answer.

**Each order owns its pointer array; the records are shared.** Verified with 5 records and 2 orders:
- order[0] @0xF693B8 nodeArray=0x8001F40 -> nodes F58,F60,F88,F78,F70 (ascending)
- order[1] @0xF68FC8 nodeArray=0x8001F60 -> nodes F70,F78,F88,F60,F58 (descending)
Two distinct, non-overlapping array allocations (5*4 = 20 bytes each, allocated 0x20 apart so there is capacity headroom), holding the SAME five node addresses in different sequence. The node objects and their row data exist ONCE. So SORT builds an additional index — it neither clones the rows nor destructively reorders another order's array. Cost model: +4 bytes per record per extra order.

**ADD inserts the new node into EVERY existing order, at its correct sorted position.** Proof: the descending order was created BEFORE 'aaa' and 'aa0' were added, yet it lists them correctly placed (ghi,def,abc,aaa,aa0). Matches the post-ADD worker at RVA 0x1A1F0, which loops the order array:
```
dl = [edi+7Dh]                 ; order count
loop: dec dl
      eax = [edi+dl*4+39h]     ; order[dl]
      cmp [edi+79h],eax / je   ; skip current (handled separately below)
      ebx = node; ecx=0; call 0x1AB04   ; insert into that order
...
inc dword [edi+1Dh]            ; numchanges++
```

**`[obj+0x39]` is MRU-ordered, not creation-ordered — slot 0 is always the current order.** Observed `[obj+0x39][0] == [obj+0x79]` in every capture (the most recent ascending sort sat at slot 0 while the older descending order moved to slot 1). The helper at RVA 0x1A59C implements this: it scans the array for the current order then `memmove`s entries to place it at slot 0. Do NOT infer creation order from slot index.

**Consequences for the CA Debugger:**
- Row bytes are order-independent — reading via any order yields identical data.
- The NODE POINTER is a stable row identity across orders; use it to correlate the same record between views, or to highlight the row the program's own cursor (POINTER/current order) refers to.
- Every order is a complete permutation of all records (both orders showed COUNT=5) — orders are never filtered subsets, so per-order counts always agree.

`tags: queue,clarun,ca-debugger,sort,orders,shared-nodes,mru,add`

### DELETE compacts the node array but leaves a STALE pointer past the count — always honour count, never scan for null

*gotcha | confidence: confirmed | knowledge-base entry 67*

Verified with a 360-byte record queue (`MyQLargeType`: STRING(320) + LONG,DIM(10)), 3 ADDs then GET(MyLQ,2) + DELETE(MyLQ).

**DELETE behaviour:** `[order+0x01]` count goes 3 -> 2, and the node-pointer array at `[order+0x05]` is COMPACTED (memmove down). The removed node is unlinked and freed.

**THE TRAP:** the vacated slot is NOT cleared. Raw array slots observed:
```
before DELETE:  0x8000F48  0x8000F78  0x8000F68  | 0x0 ...
after  DELETE:  0x8000F48  0x8000F68  0x8000F68  | 0x0 ...
                                      ^^^^^^^^^ stale duplicate of the last live node
```
So `slot[count]` can contain a plausible, dereferenceable pointer to a STILL-LIVE node. A reader that walked the array until it hit NULL (or that trusted array capacity) would render the last record TWICE. **`count` from `[order+0x01]` is the only authority** — read exactly `count` entries, never null-terminate, never use the allocation size of the array (arrays are allocated with capacity headroom, e.g. 20 bytes of pointers in a 32-byte slot).

**Multi-field + DIM array decoding CONFIRMED.** TSWD gave the layout (`TEST string/320` at +0, `NUMBERARR array/40 [1..10] of int/4` at +320) and decoding the decompressed 360-byte row against it produced exactly the coded values. Also note Clarion does NOT clear the record buffer between ADDs, so fields set only in an earlier row persist into later rows (NumberArr[10]=456 appeared in rows 2 and 3 although only row 1 assigned it) — that is faithful data, not a decode bug; the debugger should display it as stored.

**More RLE token forms exercised and validated** (row 0, payloadLen=34, decodes to exactly 360):
```
95              literal 21 -> '1234567890qwertyyuiop'
41 2B 20        extended count (1<<8)|0x2B = 299, fill 0x20  -> 320 total for TEST
81 7B           literal 1  -> 123
23 00           short fill 35 zeros
84 C8 01 00 00  literal 4  -> 456
```
This covers the 14-bit extended-count form, short fills and literals. STILL untested: the u16 form (count > 0x30) and u32 form (count == 0x30), which need a single run longer than 12287 bytes.

Storage classes / operations now verified: local small, local large, global (static data), QUEUE parameter, reference/NEW'd, sorted + multiple orders, multi-field with DIM array, and DELETE. Still untested: THREADed queue (.cwtls / THR$GetInstance) and class-member queue.

`tags: queue,clarun,ca-debugger,delete,stale-pointer,count,dim-array,rle`

---

## ClaRUN.dll internals reference

Disassembly of the entry points, for anyone re-deriving or extending this work.

### Cla$ADDqueue / Cla$FREEqueue disassembly — thin wrappers over private ClaRUN.dll workers

*pattern | confidence: confirmed | knowledge-base entry 57*

Live-disassembled in ClaRUN.dll (base 0x5B8F0000 in one test run — ASLR/ordering may shift addresses, re-resolve live each session via the IAT).

`Cla$ADDqueue(ecx=queue-control-block ptr)`:
```
push ebx / push ecx
mov ecx,eax          ; ecx = arg (queue control-block pointer)
mov eax,ecx
call <private worker>   ; grows/copies record into +0x08 block; returns 0 on FAILURE
cmp eax,0
jne short <skip>        ; success -> skip error path
  mov eax,[ecx+8]        ; failure: read the data-block ptr
  mov bl,0
  call <private>          ; report error
  mov eax,[ecx+8]
  call <private>          ; free partial allocation
skip:
pop ecx / pop ebx / ret
```

`Cla$FREEqueue(eax=queue-control-block ptr)`:
```
push ebx / push ecx
mov ebx,eax
cmp ebx,0 / je exit
cmp dword [ebx+8],0 / je skip_free   ; +0x08 = the heap block pointer
  mov ecx,[ebx+8]
  mov eax,ecx / call <private>        ; free the block
  mov eax,ecx / call <private>        ; bookkeeping/unregister
skip_free:
  mov dword [ebx+8],0                 ; null the pointer — classic use-after-free guard
exit:
pop ecx / pop ebx / ret
```

This directly confirms the pre-existing knowledge-base gotcha that DISPOSE(queue) (and, per this trace, scope-exit RETURN) calls FREE internally: in Qtester's `Test` PROCEDURE, `RETURN` after `ADD(MyQ)` compiles straight into a `call ClaRUN.dll!Cla$FREEqueue` on the same control-block pointer — no explicit FREE/DISPOSE was written in source.

**Why:** established for [[clarun-queue-hidden-control-block]] — needed to know exactly which field is safe to read (control-block +0x08) vs which internal calls mutate state, so the CA Debugger's queue-record viewer can read without racing/corrupting the live queue.

**How to apply:** When building a "peek at all queue records" feature, never call into Cla$ADDqueue/GETqueue/etc. from the debugger side (they mutate +0x08 and can trigger allocation/free) — only read memory at the control block and its +0x08 target. See [[clarun-queue-record-storage-todo]] for the remaining unknown: exact byte offset of row data inside the +0x08 block.

`tags: queue,clarun,disassembly,add,free,dispose,ca-debugger`

---

## Field layout for reference queues (use TSWD, not the runtime descriptor)

A `&MyQType` reference queue appeared to have no field layout in TSWD. It does — the existing decoder was stopping one reference hop short. This section covers the diagnosis, the implemented fix, and a retracted claim about a second call site.

### Reference-queue field layout IS in TSWD — GroupTypeOf only follows ONE reference hop; reference depth mirrors the pointer chain

*debug_insight | confidence: confirmed | knowledge-base entry 72*

Corrects the "GAP" recorded in [[clarun-queue-reference-new-inline-image]], which claimed TSWD carries no field layout for a `&MyQType` reference queue. The layout IS there; the existing decoder simply stops one hop short. No runtime-descriptor reverse engineering is needed for field display — reuse the existing TSWD type decoder.

Proof via ClarionDbg's own `typechain` diagnostic (Qtester.exe):
```
MYQ     typeRef 0x178 -> tag 0x16 Reference
                      -> 0x17D    tag 0x08 Group size=200        (depth 1)
MYREFQ  typeRef 0x1E4 -> tag 0x16 Reference
                      -> 0x1E9    tag 0x16 Reference
                      -> 0x1EE    tag 0x08 Group size=200        (depth 2)
```
Group size 200 matches MyQType's STRING(200) in both cases. `ParseType` already builds the whole chain (each `.Referent` linked), so the data was never missing.

Root cause — `GroupTypeOf` follows exactly one hop, and the logic is DUPLICATED in two places:
- `src/ClarionDbg.Cli/DebugEngine.Locals.cs` ~line 175 (the pad's Locals/Watch renderer)
- `src/ClarionDbg.Cli/Program.cs` ~line 427 (the CLI `locals` dump)
```csharp
if (t.Kind == TypeKind.Group) return t;
if (t.Kind == TypeKind.Reference && t.Referent != null && t.Referent.Kind == TypeKind.Group) return t.Referent;
return null;
```
A `&QUEUE` local is reference->reference->group, so both return null and no members are shown. Fix: follow the chain transitively with a depth cap and cycle guard (ideally as one shared helper in ClarionDbg.Core so the duplication goes away).

**KEY INSIGHT — reference depth == number of dereferences to reach the record image.** The type chain mirrors the runtime pointer chain exactly, verified against live memory:
- `MyQ QUEUE(MyQType)`: 1 hop; slot holds the RECORD IMAGE pointer (control block found separately on the frame by signature scan).
- `MyRefQ &MyQType`: 2 hops; slot holds the CONTROL BLOCK pointer, whose +0x00 is the record image.
So the hop count is not cosmetic — it tells the reader how many pointer reads to perform, and independently corroborates the empirical finding that a NEW'd queue's reference slot IS the control block.

Practical consequence: prefer reusing the existing TSWD decoder (`ResolveType` / `ClarionType.Members` with offsets, plus `FormatValueAt` / `ClarionTypeLabel` for rendering) over decoding the runtime descriptor at `u32[ctrl+0x04]`. That keeps ONE field-rendering path shared with the Locals panel. Decoding the runtime descriptor remains optional and is only worth doing if layout is ever needed with no TSWD at all (see [[clarion-queue-runtime-field-descriptor]] for what was learned about it).

`tags: queue,tswd,ca-debugger,reference-queue,typechain,GroupTypeOf,field-layout,correction`

### FIXED in CA-Debugger: ClarionType.ResolveGroup follows N reference hops; reference queues now show fields (verified static + live)

*decision | confidence: confirmed | knowledge-base entry 74*

Implements the fix identified in [[clarion-queue-reference-layout-is-in-tswd]]. No runtime-descriptor decoding was needed — the existing TSWD decoder was reused, per the developer's suggestion.

**Change (3 files, built clean with `dotnet build`, net48):**
1. `src/ClarionDbg.Core/TswdDebugInfo.cs` — added `ClarionType.ResolveGroup(out int hops)`: walks `.Referent` transitively to the first `Kind == Group`, returning how many hops it took, with a `guard < 8` bound so cyclic/deep ABC object graphs return null instead of spinning.
2. `src/ClarionDbg.Cli/DebugEngine.Locals.cs` — `GroupTypeOf` now delegates to it (kept the old 1-arg signature, added a 2-arg overload reporting hops). **Critically**, `NodeJson` previously did a single `ReadU32(va)` for every by-ref row; it now performs one deref PER HOP (`derefs = hops < 1 ? 1 : hops`), because a `&QUEUE` slot holds the CONTROL BLOCK, not the record image — a single deref would have rendered the 16-byte control header as the first members. Never deref fewer than once: a code-0x16 slot whose typeRef points straight at a GROUP reports 0 hops but is still a pointer.
3. `src/ClarionDbg.Cli/Program.cs` — the CLI `locals` dump used a duplicate copy of the 1-hop logic; now calls `ResolveGroup` and prints `hops=N` when N>1. The duplication is gone, so the two paths can no longer drift.

**Verified, static (`ClarionDbg locals --proc Test`):**
```
[ebp-36]  MYREFQ  code=0x16 ->0x16  &GROUP(size=200) typeRef=0x1E4 hops=2
    +0     TEST    string/200 tag=0x18            <- previously NO members at all
```
`MYQ` / `MYLQ` still resolve at 1 hop — no regression.

**Verified, live (`framelocals` on the paused frame):**
- `MYREFQ` slot value 0xC49420 (the control block); emitted row `addr=0xC49430` = ctrl+0x10 = the record image, i.e. two derefs applied. Emitted `typeRef=494` = 0x1EE, matching the group typeRef `typechain` reported at depth 2, so host-side expansion lands on the fields.
- `MYQ` slot 0xC490F0 -> `addr=0xC490F0` (one deref, unchanged).

**Build note:** ClarionDbg is an SDK-style csproj — build it with `dotnet build`, NOT the .NET Framework MSBuild (`C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe`), which fails with MSB4041 "project XML namespace must be the MSBuild XML namespace". The Clarion solution still uses that Framework MSBuild; the two build systems are different here.

`tags: ca-debugger,fix,ResolveGroup,reference-queue,tswd,dotnet-build,implemented`

### CORRECTION: CodeForType needs NO change — group-member expansion is gated in NodeJson by the full ClarionType

*debug_insight | confidence: confirmed | knowledge-base entry 76*

Retracts a claim made while reviewing the blast radius of [[ca-debugger-resolvegroup-multihop-fix]]. I asserted that `CodeForType`'s one-hop check (`t.Referent.Kind == TypeKind.Group`) left an asymmetry where a `&QUEUE` expanded as a top-level local but not as a GROUP member. That is WRONG, established by tracing the call chain rather than reading the check in isolation.

`GroupChildrenJson` renders each member as:
```csharp
sb.Append(NodeJson(mName, mb.Type, mc, mt, msz, mpl, mva, null, module));
```
It passes the member's FULL `ClarionType` (`mb.Type`), and `NodeJson` computes `GroupTypeOf(type, out refHops)` itself. Expansion is gated by:
```csharp
bool byRef = code == 0x16 || (type != null && type.Kind == TypeKind.Reference);
if (byRef && g != null)   // <- the full type decides, not CodeForType's target
```
`CodeForType` only supplies the flat (code,target,size,places); `code` is 0x16 for ANY reference, which is all `byRef` requires. So a `&QUEUE` member gets `byRef` true and `g` resolved at 2 hops, and takes the expandable branch with 2 derefs. `CodeForType`'s `target` is consulted only on the LEAF path and for type labels — which a resolved group never reaches.

Conclusion: the ResolveGroup fix repaired the member path and the top-level path simultaneously, because both funnel through NodeJson. Editing CodeForType would be a no-op at best; forcing `target = 0x08` there could actively muddy the leaf/label path for references that genuinely cannot resolve.

**Genuinely still unaddressed (verified as real):**
1. The GLOBALS path (`DataSymbol` decode) tests `Kind == Group` only and follows no references at all, so a module-level `&MyQType` will not expand in the `globals` dump. Separate code path; `ResolveGroup` does not reach it.
2. The >=2-hop deref assumption is empirically verified for exactly ONE construct (`&MyQType`: slot -> control block -> record image). It is sound wherever the TSWD chain mirrors real pointer indirection, but unverified beyond that case. A construct encoding 2 hops that is only one pointer at runtime would yield a bogus second deref; the per-step `ptr != 0` guard catches nulls, not garbage.
3. The member claim above is from code reading, NOT a live test. A `&MyQType` field on a queue (e.g. `GlobalSubQ &MyQType` assigned `&= MyRefQ`) would produce a real 2-hop member and settle it from live output — not yet done.

**Method note worth keeping:** for a flat-tuple helper like CodeForType, check what CONSUMES the tuple before concluding a field is load-bearing.

`tags: ca-debugger,correction,CodeForType,NodeJson,reference-queue,retraction`

---

## Threaded data without the func-eval

THR$GetInstance reduced to arithmetic plus one thread-local lookup, so threaded data can in principle be resolved by pure reads. Formula derived and structurally proven; one capability (reading a thread's TEB) still missing.

### THREADed data can be resolved WITHOUT the func-eval: formula derived and structurally proven; needs a TEB read (registry route undecoded)

*debug_insight | confidence: likely | knowledge-base entry 75*

Addresses limitation 1 of [[clarun-queue-threaded-thr-getinstance]]. THR$GetInstance (ClaRUN RVA 0xD0198) was disassembled and its logic reduced to arithmetic plus one thread-local lookup.

**Derived formula (all pure reads except step 2):**
```
tlsIndex  = u32[clarunBase + 0x13F12C]          // Win32 TLS index, a ClaRUN global
threadObj = <TLS slot tlsIndex of the TARGET thread>
slotIndex = u32[cwtlsBase]                      // first dword of the module's .cwtls
blockBase = u32[threadObj + 0x80 + slotIndex*4] // per-thread copy of .cwtls
instance  = templateVa - cwtlsBase + blockBase
```
Measured constants in this build: tlsIndex = 10, slotIndex = 1.

Evidence from the disassembly:
- `curThreadObj` (RVA 0xD1FC4) is literally `push dword [clarun+0x13F12C] / call KERNEL32!TlsGetValue / ret` — so the THREAD object pointer lives in a Win32 TLS slot.
- THR$GetInstance tail: `eax = templateVa; ebx = [edx]; sub ebx,[ecx+0x10]; add eax,ebx` where `[ecx+0x10]` is cwtlsBase and edx = `&threadObj[0x80 + index*4]`, index = `[cwtlsBase]`.
- `Cla$THREAD` (RVA 0xD1370) = `curThreadObj; eax = [eax+0x14]; inc eax` — so **threadObj+0x14 is the 0-based thread ordinal** (Clarion's THREAD() is 1-based). A useful sanity field when validating a candidate THREAD object.

**Structurally PROVEN (not just inferred):** dumped the .cwtls template and the derived per-thread block side by side. The block is a FIXED-UP COPY at identical internal offsets:
```
off  template     thread block   meaning
+00  0x00000001   0x00000001     slot index (copied verbatim)
+08  0x00C83020   0x0167E7A0     ctrl+0x00 record image  <- fixed up per thread
+0C  0x00C82094   0x00C82094     ctrl+0x04 descriptor    <- SHARED, identical
+10  0x00000000   0x01659C18     ctrl+0x08 queue object  <- null in template
+14  0x00000014   0x00000014     ctrl+0x0C recordSize 20 <- identical
```
This independently corroborates three earlier findings: the control block sits at template offset +0x08 (matching the observed instance-0x18), the field descriptor is NOT thread-local, and the queue object is NULL until first use.

**Remaining work — one of two routes for step 2:**
1. **TEB route (recommended, standard and safe).** Get the thread's TEB base via `NtQueryInformationThread(ThreadBasicInformation)`, then on x86 read `TlsSlots` at `TEB+0xE10` (`threadObj = u32[teb + 0xE10 + tlsIndex*4]` for tlsIndex < 64; for >= 64 use `TlsExpansionSlots` at `TEB+0xF94` then `(tlsIndex-64)*4`). This is a pure read, works for ANY thread (not just the paused one, so an all-threads view becomes possible) and works post-mortem given a dump containing TEBs. ClarionDbg has no TEB accessor yet — that is the one new capability required.
2. **Global registry route (NOT decoded).** ClaRUN keeps a collection at `clarun + 0x158F00`; `_6THREAD__Find@FUl` (RVA 0xD1E5C) does `eax = 0x158F00; call 0xC6EAC` with ebx = id. Its header reads `+0x00` = storage pointer, `+0x04` = capacity (596 observed). A walk assuming a flat pointer array found NO THREAD objects, so the storage layout is something else. CAUTION: the same 0x158F00 global is also referenced by the section-lookup helper at RVA 0xD0230, so the identification is not certain — do not build on this without decoding the collection class (methods at 0xC6EAC / 0xC6FBC / 0xC724C / 0xC726C / 0xC7058).

Until route 1 or 2 is implemented, keep using the existing `THR$GetInstance` func-eval for threaded data.

`tags: queue,clarun,threaded,cwtls,thr-getinstance,tls,teb,ca-debugger,partial`

---

## Build and tooling notes

Hard-won practicalities about reproducing these results.

### Incremental MSBuild on Clarion projects can leave a stale EXE — breakpoints then land mid-instruction and crash (0xC0000005)

*gotcha | confidence: confirmed | knowledge-base entry 61*

Symptom: after editing a .clw and building with `/t:Build`, launching under the CA Debugger gave "0 breakpoint hit(s)" and the target died with exit code 3221225477 (0xC0000005 ACCESS_VIOLATION), while an identical command had worked minutes earlier. `disasm` then failed with "target is running — disasm is only valid while paused".

Cause: the incremental build only relinked — its log showed just `Making Qtester.exe` with no compile step. `/t:Rebuild` showed `Making Qtester.obj : file does not exist / made Qtester.obj`, i.e. the object file was NOT being regenerated by the incremental path. The resulting EXE's code did not match the addresses being resolved from it, so the planted INT3 landed mid-instruction and corrupted execution.

**Why:** cost a long detour chasing a phantom debugger bug; the developer spotted it immediately ("Program crashes every time. Do a rebuild.") and the rebuild fixed it outright.

**How to apply:** when hand-editing .clw and then debugging at resolved RVAs, always build with `/t:Rebuild`, not `/t:Build`. Verify the build log actually contains a compile line (`made <name>.obj`) — if you only see `Making <name>.exe`, the source change did NOT make it into the binary. Also re-resolve line->RVA after every rebuild: addresses shift (line 30's ADD moved 0x10D8 -> 0x10DC, and frame layout moved MYQ from ebp-48 to ebp-52 when one LONG local was added).

`tags: msbuild,rebuild,ca-debugger,stale-binary,access-violation,breakpoint`

---

## Appendix: partial / unfinished work

Recorded so it is not lost and not re-derived. **Not implementable as written** — each entry states exactly what is missing.

### Runtime QUEUE field descriptor at ctrl+0x04 — header decoded, field records only partly; Cla$WHO/WHERE/HOWMANY are its walkers

*debug_insight | confidence: uncertain | knowledge-base entry 73 (PARTIAL)*

PARTIAL findings, recorded so the work is not lost. This became OPTIONAL once it was established that TSWD does carry reference-queue layout (see [[clarion-queue-reference-layout-is-in-tswd]]) — pursue only if layout is ever needed with no TSWD present at all.

**The descriptor is Clarion's generic GROUP field descriptor**, and the runtime exposes walkers for it. Every `Cla$XXXqueue` introspection export is a thin wrapper that unpacks the control block and delegates to the generic version:
```
Cla$XXXqueue(eax = control block, ebx = field index)
    ebx = [eax]        ; ctrl+0x00 = record image
    ecx = [eax+4]      ; ctrl+0x04 = DESCRIPTOR
    eax = 0
    call Cla$XXX
```
Generic walker RVAs in ClaRUN.dll: `Cla$GETGROUP 0x7E1C`, `Cla$ISGROUP 0x7FA8`, `Cla$HOWMANY 0x7FF4`, `Cla$WHO 0x8054`, `Cla$WHAT 0x80A0`, `Cla$WHERE 0x8124`. Queue wrappers: `Cla$GETGROUPqueue 0x7D1C`, `Cla$ISGROUPqueue 0x7D40`, `Cla$HOWMANYqueue 0x7D64`, `Cla$WHOqueue 0x7D88`, `Cla$WHATqueue 0x7DAC`, `Cla$WHEREqueue 0x7DF8`. Disassembling WHERE (offset), WHO (name) and HOWMANY (count) would give the field-record format exactly — that step was NOT done.

**Header decoded and verified** against `MyQLargeType` (STRING(320) + LONG,DIM(10), recordSize 360, 2 fields), descriptor at EXE RVA 0x2110:
```
+0x00  u16  0x0016          tag/kind
+0x02  u32  360             recordSize        (verified)
+0x06  u32  2               field count       (verified)
+0x0A  u32  0x25            length-ish (37; descriptor spans 40 bytes to the next one — not confirmed)
+0x0E  ...  field records with INLINE NUL-terminated names
```
Raw: `16 00 | 68 01 00 00 | 02 00 00 00 | 25 00 00 00 | 12 02 21 40 'TEST\0' 06 12 'NUMBERARR\0' 01 0A 00 00 00`
Descriptors are packed back-to-back: the next one begins at +0x28 and decodes as recordSize 200 / 1 field (MyQType) — a useful self-check.

**Field records NOT reliably decoded.** Observations only, do not implement against these: names are inline and NUL-terminated; a STRING field appears as `12 02 <2 bytes>` where the low 12 bits of those 2 bytes big-endian give the size (`21 40` -> 0x140 = 320; `20 C8` -> 0x0C8 = 200); the DIM(10) extent shows up as `0A 00 00 00` after the NUMBERARR name; per-field record length appears to vary by type. Field offsets were never located — `Cla$WHERE` is the function that would answer that definitively.

Note the header offsets are UNALIGNED (recordSize at +0x02, count at +0x06), consistent with the rest of the queue structures.


---

## Appendix: superseded findings

Kept deliberately, because both were reasonable readings of partial evidence and the reasoning is
instructive. **Do not implement against these** -- each is corrected by an entry above.

### Open question: exact row-data layout inside a QUEUE's +0x08 heap block

*debug_insight | confidence: uncertain | knowledge-base entry 58 (SUPERSEDED)*

After ADD(MyQ) with MyQ.Test='abc' (STRING(32)), the queue control block's +0x08 heap pointer led to a block whose first 16 bytes look like a self-describing header:
- +0x00: pointer into ClaRUN.dll's own data segment (possibly a shared type-descriptor/vtable-ish pointer, not per-instance)
- +0x04: same value as control-block+0x04 (record-descriptor pointer) — redundant copy
- +0x08: another pointer, exactly +0x90 (144) bytes further into the SAME allocation
- +0x0C: 1 — matches the single ADD; likely record COUNT

Following the +0x08 inner pointer (block+0x90) led to a further small structure: dwords {0, 32 (=record size), 0x17 (23), then THREE repeated pointers to the same ClaRUN.dll address, then 1, then zeros}. The literal bytes we wrote ('abc' = 0x61 0x62 0x63) were NOT found anywhere in the first 1024 bytes scanned from the +0x08 block start — so the actual row storage is either further away, behind one more pointer hop we haven't followed, or uses a paged/segmented allocation scheme (the 3 repeated pointers look like a generic pool/free-list node, possibly unrelated to this specific queue's row bytes).

**Why:** this is the missing piece for the CA Debugger's "read all queue records" feature — we know the header exists and roughly where the count lives, but not yet where individual record bytes are.

**How to apply / next steps to try:**
1. ADD 2-3 records with distinct content ('abc','def','ghi') and diff the block memory before/after each ADD — the bytes that change on each ADD are the real row storage, found empirically without full disassembly.
2. Dereference the repeated 0x5BA24848-style ClaRUN.dll pointers (likely a class vtable or shared type descriptor) — compare across two independently-declared QUEUE locals of different record shapes to see if it's per-type (shared) or per-instance.
3. Get a clean (non-mislabeled) disassembly of the actual private worker `call`ed from Cla$ADDqueue's first instruction (do this by resolving its address directly rather than relying on the IAT-nearest-name heuristic, which mislabels internal ClaRUN.dll helpers with the nearest EXPORTED name).
See [[clarun-queue-hidden-control-block]] and [[clarun-queue-add-free-disasm]] for what's already confirmed.

### CORRECTION: control-block+0x08 block's "+0x0C=1" is a constant type tag, NOT a record count

*debug_insight | confidence: confirmed | knowledge-base entry 59 (SUPERSEDED)*

Revises [[clarun-queue-record-storage-todo]]. Ran the 1-record test (MyQ.Test='abc') AND a 3-record test (ADD 'abc','def','ghi' sequentially) against a rebuilt Qtester.exe. In ALL captures — after 1 add, after 2 adds, after 3 adds — the allocated block at control-block+0x08 always showed the SAME header shape and +0x0C was ALWAYS exactly 1. A real per-queue record count would have incremented (1, then 2, then 3); it didn't. So +0x0C in that block is a constant/type tag (e.g. "this is a queue-storage-kind block"), not a live count.

Also: none of the literal record bytes ('abc'/'def'/'ghi' — 0x61 0x62 0x63 / 0x64 0x65 0x66 / 0x67 0x68 0x69) were found anywhere in the first 2048-4096 bytes scanned from the control-block+0x08 pointer, across any of the captures. And the block's address at +0x08 was DIFFERENT on every single ADD call (even just going from add#1 to add#2 within the same conceptual queue) — strongly suggesting this +0x08 block is a small, freshly-(re)allocated-per-call structure (maybe a transient cursor/scratch object used during the Add operation itself), NOT the persistent, growing row-storage array. The actual persistent multi-record storage must be reachable some other way — not yet found.

**Why:** empirical multi-ADD test was run specifically to falsify the "count" hypothesis recorded with only one data point; the revision is important so nobody builds the CA Debugger's queue-record reader against a wrong offset.

**How to apply / next steps:** Don't trust the +0x08 immediate block as "the record array". To find real row storage: (1) get a clean disassembly of the actual private worker Cla$ADDqueue calls (resolve its literal address directly, don't rely on IAT-nearest-name labelling which mislabels internal helpers), and read its pointer arithmetic byte-for-byte; or (2) set a hardware/memory write-watch on the known 'abc' bytes' source location (the record-image local) and see where the runtime copies them TO, which pins down the true destination empirically without guessing offsets.

---

*Exported from the Clarion Assistant knowledge base (`%%APPDATA%%\clarionassistant\memory.db`, entries 56-76) on 2026-08-04. Regenerate with `scratchpad/export_kb.py`.*
