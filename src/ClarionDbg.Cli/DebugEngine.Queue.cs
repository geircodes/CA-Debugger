using System;
using System.Collections.Generic;
using System.Text;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------------ QUEUE row enumeration
        //
        // Show every row of a live Clarion QUEUE using ONLY memory reads, so the debuggee's record
        // buffer, cursors and change counter are never disturbed. Calling a runtime entry point such as
        // Cla$GETqueueptr would overwrite the record buffer and bump numchanges — so we never do.
        //
        // Full derivation, per-storage-class evidence and the disassembly this is ported from:
        // docs/clarion-queue-internals.md. The walk itself is short:
        //
        //   recordSize = u32[ctrl + 0x0C]        authoritative — never sum TSWD member sizes
        //   obj        = u32[ctrl + 0x08]        NULL => the queue was never added to; 0 records
        //   order      = u32[obj  + 0x79]        the order the program itself currently sees
        //   count      = u32[order + 0x01]       identical to RECORDS(q)
        //   nodeArray  = u32[order + 0x05]       flat array of 4-byte node pointers
        //   node       = u32[nodeArray + i*4]
        //   dataPtr    = u32[node + 0x04]        raw row, or {u32 len; payload} when compressed
        //
        // Only *locating* ctrl differs per storage class, and that is what DiscoverQueueForSlot does.

        private const int CtrlRecordImage = 0x00;   // -> the record-image group
        private const int CtrlDescriptor  = 0x04;   // -> compiler-generated static field descriptor
        private const int CtrlQueueObject = 0x08;   // -> the runtime queue object (heap); 0 until first ADD
        private const int CtrlRecordSize  = 0x0C;

        private const int ObjCompressed = 0x2D;     // != 0 => rows are RLE-compressed
        private const int ObjCurOrder   = 0x79;     // -> the CURRENT order object
        private const int ObjOrderCount = 0x7D;

        private const int OrderCount     = 0x01;    // == RECORDS(q)
        private const int OrderNodeArray = 0x05;
        private const int NodeDataPtr    = 0x04;

        /// <summary>How many rows one <c>queuerows</c> reply will carry. The host pages with from/count and
        /// always learns the true total, so this only bounds a single JSON line — a real ABC browse queue can
        /// hold tens of thousands of rows.</summary>
        private const int QueueRowWindow = 200;

        /// <summary>A sanity ceiling on the row count read out of the target. `count` is authoritative for a
        /// healthy queue, but it is debuggee memory reached through several pointer hops — if a signature match
        /// was wrong, this is what stops a garbage dword from driving a multi-million-iteration read loop.</summary>
        private const int QueueCountCeiling = 5_000_000;

        /// <summary>A located live QUEUE: where its control block is, and the current order's row set.</summary>
        private sealed class QueueInfo
        {
            public uint Ctrl;
            public uint RecordImage;  // u32[ctrl+0x00] — the group the program's own MyQ.Field writes reach
            public uint RecordSize;
            public uint Obj;          // 0 => never added to (Cla$FREEqueue also nulls this on scope exit)
            public uint Order;
            public uint NodeArray;
            public int Count;
            public bool Compressed;
        }

        // ---------------------------------------------------------------- locating the control block

        /// <summary>Validate a candidate control-block address and read its queue state.
        ///
        /// The signature is deliberately BOTH conditions — <c>u32[ctrl+0x00] == recordImage</c> AND
        /// <c>u32[ctrl+0x0C] == recordSize</c>. Matching on size alone produced a false positive 140 bytes
        /// away during the reverse engineering. Pass <paramref name="expectRecordImage"/> as 0 to skip the
        /// first test (used when the caller already knows the address IS a control block, e.g. a NEW'd
        /// reference queue whose slot holds it directly).</summary>
        private QueueInfo ReadQueueAt(uint ctrl, uint expectedRecordSize, uint expectRecordImage)
        {
            if (ctrl == 0 || expectedRecordSize == 0) return null;
            var blk = new byte[16];
            if (ReadBlock(ctrl, blk) != 16) return null;

            uint image = U32At(blk, CtrlRecordImage);
            uint size  = U32At(blk, CtrlRecordSize);
            if (size != expectedRecordSize) return null;
            if (expectRecordImage != 0 && image != expectRecordImage) return null;
            if (image == 0) return null;

            var qi = new QueueInfo
            {
                Ctrl = ctrl,
                RecordImage = image,
                RecordSize = size,
                Obj = U32At(blk, CtrlQueueObject),
            };

            // A queue that was never added to (or that Cla$FREEqueue has already released on scope exit)
            // has a NULL object. That is a legitimate empty queue, not a failure — report 0 rows.
            if (qi.Obj == 0) return qi;

            // The queue object's fields are UNALIGNED (+0x2D, +0x79, +0x7D are all = 1 mod 4), so read a
            // block and index it byte-wise. Aligned dword reads here silently return shifted garbage.
            var obj = new byte[0x88];
            if (ReadBlock(qi.Obj, obj) < 0x81) return qi;

            qi.Compressed = U32At(obj, ObjCompressed) != 0;   // test != 0, never == 2 (see the doc)
            qi.Order = U32At(obj, ObjCurOrder);
            if (qi.Order == 0) return qi;

            var ord = new byte[16];
            if (ReadBlock(qi.Order, ord) != 16) { qi.Order = 0; return qi; }

            uint rawCount = U32At(ord, OrderCount);
            qi.NodeArray = U32At(ord, OrderNodeArray);
            if (rawCount > QueueCountCeiling || (rawCount > 0 && qi.NodeArray == 0)) { qi.Order = 0; return qi; }
            qi.Count = (int)rawCount;
            return qi;
        }

        /// <summary>Locate the QUEUE behind a frame slot, or null when the slot is not a queue at all.
        ///
        /// Doubles as queue DETECTION: a plain <c>&amp;GROUP</c> that is not a queue simply has no control
        /// block anywhere that satisfies the signature. There is no TSWD symbol for the control block — the
        /// compiler synthesises it with no debug record — so it can only be found dynamically.
        ///
        /// <paramref name="hops"/> is the reference depth <see cref="ClarionType.ResolveGroup"/> reported,
        /// which is exactly how many pointer reads reach the record image.</summary>
        private QueueInfo DiscoverQueueForSlot(uint slotVa, byte code, int hops, uint recordSize,
                                               uint frameEbp, List<LocalSym> locals)
        {
            if (recordSize == 0) return null;

            // A DIRECT group local (code 0x08, no reference hop): the local IS the record image, so scan the
            // frame for a control block pointing at the slot itself. This is the small-record shape from the
            // doc's first entry (record image inline on the frame, control block a few bytes away).
            bool byRef = code == 0x16 || hops > 0;
            if (!byRef)
                return ScanFrameForCtrl(slotVa, recordSize, frameEbp, locals);

            uint p = ReadU32(slotVa);
            if (p == 0) return null;

            // Two shapes reach here, and they are told apart by what `p` points at.
            //
            // (1) `p` IS the control block. True for a QUEUE PARAMETER (which arrives as a pointer to the
            //     caller's control block at ebp-4) and for a NEW'd `&MyQType` (whose reference slot holds the
            //     control block). Cheap to test directly, so try it first.
            //
            //     A NEW'd queue is self-validating: Cla$NEWqueue mallocs recordSize+0x10 and places the record
            //     image INLINE right after the 16-byte header, so u32[ctrl+0x00] == ctrl+0x10 exactly. Use
            //     that as the record-image expectation when it holds, which makes the match airtight; other-
            //     wise fall back to "points somewhere readable".
            var probe = new byte[16];
            if (ReadBlock(p, probe) == 16 && U32At(probe, CtrlRecordSize) == recordSize)
            {
                uint image = U32At(probe, CtrlRecordImage);
                bool inlineImage = image == p + 0x10;                 // the NEW'd self-check
                bool plausible = inlineImage || (image != 0 && image != p);
                if (plausible)
                {
                    var direct = ReadQueueAt(p, recordSize, inlineImage ? p + 0x10 : 0);
                    if (direct != null) return direct;
                }
            }

            // (2) `p` is the RECORD IMAGE — the large-record local shape, where the compiler puts the record
            //     on the heap and TSWD reports the local as a reference to it. The control block is still a
            //     16-byte frame slot, found by signature.
            return ScanFrameForCtrl(p, recordSize, frameEbp, locals);
        }

        /// <summary>Signature-scan the memory AROUND a record image for its control block. Used for global
        /// queues (static data) and for a resolved per-thread instance.
        ///
        /// The offset genuinely varies and must never be hardcoded: a non-threaded global's control block was
        /// measured 0x4C BELOW its record image, a threaded instance's at instance-0x18. Both fall inside the
        /// window below, and the two-condition signature is what makes the match trustworthy.</summary>
        private QueueInfo ScanNearImageForCtrl(uint recordImage, uint recordSize)
        {
            if (recordImage == 0) return null;
            const uint back = 0x200, fwd = 0x40;
            uint lo = recordImage > back ? recordImage - back : 0;
            int span = (int)(recordImage - lo + fwd);
            var win = new byte[span];
            int got = ReadBlock(lo, win);
            if (got < 16) return null;

            // Search from the record image BACKWARDS: every measured layout put the control block below the
            // image, so this finds the real one before any coincidental match further out.
            int start = (int)(recordImage - lo);
            for (int d = 0; d <= start; d += 4)
            {
                int off = start - d;
                if (off + 16 > got) continue;
                if (U32At(win, off + CtrlRecordImage) != recordImage) continue;
                if (U32At(win, off + CtrlRecordSize) != recordSize) continue;
                var qi = ReadQueueAt(lo + (uint)off, recordSize, recordImage);
                if (qi != null) return qi;
            }
            return null;
        }

        /// <summary>Signature-scan a stack frame for the 16-byte control block belonging to
        /// <paramref name="recordImage"/>. The control-block offset is NOT a constant — it moves when other
        /// locals are added, and differs per storage class — so never hardcode it.</summary>
        private QueueInfo ScanFrameForCtrl(uint recordImage, uint recordSize, uint frameEbp, List<LocalSym> locals)
        {
            if (frameEbp == 0 || recordImage == 0) return null;

            // Cover every named local plus headroom, since the control block can sit below all of them.
            int deepest = 128;
            if (locals != null)
                foreach (var l in locals)
                    if (-l.FrameOff + 64 > deepest) deepest = -l.FrameOff + 64;
            if (deepest > 4096) deepest = 4096;
            if (frameEbp < (uint)deepest) return null;

            uint lo = frameEbp - (uint)deepest;
            var win = new byte[deepest];
            int got = ReadBlock(lo, win);
            if (got < 16) return null;

            for (int off = 0; off + 16 <= got; off += 4)
            {
                if (U32At(win, off + CtrlRecordImage) != recordImage) continue;
                if (U32At(win, off + CtrlRecordSize) != recordSize) continue;
                var qi = ReadQueueAt(lo + (uint)off, recordSize, recordImage);
                if (qi != null) return qi;
            }
            return null;
        }

        // ---------------------------------------------------------------- reading rows

        /// <summary>Read and decode one row of a queue. Returns null when the row is unreadable or its
        /// compressed payload is malformed.</summary>
        private byte[] ReadQueueRow(QueueInfo qi, int index)
        {
            if (qi == null || qi.NodeArray == 0 || index < 0 || index >= qi.Count) return null;

            uint node = ReadU32(qi.NodeArray + (uint)index * 4);
            if (node == 0) return null;
            uint dataPtr = ReadU32(node + NodeDataPtr);
            if (dataPtr == 0) return null;

            int size = (int)qi.RecordSize;
            if (!qi.Compressed)
            {
                // Uncompressed node class: node+0x04 points straight at recordSize bytes of record data.
                var raw = new byte[size];
                return ReadBlock(dataPtr, raw) == size ? raw : null;
            }

            // Compressed node class: node+0x04 -> { u32 payloadLen; byte payload[] }. payloadLen == 0 means
            // the runtime stored a plain memcpy rather than a run-length stream (ClarionRle handles that).
            uint payloadLen = ReadU32(dataPtr);
            if (payloadLen > (uint)(size * 2 + 64)) return null;   // a stream never exceeds this in practice
            int n = payloadLen == 0 ? size : (int)payloadLen;
            var payload = new byte[n];
            if (ReadBlock(dataPtr + 4, payload) != n) return null;
            return ClarionRle.Decode(payload, (int)payloadLen, size);
        }

        // ---------------------------------------------------------------- rendering rows

        /// <summary>Render a decoded row's fields as JSON child rows, read out of the row BUFFER rather than
        /// from target memory. Mirrors <see cref="GroupChildrenJson"/>, with two deliberate differences:
        ///
        /// 1. No row field ever carries the edit quartet (va/typeCode/size/places). A row has no address in
        ///    the target — the bytes were decompressed on our side — and the UI keys its edit pencil purely on
        ///    the presence of "va", while HandleSetValCommand writes STRAIGHT to whatever address it is given
        ///    without re-resolving. Emitting a va here would hand the user a working-looking pencil that
        ///    corrupts unrelated memory in a live process. This viewer is read-only; keep it that way.
        /// 2. Nested groups expand EAGERLY. The lazy `expand` path re-reads members at an address, which a
        ///    buffer-sourced row cannot supply.</summary>
        private string RowFieldsJson(ClarionType g, byte[] row, string module)
        {
            if (g == null || g.Members == null || row == null) return "";
            var sb = new StringBuilder();
            bool first = true;
            foreach (var mb in g.Members)
            {
                if (!first) sb.Append(',');
                first = false;
                string mName = mb.Name ?? ("(unnamed+" + mb.Offset + ")");
                sb.Append(RowNodeJson(mName, mb.Type, row, mb.Offset, module));
            }
            return sb.ToString();
        }

        /// <summary>One field of a decoded row. Scalars and strings format out of the buffer; a reference to a
        /// group becomes a LAZY node against the address the row holds (real target memory, so the existing
        /// <c>expand</c> path serves it); arrays expand eagerly from the buffer.</summary>
        private string RowNodeJson(string name, ClarionType t, byte[] row, int off, string module)
        {
            var sb = new StringBuilder();
            sb.Append("{\"name\":").Append(Json.Str(name));

            int hops = 0;
            ClarionType g = t == null ? null : t.ResolveGroup(out hops);

            byte code, target; uint size; int places;
            CodeForType(t, out code, out target, out size, out places);
            bool byRef = code == 0x16 || (t != null && t.Kind == TypeKind.Reference);

            if (byRef && g != null)
            {
                // The row holds a pointer. Reading it out of the buffer IS the first of the hops
                // ResolveGroup counted, so only the REMAINING hops are process reads: a `&MyQType` member is
                // 2 hops (pointer -> control block -> record image), leaving exactly one deref here.
                uint ptr = U32At(row, off);
                int remaining = (hops < 1 ? 1 : hops) - 1;
                for (int i = 0; i < remaining && ptr != 0; i++) ptr = ReadU32(ptr);
                sb.Append(",\"type\":\"\"");
                if (ptr == 0)
                    sb.Append(",\"value\":").Append(Json.Str("(null)"));
                else
                    sb.Append(",\"value\":").Append(Json.Str("0x" + ptr.ToString("X")))
                      .Append(",\"ref\":true,\"addr\":\"0x").Append(ptr.ToString("X")).Append('"')
                      .Append(",\"module\":").Append(Json.Str(module))
                      .Append(",\"typeRef\":").Append(g.TypeRef);
            }
            else if (g != null)
            {
                sb.Append(",\"type\":\"\",\"value\":").Append(Json.Str("{…}"));
                sb.Append(",\"children\":[").Append(RowFieldsJson(g, row, module)).Append(']');
            }
            else if (t != null && t.Kind == TypeKind.Array)
            {
                int hi = t.LoBound + t.Length - 1;
                sb.Append(",\"type\":").Append(Json.Str(t.Length > 0 ? "ARRAY[" + t.LoBound + ".." + hi + "]" : "ARRAY"));
                sb.Append(",\"value\":").Append(Json.Str("[…]"));
                string kids = RowArrayJson(t, row, off, module);
                if (kids.Length > 0) sb.Append(",\"children\":[").Append(kids).Append(']');
            }
            else
            {
                // A string/CSTRING reference field spans 8 bytes in the row: the pointer, then the ALLOCATED
                // SIZE of the buffer it points at. Read that word from the ROW (a compressed row has no
                // address, so the peek GroupChildrenJson does at mva+4 cannot be a process read here). For
                // &STRING the word is the authoritative length; for &CSTRING only an upper bound, which is
                // why the renderer still scans to the NUL within it.
                if (code == 0x16 && target == 0x18 && size == 0)
                {
                    uint w = U32At(row, off + 4);
                    if (w > 0 && w <= 8192) size = w;
                }
                string val = FormatValueInRow(code, target, size, places, row, off);
                bool isNullRef = code == 0x16 && val == "(null)";
                sb.Append(",\"type\":").Append(Json.Str(ClarionTypeLabel(code, target, size, places, isNullRef)));
                sb.Append(",\"value\":").Append(Json.Str(val));
                // NO edit metadata — see the class comment on RowFieldsJson.
            }
            sb.Append('}');
            return sb.ToString();
        }

        private string RowArrayJson(ClarionType arr, byte[] row, int baseOff, string module)
        {
            if (arr == null || arr.Length <= 0 || arr.ElemSize == 0) return "";
            const int cap = 1000;
            int n = Math.Min(arr.Length, cap);
            var sb = new StringBuilder();
            for (int k = 0; k < n; k++)
            {
                if (k > 0) sb.Append(',');
                sb.Append(RowNodeJson("[" + (arr.LoBound + k) + "]", arr.ElemType, row,
                                      baseOff + k * (int)arr.ElemSize, module));
            }
            if (arr.Length > cap)
                sb.Append(",{\"name\":").Append(Json.Str("…"))
                  .Append(",\"type\":\"\",\"value\":").Append(Json.Str((arr.Length - cap) + " more")).Append('}');
            return sb.ToString();
        }

        // ---------------------------------------------------------------- the queuerows command

        /// <summary>queuerows reqId module typeRef ctrl [from] [count] — enumerate a located queue's rows.
        /// Stateless by design: discovery already happened where the frame pointer was in hand, so this needs
        /// only the control block and the record's typeRef. Read-only; no target code runs.</summary>
        private void HandleQueueRowsCommand(string[] parts)
        {
            if (parts.Length < 5) { EmitError("queuerows expects: queuerows reqId module typeRef ctrl [from] [count]"); return; }
            string reqId = parts[1];
            string module = parts[2];
            uint typeRef; uint.TryParse(parts[3], out typeRef);
            uint ctrl = ParseHexU(parts[4]);
            int from = 0, want = QueueRowWindow;
            if (parts.Length > 5) int.TryParse(parts[5], out from);
            if (parts.Length > 6 && int.TryParse(parts[6], out want) && want <= 0) want = QueueRowWindow;
            if (from < 0) from = 0;
            if (want > QueueRowWindow) want = QueueRowWindow;

            var m = ModuleByName(module);
            ClarionType g = null;
            if (m != null && m.Dbg != null)
            {
                var t = m.Dbg.ResolveType(typeRef);
                g = (t != null && t.Kind == TypeKind.Group) ? t : GroupTypeOf(t);
            }

            if (g == null) { EmitQueueRowsError(reqId, "could not resolve the record layout for typeRef " + typeRef); return; }

            var qi = ReadQueueAt(ctrl, g.Size, 0);
            if (qi == null) { EmitQueueRowsError(reqId, "0x" + ctrl.ToString("X") + " is not a queue control block for this record"); return; }
            EmitQueueRows(reqId, module, g, qi, from, want);
        }

        /// <summary>Decode and emit a window of a located queue's rows.</summary>
        private void EmitQueueRows(string reqId, string module, ClarionType g, QueueInfo qi, int from, int want)
        {
            var rows = new List<string>();
            int end = Math.Min(qi.Count, from + want);
            for (int i = from; i < end; i++)
            {
                // `count` is the ONLY authority on how many rows exist. DELETE compacts the node array but
                // leaves a live-looking STALE pointer in the vacated slot, so a reader that scanned to NULL
                // (or trusted the array's allocated size) would render the last row twice.
                var row = ReadQueueRow(qi, i);
                var sb = new StringBuilder();
                sb.Append("{\"name\":").Append(Json.Str("[" + (i + 1) + "]"));
                if (row == null)
                    sb.Append(",\"type\":\"\",\"value\":").Append(Json.Str("<unreadable row>"));
                else
                    sb.Append(",\"type\":\"\",\"value\":").Append(Json.Str("{…}"))
                      .Append(",\"children\":[").Append(RowFieldsJson(g, row, module)).Append(']');
                sb.Append('}');
                rows.Add(sb.ToString());
            }

            if (EmitJson)
                Console.WriteLine("@JSON {\"event\":\"queuerows\",\"reqId\":" + Json.Str(reqId)
                    + ",\"total\":" + qi.Count
                    + ",\"from\":" + from
                    + ",\"compressed\":" + (qi.Compressed ? "true" : "false")
                    + ",\"items\":[" + string.Join(",", rows) + "]}");
            else
                Console.WriteLine($"  queue at 0x{qi.Ctrl:X}: {qi.Count} record(s), recordSize {qi.RecordSize}"
                    + $", {(qi.Compressed ? "compressed" : "raw")}, showing {rows.Count} from {from}");
        }

        /// <summary>queuerowsname reqId NAME [from] — rows of a GLOBAL (module-scope) queue, by name.
        ///
        /// Separate from <c>queuerows</c> because a global cannot supply a control block up front: a plain
        /// global needs a static-data signature scan, and a THREADed one (declared <c>QUEUE,THREAD</c>, living
        /// in .cwtls) needs the THR$GetInstance func-eval first, since its TSWD address is only a template.
        ///
        /// Returns true when a func-eval was armed — the caller must then leave the pause loop, exactly as
        /// <c>watch</c> does; the continuation finishes the walk and emits the same <c>queuerows</c> event.</summary>
        private bool HandleQueueRowsByNameCommand(string[] parts, uint tid, IntPtr hThread,
                                                 ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            if (parts.Length < 3) { EmitError("queuerowsname expects: queuerowsname reqId NAME [from]"); return false; }
            string reqId = parts[1];
            string name = parts[2];
            int from = 0;
            if (parts.Length > 3) int.TryParse(parts[3], out from);
            if (from < 0) from = 0;

            LoadedModule owner; DataSymbol ds;
            if (!TryFindDataSymbol(name, out owner, out ds))
            {
                EmitQueueRowsError(reqId, "no module-scope data symbol named " + name);
                return false;
            }
            var g = (ds.Type != null && ds.Type.Kind == TypeKind.Group) ? ds.Type : GroupTypeOf(ds.Type);
            if (g == null || g.Size == 0)
            {
                EmitQueueRowsError(reqId, name + " has no resolved record layout");
                return false;
            }

            uint templateVa = owner.LoadBase + ds.Rva;
            bool threaded = owner.CwtlsHi != 0 && ds.Rva >= owner.CwtlsLo && ds.Rva < owner.CwtlsHi;

            if (!threaded)
            {
                var qi = ScanNearImageForCtrl(templateVa, g.Size);
                if (qi == null) { EmitQueueRowsError(reqId, name + " is not a queue (no control block found near its record image)"); return false; }
                EmitQueueRows(reqId, owner.Name, g, qi, from, QueueRowWindow);
                return false;
            }

            // THREADed: the TSWD address is only a template. Resolve THIS thread's instance by func-eval, then
            // finish the (pure-read) walk in the continuation. Capture everything the continuation needs —
            // `ctx` must NOT be captured, it is a ref parameter.
            int capturedFrom = from;
            var capturedG = g;
            string capturedModule = owner.Name;
            return BeginThreadedEval(owner, templateVa, tid, hThread, ref ctx, haveCtx, "queuerows " + name,
                instanceVa =>
                {
                    if (instanceVa == 0)
                    {
                        EmitQueueRowsError(reqId, name + ": could not resolve the per-thread instance");
                        return;
                    }
                    // The per-thread block is a fixed-up COPY of the .cwtls template at identical internal
                    // offsets, so the control block sits near the instance exactly as it does near a static
                    // record image — measured at instance-0x18, but scanned for rather than assumed.
                    var qi = ScanNearImageForCtrl(instanceVa, capturedG.Size);
                    if (qi == null)
                    {
                        EmitQueueRowsError(reqId, name + ": no control block found near the per-thread instance 0x"
                                                  + instanceVa.ToString("X"));
                        return;
                    }
                    EmitQueueRows(reqId, capturedModule, capturedG, qi, capturedFrom, QueueRowWindow);
                });
        }

        /// <summary>Find a module-scope data symbol by name across every loaded image with debug info. Returns
        /// the owning module so .cwtls membership (and therefore THREADed-ness) can be tested against it.</summary>
        private bool TryFindDataSymbol(string name, out LoadedModule owner, out DataSymbol sym)
        {
            owner = null; sym = null;
            foreach (var m in _modules)
            {
                if (m == null || m.Dbg == null || m.Dbg.DataSymbols == null) continue;
                foreach (var ds in m.Dbg.DataSymbols)
                    if (string.Equals(ds.Name, name, StringComparison.OrdinalIgnoreCase))
                    {
                        owner = m; sym = ds; return true;
                    }
            }
            return false;
        }

        /// <summary>Always answer a queuerows request, even on failure: the host resolves its pending callback
        /// by reqId and has no timeout, so a silent drop leaves the row spinning forever.</summary>
        private void EmitQueueRowsError(string reqId, string error)
        {
            if (EmitJson)
                Console.WriteLine("@JSON {\"event\":\"queuerows\",\"reqId\":" + Json.Str(reqId)
                    + ",\"total\":0,\"from\":0,\"items\":[],\"error\":" + Json.Str(error) + "}");
            Console.WriteLine("  queuerows: " + error);
        }

        private static uint U32At(byte[] b, int off)
        {
            if (b == null || off < 0 || off + 4 > b.Length) return 0;
            return BitConverter.ToUInt32(b, off);
        }
    }
}
