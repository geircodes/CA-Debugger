using System;
using System.Collections.Generic;
using System.Text;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------------ locals (Variables panel)
        //
        // Value rendering (FormatValueAt / FormatBcd) lives in DebugEngine.ValueFormat.cs — it is shared
        // with watch, globals, breakpoint conditions, and QUEUE rows.

        /// <summary>Build the JSON rows for one frame's locals — its proc's entry RVA keys the local set,
        /// each value read live at [frameEbp + frameOffset]. Direct GROUP locals expand inline to nested member
        /// rows; reference locals (incl. by-ref GROUP/QUEUE) are lazy (expanded on demand). Shared by the
        /// method and host-procedure groups. <paramref name="module"/> tags ref rows so the host can request
        /// expansion against the right image's TSWD.</summary>
///        private List<string> LocalRowsFor(LoadedModule m, uint entryRva, uint frameEbp)
///        {
///            var rows = new List<string>();
///            List<LocalSym> locals;
///            if (m != null && m.Dbg != null && m.Dbg.ReadLocals().TryGetValue(entryRva, out locals))
///                foreach (var l in locals)
///                {
///                    uint slotVa = (uint)((long)frameEbp + l.FrameOff);
///                    rows.Add(NodeJson(l.Name, l.Type, l.TypeCode, l.Target, l.Size, l.Places, slotVa, l.FrameOff, m.Name));
///                }
///            return rows;
///        }


		private List<string> LocalRowsFor(LoadedModule m, uint entryRva, uint frameEbp, bool suppressSelf)
		{
			var rows = new List<string>();
			List<LocalSym> locals;
			if (m != null && m.Dbg != null && m.Dbg.ReadLocals().TryGetValue(entryRva, out locals))
				foreach (var l in locals)
				{
					if (suppressSelf
						&& string.Equals(l.Name, "SELF", StringComparison.OrdinalIgnoreCase)
						&& l.TypeCode == 0x16)
						continue;
					uint slotVa = (uint)((long)frameEbp + l.FrameOff);
					// Queue discovery has to happen HERE, while the frame pointer is in hand: locating a
					// local queue's control block means signature-scanning its frame. The node then carries
					// ctrl + the live count, so the row-fetch command needs no frame of its own.
					var qi = TryDiscoverQueueLocal(l, slotVa, frameEbp, locals);
					rows.Add(NodeJson(l.Name, l.Type, l.TypeCode, l.Target, l.Size, l.Places,
									  slotVa, l.FrameOff, m.Name, qi));
				}
			return rows;
		}

		/// <summary>Is this local a live QUEUE? Returns its located control block + row count, or null for
		/// any local that is not a queue (which is most of them — a plain &amp;GROUP has no control block).</summary>
		private QueueInfo TryDiscoverQueueLocal(LocalSym l, uint slotVa, uint frameEbp, List<LocalSym> locals)
		{
			if (l == null || l.Type == null) return null;
			int hops;
			var g = l.Type.ResolveGroup(out hops);
			if (g == null || g.Size == 0) return null;
			return DiscoverQueueForSlot(slotVa, l.TypeCode, hops, g.Size, frameEbp, locals);
		}





        /// <summary>framelocals reqId va ebp — the locals of ONE call-stack frame (the Call-Stack-driven
        /// Variables model). Reads the frame's symbol locals at the supplied EBP. A ROUTINE has no frame of
        /// its own (it runs on its procedure's frame via DO), so a routine frame surfaces its enclosing
        /// procedure's locals read at the same EBP; a METHOD's enclosing procedure is a SEPARATE stack frame,
        /// so methods show only their own. Emits a `framelocals` event keyed by reqId. Read-only.</summary>
		private void HandleFrameLocalsCommand(string[] parts)
		{
			if (parts.Length < 4) { EmitError("framelocals expects: framelocals reqId va ebp"); return; }
			string reqId = parts[1];
			uint va = ParseHexU(parts[2]);
			uint ebp = ParseHexU(parts[3]);
			var rows = new List<string>();
			var m = ModuleAt(va);
			ProcSymbol sym;
			if (m != null && m.Dbg != null && ebp != 0 && m.Dbg.ResolveSymbolVerified(va - m.LoadBase, out sym))
			{
				uint entry = sym.EntryRva;
				if (sym.Kind == SymbolKind.Routine)
				{
					uint pe = EnclosingProcedureEntry(m, va - m.LoadBase);
					if (pe != 0) entry = pe;
				}

				uint queryRva = va - m.LoadBase;
				uint nextEntry = m.Dbg.NextSymbolEntryRva(sym.EntryRva);
				bool inGap = sym.Kind == SymbolKind.Method
							 && nextEntry != 0
							 && queryRva >= nextEntry;
				Console.WriteLine("@JSON {\"event\":\"console\",\"level\":\"warn\",\"text\":\"GAP CHECK:"
					+ " sym=" + sym.Name
					+ " kind=" + sym.Kind
					+ " entryRva=0x" + sym.EntryRva.ToString("X")
					+ " nextEntry=0x" + nextEntry.ToString("X")
					+ " queryRva=0x" + queryRva.ToString("X")
					+ " inGap=" + inGap + "\"}");
				rows = LocalRowsFor(m, entry, ebp, inGap);
			}
			if (EmitJson)
				Console.WriteLine("@JSON {\"event\":\"framelocals\",\"reqId\":" + Json.Str(reqId)
					+ ",\"items\":[" + string.Join(",", rows) + "]}");
		}

        /// <summary>The entry RVA of the procedure that lexically contains <paramref name="rva"/> — the
        /// greatest Procedure-kind symbol entry at or below it. Used to map a routine frame to its host
        /// procedure (they share a stack frame). 0 when none precedes.</summary>
        private static uint EnclosingProcedureEntry(LoadedModule m, uint rva)
        {
            uint best = 0;
            if (m == null || m.Dbg == null || m.Dbg.Symbols == null) return 0;
            foreach (var s in m.Dbg.Symbols)   // sorted ascending by EntryRva
                if (s.Kind == SymbolKind.Procedure && s.EntryRva <= rva && s.EntryRva >= best)
                    best = s.EntryRva;
            return best;
        }

        /// <summary>Resolve a named local of the CURRENTLY-EXECUTING frame (frame 0): map the paused EIP to its
        /// procedure (a ROUTINE shares its host procedure's frame, so route to the enclosing proc), then find a
        /// local of that name (case-insensitive) in the proc's <see cref="LocalSym"/> set and compute its live
        /// slot at [EBP + FrameOff]. Locals always live on the stack — never .cwtls — so the read is a direct,
        /// synchronous one (no THR$GetInstance func-eval). Returns false when not paused-with-context, the owning
        /// image has no debug info, or this frame declares no local of that name. Used by `watch NAME` so a
        /// procedure-local shadows a same-named global while we are paused inside its frame.</summary>
        private bool TryResolveLocalInCurrentFrame(ref Native.CONTEXT_X86 ctx, bool haveCtx, string name,
            out uint slotVa, out LocalSym found, out LoadedModule owner)
        {
            slotVa = 0; found = null; owner = null;
            if (!haveCtx || ctx.Ebp == 0) return false;
            var m = ModuleAt(ctx.Eip);
            if (m == null || m.Dbg == null) return false;
            ProcSymbol sym;
            if (!m.Dbg.ResolveSymbolVerified(ctx.Eip - m.LoadBase, out sym)) return false;
            uint entry = sym.EntryRva;
            if (sym.Kind == SymbolKind.Routine)
            {
                uint pe = EnclosingProcedureEntry(m, ctx.Eip - m.LoadBase);
                if (pe != 0) entry = pe;
            }
            List<LocalSym> locals;
            if (!m.Dbg.ReadLocals().TryGetValue(entry, out locals) || locals == null) return false;
            foreach (var l in locals)
                if (string.Equals(l.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    found = l; owner = m;
                    slotVa = (uint)((long)ctx.Ebp + l.FrameOff);
                    return true;
                }
            return false;
        }

        /// <summary>True when <paramref name="name"/> is declared as a local in SOME procedure of any loaded image
        /// (locals are cached, so this is cheap after first build). Lets a watch miss tell "out of scope right now"
        /// (a known local of a procedure we are not currently paused in) apart from a genuinely unknown name.</summary>
        private bool IsKnownLocalName(string name)
        {
            if (NameInAnyLocalSet(_exe, name)) return true;
            foreach (var m in _modules)
            {
                if (m == _exe) continue;
                if (NameInAnyLocalSet(m, name)) return true;
            }
            return false;
        }

        private static bool NameInAnyLocalSet(LoadedModule m, string name)
        {
            if (m == null || m.Dbg == null) return false;
            foreach (var kv in m.Dbg.ReadLocals())
                foreach (var l in kv.Value)
                    if (string.Equals(l.Name, name, StringComparison.OrdinalIgnoreCase))
                        return true;
            return false;
        }

        /// <summary>The GROUP/QUEUE layout a type describes — directly (a group) or through any number of
        /// reference hops. Returns null for non-aggregates. See <see cref="ClarionType.ResolveGroup"/>: a
        /// `&amp;QUEUE` local is reference-&gt;reference-&gt;group, so stopping at one hop (as this used to)
        /// left reference queues with no members at all.</summary>
        private static ClarionType GroupTypeOf(ClarionType t)
        {
            int hops;
            return GroupTypeOf(t, out hops);
        }

        /// <summary>As <see cref="GroupTypeOf(ClarionType)"/>, but also reports how many pointer
        /// dereferences reach the aggregate — 1 for `QUEUE(T)` (slot -&gt; record image), 2 for `&amp;T`
        /// (slot -&gt; control block -&gt; record image).</summary>
        private static ClarionType GroupTypeOf(ClarionType t, out int hops)
        {
            hops = 0;
            return t == null ? null : t.ResolveGroup(out hops);
        }

        /// <summary>The single composite value renderer. Three shapes:
        ///  • a DIRECT GROUP/QUEUE -> eager inline "children" (members read live at va + offset);
        ///  • a REFERENCE to a group/queue/class -> a LAZY node ("ref":true + addr/module/typeRef) the host
        ///    expands on demand via the `expand` command (avoids chasing deep/cyclic ABC object graphs);
        ///  • everything else -> a leaf through the shared FormatValueAt/ClarionTypeLabel.
        /// <paramref name="module"/> is the owning image's name, echoed on ref rows for re-resolution.
        /// <paramref name="queue"/>, when non-null, marks this node as a live QUEUE and carries its control
        /// block + row count so the host can offer a RECORDS child that fetches rows on demand.</summary>
        private string NodeJson(string name, ClarionType type, byte code, byte target, uint size, int places, uint va, int? frameOff, string module, QueueInfo queue = null)
        {
            var sb = new StringBuilder();
            sb.Append("{\"name\":").Append(Json.Str(name));
            int refHops;
            ClarionType g = GroupTypeOf(type, out refHops);

            // A slot is by-reference if its symbol code says so (0x16) OR its type record resolved to a
            // Reference. Key the deref decision on EITHER, not on Kind alone: a code-0x16 local whose typeRef
            // points straight at a 0x08 GROUP (Kind=Group, no Reference hop) must still be dereferenced —
            // reading it inline at the slot would render the pointer bytes as the first member (garbage).
            bool byRef = code == 0x16 || (type != null && type.Kind == TypeKind.Reference);

            if (byRef && g != null)
            {
                // by-ref group/queue/class: the slot holds a pointer. Mirror the old Clarion debugger —
                // show the POINTER (no "&GROUP" type noise) — and make the row ITSELF the lazy deref node
                // (ref:true + addr/module/typeRef), so expanding it goes straight to the members. No nested
                // "RECORD" hop in between: that was an extra, unnecessary click to get from the variable to
                // its own content. Still avoids blindly chasing pointers — expansion only happens on click.
                // Follow ONE deref per reference hop. A `QUEUE(T)` slot holds the record image (1 hop), but a
                // `&T` slot holds the QUEUE CONTROL BLOCK (2 hops) whose +0x00 is the record image — expanding
                // after a single deref there would render the 16-byte control header as the first members.
                // A code-0x16 slot whose typeRef points straight at a GROUP reports 0 hops yet is still a
                // pointer, so never deref fewer than once.
                int derefs = refHops < 1 ? 1 : refHops;
                uint ptr = va;
                for (int i = 0; i < derefs && ptr != 0; i++) ptr = ReadU32(ptr);
                // A QUEUE PARAMETER breaks the "reference depth == pointer depth" rule: it arrives as a
                // pointer to the CALLER's 16-byte control block, yet TSWD still reports it as a single hop
                // (reference -> group). So the loop above lands on the control block, not the record image —
                // which would render the control header's four dwords as the record's first members AND, since
                // the leaf path emits edit metadata, offer an edit pencil that writes over the live queue's
                // control block. Queue discovery already resolved the real record image, so use it.
                if (queue != null && ptr != 0 && ptr == queue.Ctrl && queue.RecordImage != 0)
                    ptr = queue.RecordImage;
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
                // direct GROUP/QUEUE instance: inline members, no "GROUP" type label (the {…}/fields convey it).
                sb.Append(",\"type\":\"\",\"value\":").Append(Json.Str("{…}"));
                sb.Append(",\"children\":[").Append(GroupChildrenJson(g, va, module)).Append(']');
            }
            else if (type != null && type.Kind == TypeKind.Array)
            {
                int hi = type.LoBound + type.Length - 1;
                sb.Append(",\"type\":").Append(Json.Str(type.Length > 0 ? "ARRAY[" + type.LoBound + ".." + hi + "]" : "ARRAY"));
                sb.Append(",\"value\":").Append(Json.Str("[…]"));
                string kids = ArrayChildrenJson(type, va, module);
                if (kids.Length > 0) sb.Append(",\"children\":[").Append(kids).Append(']');
            }
            else
            {
                string val = FormatValueAt(code, target, size, places, va);
                bool isNullRef = code == 0x16 && val == "(null)";
                sb.Append(",\"type\":").Append(Json.Str(ClarionTypeLabel(code, target, size, places, isNullRef)));
                sb.Append(",\"value\":").Append(Json.Str(val));
                // edit-variable-value: carry the live address + type so the UI can write the cell back.
                // Only editable scalar codes get this; refs/groups/unknowns stay read-only (no metadata).
                if (IsEditableCode(code))
                    sb.Append(",\"va\":\"0x").Append(va.ToString("X")).Append('"')
                      .Append(",\"typeCode\":\"0x").Append(code.ToString("X2")).Append('"')
                      .Append(",\"size\":").Append(size)
                      .Append(",\"places\":").Append(places);
            }
            if (frameOff.HasValue) sb.Append(",\"frameOff\":").Append(frameOff.Value);
            // A live QUEUE advertises its rows here. The node keeps its normal record-buffer expansion — the
            // record image is what the program itself is looking at — and the host adds a RECORDS child that
            // pulls stored rows via `queuerows`. Emitted even when records is 0, so an empty queue still reads
            // as a queue rather than as a plain group.
            if (queue != null && g != null)
                sb.Append(",\"queueCtrl\":\"0x").Append(queue.Ctrl.ToString("X")).Append('"')
                  .Append(",\"records\":").Append(queue.Count)
                  .Append(",\"queueTypeRef\":").Append(g.TypeRef);
            sb.Append('}');
            return sb.ToString();
        }

        /// <summary>Render a group's members as a JSON row array, each read at <paramref name="baseVa"/> + its
        /// byte offset. Shared by inline direct-group expansion and the on-demand <c>expand</c> handler.</summary>
        private string GroupChildrenJson(ClarionType g, uint baseVa, string module)
        {
            if (g == null || g.Members == null) return "";

            // A &STRING's own type record can never carry its current length — it's a dynamically-sized
            // allocation, sized only at runtime, so there's nothing for the compiler to embed statically
            // (confirmed against StringTheory's private `value` field: its type record's "count" is a
            // FFFFFFFF/unknown sentinel, not a real length). StringTheory itself tracks the DATA length
            // (how much of the allocated buffer is actually used — NOT the buffer's allocated capacity) in
            // a sibling `_DATAEND` int, unique to this one class — verified byte-exact against Clarion's own
            // native debugger (which showed the pointer's 16-byte content) by reading raw process memory:
            // _DATAEND held exactly 16 at the offset immediately preceding a cached copy of the same pointer
            // (VALUEPTR). Read it once per group so the `VALUE` member below can use it. `VALUE` itself is
            // now resolved by ParseType's own name-recovery (see TswdDebugInfo.cs), not guessed here.
            uint? dataEndLen = null;
            foreach (var dm in g.Members)
            {
                if (!string.Equals(dm.Name, "_DATAEND", StringComparison.OrdinalIgnoreCase) || dm.Type == null) continue;
                byte dc, dt; uint dsz; int dpl;
                CodeForType(dm.Type, out dc, out dt, out dsz, out dpl);
                if (dc != 0x11 && dc != 0x12) break;   // only trust a plain int/uint sibling
                string dv = FormatValueAt(dc, dt, dsz, dpl, (uint)((long)baseVa + dm.Offset));
                int parsed;
                if (int.TryParse(dv, out parsed) && parsed > 0) dataEndLen = (uint)parsed;
                break;
            }

            var sb = new StringBuilder();
            bool first = true;
            foreach (var mb in g.Members)
            {
                byte mc, mt; uint msz; int mpl;
                CodeForType(mb.Type, out mc, out mt, out msz, out mpl);
                uint mva = (uint)((long)baseVa + mb.Offset);
                // Apply the sibling _DATAEND length ONLY to StringTheory's `value` — other &STRING members
                // in the same group (e.g. LASTERROR) are separate, independently-allocated buffers and must
                // keep their own best-effort bounded read.
                if (mc == 0x16 && mt == 0x18 && msz == 0 && dataEndLen.HasValue
                    && string.Equals(mb.Name, "VALUE", StringComparison.OrdinalIgnoreCase))
                {
                    msz = dataEndLen.Value;
                }
                else if (mc == 0x16 && mt == 0x18 && msz == 0)
                {
                    // Clarion's native NEW(STRING(n)) allocator (used for ANY plain &STRING, including both
                    // StringTheory's `value` and its `LASTERROR`) leaves the ALLOCATED BUFFER SIZE in the 4
                    // bytes immediately following the pointer's OWN slot in this struct — verified for
                    // LASTERROR against Clarion's native debugger (`SELF.LastError &= NEW STRING(1)` in
                    // Construct: held 1, content was one space). This is buffer CAPACITY, not necessarily
                    // the true content length (only StringTheory's own `_DATAEND` tracks that, and only for
                    // `value`) — it just gives the type label something better than "?" to show. The actual
                    // on-screen text is capped hard at 32 bytes downstream regardless (FormatValueAt), so an
                    // over-large capacity here only affects the label, never a garbage-inflated read.
                    string peek = FormatValueAt(0x11, 0, 4, 0, mva + 4);
                    int candidate;
                    if (int.TryParse(peek, out candidate) && candidate > 0 && candidate <= 8192)
                        msz = (uint)candidate;
                }
                if (!first) sb.Append(',');
                first = false;
                // A null name means the compiler itself emitted no name-pool reference for this member AND
                // ParseType's own pool-based recovery (TswdDebugInfo.cs) couldn't resolve it either — a
                // genuinely unrecoverable case. Falling back to a bare "?" would make every such member
                // visually indistinguishable; tag it with its byte offset instead so it stays identifiable.
                string mName = mb.Name ?? ("(unnamed+" + mb.Offset + ")");
                sb.Append(NodeJson(mName, mb.Type, mc, mt, msz, mpl, mva, null, module));
            }
            return sb.ToString();
        }

        /// <summary>Render an array's elements as JSON child rows, each read at baseVa + k*stride. Scalar/string
        /// elements are eager leaves; GROUP elements become LAZY in-place nodes (ref:true + addr/typeRef) that
        /// reuse the on-demand <c>expand</c> path — so an array-of-group doesn't explode into members until a
        /// row is opened, and the expand handler reads members at the element's address directly (no deref).
        /// Capped to keep the DOM bounded on very large DIMs.</summary>
        private string ArrayChildrenJson(ClarionType arr, uint baseVa, string module)
        {
            if (arr == null || arr.Length <= 0 || arr.ElemSize == 0) return "";
            const int cap = 1000;
            int n = Math.Min(arr.Length, cap);
            var elem = arr.ElemType;
            var sb = new StringBuilder();
            for (int k = 0; k < n; k++)
            {
                if (k > 0) sb.Append(',');
                uint eva = (uint)((long)baseVa + (long)k * arr.ElemSize);
                string idx = "[" + (arr.LoBound + k) + "]";
                if (elem != null && elem.Kind == TypeKind.Group)
                {
                    sb.Append("{\"name\":").Append(Json.Str(idx))
                      .Append(",\"type\":\"GROUP\",\"value\":").Append(Json.Str("{…}"))
                      .Append(",\"ref\":true,\"addr\":\"0x").Append(eva.ToString("X")).Append('"')
                      .Append(",\"module\":").Append(Json.Str(module))
                      .Append(",\"typeRef\":").Append(elem.TypeRef).Append('}');
                }
                else
                {
                    byte ec, et; uint esz; int epl;
                    CodeForType(elem, out ec, out et, out esz, out epl);
                    sb.Append(NodeJson(idx, elem, ec, et, esz, epl, eva, null, module));
                }
            }
            if (arr.Length > cap)
                sb.Append(",{\"name\":").Append(Json.Str("…"))
                  .Append(",\"type\":\"\",\"value\":").Append(Json.Str((arr.Length - cap) + " more")).Append('}');
            return sb.ToString();
        }

        /// <summary>On-demand expansion of a reference node: re-resolve its referent type in the owning image's
        /// TSWD and render that group's members read live at the dereferenced address. Emits an `expanded`
        /// event keyed by the host's reqId. Read-only — no target code runs.</summary>
        private void HandleExpandCommand(string[] parts)
        {
            // expand <reqId> <module> <typeRef(dec)> <addr(hex)>
            if (parts.Length < 5) { EmitError("expand expects: expand reqId module typeRef addr"); return; }
            string reqId = parts[1];
            uint typeRef; uint.TryParse(parts[3], out typeRef);
            uint addr = ParseHexU(parts[4]);
            var rows = new List<string>();
            var m = ModuleByName(parts[2]);
            if (m != null && m.Dbg != null && addr != 0)
            {
                var t = m.Dbg.ResolveType(typeRef);
                var g = (t != null && t.Kind == TypeKind.Group) ? t : GroupTypeOf(t);
                if (g != null) rows.Add(GroupChildrenJson(g, addr, parts[2]));
            }
            if (EmitJson)
                Console.WriteLine("@JSON {\"event\":\"expanded\",\"reqId\":" + Json.Str(reqId)
                    + ",\"items\":[" + string.Join("", rows) + "]}");
        }

        private static uint ParseHexU(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s.Substring(2);
            uint v;
            uint.TryParse(s, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out v);
            return v;
        }

        /// <summary>Map a resolved member type to the flat (code,target,size,places) the value renderer takes.
        /// Reference/class-ref tags (0x16/0x26/0x29) render as a pointer, UNLESS the referent is a GROUP (lazy
        /// expand, target=0x08) or a STRING/CHAR (dereference inline, target=0x18 + the referent's own length —
        /// mirrors what ReadLocals() already does for a top-level `&STRING` local; without this a by-ref STRING
        /// group member, e.g. StringTheory's LASTERROR, rendered as a bare pointer instead of its text). Anything
        /// else defers to RenderHint.</summary>
        private static void CodeForType(ClarionType t, out byte code, out byte target, out uint size, out int places)
        {
            code = 0; target = 0; size = 0; places = 0;
            if (t == null) return;
            if (t.Kind == TypeKind.Reference || t.Tag == 0x16 || t.Tag == 0x26 || t.Tag == 0x29)
            {
                // a reference: pointer leaf, unless it targets a group (lazily expandable) or a string (deref inline)
                code = 0x16; size = 4;
                if (t.Referent != null && t.Referent.Kind == TypeKind.Group)
                {
                    target = 0x08;
                }
                else if (t.Referent != null && (t.Referent.Kind == TypeKind.String || t.Referent.Kind == TypeKind.Char))
                {
                    target = 0x18;
                    byte rc; int rp;
                    t.Referent.RenderHint(out rc, out size, out rp);   // size := the referent STRING's own char count
                }
                else if (t.Referent != null && (t.Referent.Tag == 0x29 || t.Referent.Tag == 0x26))
                {
                    // ParseType doesn't decode a 0x29/0x26 type record yet (Kind comes back Unknown, size 0) —
                    // but every observed 0x29/0x26 referent is a class string-property (e.g. StringTheory's
                    // LASTERROR, ABC control NAME/MENUTEXT/BASENAME). Treat it as string-like and dereference;
                    // FormatValueAt already falls back to a bounded 256-byte read when size<=0, same as any
                    // other &STRING of unknown length, so this is a safe best-effort rather than a guess.
                    // IMPORTANT: reset size to 0 here — it's still 4 from the pointer-slot default above, and
                    // FormatValueAt's fallback only kicks in when size is NOT a positive number (it otherwise
                    // reads exactly `size` bytes, which would silently truncate the dereferenced text to 4).
                    target = 0x18;
                    size = 0;
                }
                return;
            }
            t.RenderHint(out code, out size, out places);
        }

        /// <summary>One THREADed data symbol waiting on its own func-eval before <c>moduledata</c> can render
        /// it — its TSWD address is only a link-time TEMPLATE, and the live value lives at a per-thread
        /// instance THR$GetInstance resolves, exactly as <c>watch</c> resolves it.</summary>
        private struct PendingModuleSym { public LoadedModule Owner; public DataSymbol Ds; }

        // moduledata may need SEVERAL func-evals in a row — THR$GetInstance resolves one template at a
        // time — so the accumulation lives on the engine while the chain runs, then a single moduledata
        // event is emitted. No reqId to correlate: the host just replaces the whole panel each time
        // (buildModuleData), so this doesn't need queuerows's leak-proofing.
        private List<string> _mdRows;
        private string _mdModule;
        private Queue<PendingModuleSym> _mdPending;

        /// <summary>EXPERIMENT: moduledata — list the CURRENT module's module-scope data (the data declared
        /// in this module's DATA section), read live. Excludes file record buffers (*:RECORD) which already
        /// show in the file-buffer tree. THREADed symbols are resolved to their per-thread instance via
        /// func-eval before rendering — reading at the template address would show the wrong thread's copy
        /// (or an unfixed-up template) and, for an editable field, would WRITE to the template on edit.
        ///
        /// Returns true when a func-eval was armed for the first pending THREADed symbol, meaning the caller
        /// must leave the pause loop exactly as `watch` does; false means the event was already emitted (no
        /// THREADed symbols, or none could be resolved) and the caller should stay paused.</summary>
        private bool HandleModuleDataCommand(string[] parts, uint tid, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            _mdRows = new List<string>();
            _mdModule = null;
            _mdPending = new Queue<PendingModuleSym>();

            if (haveCtx)
            {
                var m = ModuleAt(ctx.Eip);
                ProcSymbol sym;
                if (m != null && m.Dbg != null && m.Dbg.ResolveSymbolVerified(ctx.Eip - m.LoadBase, out sym))
                {
                    int mi = sym.ModuleIdx;
                    _mdModule = m.Dbg.ModuleNameForIdx(mi);
                    var syms = m.Dbg.DataSymbols;
                    foreach (var ds in syms ?? new List<DataSymbol>())
                    {
                        if (ds.ModuleIdx != mi) continue;
                        if (ds.Name != null && ds.Name.EndsWith(":RECORD", StringComparison.OrdinalIgnoreCase))
                            continue;   // file record buffer — belongs to the file-buffer tree, not module data
                        bool threaded = m.CwtlsHi != 0 && ds.Rva >= m.CwtlsLo && ds.Rva < m.CwtlsHi;
                        if (threaded) { _mdPending.Enqueue(new PendingModuleSym { Owner = m, Ds = ds }); continue; }
                        uint va = m.LoadBase + ds.Rva;
                        ClarionType gt = ds.Type != null && ds.Type.Kind == TypeKind.Group ? ds.Type : null;
                        _mdRows.Add(NodeJson(ds.Name, gt, ds.TypeCode, 0, ds.Size, 0, va, null, m.Name));
                    }
                }
            }

            if (!haveCtx)
            {
                // No context to hijack from — render every pending THREADed symbol at its template address
                // rather than dropping it silently.
                while (_mdPending.Count > 0)
                {
                    var p = _mdPending.Dequeue();
                    uint va = p.Owner.LoadBase + p.Ds.Rva;
                    ClarionType gt = p.Ds.Type != null && p.Ds.Type.Kind == TypeKind.Group ? p.Ds.Type : null;
                    _mdRows.Add(NodeJson(p.Ds.Name, gt, p.Ds.TypeCode, 0, p.Ds.Size, 0, va, null, p.Owner.Name));
                }
                EmitModuleData();
                return false;
            }

            return DrainModuleDataPending(tid, ref ctx);
        }

        /// <summary>Resolve ONE pending THREADed module-data symbol via func-eval, or emit once none remain.
        ///
        /// Deliberately opens its OWN thread handle per call rather than threading one through from the
        /// caller: the continuation below runs from inside <see cref="OnEvalComplete"/>, a LATER, separate
        /// call — any handle captured from an earlier frame could be stale by then. <paramref name="ctx"/>
        /// is likewise only valid for the FIRST call (the real PausedWait frame); the chained calls pass
        /// <c>ref _evalSavedCtx</c>, which <see cref="BeginThreadedEval"/> guarantees is the genuine paused
        /// context at the moment each continuation runs.</summary>
        private bool DrainModuleDataPending(uint tid, ref Native.CONTEXT_X86 ctx)
        {
            if (_mdPending.Count == 0) { EmitModuleData(); return false; }

            var p = _mdPending.Dequeue();
            var owner = p.Owner; var ds = p.Ds;
            uint templateVa = owner.LoadBase + ds.Rva;
            ClarionType gt = ds.Type != null && ds.Type.Kind == TypeKind.Group ? ds.Type : null;

            IntPtr hThread = OpenThreadForContext(tid);
            bool armed = hThread != IntPtr.Zero && BeginThreadedEval(owner, templateVa, tid, hThread, ref ctx, true,
                "moduledata " + ds.Name,
                instanceVa =>
                {
                    uint va = instanceVa != 0 ? instanceVa : templateVa;
                    _mdRows.Add(NodeJson(ds.Name, gt, ds.TypeCode, 0, ds.Size, 0, va, null, owner.Name));
                    if (instanceVa != 0)
                        DrainModuleDataPending(tid, ref _evalSavedCtx);   // next pending symbol, if any
                    else
                        EmitModuleData();   // resolution failed/aborted — show what we have and stop chaining
                });
            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);

            if (armed) return true;

            // Could not arm an eval for this symbol (no THR$GetInstance import, or one already in flight —
            // BeginThreadedEval already reported why). Fall back to the template address and keep going
            // rather than dropping the symbol from the panel.
            _mdRows.Add(NodeJson(ds.Name, gt, ds.TypeCode, 0, ds.Size, 0, templateVa, null, owner.Name));
            return DrainModuleDataPending(tid, ref ctx);
        }

        private void EmitModuleData()
        {
            if (EmitJson)
                Console.WriteLine("@JSON {\"event\":\"moduledata\",\"module\":" + Json.Str(_mdModule)
                    + ",\"items\":[" + string.Join(",", _mdRows) + "]}");
            else
                Console.WriteLine($"  module data ({_mdRows.Count}) in {_mdModule ?? "(unknown)"}");
        }

        /// <summary>The single Clarion type-label authority (e.g. LONG, STRING(20), DECIMAL(7,2)). Shared by
        /// the Locals panel and watch/globals so every scope labels a type the same way.</summary>
        internal static string ClarionTypeLabel(byte code, byte target, uint size, int places, bool isNullRef = false)
        {
            switch (code)
            {
                case 0x11: return size == 2 ? "SHORT" : size == 4 ? "LONG" : "SIGNED";
                case 0x12: return size == 1 ? "BYTE" : size == 2 ? "USHORT" : size == 4 ? "ULONG" : "UNSIGNED";
                case 0x13: case 0x25: return size == 8 ? "REAL" : "SREAL";
                case 0x18: return "STRING(" + size + ")";   // STRING/CSTRING/PSTRING not yet distinguished
                case 0x23: return "DECIMAL(" + DecimalDigits(size) + "," + places + ")";
                case 0x24: return "PDECIMAL(" + DecimalDigits(size) + "," + places + ")";
                case 0x16:
                    // "&" for consistency with &GROUP/&CLASS/&REF below, and because it matters here: N is
                    // a best-effort capacity hint (StringTheory's _DATAEND, a peek at Clarion's native
                    // NEW(STRING) buffer-size trailer, or unknown), never a compile-time-exact size the way
                    // a plain inline STRING(N) local's is — and the on-screen value is always capped at 32
                    // bytes regardless. The & signals "this is a live guess", not "this is the whole string".
                    // A NULL reference has no capacity to guess at all — the "(?)" caveat only applies when
                    // there IS a live string whose length we can't pin down, so a null ref just reads "&STRING".
                    if (target == 0x18) return isNullRef ? "&STRING" : size > 0 ? "&STRING(" + size + ")" : "&STRING(?)";
                    return target == 0x08 ? "&GROUP" : target == 0x05 ? "&CLASS" : "&REF";
                case 0x04: return "GROUP";   // class-instance-by-value (e.g. ToolbarClass) — a direct 0x08 group
                case 0x08: return "GROUP";
                case 0x10: return "(opaque)";  // stub type with no member layout (window / forward-declared class)
                default:   return "TYPE(0x" + code.ToString("X2") + ")";
            }
        }

        // a Clarion packed-decimal of N bytes carries 2N-1 significant digits (the remaining nibble is the sign)
        private static int DecimalDigits(uint sizeBytes) { return sizeBytes > 0 ? (int)(sizeBytes * 2 - 1) : 0; }

    }
}
