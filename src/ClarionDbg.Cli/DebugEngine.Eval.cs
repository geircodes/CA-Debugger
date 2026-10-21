using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------------ watch (by name)

        /// <summary>
        /// watch NAME — resolve a data name and read its CURRENT value on the paused thread.
        /// Non-threaded data reads directly at template VA (returns false: stay paused).
        /// THREADed (.cwtls) data launches the THR$GetInstance func-eval (returns true: the
        /// caller must leave the pause loop so the target can run the call).
        /// </summary>
        private bool HandleWatchCommand(string[] parts, uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            if (parts.Length < 2) { EmitError("watch expects: watch NAME"); return false; }
            string name = parts[1];

            // A procedure-local shadows a same-named global while we are paused inside its frame, so resolve the
            // CURRENT frame's locals FIRST. Locals live on the stack (never .cwtls), so this is a direct read —
            // no THR$GetInstance func-eval — hence we always return false (stay paused).
            uint slotVa; LocalSym lsym; LoadedModule lowner;
            if (TryResolveLocalInCurrentFrame(ref ctx, haveCtx, name, out slotVa, out lsym, out lowner))
            {
                EmitWatchValue(name, slotVa, slotVa, false, lsym.TypeCode, lsym.Size, lsym.Target, lsym.Places);
                return false;
            }

            TswdDebugInfo.DataLocation loc; LoadedModule owner;
            if (!ResolveDataAcrossModules(name, out owner, out loc))
            {
                // Not a current-frame local and not a global. If it IS a local of some other procedure, it is
                // merely out of scope right now (we are paused elsewhere) — flag that so the Watch row reads
                // "(out of scope)" rather than the misleading "(not found)" used for genuinely unknown names.
                bool outOfScope = haveCtx && IsKnownLocalName(name);
                if (EmitJson) Console.WriteLine("@JSON " + Json.WatchMiss(name, outOfScope));
                Console.WriteLine($"  watch {name}: {(outOfScope ? "out of scope" : "not found")}");
                return false;
            }
            uint templateVa = owner.LoadBase + loc.Rva;
            bool threaded = loc.Rva >= owner.CwtlsLo && loc.Rva < owner.CwtlsHi && owner.CwtlsHi != 0;

            if (!threaded)
            {
                EmitWatchValue(name, templateVa, templateVa, false, loc.TypeCode, loc.Size);
                return false;
            }

            // The continuation runs once THR$GetInstance reports this thread's instance address.
            uint capturedSize = loc.Size;
            byte capturedCode = loc.TypeCode;
            return BeginThreadedEval(owner, templateVa, tid, hThread, ref ctx, haveCtx, "watch " + name,
                instanceVa =>
                {
                    // instanceVa == 0 means resolution failed; report a miss rather than reading address 0.
                    if (instanceVa == 0)
                    {
                        if (EmitJson) Console.WriteLine("@JSON " + Json.WatchMiss(name, false));
                        Console.WriteLine($"  watch {name}: threaded instance could not be resolved");
                        return;
                    }
                    EmitWatchValue(name, templateVa, instanceVa, true, capturedCode, capturedSize);
                });
        }

        /// <summary>Hijack the paused thread to call <c>ClaRUN!THR$GetInstance(EAX=templateVa, EBX=.cwtls
        /// base)</c> and trap its return at <see cref="EVAL_TRAP_VA"/>, so <paramref name="done"/> receives
        /// the per-thread instance address. Returns true when the eval was armed, meaning the caller MUST
        /// leave the pause loop so the target can run the call; false means nothing was armed (the reason has
        /// already been reported) and the caller should stay paused.
        ///
        /// This is the ONLY place an eval is armed, so every guard lives here.</summary>
        private bool BeginThreadedEval(LoadedModule owner, uint templateVa, uint tid, IntPtr hThread,
                                       ref Native.CONTEXT_X86 ctx, bool haveCtx, string what, Action<uint> done)
        {
            // ONE eval at a time. ContinueDebugEvent resumes the WHOLE process, so during the eval window
            // another thread can hit a breakpoint, enter PausedWait, and arm a second eval — which would
            // overwrite _evalSavedCtx/_evalTid and, worse, silently destroy a pending breakpoint re-plant:
            // the second arming's _rearm.TryGetValue finds nothing (the first already removed the entry), so
            // _evalHadRearm goes false and the restore below never happens. The 0xCC is then never re-planted
            // while _armed[va] still claims it is, and the user's breakpoint stops firing for the rest of the
            // session while the UI still shows it set. Refusing the second eval is far better.
            if (_evalActive)
            {
                EmitError(what + ": a threaded-data eval is already in flight (thread " + _evalTid + ")");
                return false;
            }
            if (owner.ThrGetInstanceIatRva == 0)
            {
                EmitError($"{what}: THREADed data but THR$GetInstance import not found in {owner.Name}");
                return false;
            }
            if (!haveCtx)
            {
                EmitError($"{what}: no thread context for func-eval");
                return false;
            }
            uint helper = ReadU32(owner.LoadBase + owner.ThrGetInstanceIatRva);
            if (helper == 0)
            {
                EmitError($"{what}: could not read THR$GetInstance address from the IAT");
                return false;
            }

            _evalDone = done;
            _evalWhat = what;

            // save the real context (deep copy — the struct holds array references)
            _evalSavedCtx = CloneContext(ref ctx);

            // suspend any pending breakpoint re-plant for this thread: the BP byte is currently
            // the ORIGINAL instruction, and the eval resume must not consume the re-arm step
            _evalHadRearm = _rearm.TryGetValue(tid, out _evalSavedRearm);
            if (_evalHadRearm) _rearm.Remove(tid);

            // hijack: EAX = template VA, EBX = .cwtls base, return lands on the magic trap
            var e = CloneContext(ref ctx);
            e.Esp = ctx.Esp - 4;
            WriteU32(e.Esp, EVAL_TRAP_VA);
            e.Eax = templateVa;
            e.Ebx = owner.LoadBase + owner.CwtlsLo;
            e.Eip = helper;
            e.EFlags &= ~TRAP_FLAG;
            Native.SetThreadContext(hThread, ref e);

            _evalActive = true;
            _evalTid = tid;
            return true;   // leave PausedWait; the debug loop continues the event and the call runs
        }

        /// <summary>The func-eval returned (AV at the magic address): collect EAX = instance VA,
        /// restore the saved thread state, run the pending continuation, and re-enter the pause loop.</summary>
        private uint OnEvalComplete(uint tid)
        {
            _evalActive = false;
            IntPtr hThread = OpenThreadForContext(tid);
            var c = NewContext();
            bool haveCtx = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref c);
            uint instanceVa = haveCtx ? c.Eax : 0;

            // restore the genuine pause state (EIP/ESP/regs exactly as before the eval)
            if (hThread != IntPtr.Zero) Native.SetThreadContext(hThread, ref _evalSavedCtx);
            if (_evalHadRearm) { _rearm[tid] = _evalSavedRearm; _evalHadRearm = false; }

            var done = _evalDone;
            string what = _evalWhat;
            _evalDone = null;
            // CONTRACT: the continuation is ALWAYS invoked, with 0 meaning "resolution failed". Skipping it on
            // failure would leave a reqId-correlated consumer (queuerows) with a request the host waits on
            // forever — its callback map has no timeout.
            if (instanceVa == 0) EmitError((what ?? "eval") + ": THR$GetInstance eval failed");
            if (done != null) done(instanceVa);
            else EmitError((what ?? "eval") + ": eval completed with no pending continuation");

            // A continuation MAY have chained straight into ANOTHER eval — moduledata resolves several
            // THREADed symbols in sequence, one eval per symbol, via DrainModuleDataPending calling itself
            // from inside `done`. If it did, _evalActive is true again and the newly-armed hijack must
            // actually RUN before anything else happens: skip the nested pause loop entirely and let Run()
            // continue the process, exactly as it did for eval #1. The NEXT trapped exception re-enters
            // this method for eval #2.
            if (_evalActive)
            {
                if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
                return Native.DBG_CONTINUE;
            }

            // We are logically still paused at the original location — resume the command loop.
            //
            // The reason string MUST stay "watch" regardless of which consumer armed the eval: the host
            // suppresses this transient pause by matching that literal string (ClarionDebuggerWebView.OnPaused
            // and ClarionDebuggerService). Any other value makes the host treat an eval round trip as a real
            // stop — the editor jumps and steals focus, panes refresh, run-to-cursor one-shots are torn down,
            // and every watched name is re-issued, some of them threaded, launching more evals from inside
            // this completion path.
            //
            // Copy the context to a local first: passing `ref _evalSavedCtx` would alias the field to
            // PausedWait's `ref ctx` parameter, so anything the nested loop assigned to ctx would write
            // straight back into the field we rely on for the restore above.
            var resumeCtx = CloneContext(ref _evalSavedCtx);
            PausedWait(tid, hThread, ref resumeCtx, true, "watch");
            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return Native.DBG_CONTINUE;
        }

        /// <summary>Undo a hijack that will never complete, so the engine does not sit with
        /// <c>_evalActive</c> stuck true and the target thread stranded inside THR$GetInstance.
        ///
        /// Needed because the completion path is the ONLY place that clears <c>_evalActive</c>, yet several
        /// things can prevent it being reached: THR$GetInstance faulting at some other address (a bad template
        /// VA or .cwtls base), the hijacked thread being blocked in a kernel wait so SetThreadContext never
        /// takes effect (reachable — PickPauseThread can select a GUI thread sitting in GetMessage), or the
        /// thread exiting. Restoring is safe even if the call never ran: the hijack is pure SetThreadContext.</summary>
        private void AbortEval(uint tid, string why)
        {
            if (!_evalActive || tid != _evalTid) return;
            _evalActive = false;
            IntPtr hThread = OpenThreadForContext(tid);
            if (hThread != IntPtr.Zero)
            {
                Native.SetThreadContext(hThread, ref _evalSavedCtx);
                Native.CloseHandle(hThread);
            }
            if (_evalHadRearm) { _rearm[tid] = _evalSavedRearm; _evalHadRearm = false; }
            var done = _evalDone;
            _evalDone = null;
            // Report through the consumer where possible: a queuerows caller has a pending reqId the host is
            // waiting on, and a bare EmitError would leave that row spinning forever.
            EmitError((_evalWhat ?? "eval") + " aborted: " + why);
            if (done != null) done(0);
        }

        /// <summary>Read and report a watch value (instanceVa = templateVa for non-threaded data). <paramref
        /// name="target"/>/<paramref name="places"/> carry a frame local's referent-type and DECIMAL scale so
        /// &amp;STRING locals deref correctly and DECIMAL locals render/edit at the right scale; both default to 0
        /// for global/static data (whose DataLocation does not carry them) — unchanged from before.</summary>
        private void EmitWatchValue(string name, uint templateVa, uint instanceVa, bool threaded, byte typeCode, uint size, byte target = 0, int places = 0)
        {
            int len = (int)Math.Min(Math.Max(size, 1), 4096);
            var buf = new byte[len];
            int read;
            Native.ReadProcessMemory(_hProcess, Ptr(instanceVa), buf, len, out read);
            if (read < 0) read = 0;
            // unified rendering: same engine-side type label + value formatter the Locals panel uses
            string value = FormatValueAt(typeCode, target, size, places, instanceVa);
            bool isNullRef = typeCode == 0x16 && value == "(null)";
            string tn = ClarionTypeLabel(typeCode, target, size, places, isNullRef);
            if (EmitJson)
                Console.WriteLine("@JSON " + Json.Watch(name, true, templateVa, instanceVa, threaded, typeCode, tn, size, places, value, buf, read, IsEditableCode(typeCode)));
            Console.WriteLine($"  watch {name}: {(tn ?? $"type 0x{typeCode:X2}")} size {size} at 0x{instanceVa:X}{(threaded ? $" (threaded; template 0x{templateVa:X})" : "")}");
            for (int row = 0; row < read; row += 16)
            {
                int n = Math.Min(16, read - row);
                var hex = new System.Text.StringBuilder(48);
                var asc = new System.Text.StringBuilder(16);
                for (int i = 0; i < n; i++)
                {
                    byte v = buf[row + i];
                    hex.Append(v.ToString("X2")).Append(' ');
                    asc.Append(v >= 0x20 && v < 0x7F ? (char)v : '.');
                }
                Console.WriteLine($"    0x{instanceVa + (uint)row:X8}: {hex.ToString().PadRight(48)} {asc}");
            }
        }
    }
}
