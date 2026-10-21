using System;
using System.Text;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------------ typed value rendering
        //
        // One decode path, two sources. Everything that renders a Clarion value — the Locals panel,
        // watch, globals, breakpoint conditions, and QUEUE rows — funnels through FormatValueCore.
        //
        // The reason the source is abstracted at all: a QUEUE row whose record is large is stored
        // RLE-COMPRESSED in the debuggee (see ClarionRle), so the decompressed row exists only as a
        // byte[] on OUR side — there is no address in the target to point a VA-based reader at. Rather
        // than duplicate the type switch (and with it FormatBcd, the cp1252 handling, and the width
        // rules) for buffer-sourced rows, the switch reads through a ByteSource and the two callers
        // supply either ReadBlock or a row buffer.

        /// <summary>Reads up to <c>buf.Length</c> bytes at <paramref name="off"/> and returns how many were
        /// actually copied — 0 meaning "unreadable". <paramref name="off"/> is a target VA for the remote
        /// source and a byte index for a row buffer. Deliberately matches <see cref="ReadBlock"/>'s
        /// signature so the remote case needs no adapter.</summary>
        private delegate int ByteSource(uint off, byte[] buf);

        // Clarion STRING/CSTRING content is Windows ANSI (cp1252), not 7-bit ASCII — Encoding.ASCII.GetString
        // replaces every byte >= 0x80 with a literal '?', which silently destroys real (or garbage-tail)
        // high-byte content and is indistinguishable from an actual '?' character in the source data. cp1252
        // maps every byte to SOME visible glyph, so what's on screen matches what's really in memory — still
        // not byte-exact proof for binary content (that needs a raw export), but no longer lossy for display.
        private static readonly Encoding Cp1252 = Encoding.GetEncoding(1252);

        /// <summary>The single Clarion value-rendering authority: read and format a typed value live from
        /// <paramref name="va"/> on the paused thread. Shared by the Locals panel and watch/globals (and, in
        /// future, module data) so every scope renders a value identically. References (&amp;STRING) are
        /// dereferenced here — which is why this lives engine-side: only the engine can read target memory.</summary>
        internal string FormatValueAt(byte code, byte target, uint size, int places, uint va)
        {
            return FormatValueCore(code, target, size, places, va, ReadBlock);
        }

        /// <summary>As <see cref="FormatValueAt"/>, but the value's own bytes come from an already-decoded
        /// QUEUE row rather than from target memory. Reference fields (code 0x16) still dereference through
        /// the live process — a row stores only the pointer, and the buffer it points at lives in the
        /// debuggee's heap.</summary>
        internal string FormatValueInRow(byte code, byte target, uint size, int places, byte[] row, int off)
        {
            return FormatValueCore(code, target, size, places, (uint)off, RowSource(row));
        }

        /// <summary>A <see cref="ByteSource"/> over a decoded QUEUE row.
        ///
        /// STRICT on purpose: it returns 0 (=> "&lt;unreadable&gt;") unless the whole request fits inside the
        /// row, where the remote source would hand back a short read. Every field of a record lies within
        /// <c>recordSize</c> by construction, so a request running past the end means the LAYOUT is wrong,
        /// not that memory was unreadable — and a partial read there would be actively misleading: the int
        /// cases BitConverter from buf[0] without consulting the returned count, so a truncated field would
        /// render a zero-padded tail as a perfectly plausible number, and FormatBcd indexes b[size-1] and
        /// would report a wrong SIGN. Failing loudly is the only honest option.</summary>
        private static ByteSource RowSource(byte[] row)
        {
            return (off, buf) =>
            {
                if (row == null || off > int.MaxValue) return 0;
                int start = (int)off;
                if (start < 0 || start > row.Length || row.Length - start < buf.Length) return 0;
                Array.Copy(row, start, buf, 0, buf.Length);
                return buf.Length;
            };
        }

        /// <summary>Decode one typed Clarion value out of <paramref name="primary"/>. Source-agnostic: the
        /// value's own bytes come from <paramref name="primary"/> at <paramref name="off"/>, while a
        /// reference (0x16) always follows its pointer through the live process via
        /// <see cref="ReadBlock"/>.</summary>
        private string FormatValueCore(byte code, byte target, uint size, int places, uint off, ByteSource primary)
        {
            int len;
            switch (code)
            {
                case 0x18: len = (int)Math.Min(size == 0 ? 1u : size, 1024u); break;
                case 0x23: case 0x24: len = (int)(size == 0 ? 1u : size); break;
                case 0x11: case 0x12: case 0x13: case 0x25: len = (int)(size == 0 ? 4u : size); break;
                case 0x16: len = 4; break;
                default:   len = size > 0 ? (int)Math.Min(size, 64u) : 4; break;
            }
            var buf = new byte[len];
            int got = primary(off, buf);
            if (got <= 0) return "<unreadable>";

            switch (code)
            {
                case 0x11:   // signed
                    if (size == 1) return ((sbyte)buf[0]).ToString();
                    if (size == 2) return BitConverter.ToInt16(buf, 0).ToString();
                    return BitConverter.ToInt32(buf, 0).ToString();
                case 0x12:   // unsigned
                    if (size == 1) return buf[0].ToString();
                    if (size == 2) return BitConverter.ToUInt16(buf, 0).ToString();
                    return BitConverter.ToUInt32(buf, 0).ToString();
                case 0x13: case 0x25:   // float (SREAL / REAL)
                    return size == 8 ? BitConverter.ToDouble(buf, 0).ToString("R")
                                     : BitConverter.ToSingle(buf, 0).ToString("R");
                case 0x18:   // STRING/CSTRING/PSTRING — show the text (cut at NUL, else trim trailing spaces)
                {
                    int n = Array.IndexOf(buf, (byte)0, 0, got);
                    if (n < 0) n = got;
                    return "'" + Cp1252.GetString(buf, 0, n).TrimEnd(' ') + "'";
                }
                case 0x23: return FormatBcd(buf, got, places, packed: false);  // DECIMAL (sign-first)
                case 0x24: return FormatBcd(buf, got, places, packed: true);   // PDECIMAL (sign-last)
                case 0x16:   // reference: the slot (or row field) holds a pointer
                {
                    uint ptr = BitConverter.ToUInt32(buf, 0);
                    if (ptr == 0) return "(null)";
                    if (target == 0x18)   // &STRING — deref and show a bounded preview (space-padded)
                    {
                        // A dynamically-allocated &STRING has no reliable length signal: whatever "size"
                        // we were given (StringTheory's own _DATAEND data-length property, or a best-effort
                        // peek at Clarion's native NEW(STRING) buffer-size trailer for a plain &STRING) is at
                        // best the ALLOCATED capacity, not necessarily the true content length — and there
                        // is no NUL/length marker inside a Clarion STRING to fall back on either. So always
                        // cap the on-screen preview at a small, fixed size regardless of source — garbage
                        // tail included is fine here; byte-exact inspection of the full buffer belongs in a
                        // raw memory/export view, not this text preview. The type label upstream (which
                        // still uses the untruncated `size`) tells the user there may be more to see.
                        //
                        // The deref is ALWAYS remote, even for a queue row: a row stores the pointer only,
                        // and the buffer it points at lives in the debuggee's heap. It is also a shallow
                        // copy, so the target may already have been reassigned or DISPOSEd — hence the
                        // unreadable fallback below rather than an assumption that the string is live.
                        const int previewCap = 32;
                        int sn = size > 0 ? (int)Math.Min(size, previewCap) : previewCap;
                        var sbuf = new byte[sn];
                        int sg = ReadBlock(ptr, sbuf);
                        if (sg <= 0) return "&0x" + ptr.ToString("X") + " <unreadable>";
                        int nz = Array.IndexOf(sbuf, (byte)0, 0, sg);   // CSTRING terminator, if any
                        if (nz < 0) nz = sg;
                        return "'" + Cp1252.GetString(sbuf, 0, nz).TrimEnd(' ') + "'";
                    }
                    return "&0x" + ptr.ToString("X");
                }
                case 0x08:   // GROUP / CLASS instance — a composite, not a scalar; members not yet expanded
                    return "{…}";
                default:
                {
                    var sb = new StringBuilder("0x");
                    for (int i = 0; i < got; i++) sb.Append(buf[i].ToString("X2"));
                    return sb.ToString();
                }
            }
        }

        /// <summary>Decode a Clarion packed-BCD decimal. Two layouts (verified in clarion-pdb):
        /// DECIMAL (sign-first): sign = high nibble of byte 0 (non-zero = negative); digits = byte0.low,
        /// then byte_i.high, byte_i.low (MSB first). PDECIMAL (sign-last/IBM): sign = low nibble of the last
        /// byte (0x0D = negative); digits = byte_i.high, byte_i.low up to the last byte's high nibble.</summary>
        private static string FormatBcd(byte[] b, int size, int places, bool packed)
        {
            var digits = new StringBuilder();
            bool neg;
            if (!packed)
            {
                neg = (b[0] >> 4) != 0;
                digits.Append((b[0] & 0xf).ToString());
                for (int i = 1; i < size; i++) { digits.Append(((b[i] >> 4) & 0xf)); digits.Append((b[i] & 0xf)); }
            }
            else
            {
                neg = (b[size - 1] & 0xf) == 0xd;
                for (int i = 0; i < size - 1; i++) { digits.Append(((b[i] >> 4) & 0xf)); digits.Append((b[i] & 0xf)); }
                digits.Append(((b[size - 1] >> 4) & 0xf));
            }

            string ds = digits.ToString();
            string intPart, fracPart = "";
            if (places > 0)
            {
                if (ds.Length <= places) ds = ds.PadLeft(places + 1, '0');
                intPart = ds.Substring(0, ds.Length - places);
                fracPart = ds.Substring(ds.Length - places);
            }
            else intPart = ds;

            intPart = intPart.TrimStart('0');
            if (intPart.Length == 0) intPart = "0";
            string val = places > 0 ? intPart + "." + fracPart : intPart;
            return (neg && val != "0") ? "-" + val : val;
        }
    }
}
