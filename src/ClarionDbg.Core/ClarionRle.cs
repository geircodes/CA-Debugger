using System;

namespace ClarionDbg.Core
{
    /// <summary>
    /// The run-length codec ClaRUN.dll uses to compress QUEUE rows whose record is large
    /// (<c>recordSize &gt;= 0x80</c>). Ported byte-for-byte from the decoder at ClaRUN.dll RVA 0x193EB,
    /// which is reached through the compressed node class's vtable +0x08 slot (RVA 0x1BDA0).
    ///
    /// Pure decode — no process access — so it lives in Core and is testable without a debuggee.
    /// See <c>docs/clarion-queue-internals.md</c>, "Row storage and the RLE codec".
    /// </summary>
    public static class ClarionRle
    {
        /// <summary>
        /// Decode one stored QUEUE row into exactly <paramref name="destSize"/> bytes
        /// (the queue's <c>recordSize</c>, read from <c>u32[ctrl+0x0C]</c>).
        ///
        /// <paramref name="payloadLen"/> is the <c>u32</c> that precedes the payload at
        /// <c>u32[node+0x04]</c>. **Zero means the row is NOT compressed** — the runtime stored a plain
        /// memcpy of the record, so the payload is copied out verbatim (the same branch the runtime's
        /// dispatcher takes when <c>[storage] == 0</c>).
        ///
        /// Returns null when the stream is malformed — truncated mid-token, or emitting more than
        /// <paramref name="destSize"/> bytes. A short-but-well-formed stream is NOT an error: the
        /// remainder stays zero-filled and the row is returned, because a caller reading a live process
        /// can legitimately catch a row mid-write. Never throws: this decodes debuggee-controlled bytes.
        /// </summary>
        public static byte[] Decode(byte[] payload, int payloadLen, int destSize)
        {
            if (payload == null || destSize <= 0) return null;

            var dest = new byte[destSize];

            // payloadLen == 0 => raw copy, not an empty run-length stream.
            if (payloadLen <= 0)
            {
                int n = Math.Min(destSize, payload.Length);
                Array.Copy(payload, 0, dest, 0, n);
                return dest;
            }

            int end = Math.Min(payloadLen, payload.Length);
            int i = 0, o = 0;

            while (i < end)
            {
                byte token = payload[i++];
                int count = token & 0x3F;

                if ((token & 0x40) != 0)
                {
                    // Extended count. The three forms are distinguished by the 6-bit field itself, so the
                    // order of these tests matters: 0x30 exactly selects the 32-bit form, anything ABOVE
                    // 0x30 the 16-bit form, and everything below extends to 14 bits with one more byte.
                    if (count == 0x30)
                    {
                        if (i + 4 > end) return null;
                        count = (int)BitConverter.ToUInt32(payload, i);
                        i += 4;
                    }
                    else if (count > 0x30)
                    {
                        if (i + 2 > end) return null;
                        count = BitConverter.ToUInt16(payload, i);
                        i += 2;
                    }
                    else
                    {
                        if (i + 1 > end) return null;
                        count = (count << 8) | payload[i++];
                    }
                }

                if (count < 0 || o + count > destSize) return null;   // would overrun the record

                if ((token & 0x80) != 0)
                {
                    if (i + count > end) return null;                 // truncated literal run
                    Array.Copy(payload, i, dest, o, count);
                    i += count;
                }
                else
                {
                    if (i + 1 > end) return null;                     // truncated fill run
                    byte val = payload[i++];
                    for (int k = 0; k < count; k++) dest[o + k] = val;
                }
                o += count;
            }

            return dest;
        }
    }
}
