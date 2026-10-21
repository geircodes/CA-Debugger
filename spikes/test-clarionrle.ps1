# Validate ClarionRle.Decode against the byte-exact examples recorded in
# docs/clarion-queue-internals.md ("Row storage and the RLE codec" + the DELETE entry).
#
# RUN UNDER 32-BIT POWERSHELL — ClarionDbg.Core.dll is x86 (it debugs 32-bit Clarion targets), so
# 64-bit PowerShell throws BadImageFormatException on Add-Type. Worse, that failure is QUIET here:
# the Decode calls then return $null, and the three "expected null" negative cases PASS anyway. A
# run where the positive cases fail and the negative ones pass means the assembly never loaded —
# not that the codec is broken.
#
#   C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -NoProfile -File spikes\test-clarionrle.ps1
#
# Cases 1-2 are byte-exact captures from a live process, so they genuinely verify the port.
# Cases 7-8 (the u16/u32 count forms) only prove self-consistency with the disassembly — those forms
# have never been observed live, and need a single run longer than 12287 bytes (e.g. STRING(20000)).
$dll = Join-Path $PSScriptRoot "..\src\ClarionDbg.Core\bin\Debug\net48\ClarionDbg.Core.dll"
Add-Type -Path $dll

function Check($name, $ok, $detail) {
  if ($ok) { Write-Output "PASS  $name" } else { Write-Output "FAIL  $name  -- $detail" }
}

# ---- Case 1: 200-byte record holding 'ghi' -> 12 stored bytes, payloadLen 7
# payload: 83 67 68 69 40 C5 20   => literal 3 ('ghi') + fill 197 x 0x20
$p1 = [byte[]]@(0x83,0x67,0x68,0x69,0x40,0xC5,0x20)
$r1 = [ClarionDbg.Core.ClarionRle]::Decode($p1, 7, 200)
Check "case1 non-null" ($null -ne $r1) "returned null"
if ($r1) {
  Check "case1 length 200" ($r1.Length -eq 200) "got $($r1.Length)"
  $txt = [System.Text.Encoding]::ASCII.GetString($r1[0..2])
  Check "case1 text 'ghi'" ($txt -eq 'ghi') "got '$txt'"
  $spaces = ($r1[3..199] | Where-Object { $_ -ne 0x20 }).Count
  Check "case1 197 trailing spaces" ($spaces -eq 0) "$spaces non-space bytes in the tail"
}

# ---- Case 2: MyQLargeType row 0 -- STRING(320) + LONG,DIM(10), recordSize 360, payloadLen 34
# 95                        literal 21 -> '1234567890qwertyyuiop'
# 41 2B 20                  extended count (1<<8)|0x2B = 299, fill 0x20   -> 320 total for TEST
# 81 7B                     literal 1  -> 123          (NumberArr[1] low byte)
# 23 00                     short fill 35 zeros
# 84 C8 01 00 00            literal 4  -> 456          (NumberArr[10])
$lit = [System.Text.Encoding]::ASCII.GetBytes('1234567890qwertyyuiop')
$p2 = [System.Collections.Generic.List[byte]]::new()
$p2.Add(0x95); $p2.AddRange($lit)
$p2.AddRange([byte[]]@(0x41,0x2B,0x20))
$p2.AddRange([byte[]]@(0x81,0x7B))
$p2.AddRange([byte[]]@(0x23,0x00))
$p2.AddRange([byte[]]@(0x84,0xC8,0x01,0x00,0x00))
$p2a = $p2.ToArray()
Check "case2 payloadLen is 34" ($p2a.Length -eq 34) "built $($p2a.Length) bytes"

$r2 = [ClarionDbg.Core.ClarionRle]::Decode($p2a, 34, 360)
Check "case2 non-null" ($null -ne $r2) "returned null"
if ($r2) {
  Check "case2 length 360" ($r2.Length -eq 360) "got $($r2.Length)"
  $t = [System.Text.Encoding]::ASCII.GetString($r2[0..19])
  Check "case2 TEST prefix" ($t -eq '1234567890qwertyyuio') "got '$t'"
  $pad = ($r2[21..319] | Where-Object { $_ -ne 0x20 }).Count
  Check "case2 TEST padded to 320" ($pad -eq 0) "$pad non-space bytes in TEST tail"
  # NUMBERARR is at +320, LONG,DIM(10): [1] at +320, [10] at +320+9*4 = +356
  $n1  = [BitConverter]::ToInt32($r2, 320)
  $n10 = [BitConverter]::ToInt32($r2, 356)
  Check "case2 NumberArr[1] == 123" ($n1 -eq 123) "got $n1"
  Check "case2 NumberArr[10] == 456" ($n10 -eq 456) "got $n10"
  $mid = ($r2[324..355] | Where-Object { $_ -ne 0 }).Count
  Check "case2 NumberArr[2..9] zero" ($mid -eq 0) "$mid non-zero bytes"
}

# ---- Case 3: payloadLen == 0 means a RAW copy, not an empty stream
$p3 = [byte[]]@(0x41,0x42,0x43)
$r3 = [ClarionDbg.Core.ClarionRle]::Decode($p3, 0, 8)
Check "case3 raw copy" ($r3 -and $r3.Length -eq 8 -and $r3[0] -eq 0x41 -and $r3[2] -eq 0x43 -and $r3[3] -eq 0) "unexpected raw result"

# ---- Case 4: malformed input must return null, never throw
# a fill token whose count would overrun the record
$r4 = [ClarionDbg.Core.ClarionRle]::Decode([byte[]]@(0x40,0xC5,0x20), 3, 10)
Check "case4 overrun rejected" ($null -eq $r4) "expected null"
# a literal token truncated mid-run
$r5 = [ClarionDbg.Core.ClarionRle]::Decode([byte[]]@(0x85,0x41,0x42), 3, 200)
Check "case5 truncated literal rejected" ($null -eq $r5) "expected null"
# an extended-count token with no count byte following
$r6 = [ClarionDbg.Core.ClarionRle]::Decode([byte[]]@(0x41), 1, 200)
Check "case6 truncated extended count rejected" ($null -eq $r6) "expected null"

# ---- Case 5: the 16-bit and 32-bit count forms (from disassembly, never observed live)
# token 0x71: 0x40 set, count field 0x31 > 0x30 -> u16 count follows
$r7 = [ClarionDbg.Core.ClarionRle]::Decode([byte[]]@(0x71,0x00,0x10,0x5A), 4, 4096)
Check "case7 u16 fill count 4096" ($r7 -and $r7.Length -eq 4096 -and (($r7 | Where-Object { $_ -ne 0x5A }).Count -eq 0)) "u16 form failed"
# token 0x70: 0x40 set, count field exactly 0x30 -> u32 count follows
$r8 = [ClarionDbg.Core.ClarionRle]::Decode([byte[]]@(0x70,0x00,0x40,0x00,0x00,0x5B), 6, 16384)
Check "case8 u32 fill count 16384" ($r8 -and $r8.Length -eq 16384 -and (($r8 | Where-Object { $_ -ne 0x5B }).Count -eq 0)) "u32 form failed"
