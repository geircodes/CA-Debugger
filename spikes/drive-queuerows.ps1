# Drive ClarionDbg's queue viewer end to end against a live target.
#
# Chains the requests the host UI would make: pause -> stack -> framelocals -> queuerows for every
# local that came back marked as a queue. Prints the decoded rows.
#
# Uses EVENT-BASED output draining (OutputDataReceived + BeginOutputReadLine), never a blocking
# ReadLine — a blocking read against this engine deadlocks (see docs/HANDOVER-queue-viewer.md).
#
#   powershell -NoProfile -File spikes\drive-queuerows.ps1 -Exe <QTesterDir>\Qtester.exe -Line 101
#   powershell -NoProfile -File spikes\drive-queuerows.ps1 -Exe <QTesterDir>\Qtester.exe -Line 62 -Frame 0
#
# -Frame picks which call-stack frame's locals to inspect (0 = innermost).
param(
  [int]$Line = 101,
  [int]$Frame = 0,
  [Parameter(Mandatory)][string]$Exe,
  [string]$Module = "Qtester",
  [int]$TimeoutSec = 60,
  [string]$Global = "",  # inspect a module-scope queue by name (queuerowsname) instead of frame locals
  [switch]$Follow,       # also expand any reference field inside a row, in the SAME run (ASLR moves
                         # addresses between runs, so a two-run check compares stale addresses)
  [switch]$Raw           # also echo every engine line, for debugging the driver itself
)

$dbg = Join-Path $PSScriptRoot "..\src\ClarionDbg.Cli\bin\Debug\net48\ClarionDbg.exe"
if (-not (Test-Path $dbg)) { Write-Error "ClarionDbg.exe not found at $dbg - run dotnet build first"; exit 1 }
if (-not (Test-Path $Exe)) { Write-Error "target not found at $Exe"; exit 1 }

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $dbg
$psi.Arguments = "break `"$Exe`" --bp ${Module}:${Line} --interactive --json"
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true

$proc = New-Object System.Diagnostics.Process
$proc.StartInfo = $psi

# Thread-safe sink: the OutputDataReceived callback runs on a pool thread.
$lines = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())
$sink = { if ($null -ne $EventArgs.Data) { [void]$Event.MessageData.Add($EventArgs.Data) } }
$outEvt = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action $sink -MessageData $lines
$errEvt = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived  -Action $sink -MessageData $lines

[void]$proc.Start()
$proc.BeginOutputReadLine()
$proc.BeginErrorReadLine()

function Send($cmd) {
  Write-Host ">> $cmd" -ForegroundColor DarkGray
  $proc.StandardInput.WriteLine($cmd)
  $proc.StandardInput.Flush()
}

$state = 'wait-pause'
$next = 0
$reqQueue = New-Object System.Collections.Queue
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$seen = 0
$rowsShown = 0

while ((Get-Date) -lt $deadline) {
  if ($seen -ge $lines.Count) {
    if ($proc.HasExited -and $seen -ge $lines.Count) { break }
    Start-Sleep -Milliseconds 40
    continue
  }

  # NOTE: not $line — PowerShell variables are case-insensitive, so that would assign a string to
  # the [int]$Line parameter and every subsequent .StartsWith() call would fail on an Int32.
  $ln = $lines[$seen]; $seen++
  if ($Raw) { Write-Host "   $ln" -ForegroundColor DarkCyan }
  if (-not $ln.StartsWith('@JSON ')) { continue }

  try { $evt = $ln.Substring(6) | ConvertFrom-Json } catch { continue }
  $name = $evt.event

  if ($name -eq 'paused' -and $state -eq 'wait-pause') {
    Write-Host "paused at $($evt.module) line $($evt.line) in $($evt.proc)" -ForegroundColor Green
    if ($Global -ne "") { $state = 'wait-rows'; Send "queuerowsname 1 $Global"; continue }
    $state = 'wait-stack'
    Send 'stack'
    continue
  }

  if ($name -eq 'stack' -and $state -eq 'wait-stack') {
    if ($Frame -ge $evt.frames.Count) {
      Write-Host "no frame $Frame (stack has $($evt.frames.Count))" -ForegroundColor Red
      Send 'quit'; $state = 'done'; continue
    }
    $f = $evt.frames[$Frame]
    Write-Host "frame $Frame = $($f.proc) at $($f.va) ebp $($f.ebp)" -ForegroundColor Green
    $state = 'wait-locals'
    Send "framelocals 1 $($f.va) $($f.ebp)"
    continue
  }

  if ($name -eq 'framelocals' -and $state -eq 'wait-locals') {
    Write-Host ""
    Write-Host "locals ($($evt.items.Count)):" -ForegroundColor Yellow
    foreach ($it in $evt.items) {
      $q = ''
      if ($null -ne $it.queueCtrl) { $q = "   <-- QUEUE ctrl=$($it.queueCtrl) records=$($it.records) typeRef=$($it.queueTypeRef)" }
      Write-Host ("  {0,-12} {1,-12} {2}{3}" -f $it.name, $it.type, $it.value, $q)
      if ($null -ne $it.queueCtrl) {
        $next++
        $reqQueue.Enqueue("queuerows $next $($it.module) $($it.queueTypeRef) $($it.queueCtrl)")
      }
    }
    Write-Host ""
    if ($reqQueue.Count -eq 0) { Write-Host "no queues found in this frame" -ForegroundColor Red; Send 'quit'; $state = 'done'; continue }
    $state = 'wait-rows'
    Send $reqQueue.Dequeue()
    continue
  }

  if ($name -eq 'queuerows') {
    if ($null -ne $evt.error) {
      Write-Host "queuerows error: $($evt.error)" -ForegroundColor Red
    } else {
      $comp = 'raw'
      if ($evt.compressed) { $comp = 'RLE-compressed' }
      Write-Host "rows: total=$($evt.total) from=$($evt.from) ($comp)" -ForegroundColor Yellow
      foreach ($r in $evt.items) {
        Write-Host "  $($r.name) $($r.value)"
        foreach ($c in $r.children) {
          $kids = ''
          if ($null -ne $c.children) {
            $vals = @()
            foreach ($k in $c.children) { $vals += "$($k.name)=$($k.value)" }
            $kids = '  { ' + ($vals -join ' ') + ' }'
          }
          $mark = ''
          if ($c.ref -eq $true) { $mark = '   <-- ref, typeRef=' + $c.typeRef }
          Write-Host ("      {0,-12} {1,-14} {2}{3}{4}" -f $c.name, $c.type, $c.value, $kids, $mark)
          # Follow a reference field inside a row while the process is still live and at the SAME
          # load base, so the address is the one this run actually produced.
          if ($Follow -and $c.ref -eq $true -and $c.addr) {
            $next++
            $reqQueue.Enqueue("expand $next $($c.module) $($c.typeRef) $($c.addr)")
          }
        }
      }
      $rowsShown++
    }
    Write-Host ""
    if ($reqQueue.Count -gt 0) { Send $reqQueue.Dequeue() } else { Send 'quit'; $state = 'done' }
    continue
  }

  if ($name -eq 'expanded') {
    Write-Host "expanded (a row's reference field):" -ForegroundColor Yellow
    foreach ($it in $evt.items) {
      Write-Host ("      {0,-12} {1,-14} {2}" -f $it.name, $it.type, $it.value)
    }
    Write-Host ""
    if ($reqQueue.Count -gt 0) { Send $reqQueue.Dequeue() } else { Send 'quit'; $state = 'done' }
    continue
  }

  if ($name -eq 'error') { Write-Host "engine error: $($evt.message)" -ForegroundColor Red }
  if ($name -eq 'exited') { break }
}

if ($state -ne 'done') { Write-Host "driver stopped in state '$state' (timeout or early exit)" -ForegroundColor Red }
try { if (-not $proc.HasExited) { $proc.Kill() } } catch { }
Unregister-Event -SourceIdentifier $outEvt.Name -ErrorAction SilentlyContinue
Unregister-Event -SourceIdentifier $errEvt.Name -ErrorAction SilentlyContinue
Write-Host "done ($rowsShown queue(s) reported)" -ForegroundColor Green
