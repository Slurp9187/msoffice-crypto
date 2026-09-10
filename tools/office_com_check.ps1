<#
.SYNOPSIS
    Open a password-protected Office file in the real Microsoft Office application for its
    format -- Word, Excel or PowerPoint -- and say whether it read it.

.DESCRIPTION
    The Microsoft Office leg of the four-reader acceptance gate (GH #8), and the only one
    `cargo test` can never run: it needs Office installed and an interactive desktop
    session, which no CI runner has. tools/acceptance_gate.py drives it; it can also be run
    by hand. Until 2026-09-05 this was tools/word_com_check.ps1 and knew only Word; the
    Office-16-written .xlsx and .pptx controls needed Excel and PowerPoint, so the
    application is now chosen by extension.

    Two opens, and both matter:

      1. the right password  -> the application must open the file AND the text it
                                recovers must contain the expected text. Asserting on
                                content is the point: alerts are suppressed, which also
                                hides "unreadable content, repair?" dialogs, and a repaired
                                file is a failure that looks like success.
      2. a wrong password    -> the application must REFUSE, and refuse for the password
                                reason. Reaching that error means it walked the container,
                                found EncryptionInfo, accepted its header and XML and ran
                                the KDF -- every step that depends on the file being
                                well-formed -- before failing on the one thing that was
                                meant to fail. That is the control that makes the first
                                open mean something.

    What "refused for the password reason" looks like, measured on Microsoft 365 build
    16.0.19127.20302 against Office's own fixtures (tests/fixtures/*16_agile.*):

      Word        Documents.Open(..., PasswordDocument) throws HRESULT 0x800A1520.
                  Others seen: 0x800A17C8 = no usable EncryptionInfo; 0x800A141F = the
                  stream or its XML was rejected; 0x800A1066 "Command failed" = the
                  verifier passed and something after it failed (Word requires and
                  checks dataIntegrity, so this is the tampered-file code).
      Excel       Workbooks.Open(..., Password) throws 0x800A03EC -- Excel's one HRESULT
                  for everything -- with the message "The password you supplied is not
                  correct. Verify that the CAPS LOCK key is off ...". The message is the
                  verdict, so it is matched too.
      PowerPoint  Presentations.Open has no password parameter; the password rides in the
                  file name as "path::password::". A wrong one does not throw: PowerPoint
                  raises a modal password prompt (a top-level window of class NUIDialog
                  titled "Microsoft PowerPoint", one NetUIHWND child, so there is no
                  control text to read) and the call blocks. ppAlertsNone does not
                  suppress it and ProtectedViewWindows.Open behaves the same. So every
                  open here runs under a watcher that records any NUIDialog the
                  application shows and closes it (WM_CLOSE); the blocked Open then
                  throws 0x80004005. PowerPoint's refusal is "prompted, then threw",
                  and the control that it is the PASSWORD prompt is that the right
                  password opens the same file with no dialog at all.

    The watcher runs for Word and Excel too. A dialog during the right-password open of
    any of the three is reported and is a failure, whatever the text says.

    What this leg cannot give: bytes. An application parses the package into a document
    and never hands the ZIP back, so its bar is opens + content matches + wrong password
    refused. The two independent implementations are the byte-identical legs.

.NOTES
    Exit status (the harness reads these, and so can a human):
      0  both opens gave the right answer
      2  the right password opened the file but the content differs, or a dialog had to
         be dismissed to open it
      3  the wrong password OPENED the file
      4  the wrong password was refused, but not with the password error
      5  the right password did not open the file (the HRESULT is printed)
      6  the extension names no application this script drives

    Every application is Quit inside a finally, and anything still alive afterwards is
    stopped: a leaked WINWORD.EXE holds Normal.dotm and blocks the next run's open on a
    dialog nothing is there to dismiss, and a leaked POWERPNT.EXE blocks the next
    watcher.

    Run: pwsh -NoProfile -File tools/office_com_check.ps1 [-Path <artifact>] [-Password testpass]
         [-ExpectedTextFile tests/fixtures/plain_content.txt | -ExpectedText '...']
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path ([IO.Path]::GetTempPath()) 'msoffice_crypto_encrypt_ooxml.docx'),
    [string]$Password = 'testpass',
    [string]$WrongPassword = 'definitely-not-the-password',
    [string]$ExpectedTextFile = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tests\fixtures\plain_content.txt'),
    [string]$ExpectedText = ''
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Path)) { throw "artifact not found: $Path -- run the crypto-ops test suite first" }
$Path = (Resolve-Path $Path).Path

function Normalize([string]$s) { return (($s -replace '\s+', ' ').Trim()) }
if ($ExpectedText -ne '') {
    $expected = Normalize $ExpectedText; $expectedSource = '-ExpectedText'
} else {
    $expected = Normalize (Get-Content -Raw $ExpectedTextFile); $expectedSource = (Split-Path $ExpectedTextFile -Leaf)
}

$app = switch -Regex ([IO.Path]::GetExtension($Path).ToLowerInvariant()) {
    '^\.(docx|docm|dotx|dotm)$' { 'Word'; break }
    '^\.(xlsx|xlsm|xltx|xltm)$' { 'Excel'; break }
    '^\.(pptx|pptm|ppsx|ppsm|potx|potm)$' { 'PowerPoint'; break }
    default { '' }
}
if ($app -eq '') { "NO APPLICATION for extension $([IO.Path]::GetExtension($Path))"; exit 6 }
$processName = @{ Word = 'WINWORD'; Excel = 'EXCEL'; PowerPoint = 'POWERPNT' }[$app]

function Hex($e) {
    $hr = $e.Exception.HResult
    if ($e.Exception.InnerException) { $hr = $e.Exception.InnerException.HResult }
    '0x{0:X8}' -f ($hr -band 0xFFFFFFFF)
}

# ---- the dialog watcher -----------------------------------------------------------------
# A background job (its own process, so it runs while the COM call blocks this one) that
# polls the application's top-level windows. A visible NUIDialog is an Office modal prompt
# -- the password prompt, a repair prompt. It is logged and closed, and if the application
# is still blocked after the deadline it is stopped so the caller's Open throws rather
# than hangs.
$watcherScript = {
    param([string]$ProcessName, [int]$DeadlineSeconds)
    Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices; using System.Collections.Generic;
public static class OfficeWin {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc p, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static string FindDialog(HashSet<uint> pids, out IntPtr hwnd) {
    IntPtr found = IntPtr.Zero; string desc = null;
    EnumWindows((h, l) => {
      uint pid; GetWindowThreadProcessId(h, out pid);
      if (!pids.Contains(pid) || !IsWindowVisible(h)) return true;
      var c = new StringBuilder(256); GetClassName(h, c, 256);
      if (c.ToString() != "NUIDialog" && c.ToString() != "#32770") return true;
      var t = new StringBuilder(256); GetWindowText(h, t, 256);
      found = h; desc = "class=" + c + " title=[" + t + "]"; return false; }, IntPtr.Zero);
    hwnd = found; return desc;
  }
}
"@
    $deadline = (Get-Date).AddSeconds($DeadlineSeconds)
    while ((Get-Date) -lt $deadline) {
        $pids = [System.Collections.Generic.HashSet[uint32]]::new()
        Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | ForEach-Object { [void]$pids.Add([uint32]$_.Id) }
        if ($pids.Count -gt 0) {
            $hwnd = [IntPtr]::Zero
            $desc = [OfficeWin]::FindDialog($pids, [ref]$hwnd)
            if ($hwnd -ne [IntPtr]::Zero) {
                "DIALOG $desc -> WM_CLOSE"
                [void][OfficeWin]::PostMessage($hwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
                Start-Sleep -Seconds 2
                if ([OfficeWin]::IsWindow($hwnd)) {
                    "DIALOG survived WM_CLOSE; stopping $ProcessName"
                    Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Stop-Process -Force
                }
            }
        }
        Start-Sleep -Milliseconds 300
    }
}
function Start-Watcher { Start-Job -ScriptBlock $watcherScript -ArgumentList $processName, 90 }
function Stop-Watcher($job) {
    Stop-Job $job -ErrorAction SilentlyContinue
    $log = @(Receive-Job $job -ErrorAction SilentlyContinue | Where-Object { $_ -is [string] })
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    return $log
}

# ---- per-application open and text ---------------------------------------------------------
function Open-Document($application, [string]$path, [string]$pw) {
    switch ($app) {
        'Word' {
            # Documents.Open(FileName, ConfirmConversions, ReadOnly, AddToRecentFiles, PasswordDocument)
            return $application.Documents.Open($path, $false, $true, $false, $pw)
        }
        'Excel' {
            # Workbooks.Open(FileName, UpdateLinks, ReadOnly, Format, Password)
            return $application.Workbooks.Open($path, 0, $true, [Type]::Missing, $pw)
        }
        'PowerPoint' {
            # Presentations.Open(FileName, ReadOnly, Untitled, WithWindow); msoTrue = -1, msoFalse = 0
            return $application.Presentations.Open("${path}::${pw}::", -1, 0, 0)
        }
    }
}
function Get-DocumentText($document) {
    switch ($app) {
        'Word' { return [string]$document.Content.Text }
        'Excel' {
            $parts = @()
            foreach ($ws in $document.Worksheets) {
                foreach ($cell in $ws.UsedRange.Cells) { $v = [string]$cell.Value2; if ($v) { $parts += $v } }
            }
            return ($parts -join ' ')
        }
        'PowerPoint' {
            $parts = @()
            foreach ($slide in $document.Slides) {
                foreach ($shape in $slide.Shapes) { if ($shape.HasTextFrame) { $parts += [string]$shape.TextFrame.TextRange.Text } }
            }
            return ($parts -join ' ')
        }
    }
}
function Close-Document($document) {
    switch ($app) {
        'Word' { $document.Close(0) }
        'Excel' { $document.Close($false) }
        'PowerPoint' { $document.Close() }
    }
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($document)
}
function Test-PasswordRefusal([string]$hex, [string]$message, [string[]]$dialogs) {
    switch ($app) {
        'Word' { return ($hex -eq '0x800A1520') }
        'Excel' { return ($hex -eq '0x800A03EC' -and $message -match 'password you supplied is not correct') }
        'PowerPoint' { return (@($dialogs | Where-Object { $_ -like 'DIALOG *' }).Count -gt 0) }
    }
}
$refusalDescription = @{
    Word = 'password incorrect -- container, header, XML and KDF all accepted'
    Excel = '"The password you supplied is not correct" -- container, header, XML and KDF all accepted'
    PowerPoint = 'PowerPoint prompted for a password instead of opening (prompt dismissed); the same file opens with the right password and no prompt'
}[$app]

if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
    throw "$processName is already running; close it first -- a live instance turns opens into dialogs this script cannot dismiss, and the watcher would stop it"
}

$application = $null
$exit = 0
try {
    $application = New-Object -ComObject "$app.Application"
    try { "$app $($application.Version) build $($application.Build)" } catch { "$app (version query failed)" }
    if ($app -ne 'PowerPoint') { $application.Visible = $false }   # PowerPoint has no headless mode; WithWindow=0 is the closest
    switch ($app) {
        'Word' { $application.DisplayAlerts = 0 }
        'Excel' { $application.DisplayAlerts = $false }
        'PowerPoint' { $application.DisplayAlerts = 1 }            # ppAlertsNone
    }

    # 1. the right password
    $watcher = Start-Watcher
    $document = $null
    try {
        try {
            $document = Open-Document $application $Path $Password
        } catch {
            $dialogs = Stop-Watcher $watcher; $watcher = $null
            $dialogs | ForEach-Object { "  $_" }
            "RIGHT PASSWORD : DID NOT OPEN -- $app threw $(Hex $_) :: $($_.Exception.Message.Trim())"
            exit 5
        }
        $text = Normalize (Get-DocumentText $document)
        $dialogs = Stop-Watcher $watcher; $watcher = $null
        $dialogs | ForEach-Object { "  $_" }
        if ($dialogs.Count -gt 0) {
            "RIGHT PASSWORD : OPENED ONLY AFTER A DIALOG WAS DISMISSED -- a repaired file is a failure"
            exit 2
        }
        if ($text.Contains($expected)) {
            "RIGHT PASSWORD : OPENED in $app, content matches $expectedSource"
        } else {
            "RIGHT PASSWORD : OPENED, BUT CONTENT DIFFERS -- got: $($text.Substring(0, [Math]::Min(200, $text.Length)))"
            exit 2
        }
    } finally {
        if ($watcher) { [void](Stop-Watcher $watcher) }
        if ($document) { Close-Document $document }
    }

    # 2. a wrong password -- must be refused, and refused for the right reason
    $watcher = Start-Watcher
    $document = $null
    try {
        try {
            $document = Open-Document $application $Path $WrongPassword
            $dialogs = Stop-Watcher $watcher; $watcher = $null
            $dialogs | ForEach-Object { "  $_" }
            'WRONG PASSWORD : OPENED -- THIS IS A FAILURE'
            exit 3
        } catch {
            $hex = Hex $_
            $message = $_.Exception.Message.Trim()
            $dialogs = Stop-Watcher $watcher; $watcher = $null
            $dialogs | ForEach-Object { "  $_" }
            if (Test-PasswordRefusal $hex $message $dialogs) {
                "WRONG PASSWORD : REFUSED $hex ($refusalDescription)"
            } else {
                "WRONG PASSWORD : REFUSED $hex :: $message -- NOT the password error; $app rejected the file for another reason"
                exit 4
            }
        }
    } finally {
        if ($watcher) { [void](Stop-Watcher $watcher) }
        if ($document) { Close-Document $document }
    }
} finally {
    if ($application) { try { $application.Quit() } catch { }; [void][Runtime.InteropServices.Marshal]::ReleaseComObject($application) }
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    # Quit() returns before the process does (PowerPoint takes about a second), so poll
    # before concluding anything leaked. Anything alive after that is ours: the guard
    # above refused to start if one was already running.
    $deadline = (Get-Date).AddSeconds(20)
    do {
        $leaked = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if (-not $leaked) { break }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    if ($leaked) { Write-Warning "$processName still running after Quit(); stopping it"; $leaked | Stop-Process -Force }
}
