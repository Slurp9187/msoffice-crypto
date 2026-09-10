<#
.SYNOPSIS
    Open the 97-2003 binary documents this crate decrypted in real Word, Excel and
    PowerPoint, with NO password, and say whether each application read the content.

.DESCRIPTION
    The second oracle for GH #4 (the first is msoffcrypto-tool, whose output the suite
    compares byte for byte). `cargo test --features legacy-binary` writes one artifact
    per fixture to the system temp directory --
    msoffice_crypto_decrypted_<fixture> -- and this script opens each in the
    application that wrote the fixture, without a password, and asserts on what it
    finds: the sentence Word and Excel put into their fixture, the slide count for
    PowerPoint (whose fixture is a blank slide and carries no text).

    Two controls per format make the open mean something:

      1. the ENCRYPTED fixture opens WITH the password and shows the same content, so
         the expectation is the file's own and not something the decrypt invented;
      2. the ENCRYPTED fixture is REFUSED with a wrong password, so the application is
         actually consulting the password and not silently repairing the file
         (Word and Excel; see the PowerPoint section for why not there).

    DisplayAlerts is off, which also hides an "unreadable content, repair?" dialog --
    a repaired file is a failure that looks like success -- so every open asserts on
    content, never on Open() returning.

    PowerPoint's Presentations.Open has no password parameter; the documented COM idiom
    is a "path::password::" file name, used here for the two controls.

.NOTES
    Every application is Quit in a finally. A leaked WINWORD.EXE / EXCEL.EXE / POWERPNT.EXE
    blocks the next run, and the guard at the top refuses to start beside one.
    Run: pwsh -NoProfile -File tools/office_com_check_binary.ps1
#>
[CmdletBinding()]
param(
    [string]$FixtureDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tests\fixtures'),
    [string]$ArtifactDir = [IO.Path]::GetTempPath(),
    [string]$Password = 'testpass'
)
$ErrorActionPreference = 'Stop'
$FixtureDir = (Resolve-Path $FixtureDir).Path
$ArtifactDir = (Resolve-Path $ArtifactDir).Path
$wrong = 'definitely-not-the-password'
$failures = 0

$busy = Get-Process -Name WINWORD, EXCEL, POWERPNT -ErrorAction SilentlyContinue
if ($busy) { throw "Close these first: $(($busy.Name | Sort-Object -Unique) -join ', ')" }

function Artifact([string]$fixture) {
    $p = Join-Path $ArtifactDir "msoffice_crypto_decrypted_$fixture"
    if (-not (Test-Path $p)) { throw "artifact not found: $p -- run cargo test --features legacy-binary first" }
    return (Resolve-Path $p).Path
}
function Fixture([string]$name) { return (Join-Path $FixtureDir $name) }
function Report([string]$label, [bool]$ok, [string]$detail) {
    if ($ok) { "PASS  $label : $detail" } else { "FAIL  $label : $detail"; $script:failures++ }
}
function HResultHex($err) {
    $hr = $err.Exception.HResult
    if ($err.Exception.InnerException) { $hr = $err.Exception.InnerException.HResult }
    return '0x{0:X8}' -f ($hr -band 0xFFFFFFFF)
}

# ---- Word ---------------------------------------------------------------------------
$expectedDoc = 'msoffice-crypto fixture: word97 doc, binary format, password testpass.'
$word = $null
try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    function Open-Doc([string]$path, [string]$pw) {
        # Documents.Open(FileName, ConfirmConversions, ReadOnly, AddToRecentFiles, PasswordDocument)
        if ($pw -eq $null) { return $word.Documents.Open($path, $false, $true, $false) }
        return $word.Documents.Open($path, $false, $true, $false, $pw)
    }
    foreach ($case in @(
        @{ label = 'word97 decrypted, NO password'; path = (Artifact 'word97_password.doc'); pw = $null },
        @{ label = 'word97 encrypted fixture, right password (control)'; path = (Fixture 'word97_password.doc'); pw = $Password }
    )) {
        $doc = $null
        try {
            $doc = Open-Doc $case.path $case.pw
            $text = ([string]$doc.Content.Text).Trim()
            Report $case.label ($text.Contains($expectedDoc)) "opened; text = '$text'"
        } catch {
            Report $case.label $false "REFUSED $(HResultHex $_) $($_.Exception.Message)"
        } finally {
            if ($doc) { $doc.Close(0); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($doc) }
        }
    }
    $doc = $null
    try {
        $doc = Open-Doc (Fixture 'word97_password.doc') $wrong
        Report 'word97 encrypted fixture, wrong password (control)' $false 'OPENED -- Word did not consult the password'
    } catch {
        $hex = HResultHex $_
        Report 'word97 encrypted fixture, wrong password (control)' ($hex -eq '0x800A1520') "refused $hex"
    } finally {
        if ($doc) { $doc.Close(0); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($doc) }
    }
} finally {
    if ($word) { $word.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($word) }
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

# ---- Excel --------------------------------------------------------------------------
$expectedXls = 'msoffice-crypto fixture: excel97 xls binary format password testpass'
$expectedXor = 'msoffice-crypto unencrypted fixture'
$excel = $null
try {
    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $excel.DisplayAlerts = $false
    function Open-Xls([string]$path, [string]$pw) {
        # Workbooks.Open(Filename, UpdateLinks, ReadOnly, Format, Password)
        if ($pw -eq $null) { return $excel.Workbooks.Open($path, 0, $true) }
        return $excel.Workbooks.Open($path, 0, $true, 5, $pw)
    }
    foreach ($case in @(
        @{ label = 'excel97 RC4 decrypted, NO password'; path = (Artifact 'excel97_password.xls'); pw = $null; expect = $expectedXls },
        @{ label = 'excel97 RC4 encrypted fixture, right password (control)'; path = (Fixture 'excel97_password.xls'); pw = $Password; expect = $expectedXls },
        @{ label = 'excel97 XOR decrypted, NO password'; path = (Artifact 'excel97_xor.xls'); pw = $null; expect = $expectedXor },
        @{ label = 'excel97 XOR fixture (generated), right password (control)'; path = (Fixture 'excel97_xor.xls'); pw = $Password; expect = $expectedXor }
    )) {
        $wb = $null
        try {
            $wb = Open-Xls $case.path $case.pw
            # Every non-empty cell of the first sheet: the fixture's sentence is not
            # necessarily in A1, and asserting on the whole sheet is what shows the
            # decrypt reached every record.
            $cells = @()
            foreach ($cell in $wb.Worksheets.Item(1).UsedRange.Cells) {
                $v = [string]$cell.Value2
                if ($v -ne '') { $cells += $v }
            }
            Report $case.label ($cells -contains $case.expect) "opened; cells = '$($cells -join ' | ')'"
        } catch {
            Report $case.label $false "REFUSED $(HResultHex $_) $($_.Exception.Message)"
        } finally {
            if ($wb) { $wb.Close($false); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($wb) }
        }
    }
    foreach ($case in @(
        @{ label = 'excel97 RC4 encrypted fixture, wrong password (control)'; path = (Fixture 'excel97_password.xls') },
        @{ label = 'excel97 XOR fixture, wrong password (control)'; path = (Fixture 'excel97_xor.xls') }
    )) {
        $wb = $null
        try {
            $wb = Open-Xls $case.path $wrong
            Report $case.label $false 'OPENED -- Excel did not consult the password'
        } catch {
            Report $case.label $true "refused $(HResultHex $_)"
        } finally {
            if ($wb) { $wb.Close($false); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($wb) }
        }
    }
} finally {
    if ($excel) { $excel.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($excel) }
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

# ---- PowerPoint ---------------------------------------------------------------------
$ppt = $null
try {
    $ppt = New-Object -ComObject PowerPoint.Application
    function Open-Ppt([string]$path, [string]$pw) {
        # Presentations.Open(FileName, ReadOnly, Untitled, WithWindow); the password
        # travels in the file name as "path::password::".
        $name = if ($pw -eq $null) { $path } else { "${path}::${pw}::" }
        return $ppt.Presentations.Open($name, -1, 0, 0)
    }
    function Slide-Summary($pres) {
        $texts = @()
        foreach ($slide in $pres.Slides) {
            foreach ($shape in $slide.Shapes) {
                if ($shape.HasTextFrame -and $shape.TextFrame.HasText) { $texts += $shape.TextFrame.TextRange.Text }
            }
        }
        return "slides = $($pres.Slides.Count); text = '$($texts -join ' | ')'"
    }
    foreach ($case in @(
        @{ label = 'powerpoint97 decrypted, NO password'; path = (Artifact 'powerpoint97_password.ppt'); pw = $null },
        @{ label = 'powerpoint97 encrypted fixture, right password (control)'; path = (Fixture 'powerpoint97_password.ppt'); pw = $Password }
    )) {
        $pres = $null
        try {
            $pres = Open-Ppt $case.path $case.pw
            $summary = Slide-Summary $pres
            Report $case.label ($pres.Slides.Count -eq 1) "opened; $summary"
        } catch {
            Report $case.label $false "REFUSED $(HResultHex $_) $($_.Exception.Message)"
        } finally {
            if ($pres) { $pres.Close(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($pres) }
        }
    }
    # No wrong-password control for PowerPoint. With the "path::password::" idiom a wrong
    # password makes PowerPoint 16 prompt modally (or, measured once, crash with
    # 0x800706BE) and there is no DisplayAlerts to suppress it, so an automated run hangs.
    # The right-password control above is what the expectation rests on: the fixture was
    # written by PowerPoint itself, so it needs no proof that PowerPoint consults the
    # password.
} finally {
    if ($ppt) { $ppt.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($ppt) }
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

$deadline = (Get-Date).AddSeconds(20)
do {
    $leaked = Get-Process -Name WINWORD, EXCEL, POWERPNT -ErrorAction SilentlyContinue
    if (-not $leaked) { break }
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $deadline)
if ($leaked) { Write-Warning "still running after Quit(), stopping: $(($leaked.Name | Sort-Object -Unique) -join ', ')"; $leaked | Stop-Process -Force }

if ($failures -gt 0) { "$failures check(s) FAILED"; exit 1 }
'all checks passed'
