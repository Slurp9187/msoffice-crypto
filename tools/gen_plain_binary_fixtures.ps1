<#
.SYNOPSIS
    Generate the three UNENCRYPTED 97-2003 binary fixtures in tests/fixtures/.

.DESCRIPTION
    word97_plain.doc, excel97_plain.xls and powerpoint97_plain.ppt are the negative
    control for the legacy detection paths in src/binary_office.rs. Every other legacy
    fixture in the corpus is password-protected, so without these a `probe` that returned
    `encrypted: Some(true)` unconditionally -- or `None` unconditionally -- would pass
    every legacy assertion in the suite. See src/classify_tests.rs,
    `an_unprotected_legacy_binary_document_reports_unencrypted`, and CLAUDE.md
    § Testing Rules, "Include a negative control".

    Why Microsoft Office COM rather than LibreOffice, which is also on this machine and
    can write all three formats: the *_password twins were saved by Office 16, so an
    Office-written control differs from its twin in exactly one variable -- the password.
    A LibreOffice-written control would leave "or is this a LibreOffice quirk?" open,
    which is the ambiguity a control exists to remove. (Measured, for the record:
    LibreOffice's `--convert-to "ppt:MS PowerPoint 97"` writes 459,264 bytes, of which
    442,604 are a preview bitmap in \005SummaryInformation that no test reads. Disabling
    /org.openoffice.Office.Common/Save/Document/GenerateThumbnail in the user profile does
    not suppress it on the binary export path.)

    NOT byte-reproducible. Office stamps the CFB directory entries with creation and
    modification FILETIMEs and writes a fresh document GUID, so a rerun produces a
    different file with the same classification. The same caveat applies to
    tools/gen_agile_fixtures.py; the fixtures are committed, not regenerated per build.

    Sizes as generated on Microsoft 365 build 16.0.19127.20302:
        word97_plain.doc          25,088 bytes
        excel97_plain.xls         25,600 bytes
        powerpoint97_plain.ppt   257,536 bytes
    The .ppt is 200 KB of master-slide and font machinery that PowerPoint writes into
    every presentation; ppLayoutBlank is the floor. A ppLayoutText slide carrying the
    same string measured 274,944 -- 17,408 bytes for text nothing asserts.

    The author fields are cleared before each SaveAs, because tests/fixture_identity.rs
    asserts that every Office-written fixture -- word97_plain.doc among them -- carries an
    Author and LastAuthor that are empty or absent. Office stamps Application.UserName into
    everything it saves, so a run that did not clear them produced fixtures this
    repository's own suite rejects, which is what this script used to do while its header
    said the leak was expected and left the remedy to the reader.

    Two things that header also got wrong, both checked rather than reasoned about:
    PowerPoint.Application has no UserName property at all (Get-Member: False) and Word
    rejects an empty one outright ("Bad parameter"), so the advice to set
    $word.UserName / $excel.UserName / $ppt.UserName could not have worked on any of the
    three; and the decision was cited as
    "GH #9", which docs/design/development-record.md section 7 describes as the publish
    issue about a fresh cargo test inside the unpacked tarball. Whether #9 also carried the
    metadata item is not resolvable from this repository -- the issues live in the archived
    one -- so the check is named here instead of the number.

    Clearing the properties is not the whole story for a fixture that is committed:
    Office's own Document Inspector is what produced the empty fields in the six
    regenerated fixtures, and this script reproduces that result rather than that process.
    Run tests/fixture_identity.rs after any regeneration; it reads all four places the name
    hides, only one of which a grep over tests/fixtures/ can see.

.NOTES
    Every application is Quit inside a finally block. A leaked WINWORD.EXE holds
    Normal.dotm and makes the next run's Documents.Add() block on a "in use" dialog that
    nothing is there to dismiss, so the finally is not tidiness -- it is what keeps the
    script rerunnable.

    Run from anywhere:
        pwsh -File tools/gen_plain_binary_fixtures.ps1

    Verify against the independent oracle afterwards:
        py -3 -c "import msoffcrypto; print(msoffcrypto.OfficeFile(open('tests/fixtures/word97_plain.doc','rb')).is_encrypted())"
    which must print False for all three.
#>

[CmdletBinding()]
param(
    # Overridable so the script can be exercised without touching the committed corpus.
    [string]$FixtureDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tests\fixtures')
)

$ErrorActionPreference = 'Stop'

# A live instance of any of the three turns SaveAs into an interactive dialog, and this
# script has no window to dismiss it in. Refuse rather than hang.
$busy = Get-Process -Name WINWORD, EXCEL, POWERPNT -ErrorAction SilentlyContinue
if ($busy) {
    throw "Close these first, they will make SaveAs prompt: $(($busy.Name | Sort-Object -Unique) -join ', ')"
}

New-Item -ItemType Directory -Force $FixtureDir | Out-Null
$FixtureDir = (Resolve-Path $FixtureDir).Path
$text = 'msoffice-crypto unencrypted fixture'

function Remove-Existing([string]$path) {
    if (Test-Path $path) { Remove-Item $path -Force }
}

# The programmatic Document Inspector, which is what produced the empty author fields in
# the fixtures already committed -- so this reproduces their state by the same route
# rather than approximating it. Word, Excel and PowerPoint each expose it on the document
# object, and it applies at save, which is what makes it reach LastAuthor as well as
# Author.
#
# Measured, because the two obvious alternatives do not work and the old header
# recommended one of them:
#
#   $app.UserName = ''                              -> "Bad parameter" (Word rejects empty)
#   $doc.BuiltInDocumentProperties('Author').Value = ''
#                                                   -> "Object reference not set to an
#                                                      instance of an object", PowerShell
#                                                      cannot assign through a
#                                                      parameterised COM property
#
# Set on the document, never on the application: it is a per-document flag, and a
# fixture that was saved without it carries the name whatever the application was told.
function Set-RemovePersonalInformation($item) {
    $item.RemovePersonalInformation = $true
}

# ---- Word 97-2003 (.doc) --------------------------------------------------------------
# wdFormatDocument97 = 0. The FIB's fEncrypted bit (0x0100 at offset 0x0A) stays clear,
# which is the single bit src/binary_office.rs::probe_word reads to reach Some(false).
#
# [string] on the path is load-bearing: Join-Path yields a PSObject-wrapped string and
# SaveAs2's [ref] parameter rejects it with "Cannot convert ... psobject to type Object".
[string]$wordPath = Join-Path $FixtureDir 'word97_plain.doc'
Remove-Existing $wordPath
$word = $null; $doc = $null
try {
    $word = New-Object -ComObject Word.Application
    $word.Visible = $false
    $word.DisplayAlerts = 0
    $doc = $word.Documents.Add()
    $doc.Content.Text = $text
    Set-RemovePersonalInformation $doc
    $doc.SaveAs2([ref]$wordPath, [ref]0)
} finally {
    if ($doc) { $doc.Close(0); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($doc) }
    if ($word) { $word.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($word) }
    # Inside the finally, not after the last block: a failure mid-try aborts the script,
    # and a Quit() whose RCW is never released leaves WINWORD.EXE running anyway.
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

# ---- Excel 97-2003 (.xls) -------------------------------------------------------------
# xlExcel8 = 56. No FILEPASS (0x002F) record is written. probe_excel's walk reads BOF,
# INTERFACEHDR, then MMS (0x00C1) -- a record [MS-XLS] requires to be encrypted, met in
# the clear -- and that third record is the proof there is no FILEPASS. The walk never
# reaches the globals EOF; it is the record walk itself that this fixture exercises.
[string]$excelPath = Join-Path $FixtureDir 'excel97_plain.xls'
Remove-Existing $excelPath
$excel = $null; $wb = $null
try {
    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $excel.DisplayAlerts = $false
    $wb = $excel.Workbooks.Add()
    $wb.Worksheets.Item(1).Range('A1').Value2 = $text
    Set-RemovePersonalInformation $wb
    $wb.SaveAs($excelPath, 56)
} finally {
    if ($wb) { $wb.Close($false); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($wb) }
    if ($excel) { $excel.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($excel) }
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

# ---- PowerPoint 97-2003 (.ppt) --------------------------------------------------------
# ppSaveAsPresentation = 1, ppLayoutBlank = 12. The UserEditAtom this writes has
# recLen 0x1C; its encrypted twin's is 0x20. probe_powerpoint first checks the header at
# offsetToCurrentEdit is a UserEditAtom at all (0x0000, 0x0FF5), then that length is the
# verdict.
[string]$pptPath = Join-Path $FixtureDir 'powerpoint97_plain.ppt'
Remove-Existing $pptPath
$ppt = $null; $pres = $null
try {
    $ppt = New-Object -ComObject PowerPoint.Application
    # $false = msoFalse: no document window. PowerPoint has no headless mode; this is the
    # closest it offers, and it is why the finally below matters more here than anywhere.
    $pres = $ppt.Presentations.Add($false)
    [void]$pres.Slides.Add(1, 12)
    Set-RemovePersonalInformation $pres
    $pres.SaveAs($pptPath, 1)
} finally {
    if ($pres) { $pres.Close(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($pres) }
    if ($ppt) { $ppt.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($ppt) }
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
}

foreach ($p in @($wordPath, $excelPath, $pptPath)) {
    if (-not (Test-Path $p)) { throw "not written: $p" }
    '{0,-24} {1,8} bytes' -f (Split-Path $p -Leaf), (Get-Item $p).Length
}

# PowerPoint's Quit() returns before the process does -- measured at roughly a second on
# this machine -- so poll rather than warning on the first look. Anything still alive here
# is ours: the guard at the top refused to start if one of the three was already running.
$deadline = (Get-Date).AddSeconds(20)
do {
    $leaked = Get-Process -Name WINWORD, EXCEL, POWERPNT -ErrorAction SilentlyContinue
    if (-not $leaked) { break }
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $deadline)

if ($leaked) {
    # Not tidiness: a surviving WINWORD.EXE holds Normal.dotm and the next run's
    # Documents.Add() blocks on a dialog nothing is there to dismiss.
    Write-Warning "still running after Quit(), stopping: $(($leaked.Name | Sort-Object -Unique) -join ', ')"
    $leaked | Stop-Process -Force
}
