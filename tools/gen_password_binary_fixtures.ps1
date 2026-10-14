<#
.SYNOPSIS
    Generate the password-protected 97-2003 fixtures that carry a picture and, in three
    of the four, encrypted document properties.

.DESCRIPTION
    The first password fixtures (word97_password.doc and its two twins) have no picture
    and keep their properties in the clear, so neither of the two places RC4 CryptoAPI
    puts data outside the main streams was ever exercised:

      powerpoint97_picture.ppt    a picture in the Pictures stream ([MS-PPT] 2.1.3),
                                  properties in the clear (fDocProps set) -- isolates the
                                  Pictures decryption;
      word97_encprops.doc         a picture and encrypted properties: the properties
      excel97_encprops.xls        travel in an EncryptedSummary stream ([MS-OFFCRYPTO]
      powerpoint97_encprops.ppt   2.3.5.4) and \005SummaryInformation is absent.

    The Word and Excel pictures live in the Data stream and the Workbook stream, which
    were already decrypted; they are there so the reader check can assert a picture in
    every format, not because those paths changed.

    Every file is RC4 CryptoAPI at 128 bits, password `testpass`, set through each
    application's SetPasswordEncryptionOptions.

    That method's fourth argument, PasswordEncryptionFileProperties, is accepted and read
    back as True by Office 16 and then ignored: measured 2026-10-14 on Microsoft 365
    16.0, every file it wrote had Flags 0xC (fCryptoAPI | fDocProps, "properties NOT
    encrypted") and its properties in the clear. [MS-OFFCRYPTO] Appendix A <25> lists
    only Office 2003-2013 as offering the option. What Office 16 does honour is the
    "Encrypt document properties" setting (DISA STIG V-238037), EncryptDocProps = 1:
    under HKCU\Software\Policies\... it needs administrator rights, and under
    HKCU\Software\Microsoft\Office\16.0\Common\Security it does not and works. It is
    application-wide -- it overrides the per-document argument -- so this script sets it
    only around the three *_encprops saves and restores what was there before, in a
    finally.

    What those three files showed, and src/encrypted_summary.rs is written against:
    Word and Excel name the stream `encryption`, PowerPoint `EncryptedSummary`; the
    8-byte StreamDescriptorArrayOffset/Size prefix is itself encrypted under block 0;
    \005SummaryInformation is at block 0 and \005DocumentSummaryInformation at block 1.

    The picture is drawn by this script (System.Drawing), so no upstream licence travels
    with it, and its Title is a probe string the tests and the reader check look for.
    Author fields are cleared the way tools/gen_plain_binary_fixtures.ps1 clears them,
    which says why; tests/fixture_identity.rs is the check.

    NOT byte-reproducible, for the reasons gen_plain_binary_fixtures.ps1 gives, and with
    a fresh random salt per save besides. The fixtures are committed, not regenerated.

.NOTES
    Run: powershell -NoProfile -File tools/gen_password_binary_fixtures.ps1 [-FixtureDir <dir>]
#>

[CmdletBinding()]
param(
    [string]$FixtureDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tests\fixtures'),
    [string]$Password = 'testpass'
)

$ErrorActionPreference = 'Stop'

$busy = Get-Process -Name WINWORD, EXCEL, POWERPNT -ErrorAction SilentlyContinue
if ($busy) {
    throw "Close these first, they will make SaveAs prompt: $(($busy.Name | Sort-Object -Unique) -join ', ')"
}

New-Item -ItemType Directory -Force $FixtureDir | Out-Null
$FixtureDir = (Resolve-Path $FixtureDir).Path
$text = 'msoffice-crypto picture fixture'
$title = 'msoffice-crypto summary probe'
$customName = 'msoffice-crypto probe'
$customValue = 'document summary probe'
$provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'

# A 64x48 gradient, drawn here so the bytes are this script's own output.
Add-Type -AssemblyName System.Drawing
$pngPath = Join-Path ([IO.Path]::GetTempPath()) 'msoffice_crypto_fixture_picture.png'
$jpgPath = Join-Path ([IO.Path]::GetTempPath()) 'msoffice_crypto_fixture_picture.jpg'
$emfPath = Join-Path ([IO.Path]::GetTempPath()) 'msoffice_crypto_fixture_picture.emf'
$bmp = New-Object System.Drawing.Bitmap 64, 48
try {
    for ($x = 0; $x -lt 64; $x++) {
        for ($y = 0; $y -lt 48; $y++) {
            $bmp.SetPixel($x, $y, [System.Drawing.Color]::FromArgb(255, $x * 4, $y * 5, 128))
        }
    }
    $bmp.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Save($jpgPath, [System.Drawing.Imaging.ImageFormat]::Jpeg)
} finally {
    $bmp.Dispose()
}

# An EMF too. The three pictures in each presentation are one per blip shape that
# src/powerpoint97.rs decrypts differently -- PNG and JPEG end their fixed fields in a
# 1-byte tag, a metafile in a 34-byte OfficeArtMetafileHeader -- so each layout is
# checked against what PowerPoint wrote, not only against [MS-ODRAW].
$screen = [System.Drawing.Graphics]::FromHwnd([IntPtr]::Zero)
$hdc = $screen.GetHdc()
try {
    $emf = New-Object System.Drawing.Imaging.Metafile($emfPath, $hdc, [System.Drawing.Imaging.EmfType]::EmfOnly)
} finally {
    $screen.ReleaseHdc($hdc); $screen.Dispose()
}
try {
    $g = [System.Drawing.Graphics]::FromImage($emf)
    $g.FillRectangle([System.Drawing.Brushes]::SteelBlue, 0, 0, 64, 48)
    $g.DrawEllipse([System.Drawing.Pens]::Black, 8, 8, 48, 32)
    $g.Dispose()
} finally {
    $emf.Dispose()
}

function Remove-Existing([string]$path) {
    if (Test-Path $path) { Remove-Item $path -Force }
}

# BuiltInDocumentProperties('Title').Value cannot be assigned from PowerShell (a
# parameterised COM property; gen_plain_binary_fixtures.ps1 records the error), so the
# two calls go through late binding.
function Set-Title($item, [string]$value) {
    $props = $item.BuiltInDocumentProperties
    $prop = [System.__ComObject].InvokeMember('Item', 'GetProperty', $null, $props, @('Title'))
    [void][System.__ComObject].InvokeMember('Value', 'SetProperty', $null, $prop, @($value))
    # And a custom property, which lives only in \005DocumentSummaryInformation. The
    # Title alone does not prove a reader got the properties back: Word also keeps it in
    # the table stream's associated strings, and opened rc.5's output -- properties still
    # encrypted -- showing the Title. Add(Name, LinkToContent, msoPropertyTypeString = 4,
    # Value).
    $custom = $item.CustomDocumentProperties
    [void][System.__ComObject].InvokeMember('Add', 'InvokeMethod', $null, $custom, @($customName, $false, 4, $customValue))
}

function Protect($item) {
    $item.RemovePersonalInformation = $true
    $item.SetPasswordEncryptionOptions($provider, 'RC4', 128, $false)
    $item.Password = $Password
}

$securityKey = 'HKCU:\Software\Microsoft\Office\16.0\Common\Security'
$keyExisted = Test-Path $securityKey
$previous = if ($keyExisted) { (Get-ItemProperty $securityKey).EncryptDocProps } else { $null }
function Set-EncryptDocProps([bool]$on) {
    if ($on) {
        if (-not (Test-Path $securityKey)) { New-Item -Path $securityKey -Force | Out-Null }
        New-ItemProperty -Path $securityKey -Name EncryptDocProps -PropertyType DWord -Value 1 -Force | Out-Null
    } elseif ($null -ne $previous) {
        New-ItemProperty -Path $securityKey -Name EncryptDocProps -PropertyType DWord -Value $previous -Force | Out-Null
    } elseif (Test-Path $securityKey) {
        Remove-ItemProperty -Path $securityKey -Name EncryptDocProps -ErrorAction SilentlyContinue
        if (-not $keyExisted) { Remove-Item $securityKey }
    }
}

function Release($com) {
    if ($com) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($com) }
}

# ---- Word: wdFormatDocument97 = 0 -----------------------------------------------------
function Save-Word {
    [string]$wordPath = Join-Path $FixtureDir 'word97_encprops.doc'
    Remove-Existing $wordPath
    $word = $null; $doc = $null
    try {
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $word.DisplayAlerts = 0
        $doc = $word.Documents.Add()
        $doc.Content.Text = $text
        [void]$doc.InlineShapes.AddPicture($pngPath)
        Set-Title $doc $title
        Protect $doc
        $doc.SaveAs2([ref]$wordPath, [ref]0)
    } finally {
        if ($doc) { $doc.Close(0); Release $doc }
        if ($word) { $word.Quit(); Release $word }
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
}

# ---- Excel: xlExcel8 = 56; Shapes.AddPicture(file, msoFalse link, msoTrue save, ...) ---
function Save-Excel {
    [string]$excelPath = Join-Path $FixtureDir 'excel97_encprops.xls'
    Remove-Existing $excelPath
    $excel = $null; $wb = $null
    try {
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $excel.DisplayAlerts = $false
        $wb = $excel.Workbooks.Add()
        $ws = $wb.Worksheets.Item(1)
        $ws.Range('A1').Value2 = $text
        [void]$ws.Shapes.AddPicture($pngPath, 0, -1, 10, 30, 64, 48)
        Set-Title $wb $title
        Protect $wb
        $wb.SaveAs($excelPath, 56)
    } finally {
        if ($wb) { $wb.Close($false); Release $wb }
        if ($excel) { $excel.Quit(); Release $excel }
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
}

# ---- PowerPoint: ppSaveAsPresentation = 1, ppLayoutBlank = 12 -------------------------
function Save-Presentation([string]$name) {
    [string]$pptPath = Join-Path $FixtureDir $name
    Remove-Existing $pptPath
    $ppt = $null; $pres = $null
    try {
        $ppt = New-Object -ComObject PowerPoint.Application
        $pres = $ppt.Presentations.Add($false)
        $slide = $pres.Slides.Add(1, 12)
        [void]$slide.Shapes.AddPicture($pngPath, 0, -1, 10, 10)
        [void]$slide.Shapes.AddPicture($jpgPath, 0, -1, 110, 10)
        [void]$slide.Shapes.AddPicture($emfPath, 0, -1, 210, 10)
        Set-Title $pres $title
        Protect $pres
        $pres.SaveAs($pptPath, 1)
    } finally {
        if ($pres) { $pres.Close(); Release $pres }
        if ($ppt) { $ppt.Quit(); Release $ppt }
        [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    }
}

# The picture-only presentation first, with the setting as the machine has it (absent
# here; a machine that already sets it would write powerpoint97_picture.ppt with its
# properties encrypted, which the measurement step below would show), then the three
# that need it, inside a finally that puts the setting back.
Save-Presentation 'powerpoint97_picture.ppt'
try {
    Set-EncryptDocProps $true
    Save-Word
    Save-Excel
    Save-Presentation 'powerpoint97_encprops.ppt'
} finally {
    Set-EncryptDocProps $false
}

Remove-Item $pngPath, $jpgPath, $emfPath -Force

foreach ($n in @('word97_encprops.doc', 'excel97_encprops.xls', 'powerpoint97_picture.ppt', 'powerpoint97_encprops.ppt')) {
    $p = Join-Path $FixtureDir $n
    if (-not (Test-Path $p)) { throw "not written: $p" }
    '{0,-28} {1,8} bytes' -f $n, (Get-Item $p).Length
}

$deadline = (Get-Date).AddSeconds(20)
do {
    $leaked = Get-Process -Name WINWORD, EXCEL, POWERPNT -ErrorAction SilentlyContinue
    if (-not $leaked) { break }
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $deadline)
if ($leaked) {
    Write-Warning "still running after Quit(), stopping: $(($leaked.Name | Sort-Object -Unique) -join ', ')"
    $leaked | Stop-Process -Force
}
