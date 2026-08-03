<#
  Builds a proper multi-resolution .ico (16/24/32/48/64/128/256 px) from
  BinSifter-WindowIcon.png using System.Drawing.

  Unlike a naive resize, this first auto-detects the actual artwork's
  bounding box (trimming the blank/transparent margin baked into the
  source canvas) and crops to a small-padding square around it, so the
  icon fills its tile the way the other desktop icons do, instead of
  looking small and centered in a sea of empty space.

  Run from the repo root:
      powershell -ExecutionPolicy Bypass -File .\make_icon.ps1

  Outputs:
    BinSifter-WindowIcon.ico                   - the icon
    BinSifter-WindowIcon-cropped-preview.png    - the cropped square, for review
#>

Add-Type -AssemblyName System.Drawing

$src = Join-Path $PSScriptRoot 'BinSifter-WindowIcon.png'
$dst = Join-Path $PSScriptRoot 'BinSifter-WindowIcon.ico'
$croppedPreview = Join-Path $PSScriptRoot 'BinSifter-WindowIcon-cropped-preview.png'

if (-not (Test-Path $src)) {
    Write-Error "Source PNG not found: $src"
    exit 1
}

$srcImg = [System.Drawing.Image]::FromFile($src)

# --- Step 1: fast bounding-box scan on a small downscaled copy ---
$scanSize = 300
$scanBmp = [System.Drawing.Bitmap]::new($scanSize, $scanSize)
$g = [System.Drawing.Graphics]::FromImage($scanBmp)
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g.Clear([System.Drawing.Color]::Transparent)
$g.DrawImage($srcImg, 0, 0, $scanSize, $scanSize)
$g.Dispose()

$rect = [System.Drawing.Rectangle]::new(0, 0, $scanSize, $scanSize)
$bmpData = $scanBmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$bytes = New-Object byte[] ($bmpData.Stride * $scanSize)
[System.Runtime.InteropServices.Marshal]::Copy($bmpData.Scan0, $bytes, 0, $bytes.Length)
$scanBmp.UnlockBits($bmpData)

$cornerB = $bytes[0]; $cornerG = $bytes[1]; $cornerR = $bytes[2]; $cornerA = $bytes[3]
$hasAlpha = $cornerA -lt 250

$minX = $scanSize; $minY = $scanSize; $maxX = -1; $maxY = -1
$threshold = 24

for ($y = 0; $y -lt $scanSize; $y++) {
    $rowOffset = $y * $bmpData.Stride
    for ($x = 0; $x -lt $scanSize; $x++) {
        $idx = $rowOffset + ($x * 4)
        $b = $bytes[$idx]; $gc = $bytes[$idx + 1]; $r = $bytes[$idx + 2]; $a = $bytes[$idx + 3]
        $isFg = $false
        if ($hasAlpha) {
            if ($a -gt 10) { $isFg = $true }
        } else {
            $diff = [Math]::Abs($r - $cornerR) + [Math]::Abs($gc - $cornerG) + [Math]::Abs($b - $cornerB)
            if ($diff -gt $threshold) { $isFg = $true }
        }
        if ($isFg) {
            if ($x -lt $minX) { $minX = $x }
            if ($x -gt $maxX) { $maxX = $x }
            if ($y -lt $minY) { $minY = $y }
            if ($y -gt $maxY) { $maxY = $y }
        }
    }
}
$scanBmp.Dispose()

if ($maxX -lt 0) {
    Write-Warning "No foreground content detected - using full canvas"
    $minX = 0; $minY = 0; $maxX = $scanSize - 1; $maxY = $scanSize - 1
}

# map bbox back to full-resolution coordinates
$scaleFactor = $srcImg.Width / $scanSize
$fx0 = [Math]::Floor($minX * $scaleFactor)
$fy0 = [Math]::Floor($minY * $scaleFactor)
$fx1 = [Math]::Ceiling(($maxX + 1) * $scaleFactor)
$fy1 = [Math]::Ceiling(($maxY + 1) * $scaleFactor)

$bboxW = $fx1 - $fx0
$bboxH = $fy1 - $fy0

# small uniform padding, then square up around the content's center
$pad = [Math]::Round([Math]::Max($bboxW, $bboxH) * 0.06)
$squareSize = [Math]::Max($bboxW, $bboxH) + (2 * $pad)

$centerX = $fx0 + ($bboxW / 2)
$centerY = $fy0 + ($bboxH / 2)
$sqX = [Math]::Round($centerX - ($squareSize / 2))
$sqY = [Math]::Round($centerY - ($squareSize / 2))

if ($sqX -lt 0) { $sqX = 0 }
if ($sqY -lt 0) { $sqY = 0 }
if (($sqX + $squareSize) -gt $srcImg.Width)  { $sqX = $srcImg.Width  - $squareSize }
if (($sqY + $squareSize) -gt $srcImg.Height) { $sqY = $srcImg.Height - $squareSize }
if ($sqX -lt 0) { $sqX = 0 }
if ($sqY -lt 0) { $sqY = 0 }
$squareSize = [Math]::Min($squareSize, [Math]::Min($srcImg.Width - $sqX, $srcImg.Height - $sqY))

Write-Host "Detected content bbox (full-res): x=$fx0 y=$fy0 w=$bboxW h=$bboxH"
Write-Host "Square crop region: x=$sqX y=$sqY size=$squareSize"

# --- Step 2: crop the full-res source down to that square ---
$cropped = [System.Drawing.Bitmap]::new([int]$squareSize, [int]$squareSize)
$g2 = [System.Drawing.Graphics]::FromImage($cropped)
$g2.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
$g2.InterpolationMode  = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g2.SmoothingMode      = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g2.Clear([System.Drawing.Color]::Transparent)
$srcRect = [System.Drawing.Rectangle]::new([int]$sqX, [int]$sqY, [int]$squareSize, [int]$squareSize)
$dstRect = [System.Drawing.Rectangle]::new(0, 0, [int]$squareSize, [int]$squareSize)
$g2.DrawImage($srcImg, $dstRect, $srcRect, [System.Drawing.GraphicsUnit]::Pixel)
$g2.Dispose()
$srcImg.Dispose()

$cropped.Save($croppedPreview, [System.Drawing.Imaging.ImageFormat]::Png)
Write-Host "Wrote cropped preview: $croppedPreview"

# --- Step 3: generate the multi-res ICO from the cropped square ---
$sizes = 16, 24, 32, 48, 64, 128, 256
$pngBytesList = New-Object System.Collections.Generic.List[byte[]]

foreach ($s in $sizes) {
    $bmp = [System.Drawing.Bitmap]::new($s, $s)
    $g3 = [System.Drawing.Graphics]::FromImage($bmp)
    $g3.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g3.InterpolationMode  = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g3.SmoothingMode      = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g3.PixelOffsetMode    = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g3.Clear([System.Drawing.Color]::Transparent)
    $g3.DrawImage($cropped, 0, 0, $s, $s)
    $g3.Dispose()

    $ms = [System.IO.MemoryStream]::new()
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngBytesList.Add($ms.ToArray())
    $ms.Dispose()
    $bmp.Dispose()
}
$cropped.Dispose()

$fs = [System.IO.FileStream]::new($dst, [System.IO.FileMode]::Create)
$bw = [System.IO.BinaryWriter]::new($fs)

$bw.Write([UInt16]0)
$bw.Write([UInt16]1)
$bw.Write([UInt16]$sizes.Count)

$offset = 6 + (16 * $sizes.Count)
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]
    $len = $pngBytesList[$i].Length
    $wByte = if ($s -ge 256) { 0 } else { $s }
    $hByte = if ($s -ge 256) { 0 } else { $s }
    $bw.Write([Byte]$wByte)
    $bw.Write([Byte]$hByte)
    $bw.Write([Byte]0)
    $bw.Write([Byte]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]32)
    $bw.Write([UInt32]$len)
    $bw.Write([UInt32]$offset)
    $offset += $len
}

foreach ($data in $pngBytesList) {
    $bw.Write($data)
}

$bw.Flush()
$bw.Close()
$fs.Close()

Write-Host "Wrote $dst"
Get-Item $dst | Select-Object Name, Length
