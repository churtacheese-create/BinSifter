<#
Standalone DPI diagnostic - added 2026-08-19 after two rounds of Rowan DPI
fixes (SetHighDpiMode + AutoScaleMode.Dpi, then AutoScaleDimensions on top
of that) both LOOKED correct against Microsoft's own documented WinForms
behavior but had zero visible effect on a real 150%/175%-scaled machine -
the top-bar Settings/Help/About buttons stayed truncated to their exact
100%-scale pixel widths both times. This dev sandbox is Linux-only with no
way to run or render a WinForms app at all, so every fix so far has been
reasoned from documentation, never actually observed - this script exists
to close that gap without another full installer build/install/screenshot
round-trip. It is completely standalone (does not import or require any
part of BinSifter itself) and safe to just run directly.

Run from a PowerShell 7 prompt on the affected machine, at its real scaled
resolution (no need to touch Settings, install anything, or even have
BinSifter installed):

    pwsh -File diagnose_dpi.ps1

It briefly shows one small test window (so the real Show()/CreateHandle()
code path that actually triggers PerformAutoScale() runs, exactly like the
real app), then closes itself automatically after 2 seconds - no need to
click anything. Every diagnostic value is also printed to the console
before and after the window closes, so the console output alone is what's
needed back, no screenshot required (though one of the small test window
itself, if it's still on screen, wouldn't hurt).

What this checks, and why each one matters:
  1. Application.SetHighDpiMode()'s own return value - BinSifter's real
     code currently discards this ([void]...), so a silent failure there
     would explain BOTH fixes having zero effect with no way to have
     noticed from the logs alone. A process's DPI-awareness mode is
     typically locked in at process startup (often by pwsh.exe's own
     manifest, before any of BinSifter's own script code ever runs) - if
     that already locked in something other than Per-Monitor-V2-aware,
     a later SetHighDpiMode() call can legitimately fail, and everything
     downstream (AutoScaleMode, AutoScaleDimensions) becomes moot.
  2. The process's actual live DPI awareness (via shcore.dll's
     GetProcessDpiAwareness - a direct, load-bearing Windows API answer,
     not an inference) - confirms or refutes #1 independently.
  3. The test form's real DeviceDpi once actually shown (a genuine .NET
     Core WinForms property - the exact DPI value the form's own window
     handle was created at) versus the plain 96 baseline this whole app's
     hardcoded pixel values were chosen against - this is the ACTUAL scale
     ratio WinForms had available to work with, whatever it turned out to
     do with it.
  4. A test button sized exactly like the real top-bar Settings button
     (126x44, same font/text) - measured BEFORE Show() and AGAIN after -
     if AutoScale genuinely ran, the "after" Size should be visibly larger
     than "before" (roughly the DeviceDpi/96 ratio). If they're identical,
     AutoScale did not fire at all, regardless of what #1-#3 say.
#>

$ErrorActionPreference = 'Stop'

Write-Host "================= DPI Diagnostic =================" -ForegroundColor Cyan
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)"
Write-Host "OS: $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)"
Write-Host ""

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# P/Invoke declarations - direct, load-bearing Windows API answers about
# DPI awareness, not inferred from .NET-level behavior.
Add-Type -Namespace BinSifterDiag -Name NativeDpi -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("shcore.dll")]
public static extern int GetProcessDpiAwareness(System.IntPtr hprocess, out int value);

[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern uint GetDpiForWindow(System.IntPtr hwnd);

[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern uint GetDpiForSystem();
'@

# --- Step 1: SetHighDpiMode's own return value -----------------------------
$highDpiResult = [System.Windows.Forms.Application]::SetHighDpiMode([System.Windows.Forms.HighDpiMode]::PerMonitorV2)
Write-Host "1. Application.SetHighDpiMode(PerMonitorV2) returned: $highDpiResult" -ForegroundColor $(if ($highDpiResult) { 'Green' } else { 'Red' })
if (-not $highDpiResult) {
    Write-Host "   ^ FALSE means this call failed - the process's DPI awareness was" -ForegroundColor Red
    Write-Host "     already locked in to something else before this line ran (most" -ForegroundColor Red
    Write-Host "     likely by pwsh.exe's own manifest). If this is False, everything" -ForegroundColor Red
    Write-Host "     below is explained by this alone." -ForegroundColor Red
}
Write-Host ""

[System.Windows.Forms.Application]::EnableVisualStyles()

# --- Step 2: the process's actual live DPI awareness, independent of #1 ----
$awarenessValue = 0
$hr = [BinSifterDiag.NativeDpi]::GetProcessDpiAwareness([System.IntPtr]::Zero, [ref]$awarenessValue)
$awarenessNames = @{ 0 = 'DPI_UNAWARE'; 1 = 'SYSTEM_DPI_AWARE'; 2 = 'PER_MONITOR_DPI_AWARE' }
$awarenessName = if ($awarenessNames.ContainsKey($awarenessValue)) { $awarenessNames[$awarenessValue] } else { "unknown ($awarenessValue)" }
Write-Host "2. Actual process DPI awareness (GetProcessDpiAwareness): $awarenessName" -ForegroundColor $(if ($awarenessValue -eq 2) { 'Green' } else { 'Red' })
if ($awarenessValue -ne 2) {
    Write-Host "   ^ Needs to be PER_MONITOR_DPI_AWARE for AutoScaleMode.Dpi to have" -ForegroundColor Red
    Write-Host "     anything meaningful to work with. Anything else confirms #1's" -ForegroundColor Red
    Write-Host "     failure (or a different cause) independently." -ForegroundColor Red
}
Write-Host ""
Write-Host "   System DPI (GetDpiForSystem): $([BinSifterDiag.NativeDpi]::GetDpiForSystem()) (96 = 100% scale, 144 = 150%, 168 = 175%, 192 = 200%)"
Write-Host ""

# --- Step 3 & 4: build a real form + a real button sized like the actual ---
# --- top-bar Settings button, measure before/after Show() -----------------
$form = New-Object System.Windows.Forms.Form
$form.Text = 'BinSifter DPI Diagnostic - closes itself in 2s'
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.Size = New-Object System.Drawing.Size(400, 200)
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$form.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)

$button = New-Object System.Windows.Forms.Button
$button.Text = "$([char]0x2699)  Settings"
$button.Size = New-Object System.Drawing.Size(126, 44)
$button.Location = New-Object System.Drawing.Point(20, 20)
$button.Font = New-Object System.Drawing.Font('Segoe UI', 11.5)
$form.Controls.Add($button)

$sizeBeforeShow = $button.Size
$locBeforeShow = $button.Location

$resultLabel = New-Object System.Windows.Forms.Label
$resultLabel.AutoSize = $true
$resultLabel.Location = New-Object System.Drawing.Point(20, 80)
$resultLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.Controls.Add($resultLabel)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 2000
$timer.Add_Tick({
    $timer.Stop()
    $form.Close()
})

$form.Add_Shown({
    $timer.Start()

    $deviceDpi = $form.DeviceDpi
    $sizeAfterShow = $button.Size
    $locAfterShow = $button.Location
    $hwndDpi = [BinSifterDiag.NativeDpi]::GetDpiForWindow($form.Handle)

    Write-Host "3. Form.DeviceDpi once actually shown: $deviceDpi (this is the real, live DPI WinForms had to work with)"
    Write-Host "   GetDpiForWindow(form handle): $hwndDpi (should match DeviceDpi above)"
    Write-Host ""
    Write-Host "4. Test button (126x44 design size, same as the real top-bar Settings button):"
    Write-Host "   Size BEFORE Show(): $($sizeBeforeShow.Width) x $($sizeBeforeShow.Height)"
    Write-Host "   Size AFTER  Show(): $($sizeAfterShow.Width) x $($sizeAfterShow.Height)"
    $scaleRatio = $deviceDpi / 96.0
    $expectedWidth = [Math]::Round(126 * $scaleRatio)
    $expectedHeight = [Math]::Round(44 * $scaleRatio)
    Write-Host "   Expected AFTER (126x44 * $($deviceDpi)/96 = ${scaleRatio}x): ~$expectedWidth x $expectedHeight"
    Write-Host ""

    if ($sizeAfterShow.Width -eq $sizeBeforeShow.Width) {
        Write-Host "   ==> AutoScale did NOT resize the button at all. Location/Size are" -ForegroundColor Red
        Write-Host "       identical before and after Show(). This is the real, direct" -ForegroundColor Red
        Write-Host "       confirmation of the bug, independent of steps 1-2's explanation." -ForegroundColor Red
        $resultLabel.Text = "AutoScale did NOT resize this button (bug reproduced)."
        $resultLabel.ForeColor = [System.Drawing.Color]::Red

        # --- Step 5: try forcing it manually - a documented rough edge for
        # PerMonitorV2 specifically is that .NET WinForms' automatic rescale
        # is largely driven by handling the WM_DPICHANGED message (the
        # signal Windows sends when a window's effective DPI actually
        # CHANGES, e.g. dragged to a different monitor) rather than firing
        # unconditionally on first Show() - on a single-monitor machine, the
        # window is simply CREATED directly at its final DPI with no monitor-
        # to-monitor "change" event ever occurring, so that automatic path
        # may never run at all. PerformAutoScale() is the same underlying
        # method Form's own automatic handling calls - invoking it directly,
        # ourselves, sidesteps whatever specific automatic trigger isn't
        # firing, regardless of why.
        Write-Host ""
        Write-Host "5. Trying a manual `$form.PerformAutoScale() call as a direct fix candidate..." -ForegroundColor Cyan
        Write-Host "   Form.AutoScaleDimensions right before this call: $($form.AutoScaleDimensions.Width) x $($form.AutoScaleDimensions.Height)"
        $form.PerformAutoScale()
        Write-Host "   Form.AutoScaleDimensions right after this call:  $($form.AutoScaleDimensions.Width) x $($form.AutoScaleDimensions.Height)"
        $sizeAfterManualScale = $button.Size
        Write-Host "   Button size after manual PerformAutoScale(): $($sizeAfterManualScale.Width) x $($sizeAfterManualScale.Height)"
        if ($sizeAfterManualScale.Width -gt $sizeBeforeShow.Width) {
            Write-Host "   ==> WORKED. Manually calling PerformAutoScale() (e.g. from the" -ForegroundColor Green
            Write-Host "       main form's Add_Shown handler, right after Show() happens) is" -ForegroundColor Green
            Write-Host "       the real fix - the automatic trigger just isn't firing on its" -ForegroundColor Green
            Write-Host "       own for this window." -ForegroundColor Green
            $resultLabel.Text = "Manual PerformAutoScale() WORKED - real fix identified."
            $resultLabel.ForeColor = [System.Drawing.Color]::Green
        }
        else {
            Write-Host "   ==> Still didn't resize." -ForegroundColor Red

            # --- Step 6: bypass PerformAutoScale()'s own ratio-already-
            # matches gating entirely (if AutoScaleDimensions silently got
            # updated to match current DPI by step 5's own call, or by
            # whatever the automatic path already attempted before Shown
            # even fired, PerformAutoScale() would see ratio=1 and
            # legitimately decide there's nothing left to do - regardless of
            # whether the control's actual on-screen/Size-property state
            # ever reflects a real 1.75x scale). Control.Scale(SizeF) is the
            # lower-level, UNCONDITIONAL method PerformAutoScale() itself
            # calls internally once it decides scaling is needed - calling
            # it directly, with a manually computed ratio, sidesteps
            # whatever gating logic is preventing PerformAutoScale() from
            # reaching that decision on its own. Tested on a FRESH, never-
            # touched button (not the one steps 4-5 already poked at) so a
            # prior scaling attempt can't mask or double-apply here.
            Write-Host ""
            Write-Host "6. Trying a direct `$button2.Scale() call with a manually computed 1.75x ratio (bypasses PerformAutoScale entirely)..." -ForegroundColor Cyan
            $button2 = New-Object System.Windows.Forms.Button
            $button2.Text = "$([char]0x2699)  Settings"
            $button2.Size = New-Object System.Drawing.Size(126, 44)
            $button2.Location = New-Object System.Drawing.Point(160, 20)
            $button2.Font = New-Object System.Drawing.Font('Segoe UI', 11.5)
            $form.Controls.Add($button2)
            $sizeBeforeManualRatioScale = $button2.Size

            $manualRatio = $deviceDpi / 96.0
            $button2.Scale((New-Object System.Drawing.SizeF($manualRatio, $manualRatio)))
            $sizeAfterManualRatioScale = $button2.Size
            Write-Host "   Fresh button size BEFORE .Scale($manualRatio): $($sizeBeforeManualRatioScale.Width) x $($sizeBeforeManualRatioScale.Height)"
            Write-Host "   Fresh button size AFTER  .Scale($manualRatio): $($sizeAfterManualRatioScale.Width) x $($sizeAfterManualRatioScale.Height)"

            if ($sizeAfterManualRatioScale.Width -gt $sizeBeforeManualRatioScale.Width) {
                Write-Host "   ==> WORKED. Control.Scale(SizeF) with a manually computed" -ForegroundColor Green
                Write-Host "       DeviceDpi/96.0 ratio is the real fix - bypass AutoScaleMode/" -ForegroundColor Green
                Write-Host "       AutoScaleDimensions/PerformAutoScale entirely and call this" -ForegroundColor Green
                Write-Host "       directly on the form (which recursively scales every child)" -ForegroundColor Green
                Write-Host "       once DeviceDpi is known, right after Show()." -ForegroundColor Green
                $resultLabel.Text = "Manual .Scale(1.75x) WORKED - this is the real fix."
                $resultLabel.ForeColor = [System.Drawing.Color]::Green
            }
            else {
                Write-Host "   ==> Still didn't resize even with a direct, unconditional Scale()" -ForegroundColor Red
                Write-Host "       call. Something more unusual is going on - possibly this" -ForegroundColor Red
                Write-Host "       PowerShell/.NET combination's WinForms build itself, not just" -ForegroundColor Red
                Write-Host "       a gating/timing issue. Worth trying a completely manual fix" -ForegroundColor Red
                Write-Host "       instead: compute DeviceDpi/96.0 once and multiply every" -ForegroundColor Red
                Write-Host "       hardcoded pixel value directly when building each control," -ForegroundColor Red
                Write-Host "       rather than relying on any WinForms auto-scale mechanism." -ForegroundColor Red
                $resultLabel.Text = "Even direct .Scale() failed - needs a fully manual fix."
                $resultLabel.ForeColor = [System.Drawing.Color]::Red
            }
        }
    }
    else {
        Write-Host "   ==> AutoScale DID resize the button. If the real app still shows" -ForegroundColor Green
        Write-Host "       truncated text, the bug is elsewhere (e.g. Location math in" -ForegroundColor Green
        Write-Host "       Move-TopBarControls running before vs after the resize, or a" -ForegroundColor Green
        Write-Host "       stale cached installer build)." -ForegroundColor Green
        $resultLabel.Text = "AutoScale DID resize this button (see console for numbers)."
        $resultLabel.ForeColor = [System.Drawing.Color]::Green
    }
})

Write-Host "Showing a small test window for 2 seconds..." -ForegroundColor Cyan
[System.Windows.Forms.Application]::Run($form)

Write-Host ""
Write-Host "================= End of diagnostic - paste everything above back ================="
