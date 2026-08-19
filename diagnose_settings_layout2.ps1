<#
    diagnose_settings_layout2.ps1

    Round 2 of the Settings-page-controls-invisible diagnostic (2026-08-19).
    The first diagnostic (diagnose_settings_layout.ps1) built the Settings
    TableLayoutPanel in isolation, made it visible immediately, and it
    scaled perfectly - which ruled out a general TableLayoutPanel/Scale()
    bug and pointed at ONE remaining structural difference: in the real
    app, Settings starts out Visible = $false (only Dashboard is shown at
    first) at the moment Scale() runs, and only becomes visible later when
    the user actually navigates to it.

    A first fix attempt (briefly flipping every page Visible = $true then
    back to $false right after Scale(), wrapped in
    $content.SuspendLayout()/ResumeLayout()) did NOT fix the real app -
    confirmed by direct user re-test. Rather than guess a third time, this
    script reproduces the FULL real sequence - two pages (a simple
    Dashboard-like one and the real Settings layout), Settings starting
    invisible, Scale() run while it's still invisible, then several
    different recovery attempts tried in order - and dumps real
    Location/Size for the key controls at every single stage, so we can
    see exactly which stage (if any) actually fixes it, instead of
    assuming.

    Run directly, no build/install needed:
        pwsh -File diagnose_settings_layout2.ps1
    Paste back everything it prints.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[void][System.Windows.Forms.Application]::SetHighDpiMode([System.Windows.Forms.HighDpiMode]::PerMonitorV2)
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Settings Layout Diagnostic v2'
$form.Size = New-Object System.Drawing.Size(1400, 900)
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$form.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)

$content = New-Object System.Windows.Forms.Panel
$content.Dock = [System.Windows.Forms.DockStyle]::Fill
$form.Controls.Add($content)

# ---- a trivial "Dashboard" page, shown first, same as the real app ----
$dashPage = New-Object System.Windows.Forms.Panel
$dashPage.Dock = [System.Windows.Forms.DockStyle]::Fill
$dashLbl = New-Object System.Windows.Forms.Label
$dashLbl.Text = 'Dashboard placeholder'
$dashLbl.AutoSize = $true
$dashPage.Controls.Add($dashLbl)

# ---- the real Settings layout, built identically to
#      diagnose_settings_layout.ps1's repro ----
$settingsPage = New-Object System.Windows.Forms.Panel
$settingsPage.Dock = [System.Windows.Forms.DockStyle]::Fill
$settingsPage.AutoScroll = $true

$layout = New-Object System.Windows.Forms.TableLayoutPanel
$layout.ColumnCount = 3
$layout.AutoSize = $true
$layout.Dock = [System.Windows.Forms.DockStyle]::Top
$null = $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
$null = $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$null = $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
$settingsPage.Controls.Add($layout)

$rowIndex = 0
$fieldLabels = @(
    'Path to binaries to scan', 'NSRL text file path', 'Path to YARA rules',
    'Path to capa rules', 'Path to tools', 'Path to Ghidra - optional'
)
$fieldTextBoxes = @()
foreach ($labelText in $fieldLabels) {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $labelText
    $lbl.AutoSize = $true
    $lbl.Anchor = [System.Windows.Forms.AnchorStyles]::Left
    $lbl.Margin = New-Object System.Windows.Forms.Padding(3, 12, 12, 3)

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $txt.Width = 620
    $txt.Margin = New-Object System.Windows.Forms.Padding(3, 6, 8, 3)
    $fieldTextBoxes += $txt

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = 'Browse...'
    $btn.Size = New-Object System.Drawing.Size(100, 30)

    $null = $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $layout.Controls.Add($lbl, 0, $rowIndex)
    $layout.Controls.Add($txt, 1, $rowIndex)
    $layout.Controls.Add($btn, 2, $rowIndex)
    $rowIndex++
}

$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = 'Save Settings'
$btnSave.Size = New-Object System.Drawing.Size(160, 38)
$btnSave.Margin = New-Object System.Windows.Forms.Padding(3, 20, 0, 0)
$null = $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
$layout.Controls.Add($btnSave, 1, $rowIndex)
$rowIndex++

$lblAvHeader = New-Object System.Windows.Forms.Label
$lblAvHeader.Text = 'Antivirus'
$lblAvHeader.AutoSize = $true
$lblAvHeader.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$lblAvHeader.Margin = New-Object System.Windows.Forms.Padding(3, 28, 0, 3)
$null = $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
$layout.Controls.Add($lblAvHeader, 1, $rowIndex)
$rowIndex++

$lblAvExplainer = New-Object System.Windows.Forms.Label
$lblAvExplainer.Text = "Detects which antivirus product(s) are registered with Windows Security on this machine. The automated exclusion button below only works for Windows Defender - for any other product, this points you at where to add the exclusion yourself."
$lblAvExplainer.AutoSize = $false
$lblAvExplainer.Width = 620
$lblAvExplainer.Height = 50
$lblAvExplainer.Margin = New-Object System.Windows.Forms.Padding(3, 0, 8, 6)
$null = $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
$layout.Controls.Add($lblAvExplainer, 1, $rowIndex)
$rowIndex++

$btnDetectAv = New-Object System.Windows.Forms.Button
$btnDetectAv.Text = 'Detect installed antivirus'
$btnDetectAv.Size = New-Object System.Drawing.Size(320, 32)
$btnDetectAv.Margin = New-Object System.Windows.Forms.Padding(3, 0, 0, 3)
$null = $layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
$layout.Controls.Add($btnDetectAv, 1, $rowIndex)
$rowIndex++

# ---- assemble pages exactly like $pageMap in the real app ----
$dashPage.Visible = $false
$settingsPage.Visible = $false
$content.Controls.Add($dashPage)
$content.Controls.Add($settingsPage)
$dashPage.Visible = $true   # only Dashboard shown at first, same as real app

function Write-Bounds {
    param([string]$Label, [System.Windows.Forms.Control]$Ctrl)
    Write-Host ("   {0,-16} Location=({1,5},{2,5})  Size=({3,5} x {4,4})  Visible={5}" -f `
        $Label, $Ctrl.Location.X, $Ctrl.Location.Y, $Ctrl.Size.Width, $Ctrl.Size.Height, $Ctrl.Visible)
}
function Write-AllBounds {
    param([string]$Stage)
    Write-Host ""
    Write-Host "=== $Stage ==="
    Write-Bounds "settingsPage"   $settingsPage
    Write-Bounds "layout"         $layout
    Write-Bounds "field[0] txt"   $fieldTextBoxes[0]
    Write-Bounds "btnSave"        $btnSave
    Write-Bounds "lblAvHeader"    $lblAvHeader
    Write-Bounds "lblAvExplainer" $lblAvExplainer
    Write-Bounds "btnDetectAv"    $btnDetectAv
}

$form.Add_Shown({
    Write-Host "================= Settings Layout Diagnostic v2 ================="
    Write-Host "PowerShell version: $($PSVersionTable.PSVersion)"

    Write-AllBounds "1. BEFORE Scale() (Settings still invisible)"

    $liveDpi = $form.DeviceDpi
    Write-Host ""
    Write-Host "Live DPI: $liveDpi  (ratio $([Math]::Round($liveDpi / 96.0, 3)))"
    if ($liveDpi -ne 96) {
        $ratio = $liveDpi / 96.0
        $form.Scale((New-Object System.Drawing.SizeF($ratio, $ratio)))
    }

    Write-AllBounds "2. AFTER Scale() (Settings STILL invisible - does Scale() even touch it?)"

    # Round-4 fix attempt as shipped: flip every page visible-then-back,
    # wrapped in content SuspendLayout/ResumeLayout.
    $content.SuspendLayout()
    $dashPage.Visible = $true
    $settingsPage.Visible = $true
    $dashPage.Visible = $true
    $settingsPage.Visible = $false
    $content.ResumeLayout($true)

    Write-AllBounds "3. AFTER round-4 visible-toggle warmup (SuspendLayout-wrapped, as shipped)"

    # Candidate fix A: PerformLayout() directly on the settings page/layout
    # while genuinely visible, no SuspendLayout anywhere.
    $settingsPage.Visible = $true
    $settingsPage.PerformLayout()
    $layout.PerformLayout()
    Write-AllBounds "4. AFTER making Settings visible for real + explicit PerformLayout() (no Suspend anywhere)"
    $settingsPage.Visible = $false

    Write-AllBounds "5. AFTER hiding Settings again (does it hold the fix from stage 4?)"

    # Final: what a real user actually sees - genuinely navigating to
    # Settings, nothing else touched after this.
    $dashPage.Visible = $false
    $settingsPage.Visible = $true
    Write-AllBounds "6. FINAL - real navigation to Settings (this is what the user actually sees)"

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 4000
    $timer.Add_Tick({ $timer.Stop(); $form.Close() })
    $timer.Start()
})

[void]$form.ShowDialog()
Write-Host ""
Write-Host "================= End of diagnostic - paste everything above back ================="
