<#
    diagnose_settings_layout.ps1

    Standalone diagnostic for the new "Settings page controls invisible"
    report (2026-08-19) - Save Settings button, the Antivirus section, and
    the Windows Defender section all failed to render after the DPI-scaling
    fix, while the six path fields above them (and their Browse... buttons)
    rendered correctly.

    This builds a MINIMAL reproduction of the real Settings page's layout:
    one TableLayoutPanel with 3 columns (AutoSize / Percent(100) / AutoSize),
    six "field rows" using all three columns (Label + TextBox + Button),
    then several rows that use ONLY the middle column - a Save button, a
    bold header Label, an explainer Label with an explicit Width/Height,
    and another Button - exactly mirroring New-SettingsPage's real
    structure. It prints every control's real Location/Size BEFORE and
    AFTER the same $form.Scale() call the real app now makes in
    Add_Shown, so we can see exactly which controls the DPI fix is (or
    isn't) actually rescaling, instead of guessing from a screenshot.

    Run directly, no build/install needed:
        pwsh -File diagnose_settings_layout.ps1
    Paste back everything it prints.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[void][System.Windows.Forms.Application]::SetHighDpiMode([System.Windows.Forms.HighDpiMode]::PerMonitorV2)
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Settings Layout Diagnostic'
$form.Size = New-Object System.Drawing.Size(1400, 900)
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$form.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)

$page = New-Object System.Windows.Forms.Panel
$page.Dock = [System.Windows.Forms.DockStyle]::Fill
$page.AutoScroll = $true
$form.Controls.Add($page)

$layout = New-Object System.Windows.Forms.TableLayoutPanel
$layout.ColumnCount = 3
$layout.AutoSize = $true
$layout.Dock = [System.Windows.Forms.DockStyle]::Top
$null = $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
$null = $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$null = $layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
$page.Controls.Add($layout)

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

function Write-Bounds {
    param([string]$Label, [System.Windows.Forms.Control]$Ctrl)
    Write-Host ("   {0,-16} Location=({1,5},{2,5})  Size=({3,5} x {4,4})  Visible={5}" -f `
        $Label, $Ctrl.Location.X, $Ctrl.Location.Y, $Ctrl.Size.Width, $Ctrl.Size.Height, $Ctrl.Visible)
}

$form.Add_Shown({
    Write-Host "================= Settings Layout Diagnostic ================="
    Write-Host "PowerShell version: $($PSVersionTable.PSVersion)"
    Write-Host ""
    Write-Host "=== BEFORE Scale() ==="
    Write-Bounds "layout"          $layout
    Write-Bounds "field[0] txt"    $fieldTextBoxes[0]
    Write-Bounds "btnSave"         $btnSave
    Write-Bounds "lblAvHeader"     $lblAvHeader
    Write-Bounds "lblAvExplainer"  $lblAvExplainer
    Write-Bounds "btnDetectAv"     $btnDetectAv

    $liveDpi = $form.DeviceDpi
    Write-Host ""
    Write-Host "Live DPI: $liveDpi  (ratio $([Math]::Round($liveDpi / 96.0, 3)))"

    if ($liveDpi -ne 96) {
        $ratio = $liveDpi / 96.0
        $form.Scale((New-Object System.Drawing.SizeF($ratio, $ratio)))
    }

    Write-Host ""
    Write-Host "=== AFTER Scale() ==="
    Write-Bounds "layout"          $layout
    Write-Bounds "field[0] txt"    $fieldTextBoxes[0]
    Write-Bounds "btnSave"         $btnSave
    Write-Bounds "lblAvHeader"     $lblAvHeader
    Write-Bounds "lblAvExplainer"  $lblAvExplainer
    Write-Bounds "btnDetectAv"     $btnDetectAv

    Write-Host ""
    Write-Host "=== AFTER a forced $($layout.GetType().Name).PerformLayout() ==="
    $layout.PerformLayout()
    Write-Bounds "layout"          $layout
    Write-Bounds "field[0] txt"    $fieldTextBoxes[0]
    Write-Bounds "btnSave"         $btnSave
    Write-Bounds "lblAvHeader"     $lblAvHeader
    Write-Bounds "lblAvExplainer"  $lblAvExplainer
    Write-Bounds "btnDetectAv"     $btnDetectAv

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 4000
    $timer.Add_Tick({ $timer.Stop(); $form.Close() })
    $timer.Start()
})

[void]$form.ShowDialog()
Write-Host ""
Write-Host "================= End of diagnostic - paste everything above back ================="
