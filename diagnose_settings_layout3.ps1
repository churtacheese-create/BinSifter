<#
    diagnose_settings_layout3.ps1

    Round 3 of the Settings-page diagnostic (2026-08-19). v2's output was
    conclusive: btnSave/lblAvExplainer/btnDetectAv were ALREADY collapsed to
    ~1px wide at Stage 1 - BEFORE $form.Scale() ever runs, while the page is
    still invisible. Root cause: $settingsPage (a Panel, Dock=Fill) is never
    given an explicit Size before its child TableLayoutPanel (AutoSize, with
    a Percent(100) middle column) gets its very first layout pass - so that
    first pass runs against WinForms' bare default Control size (200x100,
    confirmed directly in v2's Stage 1 dump), leaving almost nothing for the
    Percent(100) column. TableLayoutPanel then permanently shrinks every
    non-anchored, fixed-Size child in that column (buttons, the explainer
    label) down to fit - and never grows them back later even once the page
    is properly Dock=Fill-resized to the real window size (v2 Stage 4 proved
    this: layout/settingsPage/the anchored textbox were all correctly sized
    at 4214/4214/3739 wide, yet btnSave/lblAvExplainer/btnDetectAv were STILL
    stuck at ~2px). AutoSize labels (lblAvHeader) are immune since they
    always recompute their own size fresh, which is why only SOME controls
    on the page looked broken.

    Candidate fix tested here: give $settingsPage a generously-large
    starting Size BEFORE any child controls are added, so the very first
    layout pass never has to squeeze a Percent(100) column down to nothing
    in the first place. Dumps the same stages as v2 so the fix can be
    directly compared against the broken run.

    Run directly, no build/install needed:
        pwsh -File diagnose_settings_layout3.ps1
    Paste back everything it prints.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[void][System.Windows.Forms.Application]::SetHighDpiMode([System.Windows.Forms.HighDpiMode]::PerMonitorV2)
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Settings Layout Diagnostic v3 (candidate fix)'
$form.Size = New-Object System.Drawing.Size(1400, 900)
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$form.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)

$content = New-Object System.Windows.Forms.Panel
$content.Dock = [System.Windows.Forms.DockStyle]::Fill
$form.Controls.Add($content)

$dashPage = New-Object System.Windows.Forms.Panel
$dashPage.Dock = [System.Windows.Forms.DockStyle]::Fill
$dashLbl = New-Object System.Windows.Forms.Label
$dashLbl.Text = 'Dashboard placeholder'
$dashLbl.AutoSize = $true
$dashPage.Controls.Add($dashLbl)

$settingsPage = New-Object System.Windows.Forms.Panel
$settingsPage.Dock = [System.Windows.Forms.DockStyle]::Fill
$settingsPage.AutoScroll = $true
# ---- THE CANDIDATE FIX: a generous starting Size, set BEFORE any child
# control is added, so the TableLayoutPanel's very first layout pass has
# real room to work with instead of the bare 200x100 Control default. ----
$settingsPage.Size = New-Object System.Drawing.Size(1200, 900)

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

$dashPage.Visible = $false
$settingsPage.Visible = $false
$content.Controls.Add($dashPage)
$content.Controls.Add($settingsPage)
$dashPage.Visible = $true

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
    Write-Host "================= Settings Layout Diagnostic v3 (candidate fix) ================="
    Write-Host "PowerShell version: $($PSVersionTable.PSVersion)"

    Write-AllBounds "1. BEFORE Scale() (Settings still invisible, but page pre-sized 1200x900)"

    $liveDpi = $form.DeviceDpi
    Write-Host ""
    Write-Host "Live DPI: $liveDpi  (ratio $([Math]::Round($liveDpi / 96.0, 3)))"
    if ($liveDpi -ne 96) {
        $ratio = $liveDpi / 96.0
        $form.Scale((New-Object System.Drawing.SizeF($ratio, $ratio)))
    }

    Write-AllBounds "2. AFTER Scale() (Settings STILL invisible)"

    # No warmup/PerformLayout tricks this time - just real navigation.
    $dashPage.Visible = $false
    $settingsPage.Visible = $true
    Write-AllBounds "3. FINAL - real navigation to Settings (this is what the user actually sees)"

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 4000
    $timer.Add_Tick({ $timer.Stop(); $form.Close() })
    $timer.Start()
})

[void]$form.ShowDialog()
Write-Host ""
Write-Host "================= End of diagnostic - paste everything above back ================="
