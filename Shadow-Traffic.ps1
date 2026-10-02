<#
============================================================================
 Shadow-Traffic.ps1  —  v2.2.7
============================================================================
 PURPOSE
   Complements Block-Telemetry by answering a different question:
   "what is actually leaving this machine right now?"

   Block-Telemetry acts at the DNS level (hosts file). This script acts at
   the network level (real TCP connections + low-level TLS parser),
   including bypasses that evade classic DNS (hardcoded IP, DoH —
   documented in particular for the NVIDIA App).

 CHANGELOG v2.2.7 (vs v2.2.6)
   - [Console] SOURCE column: the ASN is shown compactly (registry handle
     dropped, organisation + AS number kept). It used to be cut at 60
     characters, which could hide the AS number itself. The HTML and CSV
     keep the full text.
   - [Log] Two new lines: "Summary: N endpoints: ..." and "Baseline
     updated: N entries (path)", so a run can be reviewed from the log.
   - [SelfTest] The SNI parser diagnostics no longer appear in the middle
     of the [PASS] lines; 2 assertions added for the ASN shortening
     (33 in total). No change to the JSON snapshot, the baseline, the HTML
     report or the command-line parameters.

 CHANGELOG v2.2.6 (vs v2.2.5)
   - [Security] HTML report: every value coming from the network (SNI, PTR
     name, ASN, process name) is now HTML-encoded. Previously a crafted
     SNI or PTR record (e.g. "<img src=x onerror=...>") was written as raw
     markup into the report and into its search attribute.
   - [Security] SNI and reverse-DNS names are validated at capture time
     (letters, digits, "_", ".", ":" and "-" only); anything else is
     discarded and the endpoint falls back to its IP / ASN.
   - [Security] CSV export: text fields starting with "=", "+", "-", "@"
     (or a tab / CR) are prefixed with an apostrophe so Excel never
     interprets them as a formula.
   - [Security] Console: control characters (e.g. ESC sequences) are
     stripped from names shown in the endpoint tables.
   - [HTML] Report redesigned in Check-Security's visual style: header
     with logo and meta bar (machine, date, OS, capture window, SNI
     capture, process filter, Block-Telemetry reference), anomaly banner
     with jump links (green "no anomaly" box otherwise), stacked
     classification bar, "Evolution since the last run" block, history
     chart with min/max, summary cards, filter chips (All / Anomalies /
     Unclassified / Known / New), sortable columns, PID next to the
     process name, "no result" message, footer.
   - [HTML] New sections: "Vanished since the last run" (the full list,
     previously only a count) and "SNI captured with no matching TCP
     connection" — both were already shown in the console.
   - [Fix] History chart: the current run was counted twice (its own JSON
     snapshot was already on disk when the history was read). The history
     is now read before the snapshot is written.
   - [Internal] Single $ScriptVersion variable for the banners and the
     HTML report. SelfTest extended (escaping, hostname validation, CSV
     protection, end-to-end HTML export). No change to the JSON snapshot,
     the baseline or the command-line parameters.

 CHANGELOG v2.2.5 (vs v2.2.4)
   - [Console] Complete visual overhaul of the console output, harmonized
     with Check-Security's rendering (no functional change — logs, JSON,
     CSV and HTML exports are untouched):
       * Framed section banners (╔═╗ / ║ ║ / ╚═╝), same 62-column frame.
       * Aligned status lines: time · icon · category │ message, with the
         suite's 1-cell-safe icons (✓ ! ✗ · + -) and fixed-width columns.
       * Live capture progress bar (20-block gauge, same glyphs as the
         Check-Security score gauge), turned into a ✓ line once finished.
       * SUMMARY rebuilt as an icon/count/description table with a
         stacked classification bar (anomalies / known / unclassified).
       * Endpoint lists (ANOMALIES, UNCLASSIFIED, VANISHED, unmatched SNI)
         rendered as aligned │-separated tables with a header row instead
         of free-form "target <- process" lines; NEW endpoints flagged with
         a "+" icon and a NEW tag.
       * Final "✓ AUDIT COMPLETE" banner listing every generated file
         (HTML / JSON / CSV / log) with "»" lines, then the same framed
         "Press ENTER" box as Check-Security.
       * SelfTest output harmonized ([PASS]/[FAIL], ═ rules, PASS · FAIL
         footer).
   - [Signature] Previous Authenticode signature removed (content changed).

 CHANGELOG v2.2.4 (vs v2.2.3)
   - [Fix] A run could print a raw, untranslated, OS-language pktmon error
     straight to the console (e.g. French "Erreur : impossible d'ouvrir le
     fichier '...etl': Le fichier spécifié est introuvable.") instead of
     one of this script's own [WARN] lines — and nothing was written to the
     log about it either. Root cause, in two parts: (1) pktmon.exe is a
     native tool, so a failure writes straight to its own stderr instead of
     throwing a catchable PowerShell exception — a try/catch around it
     never saw it. (2) the underlying cause was itself a real race
     condition: "pktmon stop" can return before the ETW capture session has
     actually finished flushing and closing its .etl file on disk, so
     converting it immediately afterward could hit that file before it was
     ready. Fixed by checking $LASTEXITCODE after every pktmon call instead
     of relying on exceptions (so a real failure is always caught and
     logged through this script's own Write-Log, in English, regardless of
     the system's display language), and by adding a short pause between
     "pktmon stop" and the pcapng conversion so the file has time to be
     ready. Reported live: a run where the SNI capture produced 0 packets
     despite the TCP window completing normally.

 CHANGELOG v2.2.3 (vs v2.2.2)
   - [Fix] -BlockTelemetryPath auto-detection was still looking for
     "Block-Telemetry_v5_2.ps1" — Block-Telemetry's old, pre-translation
     filename. It was renamed to "Block-Telemetry.ps1" during its own
     translation, but this script's default was never updated to match, so
     auto-detection silently failed even with both scripts side by side in
     the same folder (everything showed as "Unclassified" with a WARN).
     Fixed; explicit -BlockTelemetryPath was never affected.

 CHANGELOG v2.2.2 (vs v2.2.1)
   - [Critical console fix] The SUMMARY block could print a BLANK value
     instead of a number for "Never seen before (new)" (and, less visibly,
     for Anomalies/Known/Unclassified) whenever that category had EXACTLY
     ONE match. Root cause: PowerShell's pipeline collapses a single
     Where-Object match into a bare scalar object instead of an array, and
     a bare object has no .Count property — on Windows PowerShell 5.1 (the
     engine behind every desktop shortcut in this suite), that missing
     property silently resolves to nothing rather than 0 or 1. Reported by
     a real run: 1 new endpoint, line printed blank instead of "1". Fixed
     by forcing @() array context on every aggregate before it's counted,
     the same pattern already used correctly elsewhere in the script (JSON
     export, completion toast).

 CHANGELOG v2.2.1 (vs v2.2.0)
   - [Rename] Script renamed from ShadowTraffic to Shadow-Traffic. The
     solid one-word form read as an undifferentiated block of capitals in
     the all-caps console banner (SHADOWTRAFFIC) — the hyphen restores a
     visual break, consistent with the rest of the suite's naming
     (Block-Telemetry, Check-Network, Check-Boot...). Report folder, file
     prefixes, and baseline filename updated accordingly.

 CHANGELOG v2.2.0 (vs v2.1.0)
   - [Rename] Script renamed from Audit-TraficReseau_Win11 to ShadowTraffic
     (clearer, catchier identity for GitHub — no functional change). Report
     folder, file prefixes, and baseline filename updated accordingly.
   - [Translation] Full English translation of the script (code, comments,
     console output, HTML report) — the v2.1.0 fix below was originally
     shipped in French; this was never given its own version bump at the
     time, corrected here for changelog accuracy.

 CHANGELOG v2.1.0 (vs v2.0.0)
   - [Critical SNI fix] A ClientHello whose DECLARED length exceeded the
     actually captured size was rejected outright, even when the SNI was
     present and readable well before the truncation point. The declared
     lengths (RecordLen, HandshakeLen) are now used only as a CEILING, no
     longer as a rejection reason. Found on a real Windows/Edge ClientHello
     (445 bytes declared, 438 captured) — the SNI from this exact case
     ("windows.dns.nextdns.io") is now a permanent regression test.
   - [Capture] pktmon's --pkt-size raised from 512 to 9000: 512 systematically
     truncated modern ClientHellos (post-quantum extensions, ALPN...),
     especially over IPv6 where the headers already eat up 74+ bytes.
   - [DebugClientHello] New parameter: saves in hexadecimal any detected
     ClientHello whose SNI could not be extracted, in Debug-ClientHello\ —
     this is what made it possible to find the bug above.

 CHANGELOG v2.0.0 (vs v1.0.0)
   - [TCP reassembly] A ClientHello fragmented across several segments is
     now reconstructed (best-effort, strictly contiguous segments by
     sequence number only — no handling of retransmissions/reordering).
   - [QUIC/UDP visibility] UDP:443 traffic (HTTP/3) is now counted
     separately — not decoded (out of scope), but visible, so it no
     longer silently disappears from the audit's coverage.
   - [Automatic ASN resolution] IPs without a PTR record are enriched via
     the Team Cymru public DNS service (no API key, no HTTP dependency)
     — e.g. "98.66.133.185" becomes "Microsoft Corporation (AS8075)".
   - [Cross-run comparison] In addition to the "never seen before" baseline,
     each JSON report now keeps the list of observed endpoints, which
     makes it possible to detect endpoints "vanished since the last run".
   - [HTML report] Free-text search bar (in addition to the category
     filter) + mini sparkline of the "unclassified" history across the
     last runs.
   - [Suite polish] Automatic purge of old reports (-PurgeDays), completion
     toast notification (NotifyIcon, not the WinRT Toast API, which fails
     silently without a registered AUMID).

 KNOWN PARSER LIMITATIONS (documented, not hidden)
   - TCP reassembly: only strictly contiguous segments (no reordering, no
     retransmission handling). Sufficient for a normal ClientHello split
     into 2-3 segments, not for a stream with packet loss.
   - QUIC/UDP: counted, never decoded (QUIC encryption makes the SNI
     appear in the clear far less often, and decoding it is significantly
     more complex).
   - No handling of IPv6 extension headers.
   - ASN resolution: depends on the Cymru service being reachable, fails
     silently (never blocks) if unavailable or if -SkipSlowChecks is set.
   - pktmon must be available (native to Windows 10 1809+ / 11) and
     requires administrator rights — automatic elevation is triggered if
     -CaptureSNI is requested.

 PARAMETERS
   -DurationSeconds N     Length of the observation window, TCP and SNI
                          combined (default 120s)
   -BlockTelemetryPath    Path to Block-Telemetry.ps1 (auto-detected
                          if omitted, in the same folder as this script)
   -IncludeLocal          Include private/loopback IPs (excluded by default)
   -SkipSlowChecks        Disables PTR resolution AND ASN resolution
   -CaptureSNI            Enables SNI capture via pktmon (admin required)
   -ProcessName <name>    Keep only connections from this process
                          (partial match, case-insensitive)
   -PurgeDays N           Deletes reports (json/csv/html/log, never the
                          baseline) older than N days (default 60, 0=off)
   -NoToast               Disables the end-of-run notification
   -DebugClientHello      Saves in hexadecimal any detected ClientHello
                          whose SNI could not be extracted (direct OR
                          after reassembly), in Debug-ClientHello\ — to
                          diagnose a real failure case instead of guessing
   -SelfTest              Runs the internal tests, no real capture
   -Silent                Reduces console output (logs/exports still created)
============================================================================
#>

[CmdletBinding()]
param(
    [int]$DurationSeconds = 120,
    [string]$BlockTelemetryPath = "",
    [switch]$IncludeLocal,
    [switch]$SkipSlowChecks,
    [switch]$CaptureSNI,
    [string]$ProcessName = "",
    [int]$PurgeDays = 60,
    [switch]$NoToast,
    [switch]$DebugClientHello,
    [switch]$SelfTest,
    [switch]$Silent
)

#region AUTO-ELEVATION
# [Suite consistency] Same pattern as Block-Telemetry.ps1. SelfTest is
# purely read-only and runs before elevation. The base TCP audit does not
# require admin rights; only -CaptureSNI (pktmon) needs them.
if ($CaptureSNI -and -not $SelfTest) {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $Shell = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell.exe" }
        $ArgList = "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`" -CaptureSNI -DurationSeconds $DurationSeconds -PurgeDays $PurgeDays"
        if ($IncludeLocal)   { $ArgList += " -IncludeLocal" }
        if ($SkipSlowChecks) { $ArgList += " -SkipSlowChecks" }
        if ($Silent)         { $ArgList += " -Silent" }
        if ($NoToast)      { $ArgList += " -NoToast" }
        if ($DebugClientHello) { $ArgList += " -DebugClientHello" }
        if ($ProcessName)      { $ArgList += " -ProcessName `"$ProcessName`"" }
        if ($BlockTelemetryPath) { $ArgList += " -BlockTelemetryPath `"$BlockTelemetryPath`"" }
        Start-Process $Shell -Verb RunAs -ArgumentList $ArgList
        exit
    }
}
#endregion

$ErrorActionPreference = "Stop"
$Timestamp     = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportFolder  = "$env:USERPROFILE\Desktop\Maintenance_Reports\Shadow-Traffic"
$LogPath       = Join-Path $ReportFolder "Shadow-Traffic_$Timestamp.log"
$TempCapture   = Join-Path $env:TEMP "Shadow-Traffic-SNI"
$BaselinePath  = Join-Path $ReportFolder "Baseline_Shadow-Traffic.json"

if (-not (Test-Path $ReportFolder)) {
    New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Line = "[$((Get-Date).ToString('HH:mm:ss'))] [$Level] $Message"
    Add-Content -Path $LogPath -Value $Line -Encoding UTF8 -ErrorAction SilentlyContinue
}

# ----------------------------------------------------------------------
# Console rendering helpers — style harmonized with Check-Security
# (framed banners, aligned columns, 1-cell-safe icons). Purely cosmetic:
# the log file, JSON, CSV and HTML exports never depend on these.
# ----------------------------------------------------------------------
$script:ScriptVersion    = "2.2.7"
$script:BarWidth         = 62
$script:LogCategoryWidth = 20
$script:LogIcons  = @{ "OK"="✓"; "WARN"="!"; "FAIL"="✗"; "INFO"="·"; "NEW"="+"; "GONE"="-" }
$script:LogColors = @{ "OK"="Green"; "WARN"="Yellow"; "FAIL"="Red"; "INFO"="Cyan"; "NEW"="Magenta"; "GONE"="DarkGray" }
$script:ExportedFiles = $null

# ----------------------------------------------------------------------
# Output-safety helpers: everything that comes from the network (SNI, PTR,
# ASN, process names) is untrusted data before it reaches an HTML report,
# a CSV opened in Excel, or the console.
# ----------------------------------------------------------------------
function ConvertTo-HtmlSafe {
    param($Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode("$Value")
}

# Accepts hostnames (and IP text): letters, digits, "_", ".", ":" and "-".
function Test-ValidHostname {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    return ($Name -match '^[\p{L}\p{N}_.:\-]{1,253}$')
}

function Protect-CsvField {
    param($Value)
    $Text = "$Value"
    if ($Text -match '^[=+\-@\t\r]') { return "'" + $Text }
    return $Text
}

function Get-CategoryKey {
    param([string]$Category)
    if ($Category -like "ANOMALY*") { return "ANOMALY" }
    if ($Category -like "Known*")   { return "Known" }
    return "Unclassified"
}

function Write-Header {
    param([string]$Text)
    $barWidth = [Math]::Max($script:BarWidth, $Text.Length + 2)
    Write-Host ""
    Write-Host ("  ╔" + ("═" * $barWidth) + "╗") -ForegroundColor DarkCyan
    Write-Host "  ║" -NoNewline -ForegroundColor DarkCyan
    Write-Host (" $Text").PadRight($barWidth) -NoNewline -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor DarkCyan
    Write-Host ("  ╚" + ("═" * $barWidth) + "╝") -ForegroundColor DarkCyan
}

# Aligned status line: time · icon · category │ check [: value]
# -Items adds extra lines under the │ separator (same wrapping style as
# Check-Security's long values).
function Write-ConsoleLine {
    param(
        [string]$Level = "INFO",
        [string]$Category = "",
        [string]$Check = "",
        [string]$Value = "",
        [string[]]$Items = @()
    )
    if ($Silent) { return }
    $timestamp = Get-Date -Format "HH:mm:ss"
    $icon = $script:LogIcons[$Level];  if (-not $icon)  { $icon = "•" }
    $color = $script:LogColors[$Level]; if (-not $color) { $color = "Gray" }
    $iconCol = $icon.PadRight(2)
    $catCol  = $Category.PadRight($script:LogCategoryWidth)

    Write-Host "   $timestamp  " -NoNewline -ForegroundColor DarkGray
    Write-Host "$iconCol " -NoNewline -ForegroundColor $color
    Write-Host "$catCol" -NoNewline -ForegroundColor DarkCyan
    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
    if ($Value) {
        Write-Host "$Check" -NoNewline -ForegroundColor Gray
        Write-Host " : " -NoNewline -ForegroundColor DarkGray
        Write-Host "$Value" -ForegroundColor $color
    }
    else {
        $textColor = if ($Level -eq "INFO") { "Gray" } else { $color }
        Write-Host "$Check" -ForegroundColor $textColor
    }
    if ($Items.Count -gt 0) {
        $indent = " " * ("   $timestamp  $iconCol $catCol").Length
        foreach ($Item in $Items) {
            Write-Host "$indent" -NoNewline
            Write-Host "│ " -NoNewline -ForegroundColor DarkGray
            Write-Host "$Item" -ForegroundColor $color
        }
    }
}

# Live progress line for the capture window (rewritten in place with `r).
function Write-CaptureProgress {
    param([int]$Elapsed, [int]$Total, [int]$Endpoints, [switch]$Done)
    if ($Silent) { return }
    $ratio  = if ($Total -gt 0) { [Math]::Min(1.0, $Elapsed / $Total) } else { 1.0 }
    $filled = [int][Math]::Round($ratio * 20)
    $gauge  = ("█" * $filled) + ("░" * (20 - $filled))
    $level  = if ($Done) { "OK" } else { "INFO" }
    $icon   = $script:LogIcons[$level].PadRight(2)
    $color  = $script:LogColors[$level]
    $timestamp = Get-Date -Format "HH:mm:ss"
    $elapsedText = "$Elapsed".PadLeft("$Total".Length)

    Write-Host "`r   $timestamp  " -NoNewline -ForegroundColor DarkGray
    Write-Host "$icon " -NoNewline -ForegroundColor $color
    Write-Host ("Capture".PadRight($script:LogCategoryWidth)) -NoNewline -ForegroundColor DarkCyan
    Write-Host "│ " -NoNewline -ForegroundColor DarkGray
    Write-Host "$gauge" -NoNewline -ForegroundColor $color
    Write-Host "  $elapsedText/$Total s" -NoNewline -ForegroundColor Gray
    Write-Host "  ·  " -NoNewline -ForegroundColor DarkGray
    Write-Host "$Endpoints endpoints" -NoNewline:(-not $Done) -ForegroundColor Gray
}

function Limit-Text {
    param([string]$Text, [int]$Max)
    # Names come from the network (SNI / PTR / ASN): strip control
    # characters (ESC sequences, CR/LF...) before they reach the console.
    $Text = $Text -replace '[\x00-\x1F\x7F]', ''
    if ($Text.Length -le $Max) { return $Text }
    return $Text.Substring(0, [Math]::Max(1, $Max - 3)) + "..."
}

# Compact ASN text for the console: drops the registry handle before the
# first " - " ("MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
# (AS8075)" -> "Microsoft Corporation, US (AS8075)") and, if it is still
# too long, shortens the organisation name but ALWAYS keeps the "(ASnnnn)"
# suffix. The HTML and CSV keep the full text.
function Get-AsnShortName {
    param([string]$Asn, [int]$Max = 60)
    $Text = $Asn
    $Idx = $Text.IndexOf(" - ")
    if ($Idx -ge 0) { $Text = $Text.Substring($Idx + 3) }
    if ($Text.Length -gt $Max -and $Text -match '^(.*?)\s*(\(AS\d+\))$') {
        $Name   = $Matches[1]
        $Suffix = $Matches[2]
        $Keep   = $Max - $Suffix.Length - 4
        if ($Keep -ge 4) { return $Name.Substring(0, [Math]::Min($Name.Length, $Keep)) + "... " + $Suffix }
    }
    return $Text
}

# Where an endpoint's name came from (SNI / PTR / ASN / nothing).
function Get-NameSource {
    param($Row)
    if ($Row.SNI)             { return "SNI" }
    elseif ($Row.ReverseName) { return "PTR" }
    elseif ($Row.ASN)         { return (Get-AsnShortName "$($Row.ASN)") }
    else                      { return "no name" }
}

# Stacked proportional bar (like the score gauge, split by category).
function Write-StackedBar {
    param([int[]]$Counts, [string[]]$Colors, [int]$Width = 20)
    $total = 0; foreach ($c in $Counts) { $total += $c }
    if ($total -le 0) {
        Write-Host ("░" * $Width) -NoNewline -ForegroundColor DarkGray
        return
    }
    $blocks = @()
    foreach ($c in $Counts) {
        $b = [int][Math]::Round(($c / $total) * $Width)
        if ($c -gt 0 -and $b -lt 1) { $b = 1 }
        $blocks += $b
    }
    $sum = 0; foreach ($b in $blocks) { $sum += $b }
    if ($sum -ne $Width) {
        $maxIdx = 0
        for ($i = 1; $i -lt $blocks.Count; $i++) { if ($blocks[$i] -gt $blocks[$maxIdx]) { $maxIdx = $i } }
        $blocks[$maxIdx] += ($Width - $sum)
    }
    for ($i = 0; $i -lt $blocks.Count; $i++) {
        if ($blocks[$i] -gt 0) { Write-Host ("█" * $blocks[$i]) -NoNewline -ForegroundColor $Colors[$i] }
    }
}

function Write-SummaryRow {
    param([string]$Icon, [string]$Label, [int]$Count, [string]$Note, [string]$Color)
    Write-Host "   " -NoNewline
    Write-Host ($Icon.PadRight(2)) -NoNewline -ForegroundColor $Color
    Write-Host (" " + $Label.PadRight(19)) -NoNewline -ForegroundColor Gray
    Write-Host ("$Count".PadLeft(4)) -NoNewline -ForegroundColor $Color
    Write-Host "   $Note" -ForegroundColor DarkGray
}

# Aligned │-separated table. Rows: Icon, Color, Target, Proc, Count, Source, Tag.
function Write-EndpointTable {
    param([array]$Rows, [switch]$Compact, [string]$SecondHeader = "PROCESS")
    $Rows = @($Rows)
    if ($Rows.Count -eq 0) { return }

    $tw = 6; $pw = $SecondHeader.Length
    foreach ($R in $Rows) {
        if ($R.Target.Length -gt $tw) { $tw = $R.Target.Length }
        if ($R.Proc.Length   -gt $pw) { $pw = $R.Proc.Length }
    }
    $tw = [Math]::Min($tw, 52)
    $pw = [Math]::Min($pw, 30)
    $cw = 5

    $header = "   " + "   " + "TARGET".PadRight($tw) + " │ " + $SecondHeader.PadRight($pw)
    if (-not $Compact) { $header += " │ " + "COUNT".PadLeft($cw) + " │ " + "SOURCE" }
    Write-Host ""
    Write-Host $header -ForegroundColor DarkGray
    Write-Host ("   " + ("─" * ([Math]::Max(10, $header.Length - 3)))) -ForegroundColor DarkCyan

    foreach ($R in $Rows) {
        Write-Host "   " -NoNewline
        Write-Host ($R.Icon.PadRight(2) + " ") -NoNewline -ForegroundColor $R.Color
        Write-Host (Limit-Text $R.Target $tw).PadRight($tw) -NoNewline -ForegroundColor $R.Color
        Write-Host " │ " -NoNewline -ForegroundColor DarkGray
        Write-Host (Limit-Text $R.Proc $pw).PadRight($pw) -NoNewline -ForegroundColor $R.Color
        if ($Compact) {
            Write-Host ""
        }
        else {
            Write-Host " │ " -NoNewline -ForegroundColor DarkGray
            Write-Host ("$($R.Count)").PadLeft($cw) -NoNewline -ForegroundColor $R.Color
            Write-Host " │ " -NoNewline -ForegroundColor DarkGray
            Write-Host (Limit-Text "$($R.Source)" 60) -NoNewline -ForegroundColor DarkGray
            if ($R.Tag) { Write-Host "  $($R.Tag)" -NoNewline -ForegroundColor Magenta }
            Write-Host ""
        }
    }
}

# Final banner + generated files + "Press ENTER" box (after the exports).
function Write-FinalSummary {
    if ($Silent) { return }
    $barWidth = $script:BarWidth
    Write-Host ""
    Write-Host ("  ╔" + ("═" * $barWidth) + "╗") -ForegroundColor Cyan
    Write-Host "  ║" -NoNewline -ForegroundColor Cyan
    Write-Host (" ✓ AUDIT COMPLETE").PadRight($barWidth) -NoNewline -ForegroundColor Green
    Write-Host "║" -ForegroundColor Cyan
    Write-Host ("  ╚" + ("═" * $barWidth) + "╝") -ForegroundColor Cyan
    Write-Host ""
    if ($script:ExportedFiles) {
        foreach ($Key in $script:ExportedFiles.Keys) {
            $File = $script:ExportedFiles[$Key]
            if ($File -and (Test-Path $File)) {
                Write-Host ("   »  " + "$Key".PadRight(15)) -NoNewline -ForegroundColor DarkGray
                Write-Host "$File" -ForegroundColor Cyan
            }
        }
    }
    Write-Host ("─" * ($barWidth + 4)) -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-EnterPrompt {
    $inner = 51
    Write-Host ""
    Write-Host ("  ╔" + ("═" * $inner) + "╗") -ForegroundColor Cyan
    Write-Host "  ║" -NoNewline -ForegroundColor Cyan
    Write-Host ("  Press ENTER to close this window...").PadRight($inner) -NoNewline -ForegroundColor Yellow
    Write-Host "║" -ForegroundColor Cyan
    Write-Host ("  ╚" + ("═" * $inner) + "╝") -ForegroundColor Cyan
}

# ----------------------------------------------------------------------
# [1] Passive extraction of domains already known to Block-Telemetry
#     (blocked AND whitelist, extracted SEPARATELY — see fix v0.2 for the
#     ANOMALY false positive on whitelist entries)
# ----------------------------------------------------------------------
function Get-KnownDomainsFromSuite {
    param([string]$Path)

    $Result = [PSCustomObject]@{
        Blocked   = [System.Collections.Generic.HashSet[string]]::new()
        Whitelist = [System.Collections.Generic.HashSet[string]]::new()
        Source    = $Path
        Found    = $false
    }

    if (-not $Path -or -not (Test-Path $Path)) {
        Write-Log "Block-Telemetry not found ($Path) — comparison disabled, everything will be 'Unclassified'" "WARN"
        return $Result
    }

    try {
        $Content = Get-Content -Path $Path -Raw -Encoding UTF8
        $DomainPattern = '"([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,})"'

        $BlockedMatch = [regex]::Match($Content, '\$TelemetryDomains\s*=\s*\[ordered\]@\{(.*?)^\}', 'Singleline, Multiline')
        if ($BlockedMatch.Success) {
            foreach ($M in [regex]::Matches($BlockedMatch.Groups[1].Value, $DomainPattern)) {
                [void]$Result.Blocked.Add($M.Groups[1].Value.ToLowerInvariant())
            }
        }

        $WhitelistMatch = [regex]::Match($Content, '\$AbsoluteWhitelist\s*=\s*@\((.*?)^\)', 'Singleline, Multiline')
        if ($WhitelistMatch.Success) {
            foreach ($M in [regex]::Matches($WhitelistMatch.Groups[1].Value, $DomainPattern)) {
                [void]$Result.Whitelist.Add($M.Groups[1].Value.ToLowerInvariant())
            }
        }

        $Result.Found = $true
        Write-Log "Extraction succeeded: $($Result.Blocked.Count) blocked domains, $($Result.Whitelist.Count) whitelisted, from $Path"
    }
    catch {
        Write-Log "Failed to read Block-Telemetry: $_" "WARN"
    }

    return $Result
}

# ----------------------------------------------------------------------
# [2] Private / local IP filtering (noise with no interest for this audit)
# ----------------------------------------------------------------------
function Test-IsPrivateOrLocalIP {
    param([string]$IP)

    if ($IP -eq "127.0.0.1" -or $IP -eq "::1") { return $true }
    if ($IP -match '^169\.254\.') { return $true }
    if ($IP -match '^fe80:') { return $true }
    if ($IP -match '^f[cd][0-9a-f]{2}:') { return $true }   # IPv6 ULA fc00::/7
    if ($IP -match '^10\.') { return $true }
    if ($IP -match '^192\.168\.') { return $true }
    if ($IP -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
    return $false
}

# ----------------------------------------------------------------------
# [3] Best-effort reverse resolution, with caching
# ----------------------------------------------------------------------
$Global:ReverseDNSCache = @{}

function Get-ReverseName {
    param([string]$IP)

    if ($Global:ReverseDNSCache.ContainsKey($IP)) {
        return $Global:ReverseDNSCache[$IP]
    }

    $Name = $null
    try {
        $Entry = [System.Net.Dns]::GetHostEntry($IP)
        $Name = $Entry.HostName.ToLowerInvariant()
        if (-not (Test-ValidHostname $Name)) { $Name = $null }
    }
    catch {
        $Name = $null
    }

    $Global:ReverseDNSCache[$IP] = $Name
    return $Name
}

# ----------------------------------------------------------------------
# [3bis] ASN resolution via the Team Cymru public DNS service — enriches
# IPs without a PTR record (e.g. "98.66.133.185" -> "MICROSOFT-CORP-MSN-AS-BLOCK, US").
# No API key, no HTTP call: two successive DNS TXT queries (protocol
# documented by Cymru), handled like Get-ReverseName (silent failure,
# never blocking). Cached to avoid repeated queries.
# ----------------------------------------------------------------------
$Global:ASNCache = @{}

function Get-CymruQuery {
    param([string]$IP)

    if ($IP -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        $O = $IP -split '\.'
        return "$($O[3]).$($O[2]).$($O[1]).$($O[0]).origin.asn.cymru.com"
    }

    $Address = [System.Net.IPAddress]::Parse($IP)
    $Bytes = $Address.GetAddressBytes()
    $Nibbles = New-Object System.Collections.Generic.List[string]
    foreach ($O in $Bytes) {
        $Nibbles.Add("{0:x}" -f (($O -shr 4) -band 0x0F))
        $Nibbles.Add("{0:x}" -f ($O -band 0x0F))
    }
    $Nibbles.Reverse()
    return ($Nibbles -join ".") + ".origin6.asn.cymru.com"
}

function Resolve-ASNViaDNS {
    param([string]$IP)

    if ($Global:ASNCache.ContainsKey($IP)) { return $Global:ASNCache[$IP] }

    $Result = $null
    try {
        $Query = Get-CymruQuery -IP $IP

        $Response1 = Resolve-DnsName -Name $Query -Type TXT -ErrorAction Stop
        $Text1 = (@($Response1) | Select-Object -First 1).Strings -join " "
        $Fields1 = $Text1 -split '\|'

        if ($Fields1.Count -ge 1) {
            $ASN = ($Fields1[0].Trim() -split '\s+')[0]
            if ($ASN -match '^\d+$') {
                $Response2 = Resolve-DnsName -Name "AS$ASN.asn.cymru.com" -Type TXT -ErrorAction Stop
                $Text2 = (@($Response2) | Select-Object -First 1).Strings -join " "
                $Fields2 = $Text2 -split '\|'
                $Result = if ($Fields2.Count -ge 5) { "$($Fields2[4].Trim()) (AS$ASN)" } else { "AS$ASN" }
            }
        }
    }
    catch {
        $Result = $null
    }

    $Global:ASNCache[$IP] = $Result
    return $Result
}
# [4] Low-level network parser: Ethernet/IP/TCP, then TLS ClientHello/SNI
#
# Deliberately hand-written (no external dependency such as tshark).
# Each function returns $null at the slightest doubt rather than risk an
# out-of-bounds read — a malformed packet is ignored, never an exception.
# ----------------------------------------------------------------------
function ConvertTo-BigEndian16 {
    param([int]$Value)
    return @([byte](($Value -shr 8) -band 0xFF), [byte]($Value -band 0xFF))
}

function ConvertTo-BigEndian24 {
    param([int]$Value)
    return @([byte](($Value -shr 16) -band 0xFF), [byte](($Value -shr 8) -band 0xFF), [byte]($Value -band 0xFF))
}

# [Critical fix] PowerShell's -shl operator preserves the operand's
# ORIGINAL TYPE width. A [byte] shifted by 8 bits or more ALWAYS yields 0
# (the bits fall off the 8-bit register before conversion to int), even
# if the result appears to be assigned to an untyped variable.
# Example: ([byte]8 -shl 8) = 0, whereas ([int]8 -shl 8) = 2048.
# Hence the need for an explicit [int] cast BEFORE any -shl here.
function Read-UInt16BE {
    param([byte[]]$Packet, [int]$Offset)
    return (([int]$Packet[$Offset] -shl 8) -bor [int]$Packet[$Offset + 1])
}

function Read-UInt24BE {
    param([byte[]]$Packet, [int]$Offset)
    return (([int]$Packet[$Offset] -shl 16) -bor ([int]$Packet[$Offset + 1] -shl 8) -bor [int]$Packet[$Offset + 2])
}

function Read-UInt32BE {
    param([byte[]]$Packet, [int]$Offset)
    $B0 = [uint32]$Packet[$Offset]; $B1 = [uint32]$Packet[$Offset + 1]
    $B2 = [uint32]$Packet[$Offset + 2]; $B3 = [uint32]$Packet[$Offset + 3]
    return (($B0 -shl 24) -bor ($B1 -shl 16) -bor ($B2 -shl 8) -bor $B3)
}

function ConvertFrom-IPHeader {
    param([byte[]]$Packet, [int]$Offset)

    if ($Offset -lt 0 -or $Offset + 1 -gt $Packet.Length) { return $null }
    $Version = ($Packet[$Offset] -shr 4)

    if ($Version -eq 4) {
        if ($Packet.Length -lt ($Offset + 20)) { return $null }
        $IHL = ($Packet[$Offset] -band 0x0F)
        $Len = $IHL * 4
        if ($Len -lt 20 -or $Packet.Length -lt ($Offset + $Len)) { return $null }
        $Protocol = $Packet[$Offset + 9]
        $SrcIP = ([System.Net.IPAddress]::new([byte[]]$Packet[($Offset+12)..($Offset+15)])).ToString()
        $DstIP = ([System.Net.IPAddress]::new([byte[]]$Packet[($Offset+16)..($Offset+19)])).ToString()
        return [PSCustomObject]@{ SrcIP = $SrcIP; DstIP = $DstIP; Protocol = $Protocol; Next = ($Offset + $Len) }
    }
    elseif ($Version -eq 6) {
        if ($Packet.Length -lt ($Offset + 40)) { return $null }
        $Protocol = $Packet[$Offset + 6]
        $SrcIP = ([System.Net.IPAddress]::new([byte[]]$Packet[($Offset+8)..($Offset+23)])).ToString()
        $DstIP = ([System.Net.IPAddress]::new([byte[]]$Packet[($Offset+24)..($Offset+39)])).ToString()
        return [PSCustomObject]@{ SrcIP = $SrcIP; DstIP = $DstIP; Protocol = $Protocol; Next = ($Offset + 40) }
    }
    return $null
}

function ConvertFrom-NetworkLayer {
    param([byte[]]$Packet)

    $IPHeader = $null

    # Attempt 1: standard Ethernet frame (with or without an 802.1Q VLAN tag)
    if ($Packet.Length -ge 14) {
        $EtherType = Read-UInt16BE -Packet $Packet -Offset 12
        $IPStart = 14
        if ($EtherType -eq 0x8100 -and $Packet.Length -ge 18) {
            $EtherType = Read-UInt16BE -Packet $Packet -Offset 16
            $IPStart = 18
        }
        if ($EtherType -eq 0x0800 -or $EtherType -eq 0x86DD) {
            $IPHeader = ConvertFrom-IPHeader -Packet $Packet -Offset $IPStart
        }
    }

    # Attempt 2 (fallback): no recognized Ethernet frame, IP straight at the
    # head of the packet. Some pktmon capture points can deliver packets
    # without an L2 header — this fallback costs little and avoids missing
    # everything.
    if (-not $IPHeader) {
        $IPHeader = ConvertFrom-IPHeader -Packet $Packet -Offset 0
    }

    if (-not $IPHeader) { return $null }

    $Offset = $IPHeader.Next

    if ($IPHeader.Protocol -eq 6) {
        if ($Packet.Length -lt ($Offset + 20)) { return $null }

        $SrcPort = Read-UInt16BE -Packet $Packet -Offset $Offset
        $DstPort = Read-UInt16BE -Packet $Packet -Offset ($Offset + 2)
        $SeqNum  = Read-UInt32BE -Packet $Packet -Offset ($Offset + 4)
        $TCPLen  = (($Packet[$Offset+12] -shr 4) * 4)
        if ($TCPLen -lt 20 -or $Packet.Length -lt ($Offset + $TCPLen)) { return $null }

        $PayloadOffset = $Offset + $TCPLen
        if ($PayloadOffset -gt $Packet.Length) { return $null }

        return [PSCustomObject]@{
            Protocol = 6
            SrcIP = $IPHeader.SrcIP; DstIP = $IPHeader.DstIP
            SrcPort = $SrcPort; DstPort = $DstPort; SeqNum = $SeqNum
            PayloadOffset = $PayloadOffset; Packet = $Packet
        }
    }
    elseif ($IPHeader.Protocol -eq 17) {
        # UDP: fixed 8-byte header (SrcPort, DstPort, Length, Checksum).
        # Used only for COUNTING (QUIC visibility) — no content decoding,
        # out of scope (see LIMITATIONS at the top of the file).
        if ($Packet.Length -lt ($Offset + 8)) { return $null }

        $SrcPort = Read-UInt16BE -Packet $Packet -Offset $Offset
        $DstPort = Read-UInt16BE -Packet $Packet -Offset ($Offset + 2)

        return [PSCustomObject]@{
            Protocol = 17
            SrcIP = $IPHeader.SrcIP; DstIP = $IPHeader.DstIP
            SrcPort = $SrcPort; DstPort = $DstPort; SeqNum = $null
            PayloadOffset = ($Offset + 8); Packet = $Packet
        }
    }

    return $null
}

function Get-SNIFromClientHello {
    param([byte[]]$Packet, [int]$Offset)

    # [Limitation] Only handles a ClientHello that fits in a single TCP
    # segment — no reassembly here. See the CHANGELOG at the top of the file.
    #
    # [Fix v2.1] The DECLARED lengths (RecordLen, HandshakeLen) are no
    # longer used as a rejection reason when they exceed the actually
    # captured size — only as a CEILING. A modern ClientHello (post-quantum
    # extensions, ALPN...) often exceeds the capture size (pktmon's
    # --pkt-size), but the SNI almost always appears well before the
    # truncation point. Rejecting the whole buffer at the slightest
    # oversized declared length was discarding perfectly readable, present
    # SNIs. Observed on a real Windows/Edge ClientHello: 445 bytes
    # declared, 438 captured (truncated by 7 bytes right at the end), SNI
    # present in the middle.
    if ($Offset + 5 -gt $Packet.Length) { return $null }
    if ($Packet[$Offset] -ne 0x16) { return $null }                      # Content Type = Handshake
    $RecordStart = $Offset + 5
    if ($RecordStart + 4 -gt $Packet.Length) { return $null }
    if ($Packet[$RecordStart] -ne 0x01) { return $null }                 # Handshake Type = ClientHello

    $HandshakeLen = Read-UInt24BE -Packet $Packet -Offset ($RecordStart + 1)
    $Pos = $RecordStart + 4
    $End = $Pos + $HandshakeLen
    if ($End -gt $Packet.Length) { $End = $Packet.Length }   # ceiling, not a rejection

    $Pos += 2 + 32                                                       # version client + random
    if ($Pos -ge $End) { return $null }

    if ($Pos -ge $Packet.Length) { return $null }
    $SessIdLen = $Packet[$Pos]; $Pos += 1 + $SessIdLen
    if ($Pos -ge $End -or $Pos + 1 -ge $Packet.Length) { return $null }

    $CipherLen = Read-UInt16BE -Packet $Packet -Offset $Pos; $Pos += 2 + $CipherLen
    if ($Pos -ge $End -or $Pos -ge $Packet.Length) { return $null }

    $CompLen = $Packet[$Pos]; $Pos += 1 + $CompLen
    if ($Pos + 2 -gt $End -or $Pos + 2 -gt $Packet.Length) { return $null }

    $ExtTotalLen = Read-UInt16BE -Packet $Packet -Offset $Pos; $Pos += 2
    $ExtEnd = $Pos + $ExtTotalLen
    if ($ExtEnd -gt $End) { $ExtEnd = $End }
    if ($ExtEnd -gt $Packet.Length) { $ExtEnd = $Packet.Length }

    while ($Pos + 4 -le $ExtEnd) {
        $ExtType = Read-UInt16BE -Packet $Packet -Offset $Pos
        $ExtLen  = Read-UInt16BE -Packet $Packet -Offset ($Pos + 2)
        $ExtDataStart = $Pos + 4
        if ($ExtDataStart + $ExtLen -gt $Packet.Length) { return $null }

        if ($ExtType -eq 0x0000) {
            $P = $ExtDataStart
            if ($P + 2 -gt $Packet.Length) { return $null }
            $ListLen = Read-UInt16BE -Packet $Packet -Offset $P; $P += 2
            $ListEnd = $P + $ListLen
            if ($ListEnd -gt $Packet.Length) { $ListEnd = $Packet.Length }

            while ($P + 3 -le $ListEnd) {
                $NameType = $Packet[$P]
                $NameLen  = Read-UInt16BE -Packet $Packet -Offset ($P + 1)
                $P += 3
                if ($P + $NameLen -gt $Packet.Length) { return $null }
                if ($NameType -eq 0x00) {
                    $Candidate = [System.Text.Encoding]::ASCII.GetString($Packet, $P, $NameLen).ToLowerInvariant()
                    # Untrusted wire data: refuse anything that is not a plain hostname.
                    if (Test-ValidHostname $Candidate) { return $Candidate }
                    return $null
                }
                $P += $NameLen
            }
        }
        $Pos = $ExtDataStart + $ExtLen
    }

    return $null
}

function Get-PcapngPackets {
    param([string]$Path)

    $Packets = New-Object System.Collections.Generic.List[byte[]]
    $Bytes = [System.IO.File]::ReadAllBytes($Path)
    $Pos = 0
    $Total = $Bytes.Length

    while ($Pos + 8 -le $Total) {
        $BlockType = [System.BitConverter]::ToUInt32($Bytes, $Pos)
        $BlockLen  = [System.BitConverter]::ToUInt32($Bytes, $Pos + 4)
        if ($BlockLen -lt 12 -or ($Pos + [int]$BlockLen) -gt $Total) { break }

        if ($BlockType -eq 0x00000006) {
            # Enhanced Packet Block: InterfaceID(4) TsHigh(4) TsLow(4) CapLen(4) OrigLen(4) then data
            $CapLenOffset = $Pos + 8 + 4 + 4 + 4
            if ($CapLenOffset + 4 -le $Total) {
                $CapLen = [System.BitConverter]::ToUInt32($Bytes, $CapLenOffset)
                $DataOffset = $CapLenOffset + 4 + 4
                if ($DataOffset + [int]$CapLen -le $Total -and $CapLen -gt 0) {
                    $Packets.Add($Bytes[$DataOffset..($DataOffset + [int]$CapLen - 1)])
                }
            }
        }

        $Pos += [int]$BlockLen
    }

    return $Packets
}

function Save-RawClientHello {
    param([byte[]]$Data, [string]$Label, [string]$SrcInfo, [string]$DstInfo)

    try {
        $DebugFolder = Join-Path $ReportFolder "Debug-ClientHello"
        if (-not (Test-Path $DebugFolder)) { New-Item -ItemType Directory -Path $DebugFolder -Force | Out-Null }

        $File = Join-Path $DebugFolder "ClientHello_$($Timestamp)_$Label.txt"
        $Hex = ($Data | ForEach-Object { "{0:x2}" -f $_ }) -join " "

        $Content = @"

======================================================================
Label       : $Label
Source      : $SrcInfo
Destination : $DstInfo
Length      : $($Data.Length) bytes
Timestamp   : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')

--- Raw bytes (hex) ---
$Hex
"@
        Add-Content -Path $File -Value $Content -Encoding UTF8
        Write-Log "ClientHello diagnostic saved ($Label, $($Data.Length) bytes): $File"
    }
    catch {
        Write-Log "Failed to save ClientHello diagnostic: $_" "WARN"
    }
}

function Get-SNIFromPackets {
    param([string]$PcapPath)

    $Results = New-Object System.Collections.Generic.List[PSCustomObject]
    $Packets = @(Get-PcapngPackets -Path $PcapPath)

    $TotalPacketCount       = $Packets.Count
    $RecognizedLayerCount     = 0
    $TLSHandshakeCount       = 0    # Content Type 0x16 seen at the head of the TCP payload
    $ClientHelloCount        = 0    # + Handshake Type 0x01
    $WithSNICount            = 0
    $WithSNIReassembledCount  = 0
    $QUICCount               = 0    # UDP:443, not decoded — see LIMITATIONS

    # TCP streams keyed by tuple (src:port>dst:port), for a best-effort
    # reassembly attempt when the ClientHello wasn't found in a single segment.
    $Streams = @{}

    foreach ($Pkt in $Packets) {
        $Layer = ConvertFrom-NetworkLayer -Packet $Pkt
        if (-not $Layer) { continue }

        if ($Layer.Protocol -eq 17) {
            if ($Layer.SrcPort -eq 443 -or $Layer.DstPort -eq 443) { $QUICCount++ }
            continue
        }

        $RecognizedLayerCount++
        $Off = $Layer.PayloadOffset
        $IsClientHello = $false

        if ($Off -lt $Layer.Packet.Length -and $Layer.Packet[$Off] -eq 0x16) {
            $TLSHandshakeCount++
            if ($Off + 5 -lt $Layer.Packet.Length -and $Layer.Packet[$Off+5] -eq 0x01) {
                $ClientHelloCount++
                $IsClientHello = $true
            }
        }

        $SNI = Get-SNIFromClientHello -Packet $Layer.Packet -Offset $Off
        if ($SNI) {
            $WithSNICount++
            $Results.Add([PSCustomObject]@{
                SrcIP = $Layer.SrcIP; SrcPort = $Layer.SrcPort
                DstIP = $Layer.DstIP; DstPort = $Layer.DstPort
                SNI   = $SNI
            })
            continue    # found directly, no need to accumulate this stream
        }
        elseif ($IsClientHello -and $DebugClientHello) {
            Save-RawClientHello -Data $Layer.Packet[$Off..($Layer.Packet.Length - 1)] -Label "direct" `
                -SrcInfo "$($Layer.SrcIP):$($Layer.SrcPort)" -DstInfo "$($Layer.DstIP):$($Layer.DstPort)"
        }

        # No SNI in a single segment: keep the segment aside for a reassembly
        # attempt. [Fix] We only open a NEW stream if this first segment is
        # confirmed to be a ClientHello — otherwise we pollute the pool with
        # server responses (ServerHello, certificates, encrypted data) that
        # will never be a ClientHello, no matter what. A stream that is
        # already open keeps accepting its following segments without this
        # condition (those are continuation data, not new TLS headers to
        # validate).
        if ($Off -lt $Layer.Packet.Length) {
            $Key = "$($Layer.SrcIP):$($Layer.SrcPort)>$($Layer.DstIP):$($Layer.DstPort)"
            if ($Streams.ContainsKey($Key) -or $IsClientHello) {
                if (-not $Streams.ContainsKey($Key)) {
                    $Streams[$Key] = New-Object System.Collections.Generic.List[PSCustomObject]
                }
                $Streams[$Key].Add([PSCustomObject]@{
                    Seq = $Layer.SeqNum
                    Data = $Layer.Packet[$Off..($Layer.Packet.Length - 1)]
                    SrcIP = $Layer.SrcIP; SrcPort = $Layer.SrcPort
                    DstIP = $Layer.DstIP; DstPort = $Layer.DstPort
                })
            }
        }
    }

    # --- Best-effort reassembly: only STRICTLY contiguous segments by
    #     sequence number (no reordering, no retransmission handling — see
    #     LIMITATIONS at the top of the file).
    foreach ($Key in @($Streams.Keys)) {
        $Segments = @($Streams[$Key] | Sort-Object Seq)
        if ($Segments.Count -lt 2) { continue }

        $Buffer = New-Object System.Collections.Generic.List[byte]
        $Buffer.AddRange([byte[]]$Segments[0].Data)
        $ExpectedSeq = [uint32]$Segments[0].Seq + [uint32]$Segments[0].Data.Length

        for ($i = 1; $i -lt $Segments.Count; $i++) {
            if ([uint32]$Segments[$i].Seq -ne $ExpectedSeq) { break }   # break: stop here, best-effort
            $Buffer.AddRange([byte[]]$Segments[$i].Data)
            $ExpectedSeq = [uint32]$Segments[$i].Seq + [uint32]$Segments[$i].Data.Length
        }

        if ($Buffer.Count -gt 5) {
            $BufferArray = $Buffer.ToArray()
            $SNI = Get-SNIFromClientHello -Packet $BufferArray -Offset 0
            if ($SNI) {
                $WithSNIReassembledCount++
                $Results.Add([PSCustomObject]@{
                    SrcIP = $Segments[0].SrcIP; SrcPort = $Segments[0].SrcPort
                    DstIP = $Segments[0].DstIP; DstPort = $Segments[0].DstPort
                    SNI   = $SNI
                })
            }
            elseif ($DebugClientHello -and $BufferArray.Length -gt 5 -and $BufferArray[0] -eq 0x16) {
                Save-RawClientHello -Data $BufferArray -Label "reassemble" `
                    -SrcInfo "$($Segments[0].SrcIP):$($Segments[0].SrcPort)" -DstInfo "$($Segments[0].DstIP):$($Segments[0].DstPort)"
            }
        }
    }

    Write-Log "Parser diagnostic: $TotalPacketCount packets captured, $RecognizedLayerCount TCP recognized, $TLSHandshakeCount TLS handshakes, $ClientHelloCount ClientHello, $WithSNICount direct SNI, $WithSNIReassembledCount SNI via reassembly, $QUICCount QUIC packets (UDP:443, not decoded)"
    if (-not $Silent) {
        Write-ConsoleLine -Level "INFO" -Category "SNI parser" -Check "Parser statistics" -Items @(
            "$TotalPacketCount packets captured  ·  $RecognizedLayerCount TCP recognized",
            "$TLSHandshakeCount TLS handshakes  ·  $ClientHelloCount ClientHello",
            "$WithSNICount direct SNI  ·  $WithSNIReassembledCount via reassembly"
        )
        if ($QUICCount -gt 0) {
            Write-ConsoleLine -Level "WARN" -Category "SNI parser" -Check "$QUICCount QUIC packets (UDP:443) seen, not decoded — partial coverage if traffic uses HTTP/3"
        }
    }

    return $Results
}

# ----------------------------------------------------------------------
# [5] SNI capture via pktmon — start/stop kept separate to allow a unified
#     capture window (pktmon runs for the whole TCP window)
# ----------------------------------------------------------------------
function Start-CaptureSNI {
    param([string]$TempFolder)

    if (-not (Get-Command pktmon -ErrorAction SilentlyContinue)) {
        Write-Log "pktmon not found — SNI capture skipped" "WARN"
        Write-ConsoleLine -Level "WARN" -Category "pktmon" -Check "Not found — SNI capture skipped"
        return $null
    }
    if (-not (Test-Path $TempFolder)) { New-Item -ItemType Directory -Path $TempFolder -Force | Out-Null }

    $EtlPath = Join-Path $TempFolder "sni_$Timestamp.etl"
    try {
        # [Fix v2.2.4] pktmon.exe is a native tool: a failure writes its own
        # (OS-localized) message straight to stderr rather than throwing a
        # catchable PowerShell exception, so a try/catch alone never sees
        # it — the raw text used to leak straight to the console instead of
        # going through Write-Log. Every pktmon call below now redirects
        # stderr into the output stream (2>&1) and is checked against
        # $LASTEXITCODE, so a real failure is always caught, logged in
        # English through our own Write-Log, and never left to print
        # whatever language Windows itself happens to be running in.
        $null = pktmon filter remove 2>&1
        $null = pktmon filter add -p 443 2>&1
        # --pkt-size 9000 (not 512): 512 truncated modern ClientHellos
        # (post-quantum extensions, ALPN...) well before their end,
        # especially over IPv6 where the headers already eat up 74+ bytes
        # of the budget. 9000 covers even jumbo frames, at no real cost:
        # pktmon never captures more than the frame's actual size anyway.
        $out = pktmon start --capture --pkt-size 9000 -f $EtlPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "pktmon start failed (exit $LASTEXITCODE): $out" "WARN"
            Write-ConsoleLine -Level "WARN" -Category "pktmon" -Check "Failed to start — SNI capture skipped"
            return $null
        }
        Write-Log "pktmon capture started (port 443), running alongside the TCP window"
        return $EtlPath
    }
    catch {
        Write-Log "Failed to start pktmon (admin rights required): $_" "WARN"
        Write-ConsoleLine -Level "WARN" -Category "pktmon" -Check "Failed — re-run as administrator"
        return $null
    }
}

function Stop-CaptureSNI {
    param([string]$EtlPath)

    if (-not $EtlPath) { return @() }

    try {
        $out = pktmon stop 2>&1
        if ($LASTEXITCODE -ne 0) { Write-Log "pktmon stop returned exit $LASTEXITCODE`: $out" "WARN" }
        $null = pktmon filter remove 2>&1
        Write-Log "pktmon capture stopped"
    }
    catch {
        Write-Log "Failed to stop pktmon: $_" "WARN"
        return @()
    }

    # [Fix v2.2.4] "pktmon stop" can return before the ETW session has
    # fully flushed and closed the .etl file on disk — converting it
    # immediately could then fail with a spurious "file not found", even
    # though the capture itself succeeded moments earlier. A short pause
    # gives the file time to actually be ready before pktmon tries to read it.
    Start-Sleep -Milliseconds 750

    $PcapPath = [System.IO.Path]::ChangeExtension($EtlPath, ".pcapng")
    try {
        if (-not (Test-Path $EtlPath)) {
            Write-Log "pktmon capture file not found after stop ($EtlPath) — no SNI data for this run" "WARN"
            return @()
        }
        $out = pktmon pcapng $EtlPath -o $PcapPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "pktmon pcapng conversion failed (exit $LASTEXITCODE): $out" "WARN"
            Remove-Item $EtlPath -ErrorAction SilentlyContinue
            return @()
        }
    }
    catch {
        Write-Log "Failed to convert to pcapng: $_" "WARN"
        Remove-Item $EtlPath -ErrorAction SilentlyContinue
        return @()
    }

    if (-not (Test-Path $PcapPath)) {
        Write-Log "pcapng file not found after conversion" "WARN"
        return @()
    }

    $SNIs = @()
    try {
        $SNIs = @(Get-SNIFromPackets -PcapPath $PcapPath)
        Write-Log "TLS parser: $($SNIs.Count) ClientHello(s) with SNI extracted"
    }
    catch {
        Write-Log "Failed to parse pcapng: $_" "WARN"
    }

    # The pcap potentially contains sensitive browsing data (SNI = which
    # sites were visited): cleaned up immediately after extraction.
    Remove-Item $EtlPath, $PcapPath -ErrorAction SilentlyContinue

    return $SNIs
}

# ----------------------------------------------------------------------
# [6] Sampling capture of TCP connections, with process filter
# ----------------------------------------------------------------------
function Get-ConnectionCapture {
    param([int]$DurationSeconds, [bool]$Local, [bool]$FastOnly, [string]$ProcessFilter = "")

    $Seen         = @{}
    $ProcessCache   = @{}
    $IntervalSeconds = 5
    $StartTime       = Get-Date

    Write-Log "Starting TCP capture: $DurationSeconds s window, sampled every $IntervalSeconds s"

    do {
        $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

        foreach ($C in $Connections) {
            if (-not $Local -and (Test-IsPrivateOrLocalIP $C.RemoteAddress)) { continue }

            if (-not $ProcessCache.ContainsKey($C.OwningProcess)) {
                $Name = "Unknown"
                try { $Name = (Get-Process -Id $C.OwningProcess -ErrorAction Stop).ProcessName } catch { }
                $ProcessCache[$C.OwningProcess] = $Name
            }
            $ProcName = $ProcessCache[$C.OwningProcess]

            if ($ProcessFilter -and $ProcName -notlike "*$ProcessFilter*") { continue }

            $Key = "$($C.RemoteAddress)|$($C.RemotePort)|$($C.OwningProcess)"
            if (-not $Seen.ContainsKey($Key)) {
                $Seen[$Key] = [PSCustomObject]@{
                    IP = $C.RemoteAddress; Port = $C.RemotePort
                    ProcessName = $ProcName; PID = $C.OwningProcess
                    Occurrences = 0; ReverseName = $null; SNI = $null; ASN = $null
                }
            }
            $Seen[$Key].Occurrences++
        }

        if (-not $Silent) {
            $Elapsed = [int]((Get-Date) - $StartTime).TotalSeconds
            Write-CaptureProgress -Elapsed $Elapsed -Total $DurationSeconds -Endpoints $Seen.Count
        }

        Start-Sleep -Seconds $IntervalSeconds
    } while (((Get-Date) - $StartTime).TotalSeconds -lt $DurationSeconds)

    if (-not $Silent) {
        $FinalElapsed = [int][Math]::Min([double]$DurationSeconds, ((Get-Date) - $StartTime).TotalSeconds)
        Write-CaptureProgress -Elapsed $FinalElapsed -Total $DurationSeconds -Endpoints $Seen.Count -Done
    }
    Write-Log "TCP capture finished: $($Seen.Count) distinct endpoints observed"

    $Results = $Seen.Values
    if (-not $FastOnly) {
        foreach ($R in $Results) { $R.ReverseName = Get-ReverseName $R.IP }
    }

    return $Results
}

# ----------------------------------------------------------------------
# [7] Merging captured SNIs with observed connections (by destination
#     IP+port). Anything that matches nothing is kept aside, not lost.
# ----------------------------------------------------------------------
function Join-SNIIntoConnections {
    param([array]$Connections, [array]$SNIs)

    foreach ($C in $Connections) {
        $Found = $SNIs | Where-Object { $_.DstIP -eq $C.IP -and $_.DstPort -eq $C.Port } | Select-Object -First 1
        if ($Found) { $C.SNI = $Found.SNI }
    }
    return $Connections
}

function Get-UnmatchedSNIs {
    param([array]$SNIs, [array]$Connections)

    return $SNIs | Where-Object {
        $SniItem = $_
        -not ($Connections | Where-Object { $_.IP -eq $SniItem.DstIP -and $_.Port -eq $SniItem.DstPort })
    } | Select-Object DstIP, DstPort, SNI -Unique
}

# ----------------------------------------------------------------------
# [8] Classification: ANOMALY (blocked but reachable) / Known (whitelist,
#     normal) / Unclassified. SNI name (ground truth) takes priority over PTR.
# ----------------------------------------------------------------------
function Group-AndClassify {
    param([array]$Connections, [System.Collections.Generic.HashSet[string]]$Blocked, [System.Collections.Generic.HashSet[string]]$Whitelist)

    foreach ($C in $Connections) {
        $NameToCompare = if ($C.SNI) { $C.SNI } elseif ($C.ReverseName) { $C.ReverseName } else { $null }
        $Target = if ($NameToCompare) { $NameToCompare } else { $C.IP }

        $IsBlocked = $false; $IsWhitelisted = $false
        if ($NameToCompare) {
            foreach ($D in $Blocked) {
                if ($NameToCompare -eq $D -or $NameToCompare.EndsWith(".$D")) { $IsBlocked = $true; break }
            }
            if (-not $IsBlocked) {
                foreach ($D in $Whitelist) {
                    if ($NameToCompare -eq $D -or $NameToCompare.EndsWith(".$D")) { $IsWhitelisted = $true; break }
                }
            }
        }

        $Category = if ($IsBlocked)          { "ANOMALY - Blocked domain but reachable (possible bypass)" }
                     elseif ($IsWhitelisted)   { "Known (whitelist - normal)" }
                     elseif ($C.SNI)           { "Unclassified (SNI captured)" }
                     elseif ($C.ReverseName)    { "Unclassified (name resolved)" }
                     else                      { "Unclassified (IP without PTR)" }

        $C | Add-Member -NotePropertyName Target     -NotePropertyValue $Target -Force
        $C | Add-Member -NotePropertyName Category -NotePropertyValue $Category -Force
    }

    return $Connections
}

# ----------------------------------------------------------------------
# [9] Historical baseline — flags endpoints never seen before
# ----------------------------------------------------------------------
function Import-Baseline {
    param([string]$Path)

    if (-not (Test-Path $Path)) { return @{} }
    try {
        $Raw = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        $Table = @{}
        foreach ($Item in @($Raw)) { $Table[$Item.Key] = $Item }
        return $Table
    }
    catch {
        Write-Log "Baseline unreadable, starting fresh: $_" "WARN"
        return @{}
    }
}

function Update-AndSaveBaseline {
    param([array]$Results, [hashtable]$Baseline, [string]$Path)

    $Today = Get-Date -Format "dd/MM/yyyy"

    foreach ($R in $Results) {
        $Key = "$($R.Target)|$($R.ProcessName)"
        if ($Baseline.ContainsKey($Key)) {
            $Entry = $Baseline[$Key]
            $Entry.LastSeen  = $Today
            $Entry.AppearanceCount = [int]$Entry.AppearanceCount + 1
            $R | Add-Member -NotePropertyName IsNew -NotePropertyValue $false -Force
        }
        else {
            $Baseline[$Key] = [PSCustomObject]@{
                Key = $Key; Target = $R.Target; ProcessName = $R.ProcessName
                FirstSeen = $Today; LastSeen = $Today; AppearanceCount = 1
            }
            $R | Add-Member -NotePropertyName IsNew -NotePropertyValue $true -Force
        }
    }

    try {
        @($Baseline.Values) | Sort-Object Target | ConvertTo-Json -Depth 3 | Out-File $Path -Encoding UTF8 -Force
        Write-Log "Baseline updated: $(@($Baseline.Values).Count) entries ($Path)"
    }
    catch {
        Write-Log "Failed to save baseline: $_" "WARN"
    }

    return $Results
}

# ----------------------------------------------------------------------
# [10] Console report
# ----------------------------------------------------------------------
function Write-ConsoleReport {
    param([array]$Results, [array]$UnmatchedSNIs, [array]$Vanished = @())

    # [Fix v2.2.2] Each of these MUST be forced into array context with @().
    # PowerShell's pipeline silently unwraps a single matching result into a
    # bare scalar object (not an array) — and a bare object has no .Count
    # property of its own. On Windows PowerShell 5.1 (the default engine
    # behind every desktop shortcut in this suite — powershell.exe, not
    # pwsh.exe), that missing property resolves to $null, which renders as
    # a BLANK value instead of "1" in the summary below. Reproduced live:
    # exactly one [NEW] endpoint made "Never seen before (new)" print blank
    # instead of "1", while every other line (0 or 3+ matches) looked fine
    # — 0 and 2+ matches don't hit this, only the "exactly 1" case does.
    $Anomalies = @($Results | Where-Object { $_.Category -like "ANOMALY*" })
    $Known    = @($Results | Where-Object { $_.Category -like "Known*" })
    $Unclassified = @($Results | Where-Object { $_.Category -like "Unclassified*" } | Sort-Object -Property Occurrences -Descending)
    $NewOnes  = @($Results | Where-Object { $_.IsNew -eq $true })

    Write-Header "SUMMARY"
    Write-Host ""

    # Headline: total + stacked classification bar (red / green / yellow).
    Write-Host "   " -NoNewline
    Write-Host ("·".PadRight(2)) -NoNewline -ForegroundColor Cyan
    Write-Host (" " + "Endpoints observed".PadRight(19)) -NoNewline -ForegroundColor Gray
    Write-Host ("$($Results.Count)".PadLeft(4)) -NoNewline -ForegroundColor White
    Write-Host "   " -NoNewline
    Write-StackedBar -Counts @($Anomalies.Count, $Known.Count, $Unclassified.Count) -Colors @("Red", "Green", "Yellow") -Width 20
    Write-Host ""
    Write-Host ""

    if ($Anomalies.Count -gt 0) { Write-SummaryRow "✗" "Anomalies" $Anomalies.Count "blocked but reachable" "Red" }
    else                        { Write-SummaryRow "✓" "Anomalies" 0 "blocked but reachable" "Green" }
    Write-SummaryRow "✓" "Known" $Known.Count "whitelist, normal" "Green"
    if ($Unclassified.Count -gt 0) { Write-SummaryRow "!" "Unclassified" $Unclassified.Count "to review" "Yellow" }
    else                           { Write-SummaryRow "✓" "Unclassified" 0 "to review" "Green" }
    if ($NewOnes.Count -gt 0) { Write-SummaryRow "+" "New" $NewOnes.Count "never seen before" "Magenta" }
    else                      { Write-SummaryRow "·" "New" 0 "never seen before" "DarkGray" }
    Write-SummaryRow "-" "Vanished" $Vanished.Count "present in the previous run, absent now" "DarkGray"

    if ($Anomalies.Count -gt 0) {
        Write-Header "ANOMALIES — review first"
        $AnomalyRows = @($Anomalies | ForEach-Object {
            [PSCustomObject]@{
                Icon = "✗"; Color = "Red"; Target = "$($_.Target)"
                Proc = "$($_.ProcessName) (PID $($_.PID))"
                Count = $_.Occurrences; Source = (Get-NameSource $_); Tag = ""
            }
        })
        Write-EndpointTable -Rows $AnomalyRows
    }

    Write-Header "UNCLASSIFIED (sorted by frequency)"
    if ($Unclassified.Count -eq 0) {
        Write-Host ""
        Write-ConsoleLine -Level "OK" -Category "Unclassified" -Check "No unclassified endpoint observed"
    }
    else {
        $UnclassifiedRows = @($Unclassified | ForEach-Object {
            $Color = if ($_.IsNew) { "Magenta" } elseif ($_.Occurrences -ge 5) { "White" } else { "DarkGray" }
            [PSCustomObject]@{
                Icon = $(if ($_.IsNew) { "+" } else { "·" }); Color = $Color; Target = "$($_.Target)"
                Proc = "$($_.ProcessName) (PID $($_.PID))"
                Count = $_.Occurrences; Source = (Get-NameSource $_)
                Tag = $(if ($_.IsNew) { "NEW" } else { "" })
            }
        })
        Write-EndpointTable -Rows $UnclassifiedRows
    }

    if ($Vanished.Count -gt 0) {
        Write-Header "VANISHED SINCE LAST RUN"
        Write-Host ""
        Write-Host "   Present in the previous run, absent this time — not necessarily abnormal (one-off connection)" -ForegroundColor DarkGray
        $VanishedRows = @($Vanished | ForEach-Object {
            [PSCustomObject]@{ Icon = "-"; Color = "DarkGray"; Target = "$($_.Target)"; Proc = "$($_.ProcessName)" }
        })
        Write-EndpointTable -Rows $VanishedRows -Compact
    }

    if ($UnmatchedSNIs -and @($UnmatchedSNIs).Count -gt 0) {
        Write-Header "SNI CAPTURED WITH NO MATCHING TCP CONNECTION"
        Write-Host ""
        Write-Host "   Likely: connection too short to appear in the TCP sampling" -ForegroundColor DarkGray
        $SniRows = @($UnmatchedSNIs | ForEach-Object {
            [PSCustomObject]@{ Icon = "·"; Color = "Cyan"; Target = "$($_.SNI)"; Proc = "$($_.DstIP):$($_.DstPort)" }
        })
        Write-EndpointTable -Rows $SniRows -Compact -SecondHeader "DESTINATION"
    }
}

# ----------------------------------------------------------------------
# [11] HTML export — dark theme consistent with the rest of the suite
# ----------------------------------------------------------------------
function Get-UnclassifiedHistory {
    param([string]$Folder, [int]$MaxVal = 20)

    try {
        $Files = Get-ChildItem -Path $Folder -Filter "Shadow-Traffic_*.json" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch "Unclassified" } |
            Sort-Object LastWriteTime | Select-Object -Last $MaxVal

        $Values = foreach ($F in $Files) {
            try {
                $J = Get-Content $F.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($null -ne $J.Unclassified) { [int]$J.Unclassified }
            }
            catch { }
        }
        return @($Values)
    }
    catch {
        return @()
    }
}

function Export-HTMLReport {
    param(
        [array]$Results,
        [string]$Path,
        [array]$Vanished = @(),
        [array]$UnmatchedSNIs = @(),
        [array]$History = @(),
        [hashtable]$Meta = @{}
    )

    $Inv = [System.Globalization.CultureInfo]::InvariantCulture
    # @($null) would be a 1-element array: drop nulls explicitly (an
    # if-expression returning @() hands back $null to the caller).
    $Results       = @($Results       | Where-Object { $null -ne $_ })
    $Vanished      = @($Vanished      | Where-Object { $null -ne $_ })
    $UnmatchedSNIs = @($UnmatchedSNIs | Where-Object { $null -ne $_ })

    $AnomalyList     = @($Results | Where-Object { (Get-CategoryKey $_.Category) -eq "ANOMALY" })
    $KnownList       = @($Results | Where-Object { (Get-CategoryKey $_.Category) -eq "Known" })
    $UnclassifiedList = @($Results | Where-Object { (Get-CategoryKey $_.Category) -eq "Unclassified" })
    $NewList         = @($Results | Where-Object { $_.IsNew -eq $true })
    $Total           = $Results.Count

    # Anomalies first, then unclassified (most frequent first), then known.
    $Rank = @{ "ANOMALY" = 0; "Unclassified" = 1; "Known" = 2 }
    $Sorted = @($Results | Sort-Object `
        @{ Expression = { $Rank[(Get-CategoryKey $_.Category)] } }, `
        @{ Expression = { [int]$_.Occurrences }; Descending = $true }, `
        @{ Expression = { "$($_.Target)" } })

    # --- Table rows -------------------------------------------------------
    $AnomalyIndex = 0
    $AnomalyLinks = [System.Collections.Generic.List[string]]::new()
    $RowsList     = [System.Collections.Generic.List[string]]::new()
    foreach ($R in $Sorted) {
        $Key        = Get-CategoryKey $R.Category
        $RowClass   = switch ($Key) { "ANOMALY" { "row-fail" } "Known" { "row-ok" } default { "row-warn" } }
        $BadgeClass = switch ($Key) { "ANOMALY" { "fail" }     "Known" { "ok" }     default { "warn" } }
        $BadgeText  = switch ($Key) { "ANOMALY" { "Anomaly" }  "Known" { "Known" }  default { "Unclassified" } }
        $RankValue  = $Rank[$Key]

        $IdAttr = ""
        if ($Key -eq "ANOMALY") {
            $AnomalyIndex++
            $IdAttr = " id=`"anomaly-$AnomalyIndex`""
            if ($AnomalyLinks.Count -lt 12) {
                $AnomalyLinks.Add("<a class=`"fail-link`" href=`"#anomaly-$AnomalyIndex`">$(ConvertTo-HtmlSafe $R.Target)</a>")
            }
        }

        $NewBadge = if ($R.IsNew) { ' <span class="badge info">NEW</span>' } else { "" }
        $Source   = if ($R.SNI) { "SNI" } elseif ($R.ReverseName) { "PTR" } elseif ($R.ASN) { "$($R.ASN)" } else { "Raw IP" }
        $PidText  = if ($R.PID) { " <span class=`"detail`">PID $(ConvertTo-HtmlSafe $R.PID)</span>" } else { "" }
        $SearchText = ConvertTo-HtmlSafe (("$($R.Target) $($R.ProcessName) $($R.PID) $($R.Port) $Source $BadgeText").ToLowerInvariant())
        $PortValue = if ($null -ne $R.Port -and "$($R.Port)" -match '^\d+$') { [int]$R.Port } else { 0 }
        $OccValue  = if ($null -ne $R.Occurrences -and "$($R.Occurrences)" -match '^\d+$') { [int]$R.Occurrences } else { 0 }

        $RowsList.Add(@"
      <tr$IdAttr class="$RowClass" data-cat="$Key" data-new="$(if ($R.IsNew) { '1' } else { '0' })" data-search="$SearchText">
        <td class="mono">$(ConvertTo-HtmlSafe $R.Target)$NewBadge</td>
        <td data-v="$RankValue"><span class="badge $BadgeClass" title="$(ConvertTo-HtmlSafe $R.Category)">$BadgeText</span></td>
        <td>$(ConvertTo-HtmlSafe $R.ProcessName)$PidText</td>
        <td data-v="$PortValue">$(ConvertTo-HtmlSafe $R.Port)</td>
        <td data-v="$OccValue">$(ConvertTo-HtmlSafe $R.Occurrences)</td>
        <td class="detail">$(ConvertTo-HtmlSafe $Source)</td>
      </tr>
"@)
    }

    # --- Header meta bar --------------------------------------------------
    $Machine = if ($Meta.Machine) { $Meta.Machine } else { [System.Environment]::MachineName }
    $MetaItems = [System.Collections.Generic.List[string]]::new()
    $MetaItems.Add("<span><span class=`"meta-dot`"></span>Machine: <b>$(ConvertTo-HtmlSafe $Machine)</b></span>")
    $MetaItems.Add("<span>Date: <b>$(ConvertTo-HtmlSafe ((Get-Date).ToString('dd MMM yyyy HH:mm', $Inv)))</b></span>")
    if ($Meta.OS)            { $MetaItems.Add("<span>OS: <b>$(ConvertTo-HtmlSafe $Meta.OS)</b></span>") }
    if ($Meta.WindowSeconds) { $MetaItems.Add("<span>Capture window: <b>$(ConvertTo-HtmlSafe $Meta.WindowSeconds) s</b></span>") }
    $SniState = if ($Meta.CaptureSNI) { "on" } else { "off" }
    $MetaItems.Add("<span>SNI capture: <b>$SniState</b></span>")
    if ($Meta.ProcessFilter) { $MetaItems.Add("<span>Process filter: <b>$(ConvertTo-HtmlSafe $Meta.ProcessFilter)</b></span>") }
    if ($Meta.ContainsKey("RefFound")) {
        if ($Meta.RefFound) {
            $MetaItems.Add("<span>Block-Telemetry: <b>$(ConvertTo-HtmlSafe $Meta.RefBlocked) blocked &middot; $(ConvertTo-HtmlSafe $Meta.RefWhitelist) whitelisted</b></span>")
        } else {
            $MetaItems.Add("<span>Block-Telemetry: <b>not found</b></span>")
        }
    }
    $MetaBarHTML = $MetaItems -join "`n    "

    # --- Banner: anomalies / reference missing / all clear ---------------
    $BannerHTML = ""
    if ($AnomalyList.Count -gt 0) {
        $Plural = if ($AnomalyList.Count -gt 1) { "ies" } else { "y" }
        $MoreLinks = if ($AnomalyList.Count -gt $AnomalyLinks.Count) { "<span class=`"detail`">+$($AnomalyList.Count - $AnomalyLinks.Count) more in the table</span>" } else { "" }
        $BannerHTML = @"
  <div class="regression-banner">
    <span class="regression-icon">⚠</span>
    <span><strong>$($AnomalyList.Count) anomal$Plural detected</strong> — blocked domain(s) from your Block-Telemetry list that were still reachable (possible bypass). Review these first.</span>
  </div>
  <div class="fail-links" style="margin-bottom:32px">$($AnomalyLinks -join "`n    ") $MoreLinks</div>
"@
    }
    elseif ($Meta.ContainsKey("RefFound") -and -not $Meta.RefFound) {
        $BannerHTML = @"
  <div class="notice-warn">
    <span class="regression-icon">⚠</span>
    <span><strong>Block-Telemetry reference not found</strong> — endpoints could not be matched against your blocklist, so everything is shown as Unclassified. Use <code>-BlockTelemetryPath</code> to point to the script.</span>
  </div>
"@
    }
    else {
        $BannerHTML = @"
  <div class="exec-summary exec-ok" style="margin-bottom:32px">
    <span class="exec-icon">✓</span>
    <span>No anomaly — none of the observed endpoints matched a blocked domain.</span>
  </div>
"@
    }

    # --- Classification bar ------------------------------------------------
    $Segments = ""
    if ($Total -gt 0) {
        foreach ($Seg in @(@("fail", $AnomalyList.Count), @("ok", $KnownList.Count), @("warn", $UnclassifiedList.Count))) {
            if ($Seg[1] -gt 0) {
                $Pct = ($Seg[1] / $Total * 100).ToString("0.##", $Inv)
                $Segments += "<div class=`"seg $($Seg[0])`" style=`"width:$Pct%`"></div>"
            }
        }
    }
    $ClassBarHTML = @"
  <div class="score-bar-wrap">
    <div class="score-label">
      <span>Endpoint classification</span>
      <span class="score-value">$Total</span>
    </div>
    <div class="score-bar-track stacked">$Segments</div>
    <div class="legend">
      <span class="lg fail">Anomalies $($AnomalyList.Count)</span>
      <span class="lg ok">Known $($KnownList.Count)</span>
      <span class="lg warn">Unclassified $($UnclassifiedList.Count)</span>
    </div>
  </div>
"@

    # --- Evolution since the last run -------------------------------------
    $DeltaItems = [System.Collections.Generic.List[string]]::new()
    $MaxItems = 20
    $NewSorted = @($NewList | Sort-Object @{ Expression = { $Rank[(Get-CategoryKey $_.Category)] } }, @{ Expression = { "$($_.Target)" } })
    if ($Total -gt 0 -and $NewList.Count -eq $Total) {
        $DeltaItems.Add('<div class="delta-empty">Every endpoint is new — this is the first run, or the baseline was reset.</div>')
    }
    else {
        foreach ($N in ($NewSorted | Select-Object -First $MaxItems)) {
            $TagClass = if ((Get-CategoryKey $N.Category) -eq "ANOMALY") { "worse" } else { "neutral" }
            $DeltaItems.Add("<div class=`"delta-item $TagClass`"><span class=`"tag`">New</span><span>$(ConvertTo-HtmlSafe $N.Target) — $(ConvertTo-HtmlSafe $N.ProcessName)</span><span class=`"arrow`">$(Get-CategoryKey $N.Category)</span></div>")
        }
        if ($NewSorted.Count -gt $MaxItems) {
            $DeltaItems.Add("<div class=`"delta-empty`">… and $($NewSorted.Count - $MaxItems) more new endpoint(s) — use the 'New' filter in the table.</div>")
        }
    }
    foreach ($V in ($Vanished | Select-Object -First $MaxItems)) {
        $DeltaItems.Add("<div class=`"delta-item gone`"><span class=`"tag`">Vanished</span><span>$(ConvertTo-HtmlSafe $V.Target) — $(ConvertTo-HtmlSafe $V.ProcessName)</span><span class=`"arrow`">absent this run</span></div>")
    }
    if ($Vanished.Count -gt $MaxItems) {
        $DeltaItems.Add("<div class=`"delta-empty`">… and $($Vanished.Count - $MaxItems) more vanished endpoint(s) — see the dedicated table below.</div>")
    }
    if ($DeltaItems.Count -eq 0) {
        $DeltaItems.Add('<div class="delta-empty">No change since the last run.</div>')
    }
    $DeltaHTML = @"
  <div class="delta-wrap">
    <div class="delta-header">
      <span class="section-title" style="margin:0">Evolution since the last run</span>
      <span class="delta-score-diff flat">+$($NewList.Count) new · -$($Vanished.Count) vanished</span>
    </div>
    <div class="delta-list">
      $($DeltaItems -join "`n      ")
    </div>
  </div>
"@

    # --- History chart (Unclassified count over recent runs) -------------
    $HistoryChartHTML = ""
    $HistoryPoints = @(@($History | ForEach-Object { [int]$_ }) + @($UnclassifiedList.Count))
    if ($HistoryPoints.Count -ge 2) {
        $ChartW = 600; $ChartH = 80; $Pad = 8
        $MinS = ($HistoryPoints | Measure-Object -Minimum).Minimum
        $MaxS = ($HistoryPoints | Measure-Object -Maximum).Maximum
        if ($MaxS -eq $MinS) { $MaxS = $MinS + 1 }
        $StepX = ($ChartW - 2 * $Pad) / [math]::Max(1, ($HistoryPoints.Count - 1))
        $Points = [System.Collections.Generic.List[string]]::new()
        for ($i = 0; $i -lt $HistoryPoints.Count; $i++) {
            $x = $Pad + ($i * $StepX)
            $yRatio = ($HistoryPoints[$i] - $MinS) / [double]($MaxS - $MinS)
            $y = $ChartH - $Pad - ($yRatio * ($ChartH - 2 * $Pad))
            $Points.Add("$($x.ToString('0.##', $Inv)),$($y.ToString('0.##', $Inv))")
        }
        $LastX = $Points[-1].Split(',')[0]
        $LastY = $Points[-1].Split(',')[1]
        $HistoryChartHTML = @"
  <div class="delta-wrap">
    <div class="delta-header">
      <span class="section-title" style="margin:0">Unclassified endpoints (last $($HistoryPoints.Count) runs)</span>
      <span class="detail">Min $MinS — Max $MaxS</span>
    </div>
    <svg viewBox="0 0 $ChartW $ChartH" width="100%" height="$ChartH" preserveAspectRatio="none">
      <polyline points="$($Points -join ' ')" fill="none" stroke="var(--accent)" stroke-width="2" />
      <circle cx="$LastX" cy="$LastY" r="3.5" fill="var(--warn)" />
    </svg>
  </div>
"@
    }

    # --- Vanished table + unmatched SNI table ------------------------------
    $VanishedHTML = ""
    if ($Vanished.Count -gt 0) {
        $VRows = foreach ($V in $Vanished) {
            "      <tr><td class=`"mono`">$(ConvertTo-HtmlSafe $V.Target)</td><td>$(ConvertTo-HtmlSafe $V.ProcessName)</td><td class=`"detail`">$(ConvertTo-HtmlSafe $V.Category)</td></tr>"
        }
        $VanishedHTML = @"
  <p class="section-title">Vanished since the last run</p>
  <p class="detail" style="margin-bottom:12px">Present in the previous run, absent this time — not necessarily abnormal (one-off connection).</p>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Target</th><th>Process</th><th>Previous category</th></tr></thead>
    <tbody>
$($VRows -join "`n")
    </tbody>
  </table>
  </div>
"@
    }

    $SniHTML = ""
    if ($UnmatchedSNIs.Count -gt 0) {
        $SRows = foreach ($S in $UnmatchedSNIs) {
            "      <tr><td class=`"mono`">$(ConvertTo-HtmlSafe $S.SNI)</td><td>$(ConvertTo-HtmlSafe $S.DstIP):$(ConvertTo-HtmlSafe $S.DstPort)</td></tr>"
        }
        $SniHTML = @"
  <p class="section-title">SNI captured with no matching TCP connection</p>
  <p class="detail" style="margin-bottom:12px">Likely a connection too short-lived to appear in the TCP sampling.</p>
  <div class="table-wrap">
  <table>
    <thead><tr><th>SNI</th><th>Destination</th></tr></thead>
    <tbody>
$($SRows -join "`n")
    </tbody>
  </table>
  </div>
"@
    }

    # --- Static assets (single-quoted here-strings: no interpolation) ----
    $LogoSvg = @'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="9.39 8.477 484.197 428.149" style="width:76px;height:76px;margin-left:24px;align-self:flex-end;filter:drop-shadow(0 0 12px rgba(0,212,255,.4));flex-shrink:0"><path d="m347.015 235.334 42.877-112.525 67.515 25.727-42.877 112.524z" fill="#a8ce81"/><path d="m303.267 350.143 42.92-112.634 67.514 25.726-42.919 112.634z" fill="#fddb1d"/><path d="m263.921 207.033 42.879-112.525 67.406 25.685-42.877 112.525z" fill="#ef7066"/><path d="m220.505 320.972 42.588-111.764 67.406 25.685-42.588 111.764z" fill="#6eaed7"/><path d="m415.69 247.559c-12.962-10.418-30.606-21.623-53.002-30.158-1.455-.43-2.827-1.077-4.131-1.574l33.307-87.41c1.755.295 3.277.875 4.893 1.864 22.194 8.083 39.661 19.097 52.64 29.147zm-44.284 116.221a216.14 216.14 0 0 0 -53.045-30.048c-1.496-.321-2.91-.86-4.131-1.574l34.136-89.586c1.673.513 3.236.984 4.893 1.865 22.153 8.192 39.62 19.206 52.392 29.8zm122.181-212.166s-25.485-37.351-81.827-59.07c-56.66-21.216-98.7-15.447-98.482-15.364l-15.038 39.466c-.135-.3 27.632-5.533 68.583 3.971l-33.597 88.172c-41.045-9.913-68.776-3.795-68.693-4.013l-10.29 27.33s27.736-7.111 69.123 2.558l-34.717 91.108c-33.74-8.499-58.772-7.828-67.506-6.798l-14.5 38.052c10.873-1.087 47.89-2.17 95.075 15.809 56.467 21.392 82.284 57.873 82.408 57.547zm-241.467-32.87 14.747-38.705 41.45-2.259-14.748 38.705zm-91.514 240.162 14.748-38.704 41.45-2.259-14.5 38.052zm16.364-42.944 13.38-35.117 41.492-2.367-13.423 35.225zm60.11-157.752 13.382-35.118 41.45-2.259-13.381 35.117zm-30.034 78.821 13.381-35.116 41.45-2.26-13.381 35.117zm-15.038 39.466 13.38-35.117 41.45-2.26-13.38 35.117zm30.035-78.823 13.422-35.225 41.45-2.259-13.423 35.225zm-10.213-90.174 11.476-30.115 40.145-2.756-11.766 30.876zm-110.927-84.974 4.93-12.937 16.36-1.112-4.93 12.937zm76.852 67.881 8.99-23.592 35.117-2.306-9.03 23.7zm-28.691-20.768 6.835-17.94 28.455-1.483-6.836 17.94zm-24.068-24.734 5.469-14.351 23.495-.884-5.179 13.59zm40.932 183.057 11.476-30.115 39.855-1.995-11.475 30.115zm-110.927-84.974 4.93-12.938 16.36-1.111-5.178 13.59zm76.852 67.881 9.031-23.7 35.077-2.198-9.032 23.7zm-28.691-20.769 6.835-17.938 28.455-1.484-6.835 17.939zm-24.067-24.734 5.22-13.698 23.743-1.536-5.179 13.59zm41.222 182.297 11.475-30.115 40.145-2.757-11.475 30.116zm-110.927-84.974 5.178-13.59 16.112-.46-4.93 12.938zm77.1 67.229 8.74-22.94 35.119-2.307-8.783 23.05zm-28.691-20.769 6.587-17.287 28.454-1.483-6.587 17.286zm-24.026-24.843 5.178-13.59 23.495-.883-5.178 13.59z" fill="#000101"/><path d="m114.017 84.174 4.889-12.83 17.411-1.582-4.888 12.829zm88.133 61.472 9.529-25.006 32.364-1.612-9.28 24.353zm-34.836-17.383 7.913-20.766 29.355-1.887-7.913 20.766zm-29.271-19.247 6.049-15.873 22.733-1.173-6.007 15.764zm-50.589-48.909 4.102-10.763 12.995-.776-4.101 10.764zm11.525 63.532 4.93-12.938 17.411-1.583-4.93 12.938zm88.133 61.472 9.57-25.114 32.612-2.265-9.528 25.006zm-34.588-18.035 7.664-20.113 29.397-1.996-7.954 20.874zm-29.478-18.703 6.007-15.764 22.734-1.174-5.758 15.112zm-50.63-48.8 4.392-11.525 12.995-.775-4.392 11.524z" fill="#ef7066"/><path d="m68.115 204.635 4.93-12.937 17.122-.822-4.93 12.938zm87.844 62.234 9.57-25.114 32.653-2.374-9.57 25.114zm-34.547-18.144 7.913-20.766 29.107-1.235-7.664 20.113zm-29.229-19.355 5.717-15.004 22.733-1.173-5.717 15.003zm-50.92-48.04 4.391-11.524 12.995-.776-4.35 11.416zm11.814 62.77 4.93-12.937 17.122-.822-4.93 12.938zm88.133 61.473 9.28-24.353 32.654-2.374-9.57 25.115zm-34.836-17.383 7.913-20.765 29.397-1.996-7.955 20.874zm-29.229-19.355 5.717-15.004 23.023-1.934-6.007 15.764zm-50.631-48.801 4.102-10.763 12.995-.775-4.101 10.763z" fill="#6eaed7"/></svg>
'@

    $Css = @'
  :root {
    --bg: #080b12; --surface: #111827; --surface2: #1a2235;
    --border: #1e2d45; --text: #e2e8f0; --muted: #94a3b8;
    --ok: #a8ce81; --warn: #ffb347; --fail: #ef7066; --info: #7c6af7;
    --accent: #00d4ff; --accent2: #0099cc; --accent3: #005f80;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.5; }

  header { background: linear-gradient(160deg,#060c1a 0%,#0a1628 50%,#060a14 100%); border-bottom: 2px solid var(--accent3); padding: 32px 40px 24px; position: relative; overflow: hidden; }
  header::before { content:''; position:absolute; top:0; left:0; right:0; bottom:0; background: radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.06) 0%,transparent 60%), radial-gradient(ellipse at 80% 20%,rgba(124,106,247,.05) 0%,transparent 50%); pointer-events:none; }
  .titlerow { display:flex; align-items:flex-end; gap:0; position:relative; z-index:1; }
  .title-text h1 { font-family:'Cascadia Code','Consolas','Courier New',monospace; font-size:26px; font-weight:700; color:var(--accent); text-shadow:0 0 20px rgba(0,212,255,.4); letter-spacing:1px; margin:0 0 10px 0; }
  .logo-sub { font-family:'Cascadia Code','Consolas',monospace; font-size:12px; color:var(--muted); letter-spacing:2px; margin-bottom:14px; }
  .logo-sub b { color:var(--accent); }
  .meta-bar { display:flex; flex-wrap:wrap; gap:8px 24px; font-size:11.5px; color:#475569; border-top:1px solid var(--border); padding-top:12px; margin-top:4px; position:relative; z-index:1; }
  .meta-bar span { display:flex; align-items:center; gap:6px; }
  .meta-bar b { color:var(--muted); }
  .meta-dot { width:5px; height:5px; border-radius:50%; background:var(--accent); display:inline-block; box-shadow:0 0 6px var(--accent); }

  .container { max-width: 1400px; margin: 0 auto; padding: 32px 40px; }

  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }
  .stat-card .num { font-size: 36px; font-weight: 800; line-height: 1; margin-bottom: 6px; }
  .stat-card .lbl { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-card.ok   .num { color: var(--ok);   }
  .stat-card.warn .num { color: var(--warn);  }
  .stat-card.fail .num { color: var(--fail);  }
  .stat-card.info .num { color: var(--info);  }
  .stat-card.score .num { color: var(--accent); }
  .stat-card.muted .num { color: var(--muted); }

  .section-title { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 12px; }

  .table-wrap { overflow-x: auto; margin-bottom: 32px; }
  table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
  .table-wrap table { margin-bottom: 0; }
  thead th { background: var(--surface2); padding: 12px 16px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); border-bottom: 1px solid var(--border); white-space: nowrap; }
  thead th[data-sort] { cursor: pointer; user-select: none; }
  thead th[data-sort]:hover { color: var(--accent); }
  tbody td { padding: 10px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:last-child td { border-bottom: none; }
  .mono { font-family: 'Cascadia Code','Consolas','Courier New',monospace; font-size: 13px; word-break: break-all; }
  .row-fail { background: rgba(239,112,102,0.05); }
  .row-warn { background: rgba(255,179,71,0.05); }
  .row-ok   { background: rgba(168,206,129,0.03);  }
  .detail   { color: var(--muted); }

  .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; white-space: nowrap; }
  .badge.ok   { background: rgba(168,206,129,0.15);  color: var(--ok);   border: 1px solid rgba(168,206,129,0.3);  }
  .badge.warn { background: rgba(255,179,71,0.15); color: var(--warn); border: 1px solid rgba(255,179,71,0.3); }
  .badge.fail { background: rgba(239,112,102,0.15);  color: var(--fail); border: 1px solid rgba(239,112,102,0.3);  }
  .badge.info { background: rgba(124,106,247,0.15); color: var(--info); border: 1px solid rgba(124,106,247,0.3); }

  .score-bar-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 32px; }
  .score-bar-track { background: var(--surface2); border-radius: 8px; height: 18px; overflow: hidden; margin-top: 10px; }
  .score-bar-track.stacked { display: flex; }
  .seg { height: 100%; }
  .seg.fail { background: var(--fail); }
  .seg.ok   { background: var(--ok); }
  .seg.warn { background: var(--warn); }
  .legend { display: flex; flex-wrap: wrap; gap: 8px 20px; margin-top: 12px; font-size: 12px; color: var(--muted); }
  .lg::before { content: ''; display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; vertical-align: baseline; }
  .lg.fail::before { background: var(--fail); }
  .lg.ok::before   { background: var(--ok); }
  .lg.warn::before { background: var(--warn); }
  .score-label { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .score-label span:first-child { font-weight: 700; font-size: 16px; }
  .score-value { font-size: 28px; font-weight: 800; color: var(--accent); }

  footer { text-align: center; padding: 24px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 16px; }

  .delta-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 32px; }
  .delta-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; gap: 12px; flex-wrap: wrap; }
  .delta-score-diff { font-size: 16px; font-weight: 800; }
  .delta-score-diff.flat { color: var(--muted); }
  .delta-list { display: flex; flex-direction: column; gap: 8px; }
  .delta-item { display: flex; align-items: center; gap: 10px; padding: 10px 14px; border-radius: 8px; background: var(--surface2); font-size: 13px; }
  .delta-item .tag { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; padding: 2px 8px; border-radius: 6px; white-space: nowrap; }
  .delta-item.worse .tag { background: rgba(239,112,102,0.18); color: var(--fail); }
  .delta-item.neutral .tag { background: rgba(124,106,247,0.18); color: var(--info); }
  .delta-item.gone .tag { background: rgba(148,163,184,0.18); color: var(--muted); }
  .delta-item span:nth-child(2) { word-break: break-all; }
  .delta-item .arrow { color: var(--muted); margin-left: auto; white-space: nowrap; }
  .delta-empty { color: var(--muted); font-size: 13px; }

  .fail-links { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .fail-link { font-size: 12px; padding: 6px 12px; border-radius: 20px; background: rgba(239,112,102,0.12); color: var(--fail); border: 1px solid rgba(239,112,102,0.3); text-decoration: none; white-space: nowrap; }
  .fail-link:hover { background: rgba(239,112,102,0.22); }

  .search-box { width: 100%; max-width: 420px; margin-bottom: 16px; padding: 10px 14px; border-radius: 8px; border: 1px solid var(--border); background: var(--surface); color: var(--text); font-size: 13px; }
  .search-box:focus { outline: none; border-color: var(--accent); }
  .filter-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
  .filter-chip { font-size: 11px; padding: 5px 12px; border-radius: 20px; border: 1px solid var(--border); background: var(--surface2); color: var(--muted); cursor: pointer; user-select: none; }
  .filter-chip.active { background: var(--accent); color: white; border-color: var(--accent); }
  .no-results { color: var(--muted); font-size: 13px; padding: 16px; text-align: center; display: none; }

  .regression-banner { display: flex; align-items: center; gap: 14px; background: rgba(239,112,102,0.12); border: 1px solid rgba(239,112,102,0.4); border-radius: 12px; padding: 16px 20px; margin-bottom: 16px; color: var(--fail); }
  .notice-warn { display: flex; align-items: center; gap: 14px; background: rgba(255,179,71,0.10); border: 1px solid rgba(255,179,71,0.4); border-radius: 12px; padding: 16px 20px; margin-bottom: 32px; color: var(--warn); }
  .notice-warn code { font-family: 'Cascadia Code','Consolas',monospace; }
  .regression-icon { font-size: 22px; flex-shrink: 0; }

  .exec-summary { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; margin-bottom: 20px; }
  .exec-summary.exec-ok { border-color: rgba(168,206,129,0.4); background: rgba(168,206,129,0.07); display: flex; align-items: center; gap: 12px; color: var(--ok); }
  .exec-icon { font-size: 20px; }

  @media (max-width: 700px) {
    header { padding: 24px 20px 18px; }
    .container { padding: 24px 20px; }
    .title-text h1 { font-size: 20px; }
  }
'@
    
    $Js = @'
  (function () {
    var searchBox = document.getElementById('searchBox');
    var chips = document.querySelectorAll('.filter-chip');
    var table = document.getElementById('resultsTable');
    var tbody = table.tBodies[0];
    var noResults = document.getElementById('noResults');
    var activeFilter = 'ALL';

    function applyFilters() {
      var term = (searchBox.value || '').toLowerCase().trim();
      var visible = 0;
      Array.prototype.forEach.call(tbody.rows, function (row) {
        var matchesFilter = (activeFilter === 'ALL') ||
          (activeFilter === 'NEW' ? row.getAttribute('data-new') === '1' : row.getAttribute('data-cat') === activeFilter);
        var matchesSearch = !term || (row.getAttribute('data-search') || '').indexOf(term) !== -1;
        var show = matchesFilter && matchesSearch;
        row.style.display = show ? '' : 'none';
        if (show) visible++;
      });
      noResults.style.display = (visible === 0) ? 'block' : 'none';
    }

    searchBox.addEventListener('input', applyFilters);
    Array.prototype.forEach.call(chips, function (chip) {
      chip.addEventListener('click', function () {
        Array.prototype.forEach.call(chips, function (c) { c.classList.remove('active'); });
        chip.classList.add('active');
        activeFilter = chip.getAttribute('data-filter');
        applyFilters();
      });
    });

    // Click a column header to sort (click again to reverse).
    var sortCol = -1, sortAsc = true;
    var headers = table.tHead.rows[0].cells;
    Array.prototype.forEach.call(headers, function (th) {
      if (!th.hasAttribute('data-sort')) return;
      th.addEventListener('click', function () {
        var col = th.cellIndex;
        var numeric = th.getAttribute('data-sort') === 'num';
        sortAsc = (sortCol === col) ? !sortAsc : !numeric;
        sortCol = col;
        var rows = Array.prototype.slice.call(tbody.rows);
        rows.sort(function (a, b) {
          var x = a.cells[col].getAttribute('data-v') || a.cells[col].textContent.trim().toLowerCase();
          var y = b.cells[col].getAttribute('data-v') || b.cells[col].textContent.trim().toLowerCase();
          if (numeric) { x = parseFloat(x) || 0; y = parseFloat(y) || 0; }
          var r = x < y ? -1 : (x > y ? 1 : 0);
          return sortAsc ? r : -r;
        });
        rows.forEach(function (r) { tbody.appendChild(r); });
        Array.prototype.forEach.call(headers, function (h) {
          h.textContent = h.textContent.replace(/ [▲▼]$/, '');
        });
        th.textContent = th.textContent + (sortAsc ? ' ▲' : ' ▼');
      });
    });
  })();
'@

    $FooterDate = (Get-Date).ToString('dd MMM yyyy HH:mm', $Inv)
    $Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shadow-Traffic - $Timestamp</title>
<style>
$Css
</style>
</head>
<body>
<header>
  <div class="titlerow">
    <div class="title-text">
      <h1>Shadow-Traffic v$ScriptVersion</h1>
      <div class="logo-sub">by <b>Nephren</b></div>
    </div>
    $LogoSvg
  </div>
  <div class="meta-bar">
    $MetaBarHTML
  </div>
</header>
<div class="container">

$BannerHTML

$ClassBarHTML

$DeltaHTML

$HistoryChartHTML

  <p class="section-title">Summary</p>
  <div class="summary-grid">
    <div class="stat-card score"><div class="num">$Total</div><div class="lbl">Total endpoints</div></div>
    <div class="stat-card fail"><div class="num">$($AnomalyList.Count)</div><div class="lbl">Anomalies</div></div>
    <div class="stat-card ok"><div class="num">$($KnownList.Count)</div><div class="lbl">Known</div></div>
    <div class="stat-card warn"><div class="num">$($UnclassifiedList.Count)</div><div class="lbl">Unclassified</div></div>
    <div class="stat-card info"><div class="num">$($NewList.Count)</div><div class="lbl">New</div></div>
    <div class="stat-card muted"><div class="num">$($Vanished.Count)</div><div class="lbl">Vanished</div></div>
  </div>

  <p class="section-title">Detailed results</p>
  <input type="text" id="searchBox" class="search-box" placeholder="🔎 Search (target, process, source...)">
  <div class="filter-bar">
    <span class="filter-chip active" data-filter="ALL">All</span>
    <span class="filter-chip" data-filter="ANOMALY">Anomalies</span>
    <span class="filter-chip" data-filter="Unclassified">Unclassified</span>
    <span class="filter-chip" data-filter="Known">Known</span>
    <span class="filter-chip" data-filter="NEW">New</span>
  </div>
  <div class="table-wrap">
  <table id="resultsTable">
    <thead>
      <tr>
        <th data-sort="text">Target</th>
        <th data-sort="num">Category</th>
        <th data-sort="text">Process</th>
        <th data-sort="num">Port</th>
        <th data-sort="num">Seen</th>
        <th data-sort="text">Name source</th>
      </tr>
    </thead>
    <tbody>
$($RowsList -join "`n")
    </tbody>
  </table>
  </div>
  <p class="no-results" id="noResults">No result matches this filter.</p>

$VanishedHTML

$SniHTML

</div>
<footer>Report automatically generated by Shadow-Traffic.ps1 v$ScriptVersion — $(ConvertTo-HtmlSafe $Machine) — $FooterDate</footer>
<script>
$Js
</script>
</body>
</html>
"@

    try {
        $Html | Out-File -FilePath $Path -Encoding UTF8 -Force
        Write-Log "HTML export: $Path"
    }
    catch {
        Write-Log "Failed to export HTML: $_" "WARN"
    }
}

# ----------------------------------------------------------------------
# [12] JSON snapshot + CSV exports
# ----------------------------------------------------------------------
function Get-PreviousEndpoints {
    param([string]$Folder)

    try {
        $File = Get-ChildItem -Path $Folder -Filter "Shadow-Traffic_*.json" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch "Unclassified" } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1

        if (-not $File) { return @() }

        $J = Get-Content $File.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($J.Endpoints) { return @($J.Endpoints) }
        return @()
    }
    catch {
        return @()
    }
}

function Get-Vanished {
    param([array]$Previous, [array]$Current)

    $CurrentKeys = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($A in $Current) { [void]$CurrentKeys.Add("$($A.Target)|$($A.ProcessName)") }

    return @($Previous | Where-Object { -not $CurrentKeys.Contains("$($_.Target)|$($_.ProcessName)") })
}

function Remove-OldReports {
    param([string]$Folder, [int]$Days)

    if ($Days -le 0) { return }

    try {
        $Threshold = (Get-Date).AddDays(-$Days)
        # Patterns deliberately prefixed "Shadow-Traffic_": never matches
        # Baseline_Shadow-Traffic.json, which must persist indefinitely.
        $Patterns = @("Shadow-Traffic_*.json", "Shadow-Traffic_*.html", "Shadow-Traffic_*.log", "Shadow-Traffic_Unclassified_*.csv")
        $RemovedCount = 0
        foreach ($Pattern in $Patterns) {
            Get-ChildItem -Path $Folder -Filter $Pattern -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $Threshold } |
                ForEach-Object {
                    Remove-Item $_.FullName -ErrorAction SilentlyContinue
                    $RemovedCount++
                }
        }
        if ($RemovedCount -gt 0) { Write-Log "Purge: $RemovedCount old report(s) removed (older than $Days days)" }
    }
    catch {
        Write-Log "Purge failed: $_" "WARN"
    }
}

function Send-CompletionToast {
    param([string]$Message)

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        $Balloon = New-Object System.Windows.Forms.NotifyIcon
        $Balloon.Icon = [System.Drawing.SystemIcons]::Information
        $Balloon.BalloonTipTitle = "Shadow-Traffic"
        $Balloon.BalloonTipText = $Message
        $Balloon.Visible = $true
        $Balloon.ShowBalloonTip(5000)
        Start-Sleep -Milliseconds 500
        $Balloon.Dispose()
    }
    catch {
        Write-Log "Toast notification failed (non-blocking): $_" "WARN"
    }
}

function Export-Report {
    param([array]$Results, [array]$Vanished, [array]$UnmatchedSNIs = @())

    try {
        # History is read BEFORE this run's own JSON is written: otherwise the
        # current run would be counted twice in the HTML history chart.
        $History = Get-UnclassifiedHistory -Folder $ReportFolder
        $CurrentEndpoints = $Results | Select-Object Target, ProcessName, Category

        $Snapshot = [PSCustomObject]@{
            Timestamp       = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
            WindowSeconds = $DurationSeconds
            TotalEndpoints  = $Results.Count
            Anomalies       = @($Results | Where-Object { $_.Category -like "ANOMALY*" }).Count
            Unclassified      = @($Results | Where-Object { $_.Category -like "Unclassified*" }).Count
            NewOnes        = @($Results | Where-Object { $_.IsNew -eq $true }).Count
            Vanished        = $Vanished.Count
            Endpoints       = $CurrentEndpoints
        }
        $JsonPath = Join-Path $ReportFolder "Shadow-Traffic_$Timestamp.json"
        $Snapshot | ConvertTo-Json -Depth 4 | Out-File $JsonPath -Encoding UTF8 -Force
        Write-Log "JSON export: $JsonPath"

        $CsvPath = Join-Path $ReportFolder "Shadow-Traffic_Unclassified_$Timestamp.csv"
        $Results | Where-Object { $_.Category -like "Unclassified*" -or $_.Category -like "ANOMALY*" } |
            Select-Object @{ N = "Target"; E = { Protect-CsvField $_.Target } }, Category,
                          @{ N = "ProcessName"; E = { Protect-CsvField $_.ProcessName } },
                          PID, Port, Occurrences, IsNew,
                          @{ N = "SNI"; E = { Protect-CsvField $_.SNI } },
                          @{ N = "ASN"; E = { Protect-CsvField $_.ASN } } |
            Export-Csv -Path $CsvPath -Encoding UTF8 -NoTypeInformation -Force
        Write-Log "CSV export: $CsvPath"

        $HtmlPath = Join-Path $ReportFolder "Shadow-Traffic_$Timestamp.html"
        $OsText = try {
            $OsInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            "$($OsInfo.Caption) Build $($OsInfo.BuildNumber)"
        } catch { "" }
        $Meta = @{
            Machine       = $(if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Environment]::MachineName })
            OS            = $OsText
            WindowSeconds = $DurationSeconds
            CaptureSNI    = [bool]$CaptureSNI
            ProcessFilter = $ProcessName
            RefFound      = [bool]$Known.Found
            RefBlocked    = $(if ($Known.Found) { $Known.Blocked.Count } else { 0 })
            RefWhitelist  = $(if ($Known.Found) { $Known.Whitelist.Count } else { 0 })
        }
        Export-HTMLReport -Results $Results -Path $HtmlPath -Vanished $Vanished -UnmatchedSNIs $UnmatchedSNIs -History $History -Meta $Meta

        # Console summary (Write-FinalSummary) lists these after the run.
        $script:ExportedFiles = [ordered]@{
            "HTML report" = $HtmlPath
            "JSON export" = $JsonPath
            "CSV export"  = $CsvPath
            "Log file"    = $LogPath
        }

        Remove-OldReports -Folder $ReportFolder -Days $PurgeDays

        if (-not $NoToast) {
            try {
                $Anomalies = @($Results | Where-Object { $_.Category -like "ANOMALY*" }).Count
                $Unclassified = @($Results | Where-Object { $_.Category -like "Unclassified*" }).Count
                Send-CompletionToast -Message "Audit complete: $Anomalies anomaly(ies), $Unclassified unclassified, $($Vanished.Count) vanished"
            }
            catch {
                # The toast is purely cosmetic: its failure must never be
                # confused with a failure of the real export (JSON/CSV/HTML
                # already written by this point). Observed on this exact
                # case: a System.Windows.Forms TypeInitializationException
                # can escape Send-CompletionToast's internal try/catch
                # depending on the environment — hence this second barrier.
                Write-Log "Toast notification unavailable on this environment (non-blocking): $_" "WARN"
            }
        }
    }
    catch {
        Write-Log "Export failed: $_" "WARN"
    }
}

# ----------------------------------------------------------------------
# [13] SelfTest — classification logic + binary parser on a fixture
# ----------------------------------------------------------------------
function New-ClientHelloTLS {
    param([string]$HostName = "exemple-test.local")

    $HostBytes = [System.Text.Encoding]::ASCII.GetBytes($HostName)

    $NameEntry  = @(0x00) + (ConvertTo-BigEndian16 $HostBytes.Length) + $HostBytes
    $NameList  = (ConvertTo-BigEndian16 $NameEntry.Length) + $NameEntry
    $ExtSNI     = (ConvertTo-BigEndian16 0x0000) + (ConvertTo-BigEndian16 $NameList.Length) + $NameList
    $ExtWithLen = (ConvertTo-BigEndian16 $ExtSNI.Length) + $ExtSNI

    $Random32 = New-Object byte[] 32
    $Body = (ConvertTo-BigEndian16 0x0303) + $Random32 + @(0x00) + (ConvertTo-BigEndian16 2) + @(0x13,0x01) + @(0x01) + @(0x00) + $ExtWithLen

    $Handshake = @(0x01) + (ConvertTo-BigEndian24 $Body.Length) + $Body
    return @(0x16) + (ConvertTo-BigEndian16 0x0301) + (ConvertTo-BigEndian16 $Handshake.Length) + $Handshake
}

function New-EthIPv4TCPFrame {
    param([byte[]]$Payload, [uint32]$Seq = 1000, [int]$PortSrc = 51000, [int]$PortDst = 443)

    $TCPHeader = (ConvertTo-BigEndian16 $PortSrc) + (ConvertTo-BigEndian16 $PortDst) +
                 @([byte](($Seq -shr 24) -band 0xFF), [byte](($Seq -shr 16) -band 0xFF), [byte](($Seq -shr 8) -band 0xFF), [byte]($Seq -band 0xFF)) +
                 @(0,0,0,0) + @(0x50, 0x18) + (ConvertTo-BigEndian16 0xFFFF) + @(0,0) + @(0,0)

    $TotalIP = 20 + $TCPHeader.Length + $Payload.Length
    $IPHeader = @(0x45, 0x00) + (ConvertTo-BigEndian16 $TotalIP) + @(0,0) + @(0x40,0x00) + @(0x40, 0x06) + @(0,0) + @(192,0,2,1) + @(192,0,2,2)
    $Ethernet = (New-Object byte[] 12) + (ConvertTo-BigEndian16 0x0800)

    return $Ethernet + $IPHeader + $TCPHeader + $Payload
}

function New-EthIPv4UDPFrame {
    param([byte[]]$Payload, [int]$PortSrc = 55000, [int]$PortDst = 443)

    $UDPHeader = (ConvertTo-BigEndian16 $PortSrc) + (ConvertTo-BigEndian16 $PortDst) + (ConvertTo-BigEndian16 (8 + $Payload.Length)) + @(0,0)
    $TotalIP = 20 + $UDPHeader.Length + $Payload.Length
    $IPHeader = @(0x45, 0x00) + (ConvertTo-BigEndian16 $TotalIP) + @(0,0) + @(0x40,0x00) + @(0x40, 0x11) + @(0,0) + @(198,51,100,5) + @(198,51,100,9)
    $Ethernet = (New-Object byte[] 12) + (ConvertTo-BigEndian16 0x0800)

    return $Ethernet + $IPHeader + $UDPHeader + $Payload
}

function New-TestPcapng {
    # [PowerShell pitfall discovered while testing] @() does NOT wrap an
    # ALREADY-an-array value: @($OneSingleFrame) FLATTENS it into its
    # individual bytes rather than creating a 1-element container (only the
    # comma operator `,$X` does real wrapping). To avoid depending on this
    # subtlety at every call site, this parameter is typed as
    # List[byte[]] — the only type that behaves correctly with 1 AND with
    # several elements, explicitly tested both ways before writing this
    # function this way.
    param([System.Collections.Generic.List[byte[]]]$Frames)

    $Blocks = New-Object System.Collections.Generic.List[byte]

    # Section Header Block
    $ShbBody = @(0x4D,0x3C,0x2B,0x1A) + (ConvertTo-BigEndian16 1)[1,0] + (ConvertTo-BigEndian16 0)[1,0] + (New-Object byte[] 8)
    $ShbLen  = 12 + $ShbBody.Length
    $Blocks.AddRange([byte[]]((ConvertTo-BigEndian32LE 0x0A0D0D0A) + (ConvertTo-BigEndian32LE $ShbLen) + $ShbBody + (ConvertTo-BigEndian32LE $ShbLen)))

    # Interface Description Block (LinkType=1 Ethernet)
    $IdbBody = @(0x01,0x00) + @(0x00,0x00) + @(0,0,0,0)
    $IdbLen  = 12 + $IdbBody.Length
    $Blocks.AddRange([byte[]]((ConvertTo-BigEndian32LE 0x00000001) + (ConvertTo-BigEndian32LE $IdbLen) + $IdbBody + (ConvertTo-BigEndian32LE $IdbLen)))

    foreach ($Frame in $Frames) {
        $Len = $Frame.Length
        $Pad = (4 - ($Len % 4)) % 4
        $DataPad = $Frame + (New-Object byte[] $Pad)
        $EpbBody = (New-Object byte[] 4) + (New-Object byte[] 4) + (New-Object byte[] 4) + (ConvertTo-BigEndian32LE $Len) + (ConvertTo-BigEndian32LE $Len) + $DataPad
        $EpbLen = 12 + $EpbBody.Length
        $Blocks.AddRange([byte[]]((ConvertTo-BigEndian32LE 0x00000006) + (ConvertTo-BigEndian32LE $EpbLen) + $EpbBody + (ConvertTo-BigEndian32LE $EpbLen)))
    }

    return $Blocks.ToArray()
}

function ConvertTo-BigEndian32LE {
    # pcapng is natively little-endian (indicated by its magic number): here
    # we write a UInt32 in LITTLE-endian, hence a name that may look
    # contradictory next to ConvertTo-BigEndian16/24 (those serve TLS
    # content, which is ALWAYS network big-endian — two different
    # standards, each in its own place).
    param([uint32]$Value)
    return @([byte]($Value -band 0xFF), [byte](($Value -shr 8) -band 0xFF), [byte](($Value -shr 16) -band 0xFF), [byte](($Value -shr 24) -band 0xFF))
}

function New-TestFrameWithSNI {
    param([string]$HostName = "exemple-test.local", [int]$PortDst = 443)
    return New-EthIPv4TCPFrame -Payload (New-ClientHelloTLS -HostName $HostName) -Seq 1000 -PortSrc 54321 -PortDst $PortDst
}

function Invoke-SelfTest {
    $Script:PassCount = 0
    $Script:FailCount = 0

    function Assert-True {
        param($Name, $Cond)
        if ($Cond) { Write-Host "  [PASS] $Name" -ForegroundColor Green; $Script:PassCount++ }
        else       { Write-Host "  [FAIL] $Name" -ForegroundColor Red;   $Script:FailCount++ }
    }

    Assert-True "Private IP 192.168.x detected"       (Test-IsPrivateOrLocalIP "192.168.1.10")
    Assert-True "Private IP 10.x detected"            (Test-IsPrivateOrLocalIP "10.0.0.5")
    Assert-True "Private IP 172.16-31.x detected"     (Test-IsPrivateOrLocalIP "172.20.0.1")
    Assert-True "IPv6 ULA fc00::/7 detected"          (Test-IsPrivateOrLocalIP "fd12:3456::1")
    Assert-True "Loopback detected"                    (Test-IsPrivateOrLocalIP "127.0.0.1")
    Assert-True "Public IP recognized as external"  (-not (Test-IsPrivateOrLocalIP "8.8.8.8"))

    $BlockedTest   = [System.Collections.Generic.HashSet[string]]::new()
    $WhitelistTest = [System.Collections.Generic.HashSet[string]]::new()
    [void]$BlockedTest.Add("gfe.nvidia.com")
    [void]$WhitelistTest.Add("nextdns.io")

    $Fake = @([PSCustomObject]@{ ReverseName = "telemetry.gfe.nvidia.com"; SNI = $null; IP = "1.2.3.4"; Port = 443; ProcessName = "test"; PID = 1; Occurrences = 1 })
    $Classified = @(Group-AndClassify -Connections $Fake -Blocked $BlockedTest -Whitelist $WhitelistTest)
    Assert-True "Subdomain of a BLOCKED domain flagged ANOMALY" ($Classified[0].Category -like "ANOMALY*")

    $FakeUnknown = @([PSCustomObject]@{ ReverseName = "cdn.unknown-example.com"; SNI = $null; IP = "5.6.7.8"; Port = 443; ProcessName = "test"; PID = 2; Occurrences = 1 })
    $ClassifiedUnknown = @(Group-AndClassify -Connections $FakeUnknown -Blocked $BlockedTest -Whitelist $WhitelistTest)
    Assert-True "Unknown domain flagged Unclassified" ($ClassifiedUnknown[0].Category -like "Unclassified*")

    $FakeWhitelist = @([PSCustomObject]@{ ReverseName = "dns.nextdns.io"; SNI = $null; IP = "9.9.9.9"; Port = 443; ProcessName = "test"; PID = 3; Occurrences = 1 })
    $ClassifiedWhitelist = @(Group-AndClassify -Connections $FakeWhitelist -Blocked $BlockedTest -Whitelist $WhitelistTest)
    Assert-True "WHITELISTED domain flagged Known, never ANOMALY" ($ClassifiedWhitelist[0].Category -like "Known*" -and $ClassifiedWhitelist[0].Category -notlike "ANOMALY*")

    # --- Binary parser on a hand-built TLS fixture ---
    $Frame = New-TestFrameWithSNI -HostName "example-test.local" -PortDst 443
    $Layer = ConvertFrom-NetworkLayer -Packet $Frame
    Assert-True "Parser recognizes Ethernet/IPv4/TCP (fixture)" ($null -ne $Layer)
    if ($Layer) {
        Assert-True "Correct destination IP (fixture)"   ($Layer.DstIP -eq "192.0.2.2")
        Assert-True "Correct destination port (fixture)"  ($Layer.DstPort -eq 443)
        $ExtractedSNI = Get-SNIFromClientHello -Packet $Layer.Packet -Offset $Layer.PayloadOffset
        Assert-True "SNI correctly extracted from fixture" ($ExtractedSNI -eq "example-test.local")
    }

    # --- Fixture with no Ethernet header (direct IP fallback) ---
    $FrameWithoutEth = (New-TestFrameWithSNI -HostName "no-ethernet.local" -PortDst 8443) | Select-Object -Skip 14
    $FallbackLayer = ConvertFrom-NetworkLayer -Packet $FrameWithoutEth
    Assert-True "Fallback without Ethernet works (fixture)" ($null -ne $FallbackLayer -and $FallbackLayer.DstPort -eq 8443)

    # --- TCP reassembly: ClientHello split into 2 segments (real pcapng) ---
    $PcapTestPath = Join-Path $env:TEMP "SelfTest_Reassembly_$Timestamp.pcapng"
    try {
        $ClientHelloTest = New-ClientHelloTLS -HostName "test-reassembly.example.com"
        $HalfA = $ClientHelloTest[0..39]
        $HalfB = $ClientHelloTest[40..($ClientHelloTest.Length - 1)]
        $SegmentA = New-EthIPv4TCPFrame -Payload $HalfA -Seq 5000
        $SegmentB = New-EthIPv4TCPFrame -Payload $HalfB -Seq (5000 + $HalfA.Length)

        $SegmentList = [System.Collections.Generic.List[byte[]]]::new()
        $SegmentList.Add($SegmentA); $SegmentList.Add($SegmentB)
        [System.IO.File]::WriteAllBytes($PcapTestPath, (New-TestPcapng -Frames $SegmentList))

        # Parser diagnostics are console noise inside the SelfTest: mute them here.
        $PrevSilent = $Silent
        $script:Silent = [System.Management.Automation.SwitchParameter]$true
        try { $ReassembledSNIs = @(Get-SNIFromPackets -PcapPath $PcapTestPath) }
        finally { $script:Silent = $PrevSilent }
        Assert-True "Fragmented ClientHello reassembled (2 segments)" ($ReassembledSNIs.Count -eq 1 -and $ReassembledSNIs[0].SNI -eq "test-reassembly.example.com")
    }
    finally {
        Remove-Item $PcapTestPath -ErrorAction SilentlyContinue
    }

    # --- UDP/QUIC detection (counted, not decoded) ---
    $UDPFrame = New-EthIPv4UDPFrame -Payload ([byte[]](0xC0, 0x00, 0x00, 0x00)) -PortDst 443
    $UDPLayer = ConvertFrom-NetworkLayer -Packet $UDPFrame
    Assert-True "UDP:443 packet identified as such (Protocol=17)" ($null -ne $UDPLayer -and $UDPLayer.Protocol -eq 17 -and $UDPLayer.DstPort -eq 443)

    # --- Regression test: real truncated Windows/Edge ClientHello (445
    #     bytes declared, only 438 captured) that uncovered the premature
    #     rejection-on-declared-length bug. SNI expected despite the truncation.
    $RealClientHelloHex = "16 03 01 01 bd 01 00 01 b9 03 03 87 d9 ea 66 aa a0 4f 75 18 1e e5 96 96 99 27 da 0e cb 3d 46 33 99 95 9c 5b 08 39 97 e0 b7 73 8b 20 a2 d3 62 48 10 d1 3b 6b a8 73 25 21 c3 12 ea 02 c4 c4 5e 6b 95 77 38 63 90 70 1b 32 db 86 35 76 00 26 c0 2b c0 2f c0 2c c0 30 cc a9 cc a8 c0 09 c0 13 c0 0a c0 14 00 9c 00 9d 00 2f 00 35 c0 12 00 0a 13 01 13 02 13 03 01 00 01 4a 00 00 00 1b 00 19 00 00 16 77 69 6e 64 6f 77 73 2e 64 6e 73 2e 6e 65 78 74 64 6e 73 2e 69 6f 00 05 00 05 01 00 00 00 00 00 0a 00 0a 00 08 00 1d 00 17 00 18 00 19 00 0b 00 02 01 00 00 23 00 00 00 0d 00 1a 00 18 08 04 04 03 08 07 08 05 08 06 04 01 05 01 06 01 05 03 06 03 02 01 02 03 ff 01 00 01 00 00 10 00 0e 00 0c 02 68 32 08 68 74 74 70 2f 31 2e 31 00 12 00 00 00 2b 00 05 04 03 04 03 03 00 33 00 26 00 24 00 1d 00 20 0f 2a 36 b3 15 8a a7 e0 5e 66 23 c2 80 8c 00 a0 0f 4e a8 4d 3e 9d 33 bf 2e 45 82 3d 92 40 1a 3e 00 2d 00 02 01 01 00 29 00 94 00 6f 00 69 c5 b9 d7 c3 e1 26 a1 e9 3b 14 21 1b fb c7 bc 4c 2c fc d5 15 55 44 0e ec e9 aa c3 b0 7a d0 24 90 7c 88 f4 e3 a9 a5 d8 54 1e 57 69 76 cd fa 38 96 68 96 c4 22 b0 89 9f 15 67 75 2b ee db fe f7 ba fc 73 dc 82 19 3b 76 bd 8f 0a 65 11 37 b1 90 e2 d6 df ce bb 7b 32 79 3b 2f cf 54 4e 97 7e 78 e3 31 02 0d 56 88 50 9f 03 e6 6c 38 dc a0 00 21 20 ef bd 68 06 b1 1e 58 9b aa 2a 03 79 2b 7e 85 5c 5c 1c b5 78"
    $RealBytes = [byte[]](($RealClientHelloHex -split '\s+') | Where-Object { $_ -ne "" } | ForEach-Object { [Convert]::ToByte($_, 16) })
    $RealSNI = Get-SNIFromClientHello -Packet $RealBytes -Offset 0
    Assert-True "Truncated real ClientHello (445 declared/438 captured) still yields the SNI" ($RealSNI -eq "windows.dns.nextdns.io")

    # --- Cymru query construction (ASN): known test vectors ---
    Assert-True "Correct IPv4 Cymru query" ((Get-CymruQuery "1.2.3.4") -eq "4.3.2.1.origin.asn.cymru.com")
    Assert-True "Correct IPv6 Cymru query" ((Get-CymruQuery "2600:1f18:2e6a:f800:a610:fb83:4690:65ae") -eq "e.a.5.6.0.9.6.4.3.8.b.f.0.1.6.a.0.0.8.f.a.6.e.2.8.1.f.1.0.0.6.2.origin6.asn.cymru.com")

    # --- Baseline round-trip (temp file, cleaned up after the test) ---
    $BaselineTestPath = Join-Path $env:TEMP "SelfTest_Baseline_$Timestamp.json"
    try {
        $EmptyBaseline = @{}
        $FakeEndpoint = @([PSCustomObject]@{ Target = "test.example.com"; ProcessName = "test"; IP = "1.1.1.1"; Port = 443; Occurrences = 1; Category = "Unclassified (test)" })
        $R1 = @(Update-AndSaveBaseline -Results $FakeEndpoint -Baseline $EmptyBaseline -Path $BaselineTestPath)
        Assert-True "First pass flagged NEW" ($R1[0].IsNew -eq $true)

        $ReloadedBaseline = Import-Baseline -Path $BaselineTestPath
        $FakeEndpoint2 = @([PSCustomObject]@{ Target = "test.example.com"; ProcessName = "test"; IP = "1.1.1.1"; Port = 443; Occurrences = 1; Category = "Unclassified (test)" })
        $R2 = @(Update-AndSaveBaseline -Results $FakeEndpoint2 -Baseline $ReloadedBaseline -Path $BaselineTestPath)
        Assert-True "Second pass is no longer NEW" ($R2[0].IsNew -eq $false)
    }
    finally {
        Remove-Item $BaselineTestPath -ErrorAction SilentlyContinue
    }

    # --- Output safety: untrusted network data ---------------------------
    $EvilName = '<img src=x onerror=alert(1)>.evil.com'
    $Encoded  = ConvertTo-HtmlSafe $EvilName
    Assert-True "HTML encoding neutralizes markup in names" ($Encoded -notmatch '<' -and $Encoded -match '&lt;img')
    Assert-True "Hostname validation accepts normal names" ((Test-ValidHostname "example-test.local") -and (Test-ValidHostname "xn--bcher-kva.example") -and (Test-ValidHostname "a_b.example.com"))
    Assert-True "Hostname validation rejects markup / spaces / empty" (-not (Test-ValidHostname $EvilName) -and -not (Test-ValidHostname "a b.com") -and -not (Test-ValidHostname ""))
    $EvilFrame = New-TestFrameWithSNI -HostName "<img src=x onerror=alert(1)>" -PortDst 443
    $EvilLayer = ConvertFrom-NetworkLayer -Packet $EvilFrame
    Assert-True "Parser discards a ClientHello whose SNI contains markup" ($EvilLayer -and ($null -eq (Get-SNIFromClientHello -Packet $EvilLayer.Packet -Offset $EvilLayer.PayloadOffset)))
    Assert-True "CSV protection prefixes formula-like values only" ((Protect-CsvField "=HYPERLINK(""x"")") -eq "'=HYPERLINK(""x"")" -and (Protect-CsvField "@cmd") -eq "'@cmd" -and (Protect-CsvField "normal.example.com") -eq "normal.example.com")
    Assert-True "ASN shortened for the console, AS number kept" ((Get-AsnShortName "MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US (AS8075)") -eq "Microsoft Corporation, US (AS8075)" -and (Get-AsnShortName "Example Corp (AS64500)") -eq "Example Corp (AS64500)")
    $LongAsn = Get-AsnShortName ("HANDLE - " + ("A" * 80) + " (AS12345)")
    Assert-True "Long ASN name shortened but AS number never cut" ($LongAsn.Length -le 60 -and $LongAsn.EndsWith("(AS12345)"))
    Assert-True "Control characters stripped from console text" ((Limit-Text ("a" + [char]27 + "[31mb") 20) -eq "a[31mb")

    $HtmlTestPath = Join-Path $env:TEMP "SelfTest_Report_$Timestamp.html"
    try {
        $EvilResults = @([PSCustomObject]@{ Target = $EvilName; Category = "Unclassified (test)"; IsNew = $true; SNI = $EvilName; ReverseName = $null; ASN = $null; ProcessName = "<b>x</b>"; PID = 4; Port = 443; Occurrences = 2; IP = "1.2.3.4" })
        $EvilVanished = @([PSCustomObject]@{ Target = "<script>alert(2)</script>"; ProcessName = "gone"; Category = "Known (test)" })
        Export-HTMLReport -Results $EvilResults -Path $HtmlTestPath -Vanished $EvilVanished -UnmatchedSNIs $null -History @(1, 2) -Meta @{ RefFound = $true; RefBlocked = 3; RefWhitelist = 1; WindowSeconds = 10 }
        $HtmlText = if (Test-Path $HtmlTestPath) { Get-Content $HtmlTestPath -Raw -Encoding UTF8 } else { "" }
        Assert-True "HTML report generated with the Check-Security layout and logo" ($HtmlText -match 'Shadow-Traffic v' -and $HtmlText -match '<svg xmlns' -and $HtmlText -match 'summary-grid' -and $HtmlText -match 'id="resultsTable"')
        Assert-True "HTML report contains no unescaped network data" ($HtmlText -notmatch '<img src=x' -and $HtmlText -notmatch '<script>alert' -and $HtmlText -notmatch '<b>x</b>' -and $HtmlText -match '&lt;img src=x')
        Assert-True "HTML report lists vanished endpoints" ($HtmlText -match 'Vanished since the last run' -and $HtmlText -match '&lt;script&gt;alert\(2\)')
        Assert-True "HTML report omits the SNI table when there is no unmatched SNI" ($HtmlText -notmatch 'SNI captured with no matching')
    }
    finally {
        Remove-Item $HtmlTestPath -ErrorAction SilentlyContinue
    }

    $AllOK = ($Script:FailCount -eq 0)
    $Color = if ($AllOK) { "Green" } else { "Red" }
    $Icon  = if ($AllOK) { "✓" } else { "✗" }
    Write-Host ""
    Write-Host ("═" * 58) -ForegroundColor DarkCyan
    Write-Host "  $Icon  SelfTest: $Script:PassCount PASS · $Script:FailCount FAIL" -ForegroundColor $Color
    Write-Host ("═" * 58) -ForegroundColor DarkCyan
    Write-Host ""
}

# ----------------------------------------------------------------------
# MAIN EXECUTION
# ----------------------------------------------------------------------
if ($SelfTest) {
    Write-Header "SELFTEST — Shadow-Traffic v$ScriptVersion"
    Invoke-SelfTest
    return
}

if (-not $BlockTelemetryPath) {
    # [Fix v2.2.3] Was still defaulting to "Block-Telemetry_v5_2.ps1" — the
    # script's old, pre-translation filename. Block-Telemetry was renamed to
    # "Block-Telemetry.ps1" (no version suffix) during its own v5.3
    # translation, but this script's auto-detect default was never updated
    # to match, so auto-detection silently failed even when both scripts
    # sat side by side in the same folder. Reported live: -BlockTelemetryPath
    # passed explicitly worked fine, confirming the lookup logic itself was
    # never the problem — only this stale default filename was.
    $BlockTelemetryPath = Join-Path $PSScriptRoot "Block-Telemetry.ps1"
}

if (-not $Silent) { Write-Header "SHADOW-TRAFFIC — v$ScriptVersion" }
Write-Log "Starting: Duration=$DurationSeconds IncludeLocal=$IncludeLocal SkipSlowChecks=$SkipSlowChecks CaptureSNI=$CaptureSNI ProcessName=$ProcessName"

$Known = Get-KnownDomainsFromSuite -Path $BlockTelemetryPath
if (-not $Silent) {
    Write-Host ""
    if ($Known.Found) {
        Write-ConsoleLine -Level "OK" -Category "Reference" -Check "Block-Telemetry" -Value "$($Known.Blocked.Count) blocked domains  ·  $($Known.Whitelist.Count) whitelisted"
    } else {
        Write-ConsoleLine -Level "WARN" -Category "Reference" -Check "Block-Telemetry not found — everything will show as 'Unclassified'" -Items @(
            "Use -BlockTelemetryPath to point to the exact path"
        )
    }
}

# Unified capture: pktmon starts BEFORE the TCP loop and stops AFTER it,
# over the same window — so both see the same connections.
$CurrentEtlPath = $null
if ($CaptureSNI) { $CurrentEtlPath = Start-CaptureSNI -TempFolder $TempCapture }

$Results = @(Get-ConnectionCapture -DurationSeconds $DurationSeconds -Local $IncludeLocal.IsPresent -FastOnly $SkipSlowChecks.IsPresent -ProcessFilter $ProcessName)

$SNIs = @()
if ($CaptureSNI) { $SNIs = Stop-CaptureSNI -EtlPath $CurrentEtlPath }

$Results = @(Join-SNIIntoConnections -Connections $Results -SNIs $SNIs)
$UnmatchedSNIs = if ($SNIs.Count -gt 0) { @(Get-UnmatchedSNIs -SNIs $SNIs -Connections $Results) } else { @() }

if (-not $SkipSlowChecks) {
    foreach ($R in $Results) {
        if (-not $R.SNI -and -not $R.ReverseName) {
            $R.ASN = Resolve-ASNViaDNS -IP $R.IP
        }
    }
}

$Results = @(Group-AndClassify -Connections $Results -Blocked $Known.Blocked -Whitelist $Known.Whitelist)

$Baseline = Import-Baseline -Path $BaselinePath
$Results = @(Update-AndSaveBaseline -Results $Results -Baseline $Baseline -Path $BaselinePath)

$PreviousEndpoints = Get-PreviousEndpoints -Folder $ReportFolder
$Vanished = Get-Vanished -Previous $PreviousEndpoints -Current ($Results | Select-Object Target, ProcessName, Category)

# One-line summary in the log, so a run can be reviewed from the log alone.
$LogAnomalies = @($Results | Where-Object { $_.Category -like "ANOMALY*" }).Count
$LogKnown     = @($Results | Where-Object { $_.Category -like "Known*" }).Count
$LogUnclass   = @($Results | Where-Object { $_.Category -like "Unclassified*" }).Count
$LogNew       = @($Results | Where-Object { $_.IsNew -eq $true }).Count
# @($null).Count is 1 in PowerShell: drop nulls before counting.
$LogVanished  = @($Vanished | Where-Object { $null -ne $_ }).Count
Write-Log "Summary: $(@($Results).Count) endpoints: $LogAnomalies anomalies, $LogKnown known, $LogUnclass unclassified, $LogNew new, $LogVanished vanished"

if (-not $Silent) { Write-ConsoleReport -Results $Results -UnmatchedSNIs $UnmatchedSNIs -Vanished $Vanished }
Export-Report -Results $Results -Vanished $Vanished -UnmatchedSNIs $UnmatchedSNIs

Write-Log "Run finished"

if (-not $Silent) {
    Write-FinalSummary

    $FinalHtmlPath = Join-Path $ReportFolder "Shadow-Traffic_$Timestamp.html"
    if (Test-Path $FinalHtmlPath) {
        $OpenAnswer = Read-Host "  Open the HTML report in your browser? [Y/n]"
        if ($OpenAnswer -eq '' -or $OpenAnswer -match '^[Yy]') { Start-Process $FinalHtmlPath }
    }

    Write-EnterPrompt
    Read-Host | Out-Null
}

# SIG # Begin signature block
# MIIFwgYJKoZIhvcNAQcCoIIFszCCBa8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCoTEeIVopAda0J
# X4kyHqQjYR/xSDSUXREZGYZsUtG6QqCCAygwggMkMIICDKADAgECAhB6X4r8AlBU
# p0MV3JpMuQ6sMA0GCSqGSIb3DQEBCwUAMCoxKDAmBgNVBAMMH05lcGhyZW4gUG93
# ZXJTaGVsbCBDb2RlIFNpZ25pbmcwHhcNMjYwNzA0MDIzMzIwWhcNMzEwNzA0MDI0
# MzIwWjAqMSgwJgYDVQQDDB9OZXBocmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5n
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JnV5AocUnAMNIG3nYF9
# 5mOQz5NzMYJqc9D6mq3pjRlmuYIgvYEuJL5dvt8eoAiUKd+XHTaY5wl+zt7LUon+
# TmEldVwfrYvROpI+5TDyBRc5BzY4uACsA4JUM4ienjX04BBKT3uH6JwHzBluWqcG
# Xrg16NqzDiae7WNzVrev+BME00mgSvBo3hKp3sHIvFQaAmjGXLyJd+llfnBpmoD9
# JnOxMKO7VFIlhAz5cEUnFu/xDLHgARdBUfXA5odScWKiDvygNZsH1vHo07Oo7pDK
# awR3bT6lcXWRXSUmawgE1mZra+b9qpeNol+5J+86zN83RccBKZBUtQQoyy+cv20x
# VQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# HQYDVR0OBBYEFNxVaDYoNv8UXQWnbtEy/DTaQHjYMA0GCSqGSIb3DQEBCwUAA4IB
# AQCE4NqZbeximmbNEORyLxvIYiMQwP59B9R95blQQ/zugPSt4wab61yBbgO1E3mH
# mUdN0fCHhN/u0uB7h7ZBYw1w4hnzoiBac4UYzsXH4/D41gBjutbtDllRy6/zs3dl
# /hbbHAmwKXdjNVLG9cPkpWlkvKR1DJLMugU2uj+S6k+U7DfHo76sbAKqiu3biXtd
# mao6PP99EU7JBYZjsJ+BsnYcZ2KcnZ8TKiRuhSXoxAyPman7Z0BVo1H2O+fxd96b
# 4W8VclmpFh7T2CyRAHolwEy5coFYyueisO0PZg+nKwXr66+m1T1CBLQYwh79/SKO
# wGUJyU5RtTryD+hfLwkTQKVCMYIB8DCCAewCAQEwPjAqMSgwJgYDVQQDDB9OZXBo
# cmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5nAhB6X4r8AlBUp0MV3JpMuQ6sMA0G
# CWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEIFd+1gJ1cu7EHp9zls9OvY/PcmQKMH7+VYkGriu3
# yQS5MA0GCSqGSIb3DQEBAQUABIIBAMdVBjkuOkKpLa+xsPfWF3jhAY/DmCCyU21G
# uEh28S+JzG7OeufYjrEb6SK1r5tkBtcrc8g5zLPzdSj/ZwMwGQnBy/aB76cZ28Ta
# LmRg6m9qR65wPbQvAAvTWkO20e/Xtgm7v872Z+Lw5iJGMUevJ0WZx5lHPbC7WPAs
# aXelkNL6Qk8Q0/FciwOwFKOHSqMWwofmsC2MF8po/kWZgxGuPC/2Fr7F6AFzsLDV
# qo+Hu5Z/+alLqTMTZ/ldz7O8yMBxgQlPbuV/IXsnuZP/WwM7AzJ8/UoMZTUXVMNT
# uJ2SYCrDkG38PESarb7uldnwP1UWi64s2Q7rXBX48hton8tiQE4=
# SIG # End signature block
