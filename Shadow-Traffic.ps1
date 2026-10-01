<#
============================================================================
 Shadow-Traffic.ps1  —  v2.2.4
============================================================================
 PURPOSE
   Complements Block-Telemetry by answering a different question:
   "what is actually leaving this machine right now?"

   Block-Telemetry acts at the DNS level (hosts file). This script acts at
   the network level (real TCP connections + low-level TLS parser),
   including bypasses that evade classic DNS (hardcoded IP, DoH —
   documented in particular for the NVIDIA App).

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

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "  $('-' * $Text.Length)" -ForegroundColor DarkCyan
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
                    return [System.Text.Encoding]::ASCII.GetString($Packet, $P, $NameLen).ToLowerInvariant()
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
        Write-Host "  SNI diagnostic: $TotalPacketCount packets / $RecognizedLayerCount TCP / $TLSHandshakeCount TLS handshakes / $ClientHelloCount ClientHello / $WithSNICount direct SNI / $WithSNIReassembledCount via reassembly" -ForegroundColor DarkGray
        if ($QUICCount -gt 0) {
            Write-Host "  $QUICCount QUIC packets (UDP:443) seen, not decoded — partial coverage if traffic uses HTTP/3" -ForegroundColor Yellow
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
        if (-not $Silent) { Write-Host "  [WARN] pktmon not found — SNI capture skipped" -ForegroundColor Yellow }
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
            if (-not $Silent) { Write-Host "  [WARN] pktmon failed to start — SNI capture skipped" -ForegroundColor Yellow }
            return $null
        }
        Write-Log "pktmon capture started (port 443), running alongside the TCP window"
        return $EtlPath
    }
    catch {
        Write-Log "Failed to start pktmon (admin rights required): $_" "WARN"
        if (-not $Silent) { Write-Host "  [WARN] pktmon failed — re-run as administrator" -ForegroundColor Yellow }
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
            Write-Host "`r  Capturing... $Elapsed / $DurationSeconds s — $($Seen.Count) distinct endpoints seen" -NoNewline -ForegroundColor DarkGray
        }

        Start-Sleep -Seconds $IntervalSeconds
    } while (((Get-Date) - $StartTime).TotalSeconds -lt $DurationSeconds)

    if (-not $Silent) { Write-Host "" }
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
    Write-Host "  Distinct endpoints observed : $($Results.Count)"
    Write-Host "  Anomalies (blocked but reachable) : $($Anomalies.Count)" -ForegroundColor $(if ($Anomalies.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "  Known (whitelist, normal)         : $($Known.Count)" -ForegroundColor DarkGray
    Write-Host "  Unclassified to review            : $($Unclassified.Count)" -ForegroundColor Yellow
    Write-Host "  Never seen before (new)           : $($NewOnes.Count)" -ForegroundColor $(if ($NewOnes.Count -gt 0) { "Magenta" } else { "DarkGray" })
    Write-Host "  Vanished since last run            : $($Vanished.Count)" -ForegroundColor DarkGray

    if ($Anomalies.Count -gt 0) {
        Write-Header "ANOMALIES — review first"
        foreach ($A in $Anomalies) {
            Write-Host "  [!] $($A.Target)  <-  $($A.ProcessName) (PID $($A.PID))  x$($A.Occurrences)" -ForegroundColor Red
        }
    }

    Write-Header "UNCLASSIFIED (sorted by frequency)"
    foreach ($N in $Unclassified) {
        $Marker = if ($N.IsNew) { "[NEW] " } else { "" }
        $Source   = if ($N.SNI) { "(SNI: $($N.SNI))" }
                    elseif ($N.ReverseName) { "(PTR)" }
                    elseif ($N.ASN) { "($($N.ASN))" }
                    else { "(no name)" }
        $Color  = if ($N.IsNew) { "Magenta" } elseif ($N.Occurrences -ge 5) { "White" } else { "DarkGray" }
        Write-Host "  $Marker$($N.Target)  <-  $($N.ProcessName) (PID $($N.PID))  x$($N.Occurrences)  $Source" -ForegroundColor $Color
    }

    if ($Vanished.Count -gt 0) {
        Write-Header "VANISHED SINCE LAST RUN"
        Write-Host "  Present in the previous run, absent this time — not necessarily abnormal (one-off connection)" -ForegroundColor DarkGray
        foreach ($D in $Vanished) {
            Write-Host "  $($D.Target)  <-  $($D.ProcessName)" -ForegroundColor DarkGray
        }
    }

    if ($UnmatchedSNIs -and @($UnmatchedSNIs).Count -gt 0) {
        Write-Header "SNI CAPTURED WITH NO MATCHING TCP CONNECTION"
        Write-Host "  Likely: connection too short to appear in the TCP sampling" -ForegroundColor DarkGray
        foreach ($S in $UnmatchedSNIs) {
            Write-Host "  $($S.SNI)  ->  $($S.DstIP):$($S.DstPort)" -ForegroundColor Cyan
        }
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
    param([array]$Results, [string]$Path, [int]$VanishedCount = 0, [array]$History = @())

    $Rows = foreach ($R in $Results) {
        $RowColor = switch -Wildcard ($R.Category) {
            "ANOMALY*" { "#ff4d4d" }
            "Known*"    { "#5c6773" }
            default     { "#e8b64c" }
        }
        $Badge  = if ($R.IsNew) { '<span class="badge-new">NEW</span>' } else { "" }
        $Source = if ($R.SNI) { "SNI: $($R.SNI)" } elseif ($R.ReverseName) { "PTR" } elseif ($R.ASN) { $R.ASN } else { "Raw IP" }
        $CategoryAttr = ($R.Category -replace '"', '')
        $SearchText = ("$($R.Target) $($R.ProcessName) $Source").ToLowerInvariant() -replace '"', ''
@"
        <tr data-cat="$CategoryAttr" data-text="$SearchText">
            <td style="color:$RowColor">$($R.Target) $Badge</td>
            <td>$($R.Category)</td>
            <td>$($R.ProcessName)</td>
            <td>$($R.Port)</td>
            <td>$($R.Occurrences)</td>
            <td>$Source</td>
        </tr>
"@
    }

    $Anomalies = @($Results | Where-Object { $_.Category -like "ANOMALY*" }).Count
    $Unclassified = @($Results | Where-Object { $_.Category -like "Unclassified*" }).Count
    $NewOnes  = @($Results | Where-Object { $_.IsNew -eq $true }).Count

    # --- History sparkline (minimal SVG polyline, no axes/libs) ---
    $SparklineSVG = ""
    $HistoryPoints = @($History) + @($Unclassified)   # includes the current run as the last point
    if ($HistoryPoints.Count -ge 2) {
        $MaxVal = ($HistoryPoints | Measure-Object -Maximum).Maximum
        if ($MaxVal -lt 1) { $MaxVal = 1 }
        $SVGWidth = 200; $SVGHeight = 40
        $Step = $SVGWidth / ($HistoryPoints.Count - 1)
        $Pts = for ($i = 0; $i -lt $HistoryPoints.Count; $i++) {
            $X = [math]::Round($i * $Step, 1)
            $Y = [math]::Round($SVGHeight - (($HistoryPoints[$i] / $MaxVal) * ($SVGHeight - 4)) - 2, 1)
            "$X,$Y"
        }
        $PointsStr = $Pts -join " "
        $SparklineSVG = "<svg viewBox=`"0 0 $SVGWidth $SVGHeight`" width=`"200`" height=`"40`"><polyline points=`"$PointsStr`" fill=`"none`" stroke=`"#e8b64c`" stroke-width=`"2`" /></svg>"
    }

    $Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Shadow-Traffic - $Timestamp</title>
<style>
  body { background:#0a0e17; color:#d8dee9; font-family: Consolas, 'Segoe UI', monospace; margin:0; padding:32px; }
  h1 { color:#e8b64c; font-size:20px; }
  .cards { display:flex; gap:16px; margin:20px 0; flex-wrap:wrap; }
  .card { background: radial-gradient(circle at top left, #131a2a, #0a0e17); border:1px solid #263047; border-radius:8px; padding:16px 24px; min-width:160px; }
  .card .value { font-size:26px; font-weight:bold; }
  .card.red .value { color:#ff4d4d; }
  .card.yellow .value { color:#e8b64c; }
  .card.magenta .value { color:#c678dd; }
  table { width:100%; border-collapse: collapse; margin-top:20px; }
  th, td { text-align:left; padding:8px 12px; border-bottom:1px solid #1c2333; font-size:13px; }
  th { color:#7c8bab; text-transform:uppercase; font-size:11px; letter-spacing:0.05em; }
  .badge-new { background:#c678dd; color:#0a0e17; font-size:10px; padding:2px 6px; border-radius:4px; margin-left:6px; }
  #search { background:#131a2a; color:#d8dee9; border:1px solid #263047; border-radius:6px; padding:8px 12px; width:100%; max-width:400px; margin-top:8px; font-family: inherit; font-size:13px; }
  #search:focus { outline:none; border-color:#e8b64c; }
  #filter { margin:12px 0; }
  #filter button { background:#131a2a; color:#d8dee9; border:1px solid #263047; padding:6px 12px; border-radius:6px; cursor:pointer; margin-right:6px; }
  #filter button.active { border-color:#e8b64c; color:#e8b64c; }
</style>
</head>
<body>
  <h1>Shadow-Traffic — Network Traffic Audit — $Timestamp</h1>
  <div class="cards">
    <div class="card red"><div class="value">$Anomalies</div>Anomalies</div>
    <div class="card yellow"><div class="value">$Unclassified</div>Unclassified</div>
    <div class="card magenta"><div class="value">$NewOnes</div>New</div>
    <div class="card"><div class="value">$VanishedCount</div>Vanished</div>
    <div class="card"><div class="value">$($Results.Count)</div>Total endpoints</div>
    $(if ($SparklineSVG) { "<div class=`"card`"><div style=`"font-size:11px;color:#7c8bab;margin-bottom:6px;`">Unclassified (history)</div>$SparklineSVG</div>" })
  </div>
  <input id="search" type="text" placeholder="Search (target, process...)" oninput="filterByText()">
  <div id="filter">
    <button class="active" onclick="filterByCategory('all', this)">All</button>
    <button onclick="filterByCategory('ANOMALY', this)">Anomalies</button>
    <button onclick="filterByCategory('Unclassified', this)">Unclassified</button>
    <button onclick="filterByCategory('Known', this)">Known</button>
  </div>
  <table>
    <thead><tr><th>Target</th><th>Category</th><th>Process</th><th>Port</th><th>Occurrences</th><th>Name source</th></tr></thead>
    <tbody>
      $($Rows -join "`n")
    </tbody>
  </table>
  <script>
    var activeCat = 'all';
    function filterByCategory(prefix, btn) {
      document.querySelectorAll('#filter button').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      activeCat = prefix;
      applyFilters();
    }
    function filterByText() { applyFilters(); }
    function applyFilters() {
      var text = document.getElementById('search').value.toLowerCase();
      document.querySelectorAll('tbody tr').forEach(function(tr) {
        var cat = tr.getAttribute('data-cat');
        var content = tr.getAttribute('data-text') || '';
        var matchesCat = (activeCat === 'all' || cat.indexOf(activeCat) === 0);
        var matchesText = (text === '' || content.indexOf(text) !== -1);
        tr.style.display = (matchesCat && matchesText) ? '' : 'none';
      });
    }
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
    param([array]$Results, [array]$Vanished)

    try {
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
            Select-Object Target, Category, ProcessName, PID, Port, Occurrences, IsNew, SNI, ASN |
            Export-Csv -Path $CsvPath -Encoding UTF8 -NoTypeInformation -Force
        Write-Log "CSV export: $CsvPath"

        $History = Get-UnclassifiedHistory -Folder $ReportFolder
        $HtmlPath = Join-Path $ReportFolder "Shadow-Traffic_$Timestamp.html"
        Export-HTMLReport -Results $Results -Path $HtmlPath -VanishedCount $Vanished.Count -History $History

        if (-not $Silent) {
            Write-Host ""
            Write-Host "  Reports saved to: $ReportFolder" -ForegroundColor DarkGray
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
        if ($Cond) { Write-Host "  [OK] $Name" -ForegroundColor Green; $Script:PassCount++ }
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

        $ReassembledSNIs = @(Get-SNIFromPackets -PcapPath $PcapTestPath)
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

    Write-Host ""
    Write-Host "  Result: $Script:PassCount passed, $Script:FailCount failed" -ForegroundColor $(if ($Script:FailCount -eq 0) { "Green" } else { "Red" })
}

# ----------------------------------------------------------------------
# MAIN EXECUTION
# ----------------------------------------------------------------------
if ($SelfTest) {
    Write-Header "SELFTEST — Shadow-Traffic v2.2.4"
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

Write-Header "SHADOW-TRAFFIC — v2.2.4"
Write-Log "Starting: Duration=$DurationSeconds IncludeLocal=$IncludeLocal SkipSlowChecks=$SkipSlowChecks CaptureSNI=$CaptureSNI ProcessName=$ProcessName"

$Known = Get-KnownDomainsFromSuite -Path $BlockTelemetryPath
if (-not $Silent) {
    if ($Known.Found) {
        Write-Host "  Reference: $($Known.Blocked.Count) blocked domains, $($Known.Whitelist.Count) whitelisted" -ForegroundColor DarkGray
    } else {
        Write-Host "  [WARN] Block-Telemetry not found — everything will show as 'Unclassified'" -ForegroundColor Yellow
        Write-Host "          Use -BlockTelemetryPath to point to the exact path" -ForegroundColor Yellow
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

if (-not $Silent) { Write-ConsoleReport -Results $Results -UnmatchedSNIs $UnmatchedSNIs -Vanished $Vanished }
Export-Report -Results $Results -Vanished $Vanished

Write-Log "Run finished"

if (-not $Silent) {
    $FinalHtmlPath = Join-Path $ReportFolder "Shadow-Traffic_$Timestamp.html"
    if (Test-Path $FinalHtmlPath) {
        $OpenAnswer = Read-Host "  Open the HTML report in your browser? [Y/n]"
        if ($OpenAnswer -eq '' -or $OpenAnswer -match '^[Yy]') { Start-Process $FinalHtmlPath }
    }

    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  Press ENTER to close this window..." -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Read-Host
}

# SIG # Begin signature block
# MIIFwgYJKoZIhvcNAQcCoIIFszCCBa8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDW21GDa8zh5/Rl
# SiC5IeHVjrmc89+ImFToj4MN9gQDvKCCAygwggMkMIICDKADAgECAhB6X4r8AlBU
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
# ARUwLwYJKoZIhvcNAQkEMSIEINnaXNZBFv8ZdW3jqIPQqDUDbRTFyiUUkggR894/
# 1HQPMA0GCSqGSIb3DQEBAQUABIIBAM32W8nTGGgPZTHiI9rjRGgArusBWG9XXsiB
# uGN8Zd3INyTd0uP/q3lTbPU5p9/n5CGZQrg4AWPz9YkVExvS+b78E9142EhdDWNk
# F8jgdDklmtFHeCltgaAo6nlocrfdDhCPTnNgzWSX1BPwugCe1zDySkNfs/vwRuIl
# TUb+9zDHpI46ydfKeRba3NuUFoBOg5B5QYlXsvUcgG646UD3eXmkmGEzXlAYSzt/
# D0IvwsfvKQH6wBS3Ow8UfeRk2XoEI3hNZk6Ph0bQHjyO3LRE4mEiFNFxeOlmMuXC
# CbkMQM2D0li8KCXI289JzshV6Vu5Co7mcu/iS/tRVR6vMm0PwKY=
# SIG # End signature block
