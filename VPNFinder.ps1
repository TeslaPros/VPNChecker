#Requires -Version 5.1
<#
.SYNOPSIS
    VPN Detector Pro v3.1 - Advanced Network Intelligence Tool
.DESCRIPTION
    Clearly distinguishes between ACTIVE VPN (open tunnel, routed traffic)
    and INSTALLED VPN (software present but not necessarily connected).
    13 independent checks. Total Privacy Mode: no personal data shown.
.NOTES
    Run as Administrator for complete results.
    Set-ExecutionPolicy -Scope Process Bypass
    .\VPN-Detector.ps1
    .\VPN-Detector.ps1 -ExportJSON
#>

[CmdletBinding()]
param(
    [int]$TimeoutSec = 8,
    [switch]$ExportJSON
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# ═══════════════════════════════════════════════════════════════
#  ANSI PALETTE
# ═══════════════════════════════════════════════════════════════
$ESC = [char]27
function ansi($c) { "$ESC[${c}m" }

$C = @{
    Reset    = ansi 0;   Bold    = ansi 1;   Dim     = ansi 2
    Cyan     = ansi '38;5;51';  Green   = ansi '38;5;82';  Red     = ansi '38;5;196'
    Yellow   = ansi '38;5;220'; Orange  = ansi '38;5;208'; Purple  = ansi '38;5;135'
    Magenta  = ansi '38;5;207'; White   = ansi '38;5;255'; Gray    = ansi '38;5;244'
    DkGray   = ansi '38;5;237'; Blue    = ansi '38;5;39'
    BgGreen  = ansi '48;5;22';  BgRed   = ansi '48;5;52';  BgBlue  = ansi '48;5;17'
    BgOrange = ansi '48;5;130'
}

# ═══════════════════════════════════════════════════════════════
#  DATA STRUCTURE — DOUBLE SCORE
#
#  ActiveScore    = evidence that the VPN is TUNNELING TRAFFIC NOW
#                   (adapter Up, active routing, open ports, running process)
#  InstalledScore = evidence that VPN software EXISTS on the system
#                   (installed software, registry keys, drivers, Stopped services)
#
#  The final verdict shows the two states SEPARATELY:
#    "VPN ACTIVE?"    → based on ActiveScore
#    "VPN INSTALLED?" → based on InstalledScore
# ═══════════════════════════════════════════════════════════════
$ActiveScore     = 0
$InstalledScore  = 0
$ActiveEvidence  = [System.Collections.Generic.List[string]]::new()
$PassiveEvidence = [System.Collections.Generic.List[string]]::new()
$AllResults      = [ordered]@{}
$CheckStats      = [ordered]@{}   # values: 'ACTIVE' | 'PASSIVE' | 'NONE'

function Add-Active([string]$msg, [int]$weight = 15) {
    $script:ActiveScore += $weight
    $script:ActiveEvidence.Add($msg)
}
function Add-Passive([string]$msg, [int]$weight = 5) {
    $script:InstalledScore += $weight
    $script:PassiveEvidence.Add($msg)
}

# ═══════════════════════════════════════════════════════════════
#  UI FUNCTIONS
# ═══════════════════════════════════════════════════════════════
function Write-Banner {
    $w = 74; $ln = '=' * $w
    Write-Host ""
    Write-Host "$($C.Cyan)+ $ln +$($C.Reset)"
    Write-Host "$($C.Cyan)|$($C.Reset) $($C.Bold)$($C.White)VPN DETECTOR PRO  $($C.Reset)$($C.Gray).  Advanced Network Intelligence  .  v3.1$(' ' * 12)$($C.Reset)$($C.Cyan)|$($C.Reset)"
    Write-Host "$($C.Cyan)|$($C.Gray)$("  13 Checks  .  Active vs Installed  .  Privacy Mode ON  .  No personal data".PadRight($w))$($C.Reset)$($C.Cyan)|$($C.Reset)"
    Write-Host "$($C.Cyan)+ $ln +$($C.Reset)"
    Write-Host ""
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                [Security.Principal.WindowsBuiltInRole]"Administrator")
    if ($isAdmin) { Write-Host "  $($C.Green)[ADMIN]$($C.Reset)  $($C.Gray)Running as Administrator -- all checks available$($C.Reset)" }
    else          { Write-Host "  $($C.Yellow)[WARN] $($C.Reset)  $($C.Gray)Without admin privileges -- some checks might be limited$($C.Reset)" }
    Write-Host ""
}

function Write-SectionHeader([string]$title, [int]$num = 0, [string]$kind = "") {
    $numStr = if ($num -gt 0) { "$($C.DkGray)[$($C.Purple)$($C.Bold)CHECK $($num.ToString().PadLeft(2))$($C.Reset)$($C.DkGray)]$($C.Reset) " } else { "" }
    $tag    = switch ($kind) {
        'active'   { "  $($C.Red)$($C.Bold)[REAL-TIME ACTIVITY]$($C.Reset)" }
        'passive'  { "  $($C.Yellow)[INSTALLATION TRACES]$($C.Reset)" }
        'both'     { "  $($C.Orange)[ACTIVE + INSTALLATION]$($C.Reset)" }
        default    { "" }
    }
    Write-Host ""
    Write-Host "  $numStr$($C.Purple)$($C.Bold)>  $title$($C.Reset)$tag"
    Write-Host "$($C.DkGray)  $('-' * 68)$($C.Reset)"
}

function Write-CheckLine([string]$label, [string]$result, [string]$detail = "", [string]$status = "info") {
    $icon = switch ($status) {
        "ok"      { "$($C.Green)[OK]   $($C.Reset)" }
        "warn"    { "$($C.Yellow)[!!]   $($C.Reset)" }
        "active"  { "$($C.Red)[ACT]  $($C.Reset)" }   # ACTIVE VPN — open tunnel
        "install" { "$($C.Orange)[INST] $($C.Reset)" } # VPN present but not active
        "info"    { "$($C.Cyan)[i]    $($C.Reset)" }
        "neutral" { "$($C.Gray)[.]    $($C.Reset)" }
        "hidden"  { "$($C.Magenta)[*]    $($C.Reset)" }
        default   { "$($C.Gray)[.]    $($C.Reset)" }
    }
    $pad    = $label.PadRight(38)
    $resStr = if ($result) { "$($C.White)$result$($C.Reset)" } else { "" }
    $detStr = if ($detail) { "  $($C.DkGray)$detail$($C.Reset)" } else { "" }
    Write-Host "   $icon$($C.Gray)$pad$($C.Reset)  $resStr$detStr"
}

function Write-Spinner([string]$text) {
    $frames = '-','\','|','/'
    for ($i = 0; $i -lt 16; $i++) {
        Write-Host -NoNewline "`r  $($C.Cyan)[$($frames[$i % $frames.Count])]$($C.Reset)  $($C.Gray)$text...$($C.Reset)      "
        Start-Sleep -Milliseconds 60
    }
    Write-Host -NoNewline "`r$(' ' * 70)`r"
}

function Invoke-SafeWeb([string]$uri, [int]$timeout = $TimeoutSec) {
    try { return Invoke-RestMethod -Uri $uri -TimeoutSec $timeout -UseBasicParsing -ErrorAction Stop }
    catch { return $null }
}

# ═══════════════════════════════════════════════════════════════
#  VPN DATABASE
# ═══════════════════════════════════════════════════════════════

$KnownVPNProcesses = @(
    @{ N='nordvpn';               L='NordVPN' }
    @{ N='nordvpn-service';       L='NordVPN Service' }
    @{ N='expressvpn';            L='ExpressVPN' }
    @{ N='expressvpnservice';     L='ExpressVPN Service' }
    @{ N='expressvpnd';           L='ExpressVPN Daemon' }
    @{ N='surfshark';             L='Surfshark' }
    @{ N='surfsharkservice';      L='Surfshark Service' }
    @{ N='protonvpn';             L='ProtonVPN' }
    @{ N='protonvpn-service';     L='ProtonVPN Service' }
    @{ N='mullvad';               L='Mullvad VPN' }
    @{ N='mullvad-daemon';        L='Mullvad Daemon' }
    @{ N='mullvad-gui';           L='Mullvad GUI' }
    @{ N='cyberghost';            L='CyberGhost' }
    @{ N='cyberghostservice';     L='CyberGhost Service' }
    @{ N='pia';                   L='Private Internet Access' }
    @{ N='privateinternetaccess'; L='PIA Client' }
    @{ N='csclient';              L='Cisco AnyConnect' }
    @{ N='vpnagent';              L='Cisco AnyConnect Agent' }
    @{ N='vpnui';                 L='Cisco AnyConnect UI' }
    @{ N='openvpn';               L='OpenVPN' }
    @{ N='openvpn-gui';           L='OpenVPN GUI' }
    @{ N='openvpnserv';           L='OpenVPN Service' }
    @{ N='openvpnserv2';          L='OpenVPN Service v2' }
    @{ N='wireguard';             L='WireGuard' }
    @{ N='strongswan';            L='strongSwan' }
    @{ N='charon';                L='strongSwan (charon)' }
    @{ N='fortivpn';              L='FortiClient VPN' }
    @{ N='forticlient';           L='FortiClient' }
    @{ N='pulsesecure';           L='Pulse Secure' }
    @{ N='pulseservice';          L='Pulse Secure Service' }
    @{ N='f5vpn';                 L='F5 VPN' }
    @{ N='f5fpclientw';           L='F5 VPN Client' }
    @{ N='globalprotect';         L='Palo Alto GlobalProtect' }
    @{ N='pangpa';                L='GlobalProtect Agent' }
    @{ N='pangps';                L='GlobalProtect Service' }
    @{ N='softethervpn';          L='SoftEther VPN' }
    @{ N='vpnclient_r';           L='Cisco VPN Client (legacy)' }
    @{ N='cvpnd';                 L='Cisco VPN Daemon' }
    @{ N='hotspotshield';         L='Hotspot Shield' }
    @{ N='anchorfree';            L='Hotspot Shield Service' }
    @{ N='ipvanish';              L='IPVanish' }
    @{ N='ipvanishvpn';           L='IPVanish VPN' }
    @{ N='hidemyass';             L='HideMyAss VPN' }
    @{ N='tunnelbear';            L='TunnelBear' }
    @{ N='windscribe';            L='Windscribe' }
    @{ N='windscribeservice';     L='Windscribe Service' }
    @{ N='vyprvpn';               L='VyprVPN' }
    @{ N='torguard';              L='TorGuard' }
    @{ N='ivpn';                  L='IVPN' }
    @{ N='airvpn';                L='AirVPN (Eddie)' }
    @{ N='eddie-ui';              L='AirVPN Eddie UI' }
    @{ N='perfectprivacy';        L='Perfect Privacy' }
    @{ N='zenmate';               L='ZenMate VPN' }
    @{ N='avast_vpn';             L='Avast SecureLine VPN' }
    @{ N='bitdefendervpn';        L='Bitdefender VPN' }
    @{ N='kasvpn';                L='Kaspersky VPN' }
    @{ N='ksvpnagent';            L='Kaspersky VPN Agent' }
    @{ N='teamviewer_vpn';        L='TeamViewer VPN' }
    @{ N='rasman';                L='Windows RAS Manager' }
    @{ N='tor';                   L='Tor' }
    @{ N='torbrowser';            L='Tor Browser' }
    @{ N='privoxy';               L='Privoxy Proxy' }
    @{ N='proxifier';             L='Proxifier' }
    @{ N='proxycap';              L='ProxyCap' }
    @{ N='zscalertunnel';         L='Zscaler Tunnel' }
    @{ N='zscalerapp';            L='Zscaler App' }
    @{ N='netskopeClient';        L='Netskope Client' }
    @{ N='twingate';              L='Twingate' }
    @{ N='tailscale';             L='Tailscale' }
    @{ N='zerotier';              L='ZeroTier One' }
    @{ N='zerotier-one';          L='ZeroTier One Service' }
    @{ N='warp-svc';              L='Cloudflare WARP' }
    @{ N='cloudflare-warp';       L='Cloudflare WARP Client' }
    @{ N='lantern';               L='Lantern VPN' }
    @{ N='psiphon';               L='Psiphon' }
    @{ N='outline';               L='Outline VPN' }
    @{ N='bitmask';               L='Bitmask (LEAP)' }
    @{ N='i2pd';                  L='I2P Daemon' }
    @{ N='i2p';                   L='I2P' }
    @{ N='shadowsocks';           L='Shadowsocks Proxy' }
    @{ N='v2ray';                 L='V2Ray Proxy' }
    @{ N='xray';                  L='XRay Proxy' }
    @{ N='clash';                 L='Clash Core' }
    @{ N='singbox';               L='sing-box' }
    @{ N='hysteria';              L='Hysteria Proxy' }
    @{ N='privatevpn';            L='PrivateVPN' }
    @{ N='speedify';              L='Speedify VPN' }
    @{ N='hola';                  L='Hola VPN' }
    @{ N='radmin-vpn';            L='Radmin VPN' }
    @{ N='hamachi-2-ui';          L='LogMeIn Hamachi' }
    @{ N='hamachi-2';             L='Hamachi Service' }
)

$VPNAdapterRx = 'vpn|tun[0-9]?|^tap|wintun|wireguard|nordlynx|proton|mullvad|surfshark|' +
                'expressvpn|anyconnect|globalprotect|pulse|fortinet|zerotier|tailscale|' +
                'cisco|^sstp|^pptp|l2tp|ikev2|warp|hamachi|radmin|outline|shadowsocks'

$VPNPortMap = @{
    1194 = 'OpenVPN UDP/TCP';   1195 = 'OpenVPN alt';     51820 = 'WireGuard'
    51821 = 'WireGuard alt';   41641 = 'Tailscale DERP'; 1723 = 'PPTP VPN'
    1701 = 'L2TP';             500 = 'IPSec IKE';        4500 = 'IPSec NAT-T'
    8443 = 'Cisco AnyConnect'; 443 = 'SSL VPN';          943 = 'OpenVPN AS'
    9201 = 'WireGuard Mullvad';1300 = 'FortiClient';     10000 = 'SoftEther'
    5555 = 'Hamachi';          9000 = 'Outline/SS';       8388 = 'Shadowsocks'
    1080 = 'SOCKS5 Proxy';     8118 = 'Privoxy';          9050 = 'Tor SOCKS'
    9051 = 'Tor Control';      9150 = 'Tor Browser';      3128 = 'HTTP Proxy'
}

# ════════════════════════════════════════════════════════════════
Write-Banner

# ═══════════════════════════════════════════════════════════════
#  CHECK 1 — Running VPN Processes
#  TYPE: ACTIVE — a running VPN process is direct proof of activity
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Scanning $($KnownVPNProcesses.Count) known VPN processes"
Write-SectionHeader "Running VPN Processes" 1 "active"

$runningNames  = (Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | ForEach-Object { $_.ToLower() })
$detectedProcs = [System.Collections.Generic.List[hashtable]]::new()

foreach ($v in $KnownVPNProcesses) {
    if ($runningNames -contains $v.N.ToLower()) {
        $p   = Get-Process -Name $v.N -ErrorAction SilentlyContinue | Select-Object -First 1
        $mem = if ($p) { "$([math]::Round($p.WorkingSet64/1MB,1)) MB" } else { "--" }
        $detectedProcs.Add(@{ Label=$v.L; PID=$p.Id; Mem=$mem })
        Add-Active "Running VPN process: $($v.L)" 20
    }
}

if ($detectedProcs.Count -eq 0) {
    Write-CheckLine "No known VPN process running" "OK" "" "ok"
} else {
    foreach ($p in $detectedProcs) {
        Write-CheckLine $p.Label "RUNNING" "PID $($p.PID) . $($p.Mem)" "active"
    }
}
$CheckStats['Processi'] = if ($detectedProcs.Count -gt 0) { 'ACTIVE' } else { 'NONE' }
$AllResults['Processi'] = $detectedProcs

# ═══════════════════════════════════════════════════════════════
#  CHECK 2 — Windows VPN Services
#  TYPE: ACTIVE if Running / PASSIVE if Stopped (installed service)
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Analyzing Windows system services"
Write-SectionHeader "Windows VPN Services" 2 "both"

$svcPatterns = @(
    'OpenVPNService*','WireGuardTunnel*','NordVPN*','ExpressVPN*',
    'Surfshark*','ProtonVPN*','Mullvad*','CyberGhost*','PIA*',
    'vpnagent','ZeroTierOneService','tailscale','ZscalerService',
    'PANGPA','PANGPS','FortiClient*','PulseSecure*','RasMan',
    'SstpSvc','IKExt','TunnelBear*','Windscribe*',
    'HotspotShield*','IPVanish*','CloudflareWARP*','warp-svc','Hamachi*'
)

$allSvcs      = Get-Service -ErrorAction SilentlyContinue
$detectedSvcs = [System.Collections.Generic.List[hashtable]]::new()
$seenSvcNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($pat in $svcPatterns) {
    foreach ($s in ($allSvcs | Where-Object { $_.Name -like $pat -or $_.DisplayName -like $pat })) {
        if ($seenSvcNames.Add($s.Name)) {
            $detectedSvcs.Add(@{ Name=$s.Name; Display=$s.DisplayName; Status=$s.Status })
        }
    }
}
foreach ($s in ($allSvcs | Where-Object { $_.Name -match 'vpn|tun|ikev2|l2tp|pptp|warp' })) {
    if ($seenSvcNames.Add($s.Name)) {
        $detectedSvcs.Add(@{ Name=$s.Name; Display=$s.DisplayName; Status=$s.Status })
    }
}

$svcActiveCount  = 0
$svcPassiveCount = 0
if ($detectedSvcs.Count -eq 0) {
    Write-CheckLine "No VPN service detected" "OK" "" "ok"
} else {
    foreach ($s in $detectedSvcs) {
        if ($s.Status -eq 'Running') {
            Write-CheckLine $s.Display "RUNNING" $s.Name "active"
            Add-Active "Running VPN service: $($s.Display)" 20
            $svcActiveCount++
        } else {
            Write-CheckLine $s.Display "$($s.Status)" $s.Name "install"
            Add-Passive "Installed VPN service (not active): $($s.Display)" 5
            $svcPassiveCount++
        }
    }
}

$CheckStats['Servizi'] = if ($svcActiveCount -gt 0) { 'ACTIVE' } elseif ($svcPassiveCount -gt 0) { 'PASSIVE' } else { 'NONE' }
$AllResults['Servizi'] = $detectedSvcs

# ═══════════════════════════════════════════════════════════════
#  CHECK 3 — VPN Network Adapters
#  TYPE: ACTIVE if Up / PASSIVE if Disconnected (driver installed)
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Inspecting network adapters"
Write-SectionHeader "VPN Network Adapters" 3 "both"

$adapters    = Get-NetAdapter -ErrorAction SilentlyContinue
$vpnAdapters = [System.Collections.Generic.List[hashtable]]::new()

foreach ($a in $adapters) {
    if ($a.InterfaceDescription -match $VPNAdapterRx -or $a.Name -match $VPNAdapterRx) {
        $vpnAdapters.Add(@{ Name=$a.Name; Desc=$a.InterfaceDescription; Status=$a.Status })
    }
}

$adpActiveCount  = 0
$adpPassiveCount = 0
if ($vpnAdapters.Count -eq 0) {
    Write-CheckLine "No VPN adapter detected" "OK" "" "ok"
} else {
    foreach ($a in $vpnAdapters) {
        if ($a.Status -eq 'Up') {
            Write-CheckLine $a.Name "CONNECTED" $a.Desc "active"
            Add-Active "Active VPN adapter (Up): $($a.Name)" 30
            $adpActiveCount++
        } else {
            Write-CheckLine $a.Name "$($a.Status)" $a.Desc "install"
            Add-Passive "VPN adapter present but not connected: $($a.Name)" 5
            $adpPassiveCount++
        }
    }
}

$CheckStats['Adattatori'] = if ($adpActiveCount -gt 0) { 'ACTIVE' } elseif ($adpPassiveCount -gt 0) { 'PASSIVE' } else { 'NONE' }
$AllResults['Adattatori'] = $vpnAdapters

# ═══════════════════════════════════════════════════════════════
#  CHECK 4 — Routing Table
#  TYPE: ACTIVE — route on VPN interfaces = traffic routed now
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Analyzing routing table"
Write-SectionHeader "Routing Table" 4 "active"

$routes      = Get-NetRoute -ErrorAction SilentlyContinue
$defRoutes   = $routes | Where-Object { $_.DestinationPrefix -in '0.0.0.0/0','::/0' }
$vpnRoutes   = $routes | Where-Object { $_.InterfaceAlias -match $VPNAdapterRx }
$splitTunnel = ($defRoutes | Measure-Object).Count -gt 2
$hasVPNRoute = ($vpnRoutes | Measure-Object).Count -gt 0
$vpnDefault  = $defRoutes | Where-Object { $_.InterfaceAlias -match $VPNAdapterRx }

Write-CheckLine "Default IPv4/IPv6 routes"        "$($defRoutes.Count) found" "" "info"
Write-CheckLine "Routes on VPN interfaces"         "$($vpnRoutes.Count) found" "" $(if ($hasVPNRoute) { "active" } else { "ok" })
Write-CheckLine "Default gateway on VPN"           $(if ($vpnDefault) { "YES -- all traffic goes through VPN" } else { "No" }) "" $(if ($vpnDefault) { "active" } else { "ok" })
Write-CheckLine "Potential Split Tunneling"        $(if ($splitTunnel) { "Yes ($($defRoutes.Count) default routes)" } else { "Not detected" }) "" $(if ($splitTunnel) { "warn" } else { "ok" })

if ($hasVPNRoute) {
    Add-Active "$($vpnRoutes.Count) active routes on VPN interfaces" 20
    foreach ($r in ($vpnRoutes | Select-Object -First 3)) {
        Write-CheckLine "  Route" $r.DestinationPrefix "via $($r.InterfaceAlias) . metric $($r.RouteMetric)" "neutral"
    }
}
if ($vpnDefault) { Add-Active "Default gateway routed on VPN interface" 35 }

$CheckStats['Routing'] = if ($hasVPNRoute -or $vpnDefault) { 'ACTIVE' } else { 'NONE' }
$AllResults['Routing'] = @{ DefaultRoutes=$defRoutes.Count; VPNRoutes=$vpnRoutes.Count; SplitTunnel=$splitTunnel }

# ═══════════════════════════════════════════════════════════════
#  CHECK 5 — DNS & Leak Detection
#  TYPE: ACTIVE — DNS on private range during tunnel = active signal
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Analyzing DNS configuration and leak detection"
Write-SectionHeader "DNS Servers & Leak Detection" 5 "active"

$privateRx  = '(^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.|^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)'
$dnsConf    = Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
              Where-Object { $_.AddressFamily -eq 2 -and $_.ServerAddresses }
$privateDNS = $false

foreach ($dns in $dnsConf) {
    foreach ($addr in $dns.ServerAddresses) {
        $isPriv = $addr -match $privateRx
        $parts  = $addr -split '\.'
        $masked = "$($parts[0]).$($parts[1]).x.x"
        $detail = if ($isPriv) { "Private range -- possible VPN/tunnel DNS" } else { "Public/external DNS" }
        $st     = if ($isPriv) { "warn" } else { "ok" }
        Write-CheckLine "DNS on $($dns.InterfaceAlias)" $masked $detail $st
        if ($isPriv) { $privateDNS = $true }
    }
}

$leakDomains = @('whoami.akamai.net','myip.opendns.com')
$leakHits    = 0
foreach ($d in $leakDomains) {
    $r = Resolve-DnsName -Name $d -Type A -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($r -and $r.IP4Address -and $r.IP4Address -match $privateRx) { $leakHits++ }
}
Write-CheckLine "DNS Leak test (canary)" $(if ($leakHits -gt 0) { "Possible leak ($leakHits)" } else { "No leak" }) "" $(if ($leakHits -gt 0) { "warn" } else { "ok" })

$dohSvc = $allSvcs | Where-Object { $_.Name -match 'dnscrypt|doh|adguard|nextdns|pihole' }
if ($dohSvc) {
    Write-CheckLine "DoH/DNSCrypt Service" $dohSvc.DisplayName "" "warn"
    Add-Active "Active DoH/DNSCrypt -- encrypted DNS" 10
}
if ($privateDNS) { Add-Active "DNS on private IP range (typical of active VPN tunnel)" 15 }

$CheckStats['DNS'] = if ($privateDNS -or $leakHits -gt 0) { 'ACTIVE' } else { 'NONE' }
$AllResults['DNS'] = @{ PrivateDNS=$privateDNS; LeakHits=$leakHits }

# ═══════════════════════════════════════════════════════════════
#  CHECK 6 — Active Connections & VPN Ports
#  TYPE: ACTIVE — TCP established connections on VPN ports = open tunnel
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Scanning active TCP/UDP connections"
Write-SectionHeader "Active Connections on VPN Ports" 6 "active"

$tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
$udpEps   = Get-NetUDPEndpoint   -ErrorAction SilentlyContinue
$estab    = $tcpConns | Where-Object { $_.State -eq 'Established' }
$vpnTCP   = $estab | Where-Object { $VPNPortMap.ContainsKey($_.RemotePort) -or $VPNPortMap.ContainsKey($_.LocalPort) }
$wgUDP    = $udpEps | Where-Object { $_.LocalPort -in 51820,51821 }
$torSOCKS = $udpEps | Where-Object { $_.LocalPort -in 9050,9150 }
$socksEp  = $udpEps | Where-Object { $_.LocalPort -in 1080,8118,3128 }

Write-CheckLine "Total Established TCP connections" $estab.Count "" "info"
Write-CheckLine "Conn. on known VPN ports"           $vpnTCP.Count "" $(if ($vpnTCP.Count -gt 0) { "active" } else { "ok" })
Write-CheckLine "Active WireGuard UDP endpoint"       $(if ($wgUDP) { "ACTIVE" } else { "None" }) "" $(if ($wgUDP) { "active" } else { "ok" })
Write-CheckLine "Active Tor SOCKS endpoint"       $(if ($torSOCKS) { "ACTIVE" } else { "None" }) "" $(if ($torSOCKS) { "active" } else { "ok" })
Write-CheckLine "Local SOCKS5/HTTP proxy"           $(if ($socksEp) { "ACTIVE" } else { "None" }) "" $(if ($socksEp) { "warn" } else { "ok" })

$seenPorts = [System.Collections.Generic.HashSet[int]]::new()
foreach ($conn in ($vpnTCP | Select-Object -First 5)) {
    $port = if ($VPNPortMap.ContainsKey($conn.RemotePort)) { $conn.RemotePort } else { $conn.LocalPort }
    if ($seenPorts.Add($port)) { Write-CheckLine "  Port $port" "ESTABLISHED" $VPNPortMap[$port] "warn" }
}

if ($vpnTCP.Count -gt 0) { Add-Active "TCP connections on VPN ports ($($vpnTCP.Count) conn.)" 15 }
if ($wgUDP)               { Add-Active "Active WireGuard UDP endpoint" 25 }
if ($torSOCKS)            { Add-Active "Active Tor SOCKS endpoint" 20 }
if ($socksEp)             { Add-Active "Active local SOCKS5/HTTP proxy" 10 }

$CheckStats['Connessioni'] = if ($vpnTCP.Count -gt 0 -or $wgUDP -or $torSOCKS) { 'ACTIVE' } else { 'NONE' }
$AllResults['Connessioni'] = @{ TCP=$estab.Count; VPNPorts=$vpnTCP.Count; WireGuard=($null -ne $wgUDP) }

# ═══════════════════════════════════════════════════════════════
#  CHECK 7 — Installed VPN Software
#  TYPE: PURELY PASSIVE — presence != activity
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Scanning installed software in registry"
Write-SectionHeader "Installed VPN Software" 7 "passive"

$regPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$vpnKW = 'vpn|openvpn|wireguard|nordvpn|expressvpn|surfshark|protonvpn|mullvad|cyberghost|' +
         'anyconnect|globalprotect|tunnelbear|windscribe|ipvanish|hidemyass|torguard|' +
         'zerotier|tailscale|pulse secure|forticlient|f5 vpn|hotspot shield|vyprvpn|ivpn|' +
         'airvpn|perfectprivacy|zenmate|hamachi|cloudflare warp|outline|shadowsocks|psiphon|' +
         'lantern|speedify|radmin|privatevpn|strongswan|sonicwall|barracuda|zscaler|netskope'

$installedVPN = [System.Collections.Generic.List[string]]::new()
$seenSW       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($path in $regPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and $_.DisplayName -match $vpnKW } |
    ForEach-Object {
        if ($seenSW.Add($_.DisplayName)) {
            $ver = if ($_.DisplayVersion) { $_.DisplayVersion } else { "--" }
            $installedVPN.Add("$($_.DisplayName)|$ver")
        }
    }
}

if ($installedVPN.Count -eq 0) {
    Write-CheckLine "No VPN software installed" "OK" "" "ok"
} else {
    foreach ($sw in $installedVPN) {
        $parts = $sw -split '\|'
        Write-CheckLine $parts[0] "INSTALLED" "v$($parts[1])  -- does not imply active connection" "install"
    }
    Add-Passive "VPN software installed ($($installedVPN.Count)) (not proof of activity)" ([math]::Min($installedVPN.Count * 5, 20))
}

$CheckStats['Software'] = if ($installedVPN.Count -gt 0) { 'PASSIVE' } else { 'NONE' }
$AllResults['Software'] = $installedVPN

# ═══════════════════════════════════════════════════════════════
#  CHECK 8 — ASN Analysis (Total Privacy)
#  TYPE: ACTIVE — the IP category reflects the connection in use NOW
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Querying public IP ASN metadata"
Write-SectionHeader "ASN Analysis / Network Type" 8 "active"

$dcKeywords = 'vpn|hosting|datacenter|data center|cloud|server|colocation|colo|vps|virtual|' +
              'ovh|hetzner|digitalocean|linode|vultr|amazon|google cloud|microsoft azure|' +
              'cloudflare|akamai|leaseweb|serverius|choopa|m247|quadranet|frantech|buyvm|' +
              'racknerd|privacyfoundation|privacyfirst|anonymous|mullvad|nordvpn|expressvpn|' +
              'protonvpn|perfect privacy|ivpn|airvpn|torguard|cdn|fastly|zscaler|netskope|' +
              'contabo|ionos|hostinger|nexeon|aruba networks|serverplan'

Write-CheckLine "Public IP address"  "[HIDDEN - Privacy Mode]" "" "hidden"
Write-CheckLine "Hostname / PTR record"  "[HIDDEN - Privacy Mode]" "" "hidden"
Write-CheckLine "Geographic location"   "[HIDDEN - Privacy Mode]" "" "hidden"
Write-CheckLine "IP Timezone"            "[HIDDEN - Privacy Mode]" "" "hidden"
Write-CheckLine "ISP / Provider"         "[HIDDEN - Privacy Mode]" "" "hidden"

$geoData   = $null
foreach ($ep in @('https://ipinfo.io/json','https://ipapi.co/json/')) {
    $r = Invoke-SafeWeb $ep; if ($r) { $geoData = $r; break }
}

if ($geoData) {
    $org          = if ($geoData.org) { $geoData.org } else { "$($geoData.asn) $($geoData.org_name)" }
    $isDatacenter = $org -match $dcKeywords
    $orgCategory  = if ($isDatacenter) { "Datacenter / Hosting / Cloud / VPN Provider" } else { "Residential or business ISP" }
    $connType     = if ($isDatacenter) { "NON-residential -- typical of active VPN/proxy" } else { "Residential / Standard Business" }

    Write-CheckLine "ASN Category"       $orgCategory "" $(if ($isDatacenter) { "active" } else { "ok" })
    Write-CheckLine "Connection type" $connType    "" $(if ($isDatacenter) { "active" } else { "ok" })

    if ($isDatacenter) { Add-Active "Public IP on datacenter/VPN provider ASN" 35 }

    $CheckStats['ASN'] = if ($isDatacenter) { 'ACTIVE' } else { 'NONE' }
    $AllResults['ASN'] = @{ Category=$orgCategory; IsDatacenter=$isDatacenter }
} else {
    Write-CheckLine "ASN Verification" "Unreachable" "Timeout or no Internet" "warn"
    $CheckStats['ASN'] = 'NONE'
}

# ═══════════════════════════════════════════════════════════════
#  CHECK 9 — VPN Registry Keys
#  TYPE: PURELY PASSIVE — installation only
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Searching for VPN registry keys"
Write-SectionHeader "VPN Registry Keys" 9 "passive"

$regVPN = @(
    @{ P='HKLM:\SYSTEM\CurrentControlSet\Services\OpenVPNService';           L='OpenVPN Service' }
    @{ P='HKLM:\SYSTEM\CurrentControlSet\Services\WireGuard';                L='WireGuard Service' }
    @{ P='HKLM:\SOFTWARE\NordVPN';                                           L='NordVPN' }
    @{ P='HKCU:\SOFTWARE\NordVPN';                                           L='NordVPN (user)' }
    @{ P='HKLM:\SOFTWARE\ExpressVPN';                                        L='ExpressVPN' }
    @{ P='HKLM:\SOFTWARE\Surfshark';                                         L='Surfshark' }
    @{ P='HKLM:\SOFTWARE\ProtonVPN';                                         L='ProtonVPN' }
    @{ P='HKCU:\SOFTWARE\ProtonVPN';                                         L='ProtonVPN (user)' }
    @{ P='HKLM:\SOFTWARE\Mullvad VPN';                                       L='Mullvad VPN' }
    @{ P='HKCU:\SOFTWARE\Mullvad VPN';                                       L='Mullvad VPN (user)' }
    @{ P='HKLM:\SOFTWARE\CyberGhost';                                        L='CyberGhost' }
    @{ P='HKLM:\SOFTWARE\Private Internet Access';                           L='PIA' }
    @{ P='HKLM:\SOFTWARE\Cisco\Cisco AnyConnect Secure Mobility Client';     L='Cisco AnyConnect' }
    @{ P='HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect';                  L='GlobalProtect' }
    @{ P='HKLM:\SOFTWARE\Fortinet\FortiClient';                              L='FortiClient' }
    @{ P='HKLM:\SOFTWARE\Pulse Secure';                                      L='Pulse Secure' }
    @{ P='HKLM:\SOFTWARE\ZeroTier';                                          L='ZeroTier' }
    @{ P='HKLM:\SOFTWARE\Tailscale IPN';                                     L='Tailscale' }
    @{ P='HKLM:\SOFTWARE\OpenVPN-GUI';                                       L='OpenVPN GUI' }
    @{ P='HKLM:\SOFTWARE\TunnelBear';                                        L='TunnelBear' }
    @{ P='HKLM:\SOFTWARE\Windscribe';                                        L='Windscribe' }
    @{ P='HKLM:\SOFTWARE\IPVanish';                                          L='IPVanish' }
    @{ P='HKLM:\SOFTWARE\Hotspot Shield';                                    L='Hotspot Shield' }
    @{ P='HKLM:\SOFTWARE\Cloudflare WARP';                                   L='Cloudflare WARP' }
    @{ P='HKLM:\SOFTWARE\Hamachi';                                           L='LogMeIn Hamachi' }
    @{ P='HKLM:\SOFTWARE\Radmin VPN';                                        L='Radmin VPN' }
    @{ P='HKLM:\SOFTWARE\VyprVPN';                                           L='VyprVPN' }
    @{ P='HKLM:\SOFTWARE\Speedify';                                          L='Speedify' }
    @{ P='HKCU:\SOFTWARE\Psiphon';                                           L='Psiphon' }
)

$regHits = [System.Collections.Generic.List[string]]::new()
foreach ($r in $regVPN) {
    if (Test-Path $r.P) {
        $regHits.Add($r.L)
        Write-CheckLine $r.L "Key present" "Installation only -- not proof of activity" "install"
    }
}
if ($regHits.Count -eq 0) {
    Write-CheckLine "No VPN registry keys found" "OK" "" "ok"
} else {
    Add-Passive "$($regHits.Count) VPN registry key(s) (installation trace)" ([math]::Min($regHits.Count * 4, 15))
}
$CheckStats['Registro'] = if ($regHits.Count -gt 0) { 'PASSIVE' } else { 'NONE' }
$AllResults['Registro'] = $regHits

# ═══════════════════════════════════════════════════════════════
#  CHECK 10 — TAP/TUN/Wintun Drivers
#  TYPE: PASSIVE — driver installed != active connection
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Verifying installed TAP/TUN/Wintun drivers"
Write-SectionHeader "Virtual VPN Drivers" 10 "passive"

$driverHits = [System.Collections.Generic.List[string]]::new()

$pnpVPN = Get-PnpDevice -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName -match 'tap|tun|wintun|vpn|wireguard|nordlynx|zerotier|hamachi|warp' }
foreach ($p in $pnpVPN) {
    if ($driverHits -notcontains $p.FriendlyName) {
        # A PnP driver in OK state but with interface Down is passive
        $st = if ($p.Status -eq 'OK') { "install" } else { "neutral" }
        Write-CheckLine "PnP Driver" $p.FriendlyName "$($p.Status) -- driver installed" $st
        $driverHits.Add($p.FriendlyName)
    }
}

$drvSvcs = Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^tap|^tun|wintun|^ndisrd|ovpn' }
foreach ($d in $drvSvcs) {
    if ($driverHits -notcontains $d.DisplayName) {
        Write-CheckLine "Driver (service)" $d.DisplayName $d.Status "install"
        $driverHits.Add($d.DisplayName)
    }
}

try {
    $scOut   = sc.exe query type= driver 2>$null | Select-String 'SERVICE_NAME'
    $tapDrvs = $scOut | Where-Object { $_ -match 'tap|tun|wintun|vpndrv' }
    foreach ($drv in $tapDrvs) {
        $name = ($drv -split ':')[1].Trim()
        if ($driverHits -notcontains $name) {
            Write-CheckLine "Kernel driver" $name "" "install"
            $driverHits.Add($name)
        }
    }
} catch {}

if ($driverHits.Count -eq 0) {
    Write-CheckLine "No TAP/TUN/Wintun drivers found" "OK" "" "ok"
} else {
    Add-Passive "Installed VPN drivers ($($driverHits.Count)) -- not proof of activity" ([math]::Min($driverHits.Count * 5, 15))
}
$CheckStats['Driver'] = if ($driverHits.Count -gt 0) { 'PASSIVE' } else { 'NONE' }
$AllResults['Driver'] = $driverHits

# ═══════════════════════════════════════════════════════════════
#  CHECK 11 — System Proxy & Environment Variables
#  TYPE: ACTIVE — an active proxy is redirecting traffic NOW
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Verifying system proxy and environment variables"
Write-SectionHeader "System Proxy & Environment Variables" 11 "active"

$proxyActive = $false
$proxyReg    = Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue

if ($proxyReg.ProxyEnable -eq 1 -and $proxyReg.ProxyServer) {
    $proxyPort = ($proxyReg.ProxyServer -split ':')[-1]
    Write-CheckLine "IE/WinINet Proxy" "ACTIVE" "Port: $proxyPort (hidden host)" "active"
    Add-Active "Active system proxy (port $proxyPort)" 20
    $proxyActive = $true
} else {
    Write-CheckLine "IE/WinINet Proxy" "Disabled" "" "ok"
}

$envProxies = @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY','http_proxy','https_proxy','all_proxy')
foreach ($v in $envProxies) {
    $val = [System.Environment]::GetEnvironmentVariable($v, 'Process')
    if (-not $val) { $val = [System.Environment]::GetEnvironmentVariable($v, 'User') }
    if (-not $val) { $val = [System.Environment]::GetEnvironmentVariable($v, 'Machine') }
    if ($val) {
        $port = ($val -split ':')[-1] -replace '[^0-9]',''
        Write-CheckLine "Variable $v" "SET" "Port: $port (hidden host)" "active"
        Add-Active "Proxy variable '$v' set" 15
        $proxyActive = $true
    }
}

if ($proxyReg.AutoConfigURL) {
    Write-CheckLine "PAC Script (Auto-Proxy)" "PRESENT" "" "warn"
    Add-Active "Auto-proxy PAC Script configured" 10
    $proxyActive = $true
} else {
    Write-CheckLine "PAC Script (Auto-Proxy)" "Absent" "" "ok"
}

try {
    $winhttp = netsh winhttp show proxy 2>$null
    # Consider real proxy only if not "Direct access"
    if ($winhttp -match 'Proxy Server' -and $winhttp -notmatch 'Direct access') {
        $proxyLine = ($winhttp | Select-String 'Proxy Server').ToString().Trim()
        $pPort     = ($proxyLine -split ':')[-1] -replace '[^0-9]',''
        Write-CheckLine "WinHTTP Proxy (system)" "ACTIVE" "Port: $pPort (hidden host)" "active"
        Add-Active "System WinHTTP proxy configured" 15
        $proxyActive = $true
    } else {
        Write-CheckLine "WinHTTP Proxy (system)" "Direct access / No proxy" "" "ok"
    }
} catch {}

$CheckStats['Proxy'] = if ($proxyActive) { 'ACTIVE' } else { 'NONE' }
$AllResults['Proxy'] = @{ Found=$proxyActive }

# ═══════════════════════════════════════════════════════════════
#  CHECK 12 — MTU Fingerprinting
#  TYPE: ACTIVE — reduced MTU on connected interfaces = active tunnel
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Analyzing network interface MTU"
Write-SectionHeader "MTU Fingerprinting" 12 "active"

$mtuThreshold = 1480
$mtuSuspect   = $false
$ifaceMetrics = Get-NetIPInterface -ErrorAction SilentlyContinue | Where-Object { $_.NlMtu -gt 100 }

foreach ($iface in $ifaceMetrics) {
    $mtu  = $iface.NlMtu
    $note = switch ($mtu) {
        { $_ -eq 1500 }              { "Standard Ethernet" }
        { $_ -eq 1420 }              { "Typical WireGuard" }
        { $_ -in 1380..1419 }        { "Probable IPSec/OpenVPN tunnel" }
        { $_ -in 1280..1379 }        { "VPN tunnel with high overhead" }
        { $_ -lt 1280 -and $_ -gt 100 } { "Very reduced MTU -- deep tunnel" }
        default { "Standard" }
    }
    if ($mtu -lt $mtuThreshold -or $iface.InterfaceAlias -match $VPNAdapterRx) {
        $st = if ($mtu -lt $mtuThreshold) { "warn" } else { "neutral" }
        Write-CheckLine "$($iface.InterfaceAlias)" "$mtu bytes" $note $st
        if ($mtu -lt $mtuThreshold) { $mtuSuspect = $true }
    }
}

if (-not $mtuSuspect) {
    Write-CheckLine "MTU of all interfaces" "Normal (>= $mtuThreshold)" "" "ok"
} else {
    Add-Active "Reduced MTU detected -- typical of active VPN tunnel" 15
}
$CheckStats['MTU'] = if ($mtuSuspect) { 'ACTIVE' } else { 'NONE' }
$AllResults['MTU'] = @{ Suspect=$mtuSuspect; Threshold=$mtuThreshold }

# ═══════════════════════════════════════════════════════════════
#  CHECK 13 — Tor, I2P & Anonymous Networks
#  TYPE: ACTIVE — open process/port = anonymous network in use now
# ═══════════════════════════════════════════════════════════════
Write-Spinner "Detecting Tor connections and anonymous networks"
Write-SectionHeader "Tor, I2P & Anonymous Networks" 13 "active"

$torFound = $false

$anonProcs = Get-Process -Name 'tor','torbrowser','onionshare','i2pd','i2p','freenet','obfs4proxy' -ErrorAction SilentlyContinue
foreach ($t in $anonProcs) {
    Write-CheckLine "Anonymous network process" $t.Name "PID $($t.Id)" "active"
    Add-Active "Running anonymous network process: $($t.Name)" 30
    $torFound = $true
}

$torPorts = $tcpConns | Where-Object { $_.LocalPort -in 9050,9051,9150,9151 -or $_.RemotePort -in 9050,9051 }
if ($torPorts) {
    Write-CheckLine "Tor Ports (9050/9051/9150)" "OPEN" "" "active"
    Add-Active "Active Tor ports" 25
    $torFound = $true
}

$torDirs = @("$env:APPDATA\tor","$env:LOCALAPPDATA\Tor Browser","$env:USERPROFILE\Desktop\Tor Browser")
foreach ($d in $torDirs) {
    if (Test-Path $d) {
        Write-CheckLine "Tor Directory" "Present" "(hidden path for privacy)" "install"
        Add-Passive "Tor directory present (installed, not necessarily active)" 5
        # Not setting torFound here -- the directory is a passive trace
    }
}

$i2pPorts = $tcpConns | Where-Object { $_.LocalPort -in 7656,4444,4445,7657 }
if ($i2pPorts) {
    Write-CheckLine "I2P Ports (4444/7656)" "OPEN" "" "active"
    Add-Active "Active I2P ports" 25
    $torFound = $true
}

if (-not $torFound) { Write-CheckLine "No anonymous network (Tor/I2P) active" "OK" "" "ok" }
$CheckStats['Tor'] = if ($torFound) { 'ACTIVE' } else { 'NONE' }
$AllResults['Tor'] = @{ Found=$torFound }

# ════════════════════════════════════════════════════════════════════════════
#  FINAL VERDICT CALCULATION — SEPARATE
# ════════════════════════════════════════════════════════════════════════════
$ActiveScore    = [math]::Min($ActiveScore,   100)
$InstalledScore = [math]::Min($InstalledScore, 100)

$activeChecks   = @($CheckStats.Values | Where-Object { $_ -eq 'ACTIVE' }).Count
$passiveChecks  = @($CheckStats.Values | Where-Object { $_ -eq 'PASSIVE' }).Count
$totalChecks    = $CheckStats.Count

# ACTIVE VPN Verdict (based on real-time evidence)
$verdictActive = if     ($ActiveScore -ge 60) { @{ Label='ACTIVE';     Color=$C.Red;    Icon='[ACT]'; Tag='YES';     Desc='Concrete proof of tunneled traffic now' } }
                 elseif ($ActiveScore -ge 25)  { @{ Label='LIKELY';  Color=$C.Yellow; Icon='[?? ]'; Tag='LIKELY';  Desc='Activity signals -- not conclusive' } }
                 else                          { @{ Label='NOT ACTIVE'; Color=$C.Green;  Icon='[OK ]'; Tag='NO';      Desc='No proof of active tunnel detected' } }

# INSTALLED VPN Verdict (based on passive traces)
$verdictInstall = if     ($InstalledScore -ge 15) { @{ Label='YES';            Color=$C.Orange; Icon='[INST]'; Tag='YES';  Desc='VPN software/drivers present on the system' } }
                  elseif ($InstalledScore -ge 5)   { @{ Label='PROBABLY'; Color=$C.Yellow; Icon='[?  ]'; Tag='MAYBE'; Desc='Some VPN installation traces' } }
                  else                             { @{ Label='NO';             Color=$C.Green;  Icon='[OK ]'; Tag='NO';   Desc='No trace of installed VPN software' } }

# ════════════════════════════════════════════════════════════════════════════
#  CHECK SUMMARY TABLE — with ACTIVE/PASSIVE distinction
# ════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host ""
Write-Host "$($C.DkGray)  $('=' * 68)$($C.Reset)"
Write-Host "  $($C.Bold)$($C.White)  CHECK SUMMARY$($C.Reset)"
Write-Host "$($C.DkGray)  $('=' * 68)$($C.Reset)"
Write-Host "   $($C.Red)[ACT] $($C.Reset) = Active VPN signal    $($C.Orange)[INST]$($C.Reset) = Installation only    $($C.Green)[OK ] $($C.Reset) = Negative"
Write-Host "$($C.DkGray)  $('-' * 68)$($C.Reset)"

$checkOrder = [ordered]@{
    'VPN Processes'      = 'Processi'
    'Windows Services'   = 'Servizi'
    'Network Adapters'   = 'Adattatori'
    'Routing'            = 'Routing'
    'DNS / Leak'         = 'DNS'
    'Ports / Conn.'      = 'Connessioni'
    'Installed Software' = 'Software'
    'ASN / Network Type' = 'ASN'
    'Registry'           = 'Registro'
    'TAP/TUN Drivers'    = 'Driver'
    'System Proxy'       = 'Proxy'
    'MTU'                = 'MTU'
    'Tor / I2P'          = 'Tor'
}

$col1 = @(); $col2 = @()
$keys = @($checkOrder.Keys)
for ($i = 0; $i -lt $keys.Count; $i++) {
    $k   = $keys[$i]
    $key = $checkOrder[$k]
    $val = if ($CheckStats.Contains($key)) { $CheckStats[$key] } else { 'NONE' }
    $ico = switch ($val) {
        'ACTIVE'  { "$($C.Red)$($C.Bold)[ACT] $($C.Reset)" }
        'PASSIVE' { "$($C.Orange)[INST]$($C.Reset)" }
        default   { "$($C.Green)[OK ] $($C.Reset)" }
    }
    $entry = "   $ico  $($C.Gray)$($k.PadRight(20))$($C.Reset)"
    if ($i % 2 -eq 0) { $col1 += $entry } else { $col2 += $entry }
}
for ($i = 0; $i -lt [math]::Max($col1.Count, $col2.Count); $i++) {
    $l = if ($i -lt $col1.Count) { $col1[$i] } else { ' ' * 30 }
    $r = if ($i -lt $col2.Count) { $col2[$i] } else { '' }
    Write-Host "$l  $r"
}

# ════════════════════════════════════════════════════════════════════════════
#  DOUBLE VERDICT — ACTIVE + INSTALLED
# ════════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host ""
$w  = 74
$ln = '=' * $w
Write-Host "$($C.White)$($C.Bold)+ $ln +$($C.Reset)"
Write-Host "$($C.White)$($C.Bold)|$($C.Reset)$($C.Gray)$("  FINAL ANALYSIS RESULT".PadRight($w))$($C.Reset)$($C.White)$($C.Bold)|$($C.Reset)"
Write-Host "$($C.White)$($C.Bold)+ $ln +$($C.Reset)"

# Line 1: VPN ACTIVE?
$aLabel = ("  $($verdictActive.Icon)  IS VPN ACTIVE RIGHT NOW?  -->  $($verdictActive.Label)").PadRight($w)
Write-Host "$($C.White)$($C.Bold)|$($C.Reset)$($verdictActive.Color)$($C.Bold)$aLabel$($C.Reset)$($C.White)$($C.Bold)|$($C.Reset)"
Write-Host "$($C.White)$($C.Bold)|$($C.Reset)$($C.DkGray)$("     $($verdictActive.Desc)".PadRight($w))$($C.Reset)$($C.White)$($C.Bold)|$($C.Reset)"

Write-Host "$($C.White)$($C.Bold)|$($C.Reset)$($C.DkGray)$(' ' * $w)$($C.Reset)$($C.White)$($C.Bold)|$($C.Reset)"

# Line 2: VPN INSTALLED?
$iLabel = ("  $($verdictInstall.Icon)  IS VPN INSTALLED ON THE SYSTEM?   -->  $($verdictInstall.Label)").PadRight($w)
Write-Host "$($C.White)$($C.Bold)|$($C.Reset)$($verdictInstall.Color)$($C.Bold)$iLabel$($C.Reset)$($C.White)$($C.Bold)|$($C.Reset)"
Write-Host "$($C.White)$($C.Bold)|$($C.Reset)$($C.DkGray)$("     $($verdictInstall.Desc)".PadRight($w))$($C.Reset)$($C.White)$($C.Bold)|$($C.Reset)"

Write-Host "$($C.White)$($C.Bold)+ $ln +$($C.Reset)"
Write-Host ""

# Confidence bars
$bW = 42
function Write-ScoreBar([string]$label, [int]$score, [string]$color) {
    $f   = [math]::Round($score / 100 * $bW)
    $e   = $bW - $f
    $bar = "$color$('#' * $f)$($C.DkGray)$('-' * $e)$($C.Reset)"
    Write-Host "  $($C.Gray)$($label.PadRight(30))$($C.Reset)  $bar  $color$($C.Bold)$score$($C.Reset)$($C.Gray)/100$($C.Reset)"
}
Write-ScoreBar "Real-time activity:           " $ActiveScore $(
    if ($ActiveScore -ge 60) { $C.Red } elseif ($ActiveScore -ge 25) { $C.Yellow } else { $C.Green }
)
Write-ScoreBar "Installation traces:          " $InstalledScore $(
    if ($InstalledScore -ge 15) { $C.Orange } elseif ($InstalledScore -ge 5) { $C.Yellow } else { $C.Green }
)
Write-Host "  $($C.Gray)Active checks (tunnel):  $($C.White)$activeChecks$($C.Reset)$($C.Gray) / $totalChecks     Installation checks: $($C.White)$passiveChecks$($C.Reset)$($C.Gray) / $totalChecks$($C.Reset)"
Write-Host ""

# Active evidence
if ($ActiveEvidence.Count -gt 0) {
    Write-Host "  $($C.Bold)$($C.Red)Proof of VPN/tunnel activity:$($C.Reset)"
    foreach ($ev in $ActiveEvidence) {
        Write-Host "   $($C.Red)>>$($C.Reset)  $($C.White)$ev$($C.Reset)"
    }
    Write-Host ""
}

# Passive evidence
if ($PassiveEvidence.Count -gt 0) {
    Write-Host "  $($C.Bold)$($C.Orange)VPN installation traces:$($C.Reset)"
    foreach ($ev in $PassiveEvidence) {
        Write-Host "   $($C.Orange)>>$($C.Reset)  $($C.Gray)$ev$($C.Reset)"
    }
    Write-Host ""
}

if ($ActiveEvidence.Count -eq 0 -and $PassiveEvidence.Count -eq 0) {
    Write-Host "  $($C.Green)[OK]$($C.Reset)  $($C.White)No evidence of VPN or proxy collected.$($C.Reset)"
    Write-Host ""
}

# Footer
Write-Host "$($C.DkGray)  $('=' * 68)$($C.Reset)"
Write-Host "  $($C.Magenta)[*]$($C.Reset)  $($C.Gray)PRIVACY: IP, ISP, Hostname, City, Region, Timezone -- NEVER shown$($C.Reset)"
Write-Host "  $($C.Cyan)[t]$($C.Reset)  $($C.Gray)Analysis: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')$($C.Reset)"
Write-Host "  $($C.Cyan)[c]$($C.Reset)  $($C.Gray)Host: $($env:COMPUTERNAME)  .  User: $($env:USERNAME)$($C.Reset)"
Write-Host ""

# Export JSON
if ($ExportJSON) {
    $jsonPath = Join-Path $PSScriptRoot "vpn-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    @{
        timestamp      = (Get-Date -Format 'o')
        activeScore    = $ActiveScore
        installedScore = $InstalledScore
        verdictActive  = $verdictActive.Tag
        verdictInstall = $verdictInstall.Tag
        activeChecks   = $activeChecks
        passiveChecks  = $passiveChecks
        totalChecks    = $totalChecks
        activeEvidence = @($ActiveEvidence)
        passiveEvidence= @($PassiveEvidence)
        details        = $AllResults
    } | ConvertTo-Json -Depth 6 | Out-File $jsonPath -Encoding UTF8
    Write-Host "  $($C.Cyan)[j]$($C.Reset)  $($C.Gray)JSON Report: $jsonPath$($C.Reset)"
    Write-Host ""
}

Write-Host "$($C.Cyan)$('=' * 76)$($C.Reset)"
Write-Host ""