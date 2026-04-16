param(
    [Parameter(Mandatory=$true)]
    [string]$InputPath,

    [string]$OutputPath = "",

    [switch]$InPlace
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $InputPath)) {
    throw "Input file not found: $InputPath"
}

$content = Get-Content -Path $InputPath -Raw -Encoding UTF8

if (-not $OutputPath) {
    if ($InPlace) {
        $OutputPath = $InputPath
    } else {
        $base = [System.IO.Path]::GetFileNameWithoutExtension($InputPath)
        $dir  = Split-Path -Path $InputPath -Parent
        if (-not $dir) { $dir = (Get-Location).Path }
        $OutputPath = Join-Path $dir ($base + '-TeslaPro.ps1')
    }
}

$replacements = [ordered]@{
    'VPN Detector Pro v3\.1 - Advanced Network Intelligence Tool' = 'TeslaPro VPN Intelligence v3.1 - Advanced Network Telemetry Suite'
    'Distingue chiaramente tra VPN ATTIVA \(tunnel aperto, traffico instradato\)' = 'Clearly distinguishes between ACTIVE VPN (open tunnel, traffic currently routed)'
    'e VPN INSTALLATA \(software presente ma non necessariamente connessa\)\.' = 'and INSTALLED VPN (software present but not necessarily connected).'
    '13 check indipendenti\. Privacy Mode totale: nessun dato personale mostrato\.' = '13 independent checks. Full Privacy Mode: no personal data displayed.'
    'Esegui come Amministratore per risultati completi\.' = 'Run as Administrator for complete results.'
    'PALETTE ANSI' = 'TESLAPRO ANSI PALETTE'
    'STRUTTURA DATI — DOPPIO SCORE' = 'DATA MODEL — DUAL SCORE ENGINE'
    'FUNZIONI UI' = 'TESLAPRO UI FUNCTIONS'
    'DATABASE VPN' = 'VPN SIGNATURE DATABASE'
    'valori: ''ACTIVE'' \| ''PASSIVE'' \| ''NONE''' = "values: 'ACTIVE' | 'PASSIVE' | 'NONE'"

    'VPN DETECTOR PRO' = 'TESLAPRO VPN INTEL'
    '13 Check  \.  Attiva vs Installata  \.  Privacy Mode ON  \.  No dati personali' = '13 Checks  .  Active vs Installed  .  Privacy Shield ON  .  No personal data'
    'Esecuzione come Amministratore -- tutti i check disponibili' = 'Running as Administrator -- all checks available'
    'Senza privilegi admin -- alcuni check potrebbero essere limitati' = 'Without admin privileges -- some checks may be limited'

    "ATTIVITA' IN TEMPO REALE" = 'REAL-TIME ACTIVITY'
    'TRACCE INSTALLAZIONE' = 'INSTALLATION FOOTPRINTS'
    'ATTIVO \+ INSTALLAZIONE' = 'ACTIVE + INSTALLED'

    'VPN ATTIVA — tunnel aperto' = 'ACTIVE VPN -- open tunnel'
    'VPN presente ma non attiva' = 'VPN present but not active'

    'Scansione di \$\(\$KnownVPNProcesses\.Count\) processi VPN noti' = 'Scanning $($KnownVPNProcesses.Count) known VPN processes'
    'Processi VPN in Esecuzione' = 'Running VPN Processes'
    'Nessun processo VPN noto in esecuzione' = 'No known VPN processes running'
    'IN ESECUZIONE' = 'RUNNING'
    'Processo VPN in esecuzione:' = 'VPN process running:'

    'Analisi servizi di sistema Windows' = 'Analyzing Windows system services'
    'Servizi Windows VPN' = 'Windows VPN Services'
    'Nessun servizio VPN rilevato' = 'No VPN services detected'
    'Servizio VPN in esecuzione:' = 'VPN service running:'
    'Servizio VPN installato \(non attivo\):' = 'VPN service installed (not active):'

    'Ispezione adattatori di rete' = 'Inspecting network adapters'
    'Adattatori di Rete VPN' = 'VPN Network Adapters'
    'Nessun adattatore VPN rilevato' = 'No VPN adapters detected'
    'CONNESSO' = 'CONNECTED'
    'Adattatore VPN attivo \(Up\):' = 'Active VPN adapter (Up):'
    'Adattatore VPN presente ma non connesso:' = 'VPN adapter present but not connected:'

    'Analisi tabella di routing' = 'Analyzing routing table'
    'Tabella di Routing' = 'Routing Table'
    'Route default IPv4/IPv6' = 'Default IPv4/IPv6 routes'
    'trovate' = 'found'
    'Route su interfacce VPN' = 'Routes on VPN interfaces'
    'Default gateway su VPN' = 'Default gateway on VPN'
    'SI -- tutto il traffico passa per VPN' = 'YES -- all traffic is routed through VPN'
    'No' = 'No'
    'Split Tunneling potenziale' = 'Potential split tunneling'
    'Si \(\$\(\$defRoutes\.Count\) default route\)' = 'Yes ($($defRoutes.Count) default routes)'
    'Non rilevato' = 'Not detected'
    'via \$\(\$r\.InterfaceAlias\) \. metric \$\(\$r\.RouteMetric\)' = 'via $($r.InterfaceAlias) . metric $($r.RouteMetric)'
    'route attive su interfacce VPN' = 'active routes on VPN interfaces'
    'Default gateway instradato su interfaccia VPN' = 'Default gateway routed through VPN interface'

    'Analisi configurazione DNS e leak detection' = 'Analyzing DNS configuration and leak detection'
    'Server DNS & Leak Detection' = 'DNS Servers & Leak Detection'
    'Range privato -- possibile DNS VPN/tunnel' = 'Private range -- possible VPN/tunnel DNS'
    'DNS pubblico/esterno' = 'Public/external DNS'
    'DNS Leak test \(canary\)' = 'DNS leak test (canary)'
    'Possibile leak' = 'Possible leak'
    'Nessun leak' = 'No leak detected'
    'Servizio DoH/DNSCrypt' = 'DoH/DNSCrypt service'
    'DNS cifrato' = 'Encrypted DNS'
    'DoH/DNSCrypt attivo -- DNS cifrato' = 'DoH/DNSCrypt active -- encrypted DNS'
    'DNS su range IP privato \(tipico di tunnel VPN attivo\)' = 'DNS on private IP range (typical of active VPN tunnel)'

    'Scansione connessioni TCP/UDP attive' = 'Scanning active TCP/UDP connections'
    'Connessioni Attive su Porte VPN' = 'Active Connections on VPN Ports'
    'Connessioni TCP Established totali' = 'Total established TCP connections'
    'Conn\. su porte VPN note' = 'Connections on known VPN ports'
    'Endpoint UDP WireGuard \(51820\)' = 'WireGuard UDP endpoint (51820)'
    'ATTIVO' = 'ACTIVE'
    'Nessuno' = 'None'
    'Endpoint Tor SOCKS \(9050/9150\)' = 'Tor SOCKS endpoint (9050/9150)'
    'Proxy locale SOCKS5/HTTP' = 'Local SOCKS5/HTTP proxy'
    'ESTABLISHED' = 'ESTABLISHED'
    'Connessioni TCP su porte VPN' = 'TCP connections on VPN ports'
    'conn\.' = 'conns.'
    'Endpoint UDP WireGuard attivo' = 'WireGuard UDP endpoint active'
    'Endpoint Tor SOCKS attivo' = 'Tor SOCKS endpoint active'
    'Proxy locale SOCKS5/HTTP attivo' = 'Local SOCKS5/HTTP proxy active'

    'Scansione software installati nel registro' = 'Scanning installed software in registry'
    'Software VPN Installati' = 'Installed VPN Software'
    'Nessun software VPN installato' = 'No VPN software installed'
    'INSTALLATO' = 'INSTALLED'
    'non implica connessione attiva' = 'does not imply an active connection'
    "software VPN installato/i \(non prova di attivita'\)" = 'installed VPN software item(s) (not proof of activity)'

    'Interrogazione metadati ASN IP pubblico' = 'Querying public IP ASN metadata'
    'Analisi ASN / Tipo di Rete' = 'ASN Analysis / Network Type'
    'Indirizzo IP pubblico' = 'Public IP address'
    'Hostname / PTR record' = 'Hostname / PTR record'
    'Posizione geografica' = 'Geographic location'
    'Timezone IP' = 'IP timezone'
    'ISP / Operatore' = 'ISP / Provider'
    '\[NASCOSTO - Privacy Mode\]' = '[HIDDEN - Privacy Shield]'
    'Datacenter / Hosting / Cloud / VPN Provider' = 'Datacenter / Hosting / Cloud / VPN Provider'
    'ISP residenziale o aziendale' = 'Residential or enterprise ISP'
    'NON residenziale -- tipico di VPN/proxy attivo' = 'Non-residential -- typical of active VPN/proxy'
    'Residenziale / Business standard' = 'Residential / standard business connection'
    'Categoria ASN' = 'ASN category'
    'Tipo di connessione' = 'Connection type'
    'IP pubblico su ASN datacenter/VPN provider' = 'Public IP on datacenter/VPN provider ASN'
    'Verifica ASN' = 'ASN check'
    'Non raggiungibile' = 'Unavailable'
    'Timeout o assenza Internet' = 'Timeout or no Internet access'

    'Ricerca chiavi di registro VPN' = 'Searching VPN registry keys'
    'Chiavi di Registro VPN' = 'VPN Registry Keys'
    'Chiave presente' = 'Key present'
    "Solo installazione -- non prova di attivita'" = 'Installation only -- not proof of activity'
    'Nessuna chiave registro VPN trovata' = 'No VPN registry keys found'
    "chiave/i registro VPN \(traccia installazione\)" = 'VPN registry key(s) found (installation footprint)'

    'Verifica driver TAP/TUN/Wintun installati' = 'Checking installed TAP/TUN/Wintun drivers'
    'Driver Virtuali VPN' = 'Virtual VPN Drivers'
    'Nessun driver TAP/TUN/Wintun trovato' = 'No TAP/TUN/Wintun drivers found'
    'Driver PnP' = 'PnP driver'
    'driver installato' = 'driver installed'
    'Driver \(servizio\)' = 'Driver (service)'
    'Driver kernel' = 'Kernel driver'
    "Driver VPN installati \(\$\(\$driverHits\.Count\)\) -- non prova di attivita'" = 'VPN drivers installed ($($driverHits.Count)) -- not proof of activity'

    'Verifica proxy di sistema e variabili ambiente' = 'Checking system proxy and environment variables'
    'Proxy di Sistema & Variabili Ambiente' = 'System Proxy & Environment Variables'
    'Proxy IE/WinINet' = 'IE/WinINet proxy'
    'Porta:' = 'Port:'
    'host nascosto' = 'host hidden'
    'Disabilitato' = 'Disabled'
    'Variabile' = 'Variable'
    'IMPOSTATA' = 'SET'
    'PAC Script \(Auto-Proxy\)' = 'PAC script (Auto-Proxy)'
    'PRESENTE' = 'PRESENT'
    'Assente' = 'Absent'
    'WinHTTP Proxy \(sistema\)' = 'WinHTTP proxy (system)'
    'Accesso diretto / Nessun proxy' = 'Direct access / No proxy'
    'Proxy di sistema attivo' = 'System proxy active'
    "Variabile proxy '" = "Proxy variable '"
    'PAC Script di auto-proxy configurato' = 'Auto-proxy PAC script configured'
    'WinHTTP proxy di sistema configurato' = 'System WinHTTP proxy configured'

    'Analisi MTU delle interfacce di rete' = 'Analyzing MTU on network interfaces'
    'MTU Fingerprinting' = 'MTU Fingerprinting'
    'Ethernet standard' = 'Standard Ethernet'
    'WireGuard tipico' = 'Typical WireGuard'
    'Tunnel IPSec/OpenVPN probabile' = 'Probable IPSec/OpenVPN tunnel'
    'Tunnel VPN con overhead elevato' = 'VPN tunnel with high overhead'
    'MTU molto ridotto -- tunnel profondo' = 'Very low MTU -- deep tunnel'
    'Standard' = 'Standard'
    'bytes' = 'bytes'
    'MTU di tutte le interfacce' = 'MTU on all interfaces'
    'Nella norma \(>= \$mtuThreshold\)' = 'Normal (>= $mtuThreshold)'
    'MTU ridotto rilevato -- tipico di tunnel VPN attivo' = 'Reduced MTU detected -- typical of active VPN tunnel'

    'Rilevamento connessioni Tor e reti anonime' = 'Detecting Tor and anonymous networks'
    'Tor, I2P & Reti Anonime' = 'Tor, I2P & Anonymous Networks'
    'Processo rete anonima' = 'Anonymous network process'
    'Porte Tor \(9050/9051/9150\)' = 'Tor ports (9050/9051/9150)'
    'APERTE' = 'OPEN'
    'Porte I2P \(4444/7656\)' = 'I2P ports (4444/7656)'
    'Directory Tor' = 'Tor directory'
    'Presente' = 'Present'
    'percorso nascosto per privacy' = 'path hidden for privacy'
    'Directory Tor presente \(installato, non necessariamente attivo\)' = 'Tor directory present (installed, not necessarily active)'
    'Processo rete anonima in esecuzione:' = 'Anonymous network process running:'
    'Porte Tor attive' = 'Tor ports active'
    'Porte I2P attive' = 'I2P ports active'
    'Nessuna rete anonima \(Tor/I2P\) attiva' = 'No anonymous network (Tor/I2P) active'

    'CALCOLO VERDETTI FINALI — SEPARATI' = 'FINAL VERDICT CALCULATION — SEPARATE STATES'
    'basato su prove in tempo reale' = 'based on real-time evidence'
    'basato su tracce passive' = 'based on passive footprints'
    'PROBABILE' = 'LIKELY'
    'NON ATTIVA' = 'NOT ACTIVE'
    'Prove concrete di traffico tunnelato ora' = 'Concrete evidence of traffic currently routed through a tunnel'
    'Segnali di attivita -- non conclusivi' = 'Signals of activity -- not conclusive'
    'Nessuna prova di tunnel attivo rilevata' = 'No evidence of an active tunnel detected'
    'PROBABILMENTE' = 'PROBABLY'
    'Software/driver VPN presenti sul sistema' = 'VPN software/drivers present on the system'
    'Alcune tracce di installazione VPN' = 'Some VPN installation traces found'
    'Nessuna traccia di software VPN installato' = 'No trace of installed VPN software'

    'RIEPILOGO CHECK' = 'CHECK SUMMARY'
    'Segnale VPN attiva' = 'Active VPN signal'
    'Solo installazione' = 'Installation only'
    'Negativo' = 'Negative'
    'Adattatori Rete' = 'Network Adapters'
    'DNS / Leak' = 'DNS / Leak'
    'Porte / Conn\.' = 'Ports / Conn.'
    'Software Inst\.' = 'Installed SW'
    'ASN / Tipo Rete' = 'ASN / Net Type'
    'Proxy Sistema' = 'System Proxy'
    'Driver TAP/TUN' = 'TAP/TUN Drivers'
    'Tor / I2P' = 'Tor / I2P'

    "RISULTATO FINALE DELL'ANALISI" = 'FINAL TESLAPRO ANALYSIS RESULT'
    'VPN ATTIVA IN QUESTO MOMENTO\?' = 'IS A VPN ACTIVE RIGHT NOW?'
    'VPN INSTALLATA SUL SISTEMA\?' = 'IS A VPN INSTALLED ON THIS SYSTEM?'
    "Attivita' in tempo reale:" = 'Real-time activity:'
    'Tracce installazione:' = 'Installation traces:'
    'Check attivi \(tunnel\):' = 'Active checks (tunnel):'
    'Check installazione:' = 'Installation checks:'
    "Prove di attivita' VPN/tunnel:" = 'Evidence of active VPN/tunnel:'
    'Tracce di installazione VPN:' = 'VPN installation traces:'
    'Nessuna evidenza di VPN o proxy raccolta\.' = 'No VPN or proxy evidence collected.'

    'PRIVACY: IP, ISP, Hostname, Citta, Regione, Timezone -- MAI mostrati' = 'PRIVACY: IP, ISP, hostname, city, region, timezone -- NEVER shown'
    'Analisi:' = 'Analysis:'
    'Host:' = 'Host:'
    'Utente:' = 'User:'
    'Report JSON:' = 'JSON report:'
}

foreach ($pattern in $replacements.Keys) {
    $content = [regex]::Replace($content, $pattern, $replacements[$pattern])
}

# TeslaPro visual tweaks
$content = $content -replace '\$\(\$C\.Cyan\)', '$($C.Red)'
$content = $content -replace '\$\(\$C\.Purple\)', '$($C.White)'
$content = $content -replace '\$\(\$C\.Orange\)', '$($C.Yellow)'
$content = $content -replace 'Advanced Network Intelligence', 'TeslaPro Network Telemetry'
$content = $content -replace 'Privacy Mode ON', 'Privacy Shield ON'

# Optional branding additions
$content = $content -replace 'function Write-Banner \{', @'
function Write-Banner {
    # TeslaPro Edition branding layer
'@

Set-Content -Path $OutputPath -Value $content -Encoding UTF8
Write-Host "TeslaPro conversion complete: $OutputPath"
