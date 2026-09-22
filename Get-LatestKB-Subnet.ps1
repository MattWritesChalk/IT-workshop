<#
.SYNOPSIS
    Scans an IP range for live Windows machines and reports the most recently installed
    OS update (KB) on each, exporting a color-coded Excel workbook.

.DESCRIPTION
    Reuses the subnet-scan logic of Get-AutopilotHashes-Subnet-PsExec.ps1:

    1. Pings every IP in the range (in parallel) to find live hosts.
    2. Checks WinRM (TCP 5985) on each live host.
    3. Resolves hostnames via reverse DNS (Kerberos works by name; falls back to IP).
    4. WinRM path: queries the latest installed KB via Invoke-Command (+ IP retry).
    5. PsExec fallback: any live host WITHOUT WinRM, plus any WinRM host that failed
       every remoting attempt, is queried via PsExec -> remote powershell (as SYSTEM).
    6. Exports one workbook with two tabs:
         - 'Summary': machine counts per OS version, split into OK / yellow / red, with
           a TOTAL row.
         - 'KB Audit': one row per machine - ComputerName, IP, OS Version (e.g. 22H2/23H2),
           OS Build (build.revision), Latest KB, KB Publish Date, KB Install Date, Age (days),
           an optional Group Tag column (only when -GroupTag is passed), and Description.
       Detail rows are flagged:
         - YELLOW when the newest KB is older than 2 months
         - RED    when the newest KB is older than 6 months

    "Latest KB" is the Hotfix/QFE with the newest InstalledOn date returned by the OS
    (Get-HotFix / Win32_QuickFixEngineering). The KB's *publish* date is looked up from
    the Microsoft Update Catalog over the internet (the machine running THIS script needs
    outbound HTTPS to catalog.update.microsoft.com); if the catalog can't be reached the
    publish date is left blank and only the install date drives the color flag.

    Output format: .xlsx via the ImportExcel module if available (Install-Module ImportExcel).
    If ImportExcel is not installed, falls back to a .csv (no coloring) and tells you.

    PsExec requirements (fallback only) - identical to the Autopilot script:
      - PsExec.exe available (Sysinternals). Pass -PsExecPath or put it on PATH.
      - SMB (TCP 445) + admin$ reachable; account with local admin on the target.
      - Runs the remote query as SYSTEM (-s).

    SECURITY NOTE: when -Credential is used, PsExec receives the password via -p on the
    child process command line in clear text (briefly visible to local process listing).
    That's inherent to PsExec. Omit -Credential to authenticate as the current user.

.EXAMPLE
    .\Get-LatestKB-Subnet.ps1 -StartIP 10.3.12.22 -EndIP 10.3.12.25

.EXAMPLE
    .\Get-LatestKB-Subnet.ps1 -StartIP 10.4.20.1 -EndIP 10.4.20.254 `
        -Credential (Get-Credential CAM\m_goldzman) -OutputPath C:\Temp\KBAudit.xlsx

.EXAMPLE
    # WinRM-less subnet routes to the PsExec fallback automatically:
    .\Get-LatestKB-Subnet.ps1 -StartIP 10.4.20.1 -EndIP 10.4.20.254 `
        -PsExecPath C:\Tools\PsExec64.exe -Credential (Get-Credential)
#>

[CmdletBinding(DefaultParameterSetName = 'Scan')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Scan')]
    [ValidateScript({ $null -ne ($_ -as [System.Net.IPAddress]) })]
    [string]$StartIP,

    [Parameter(Mandatory, ParameterSetName = 'Scan')]
    [ValidateScript({ $null -ne ($_ -as [System.Net.IPAddress]) })]
    [string]$EndIP,

    # Test mode: skip the subnet scan and just resolve one KB's publish date from the catalog,
    # printing the result (and, with -DumpCatalogHtml, the raw HTML). Use to validate the lookup.
    #   .\Get-LatestKB-Subnet.ps1 -TestKB KB5062553 -Verbose -DumpCatalogHtml .\catalog-dump
    [Parameter(Mandatory, ParameterSetName = 'Test')]
    [string]$TestKB,

    [string]$OutputPath = ".\KBAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx",

    [System.Management.Automation.PSCredential]$Credential,

    [int]$PingTimeoutMs = 1000,

    [int]$ThrottleLimit = 32,

    # Optional free-text tag written to a 'Group Tag' column on every row (e.g. a site or wave name)
    [string]$GroupTag = '',

    # Age thresholds (based on the KB's publish date when known, else install date)
    [int]$WarnMonths = 2,     # yellow
    [int]$StaleMonths = 6,    # red

    # Look up KB publish dates from the Microsoft Update Catalog (needs internet on THIS host)
    [switch]$NoCatalogLookup,

    # Write the raw catalog HTML for each looked-up KB to this dir (for diagnosing blank dates)
    [string]$DumpCatalogHtml,

    # --- PsExec fallback options ---
    [string]$PsExecPath = 'psexec.exe',
    [int]$PsExecConnectTimeoutSec = 20,
    [switch]$NoPsExec   # disable the fallback
)

$ErrorActionPreference = 'Stop'

#region Helpers -------------------------------------------------------------

function ConvertTo-Int64FromIP ([string]$IP) {
    $bytes = ([System.Net.IPAddress]::Parse($IP)).GetAddressBytes()
    [Array]::Reverse($bytes)
    [BitConverter]::ToUInt32($bytes, 0)
}

function ConvertTo-IPFromInt64 ([int64]$Int) {
    $bytes = [BitConverter]::GetBytes([uint32]$Int)
    [Array]::Reverse($bytes)
    ([System.Net.IPAddress]::new($bytes)).ToString()
}

# The remote query, as a here-string so it can be run either via Invoke-Command (scriptblock
# below) or via PsExec (base64-encoded). Emits ONE delimited marker line so PsExec's noise
# can be filtered out. Fields: KB | InstalledOn(ticks) | Caption | OSCaption | DisplayVersion | OSBuild.
# DisplayVersion (e.g. 22H2/23H2) comes from the registry; OSBuild is the full build.revision.
$remoteKBText = @'
$ErrorActionPreference='Stop'
try {
  $hf = Get-HotFix -ErrorAction Stop |
        Where-Object { $_.HotFixID -match '^KB\d+' -and $_.InstalledOn } |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 1
  if(-not $hf){ throw 'no dated KB hotfixes found' }
  $ticks = $hf.InstalledOn.ToUniversalTime().Ticks
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
  $rk = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $cv = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
  $disp = $cv.DisplayVersion; if(-not $disp){ $disp = $cv.ReleaseId }
  $ubr  = $cv.UBR
  $build = if($os){ $os.BuildNumber } else { $cv.CurrentBuildNumber }
  $fullBuild = if($ubr){ "$build.$ubr" } else { "$build" }
  $caption = if($os){ $os.Caption } else { $cv.ProductName }
  Write-Output ('##KB##|'+$hf.HotFixID+'|'+$ticks+'|'+$hf.Description+'|'+$caption+'|'+$disp+'|'+$fullBuild)
} catch {
  Write-Output ('##KBERR##|'+$_.Exception.Message)
}
'@

# Parse the "##KB##|..." marker line into a result object (shared by both transports).
function ConvertFrom-KBMarker {
    param([string[]]$Lines, [string]$Computer, [string]$IP)

    $line = $Lines | Where-Object { $_ -match '##KB##\|' -or $_ -match '##KBERR##\|' } |
            Select-Object -First 1

    if ($line -match '##KB##\|(.+?)\|(\d+)\|(.*?)\|(.*?)\|(.*?)\|(.*)$') {
        $installed = [datetime]::new([int64]$matches[2], [System.DateTimeKind]::Utc).ToLocalTime()
        return [pscustomobject]@{
            ComputerName   = $Computer
            IP             = $IP
            KB             = $matches[1].Trim()
            Caption        = $matches[3].Trim()
            OSCaption      = $matches[4].Trim()
            DisplayVersion = $matches[5].Trim()
            OSBuild        = $matches[6].Trim()
            InstalledOn    = $installed
        }
    }
    # Back-compat: older 4-field marker (no OS fields) still parses.
    elseif ($line -match '##KB##\|(.+?)\|(\d+)\|(.*)$') {
        $installed = [datetime]::new([int64]$matches[2], [System.DateTimeKind]::Utc).ToLocalTime()
        return [pscustomobject]@{
            ComputerName   = $Computer
            IP             = $IP
            KB             = $matches[1].Trim()
            Caption        = $matches[3].Trim()
            OSCaption      = ''
            DisplayVersion = ''
            OSBuild        = ''
            InstalledOn    = $installed
        }
    }
    elseif ($line -match '##KBERR##\|(.+)$') {
        throw $matches[1].Trim()
    }
    else {
        throw 'no parseable KB output'
    }
}

# Collect one machine via PsExec -> remote powershell (as SYSTEM).
function Invoke-PsExecKB {
    param(
        [string]$Computer, [string]$IP,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$PsExecPath, [int]$ConnectTimeoutSec
    )
    $enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($script:remoteKBText))

    $pxArgs = @("\\$Computer", '-accepteula', '-nobanner', '-n', "$ConnectTimeoutSec", '-s')
    if ($Credential) {
        $pxArgs += @('-u', $Credential.UserName, '-p', $Credential.GetNetworkCredential().Password)
    }
    $pxArgs += @('powershell.exe', '-NonInteractive', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                 '-EncodedCommand', $enc)

    $out  = & $PsExecPath @pxArgs 2>&1
    $text = $out | ForEach-Object { "$_" }
    return ConvertFrom-KBMarker -Lines $text -Computer $Computer -IP $IP
}

# Look up a KB's public release date from the Microsoft Update Catalog. Best-effort; returns
# $null on any failure. Cached per-KB so we hit the catalog once per distinct KB.
#
# The catalog's markup has shifted over time and the search page's date column is partly
# script-driven, so this tries SEVERAL extraction methods and takes the first that yields a
# date. If -DumpCatalogHtml <dir> is set, the raw search + detail HTML for each KB is written
# there so the exact markup can be inspected when a lookup comes back blank.
$script:catalogCache = @{}
$script:catalogFailReason = $null      # last failure reason, surfaced once at run level
$script:catalogUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'

function Get-CatalogPage {
    param([string]$Url)
    # PS 5.1's Invoke-WebRequest uses the IE engine unless -UseBasicParsing; force TLS 1.2 too,
    # since older hosts default to TLS 1.0 and the catalog refuses it.
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
    Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30 `
        -Headers @{ 'User-Agent' = $script:catalogUA } -ErrorAction Stop
}

function Get-DatesFromDetailHtml {
    # Pull the release date from a ScopedViewInline detail page. Confirmed markup:
    #   <span id="ScopedViewHandler_date">7/8/2025</span>   (M/D/YYYY, culture-formatted)
    # A couple of fallbacks are kept in case the id changes on a future catalog revision.
    param([string]$Html)
    $raw = @()

    # Primary: the confirmed date span id.
    foreach ($m in [regex]::Matches($Html,
        'id="ScopedViewHandler_date"[^>]*>\s*([^<]+?)\s*<')) {
        $raw += $m.Groups[1].Value
    }
    # Fallbacks (only if the primary id ever changes): other date-ish ids, then a labelled field.
    if (-not $raw) {
        foreach ($m in [regex]::Matches($Html,
            'id="[^"]*(?:_date|labelLastUpdated|dateCreated|datePublished)[^"]*"[^>]*>\s*([^<]+?)\s*<')) {
            $raw += $m.Groups[1].Value
        }
        foreach ($m in [regex]::Matches($Html,
            '(?is)Last Updated[^0-9]{0,60}(\d{1,2}/\d{1,2}/\d{4})')) {
            $raw += $m.Groups[1].Value
        }
    }

    # Parse to [datetime], keep only sane dates, newest first.
    $raw | ForEach-Object {
        [datetime]$parsed = 0
        if ([datetime]::TryParse($_.Trim(), [ref]$parsed)) { $parsed }
    } | Where-Object { $_ -and $_.Year -ge 2000 -and $_ -le (Get-Date).AddDays(2) } |
        Sort-Object -Descending
}

function Get-KBDateFromSupport {
    # Fallback for KBs not in the Update Catalog (e.g. OOBE/setup updates, some definition
    # updates). The support.microsoft.com article carries a structured
    #   <meta name="meta-release-date" content="MM/DD/YYYY">
    # in its head. https://support.microsoft.com/help/<number> redirects to that article, so
    # one request (following redirects) gets us the page. Returns [datetime] or $null.
    param([string]$KB)
    $num = ($KB -replace '(?i)^KB', '').Trim()
    if (-not $num) { return $null }

    try {
        $url = "https://support.microsoft.com/help/$num"
        $resp = Get-CatalogPage -Url $url    # same TLS/UA/redirect-following request helper
        if ($DumpCatalogHtml) {
            $resp.Content | Out-File (Join-Path $DumpCatalogHtml "$KB-support.html") -Encoding UTF8
        }

        # Primary: the meta-release-date tag (attribute order varies, so match both forms).
        $m = [regex]::Match($resp.Content,
                '(?is)meta-release-date"[^>]*?content="([^"]+)"')
        if (-not $m.Success) {
            $m = [regex]::Match($resp.Content,
                '(?is)content="([^"]+)"[^>]*?name="meta-release-date"')
        }
        # Fallback: a "Month D, YYYY" in the article <title> (e.g. "...: June 23, 2026").
        $cand = @()
        if ($m.Success) { $cand += $m.Groups[1].Value }
        foreach ($t in [regex]::Matches($resp.Content,
                '(?i)(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4}')) {
            $cand += $t.Value
        }

        foreach ($c in $cand) {
            [datetime]$parsed = 0
            if ([datetime]::TryParse($c.Trim(), [ref]$parsed) -and
                $parsed.Year -ge 2000 -and $parsed -le (Get-Date).AddDays(2)) {
                return $parsed
            }
        }
    } catch {
        Write-Verbose "  support.microsoft.com lookup failed for ${KB}: $($_.Exception.Message)"
    }
    return $null
}

function Get-KBPublishDate {
    param([string]$KB)
    if ($NoCatalogLookup -or -not $KB) { return $null }
    if ($script:catalogCache.ContainsKey($KB)) { return $script:catalogCache[$KB] }

    $date = $null
    $catalogNote = $null
    try {
        # --- 1. search page: used ONLY to collect the update GUID(s) for this KB. ---
        # (The date column on the search page is filled client-side and is NOT in the raw HTML,
        #  so we always follow through to the per-update detail page for the actual date.)
        $searchUrl = "https://www.catalog.update.microsoft.com/Search.aspx?q=$KB"
        $resp = Get-CatalogPage -Url $searchUrl
        if ($DumpCatalogHtml) {
            $resp.Content | Out-File (Join-Path $DumpCatalogHtml "$KB-search.html") -Encoding UTF8
        }

        # GUIDs appear as <input id="GUID"> / id="GUID_link" / goToDetails("GUID"). A generic
        # GUID match catches all of these; unique them.
        $guids = [regex]::Matches($resp.Content,
                    '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') |
                 ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
        if (-not $guids) { throw "not in catalog" }

        # --- 2. detail page per GUID -> "Last Updated" date. Take the newest across products. ---
        $found = foreach ($g in ($guids | Select-Object -First 8)) {
            try {
                $detUrl = "https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=$g"
                $det = Get-CatalogPage -Url $detUrl
                if ($DumpCatalogHtml) {
                    $det.Content | Out-File (Join-Path $DumpCatalogHtml "$KB-detail-$g.html") -Encoding UTF8
                }
                Get-DatesFromDetailHtml -Html $det.Content | Select-Object -First 1
            } catch {
                Write-Verbose "  detail page $g failed: $($_.Exception.Message)"
            }
        }
        if ($found) { $date = ($found | Sort-Object -Descending | Select-Object -First 1) }
        if (-not $date) { $catalogNote = "found $($guids.Count) update(s) but no parseable date on any detail page" }
    }
    catch {
        $catalogNote = $_.Exception.Message
    }

    # --- 3. fallback: support.microsoft.com article (handles KBs not in the catalog). ---
    if (-not $date) {
        Write-Verbose "  catalog miss for ${KB} ($catalogNote); trying support.microsoft.com..."
        $date = Get-KBDateFromSupport -KB $KB
        if ($date) { Write-Verbose "  resolved $KB via support.microsoft.com" }
    }

    if (-not $date) {
        $script:catalogFailReason = "no date from catalog ($catalogNote) or support.microsoft.com for $KB (dump with -DumpCatalogHtml to inspect)"
        Write-Verbose "  $script:catalogFailReason"
    }

    $script:catalogCache[$KB] = $date
    return $date
}

# Ensure the dump dir exists if requested.
if ($DumpCatalogHtml) {
    if (-not (Test-Path $DumpCatalogHtml)) {
        New-Item -ItemType Directory -Path $DumpCatalogHtml -Force | Out-Null
    }
    $DumpCatalogHtml = (Resolve-Path $DumpCatalogHtml).Path
    Write-Host "Catalog HTML will be dumped to: $DumpCatalogHtml" -ForegroundColor DarkGray
}

# --- Test mode: resolve one KB and exit (no scan) ---
if ($PSCmdlet.ParameterSetName -eq 'Test') {
    Write-Host "Resolving publish date for $TestKB from the Update Catalog..." -ForegroundColor Cyan
    $d = Get-KBPublishDate -KB $TestKB
    if ($d) {
        Write-Host ("  {0} published/updated: {1:yyyy-MM-dd}" -f $TestKB, $d) -ForegroundColor Green
    } else {
        Write-Warning "  No date resolved for $TestKB."
        if ($script:catalogFailReason) { Write-Warning "  Reason: $script:catalogFailReason" }
        Write-Warning "  Re-run with -DumpCatalogHtml <dir> and inspect the saved HTML, or check outbound HTTPS to catalog.update.microsoft.com."
    }
    return
}

#endregion

#region 1. Expand IP range --------------------------------------------------

$start = ConvertTo-Int64FromIP $StartIP
$end   = ConvertTo-Int64FromIP $EndIP
if ($end -lt $start) { throw "EndIP ($EndIP) is lower than StartIP ($StartIP)." }

$ipList = for ($i = $start; $i -le $end; $i++) { ConvertTo-IPFromInt64 $i }
Write-Host "Scanning $($ipList.Count) addresses ($StartIP - $EndIP)..." -ForegroundColor Cyan

#endregion

#region 2. Parallel ping sweep ----------------------------------------------

$pingTasks = foreach ($ip in $ipList) {
    $ping = [System.Net.NetworkInformation.Ping]::new()
    [pscustomobject]@{ IP = $ip; Task = $ping.SendPingAsync($ip, $PingTimeoutMs) }
}
try { [System.Threading.Tasks.Task]::WaitAll(@($pingTasks.Task)) } catch { }

$liveIPs = $pingTasks |
    Where-Object { $_.Task.Status -eq 'RanToCompletion' -and $_.Task.Result.Status -eq 'Success' } |
    Select-Object -ExpandProperty IP

Write-Host "Live hosts: $($liveIPs.Count)" -ForegroundColor Green
if (-not $liveIPs) { Write-Warning "No live hosts found. Exiting."; return }

#endregion

#region 3. WinRM port check + hostname resolution ---------------------------

$targets = foreach ($ip in $liveIPs) {
    $client = [System.Net.Sockets.TcpClient]::new()
    $winrmOpen = $false
    try { $winrmOpen = $client.ConnectAsync($ip, 5985).Wait(2000) -and $client.Connected }
    catch { } finally { $client.Dispose() }

    $name = $ip
    try { $name = ([System.Net.Dns]::GetHostEntry($ip)).HostName } catch { }

    [pscustomobject]@{ IP = $ip; Target = $name; WinRM = $winrmOpen }
}

$winrmTargets = @($targets | Where-Object { $_.WinRM })
$noWinrm      = @($targets | Where-Object { -not $_.WinRM })
Write-Host "Targets with WinRM: $($winrmTargets.Count)   without WinRM: $($noWinrm.Count)" -ForegroundColor Green

#endregion

#region 4. WinRM collection -------------------------------------------------

$collectBlock = {
    $hf = Get-HotFix -ErrorAction Stop |
          Where-Object { $_.HotFixID -match '^KB\d+' -and $_.InstalledOn } |
          Sort-Object InstalledOn -Descending |
          Select-Object -First 1
    if (-not $hf) { throw "no dated KB hotfixes found" }
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $rk = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $cv = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
    $disp = $cv.DisplayVersion; if (-not $disp) { $disp = $cv.ReleaseId }
    $build = if ($os) { $os.BuildNumber } else { $cv.CurrentBuildNumber }
    $fullBuild = if ($cv.UBR) { "$build.$($cv.UBR)" } else { "$build" }
    [pscustomobject]@{
        ComputerName   = $env:COMPUTERNAME
        KB             = $hf.HotFixID
        Caption        = $hf.Description
        OSCaption      = if ($os) { $os.Caption } else { $cv.ProductName }
        DisplayVersion = $disp
        OSBuild        = $fullBuild
        InstalledOn    = $hf.InstalledOn
    }
}

$raw = @()          # normalized rows: ComputerName, IP, KB, Caption, InstalledOn
$icmResults = @()
$icmErrors = @()

# Map connection-string -> IP so we can stamp the IP back onto each WinRM result.
$nameToIP = @{}
foreach ($t in $winrmTargets) { $nameToIP[$t.Target] = $t.IP; $nameToIP[$t.IP] = $t.IP }

if ($winrmTargets.Count -gt 0) {
    $icmParams = @{
        ScriptBlock   = $collectBlock
        ThrottleLimit = $ThrottleLimit
        ErrorAction   = 'SilentlyContinue'
        ErrorVariable = 'icmErrors'
    }
    if ($Credential) { $icmParams.Credential = $Credential }

    Write-Host "Querying KBs via WinRM from $($winrmTargets.Count) machine(s)..." -ForegroundColor Cyan
    $icmResults = @(Invoke-Command @icmParams -ComputerName $winrmTargets.Target)

    $failedNames = @($icmErrors | ForEach-Object {
            if ($_.TargetObject) { $_.TargetObject } else { $_.OriginInfo.PSComputerName }
        } | Where-Object { $_ } | Select-Object -Unique)

    $retry = @($winrmTargets | Where-Object { $failedNames -contains $_.Target -and $_.Target -ne $_.IP })
    if ($retry.Count -gt 0) {
        $trusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
        if (-not $trusted) {
            Write-Warning "TrustedHosts is empty - IP retries will likely be refused. To allow:"
            Write-Warning '  Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.0.0.*" -Concatenate'
        }
        Write-Host "Retrying $($retry.Count) failed host(s) by IP address..." -ForegroundColor Yellow
        $icmParams.ErrorVariable = 'retryErrors'
        $icmResults += @(Invoke-Command @icmParams -ComputerName $retry.IP)
    }

    foreach ($r in $icmResults) {
        $conn = $r.PSComputerName
        $ip   = if ($nameToIP.ContainsKey($conn)) { $nameToIP[$conn] } else { $conn }
        $raw += [pscustomobject]@{
            ComputerName   = $r.ComputerName
            IP             = $ip
            KB             = $r.KB
            Caption        = $r.Caption
            OSCaption      = $r.OSCaption
            DisplayVersion = $r.DisplayVersion
            OSBuild        = $r.OSBuild
            InstalledOn    = $r.InstalledOn
        }
    }
}

#endregion

#region 5. PsExec fallback --------------------------------------------------

$failed = @()

$reached = @($icmResults | ForEach-Object { $_.PSComputerName } | Where-Object { $_ })
$unreachedWinrm = @($winrmTargets | Where-Object { $reached -notcontains $_.Target -and $reached -notcontains $_.IP })
$candidates = @($noWinrm + $unreachedWinrm | Sort-Object IP -Unique)

if ($NoPsExec) {
    foreach ($c in $candidates) { $failed += [pscustomobject]@{ Host = $c.Target; Reason = 'WinRM failed; PsExec disabled (-NoPsExec)' } }
}
elseif ($candidates.Count -gt 0) {
    $px = Get-Command $PsExecPath -ErrorAction SilentlyContinue
    if (-not $px) {
        Write-Warning "PsExec not found ('$PsExecPath'). Get it from Sysinternals and pass -PsExecPath, or add it to PATH."
        foreach ($c in $candidates) { $failed += [pscustomobject]@{ Host = $c.Target; Reason = 'WinRM failed; PsExec.exe not found' } }
    }
    else {
        Write-Host "PsExec fallback for $($candidates.Count) host(s)..." -ForegroundColor Cyan
        foreach ($c in $candidates) {
            $obj = $null; $reason = ''
            $attempts = @($c.Target); if ($c.IP -ne $c.Target) { $attempts += $c.IP }
            foreach ($addr in $attempts) {
                try {
                    $obj = Invoke-PsExecKB -Computer $addr -IP $c.IP -Credential $Credential `
                              -PsExecPath $px.Source -ConnectTimeoutSec $PsExecConnectTimeoutSec
                    break
                } catch { $reason = $_.Exception.Message }
            }
            if ($obj) {
                Write-Host "  [PsExec] $($c.Target) -> $($obj.KB)" -ForegroundColor Gray
                $raw += $obj
            } else {
                Write-Warning "  [PsExec] FAILED: $($c.Target) - $reason"
                $failed += [pscustomobject]@{ Host = $c.Target; Reason = "PsExec: $reason" }
            }
        }
    }
}

foreach ($e in $icmErrors) {
    $h = $e.TargetObject; if (-not $h) { $h = $e.OriginInfo.PSComputerName }
    Write-Verbose "WinRM error on ${h}: $($e.Exception.Message)"
}

#endregion

#region 6. Enrich with publish date + age, build final rows -----------------

if (-not $raw) { Write-Warning "No KB data collected."; return }

$now = Get-Date
$warnCut  = $now.AddMonths(-$WarnMonths)
$staleCut = $now.AddMonths(-$StaleMonths)

if (-not $NoCatalogLookup) {
    Write-Host "Looking up KB publish dates from the Update Catalog..." -ForegroundColor Cyan
}

$rows = foreach ($r in ($raw | Sort-Object ComputerName -Unique)) {
    $pub = Get-KBPublishDate -KB $r.KB
    # Age is driven by publish date when we have it, otherwise by install date.
    $ageBasis = if ($pub) { $pub } else { $r.InstalledOn }
    $flag = 'OK'
    if     ($ageBasis -lt $staleCut) { $flag = 'STALE' }   # red   (>6 mo)
    elseif ($ageBasis -lt $warnCut)  { $flag = 'WARN'  }   # yellow(>2 mo)

    [pscustomobject]@{
        'ComputerName'   = $r.ComputerName
        'IP'             = $r.IP
        'OS Version'     = $r.DisplayVersion
        'OS Build'       = $r.OSBuild
        'Latest KB'      = $r.KB
        'KB Publish Date'= if ($pub) { $pub.ToString('yyyy-MM-dd') } else { '' }
        'KB Install Date'= $r.InstalledOn.ToString('yyyy-MM-dd')
        'Age (days)'     = [int]((New-TimeSpan -Start $ageBasis -End $now).TotalDays)
        'Group Tag'      = $GroupTag
        'Flag'           = $flag
        'Description'    = $r.Caption
    }
}
$rows = @($rows | Sort-Object { switch ($_.Flag) { 'STALE' {0} 'WARN' {1} default {2} } }, 'Age (days)' -Descending:$false)

# If the catalog was queried but nothing resolved, say why once (rather than a silent blank column).
if (-not $NoCatalogLookup) {
    $gotAny = @($rows | Where-Object { $_.'KB Publish Date' -ne '' }).Count
    if ($gotAny -eq 0) {
        Write-Warning "No KB publish dates were resolved - the 'KB Publish Date' column is blank and flags fall back to install date."
        if ($script:catalogFailReason) {
            Write-Warning "  Last catalog error: $script:catalogFailReason"
        }
        Write-Warning "  This host needs outbound HTTPS to catalog.update.microsoft.com (check proxy/firewall), or run with -NoCatalogLookup to skip the lookup."
    }
    elseif ($gotAny -lt $rows.Count) {
        Write-Host "Publish date resolved for $gotAny of $($rows.Count) machine(s); the rest fall back to install date." -ForegroundColor DarkGray
    }
}

#endregion

#region 7. Export -----------------------------------------------------------

$haveImportExcel = [bool](Get-Module -ListAvailable -Name ImportExcel)

# Column set for the detail sheet. Group Tag is only included when -GroupTag was supplied,
# so an untagged run keeps the report tidy.
$detailCols = @('ComputerName','IP','OS Version','OS Build','Latest KB',
                'KB Publish Date','KB Install Date','Age (days)')
if ($GroupTag -ne '') { $detailCols += 'Group Tag' }
$detailCols += 'Description'

# Build the summary rows: counts per OS Version x Flag, plus a totals line. Pivoted in
# PowerShell (LibreOffice/Excel pivot caches aren't worth the fragility here).
$byVersion = $rows | Group-Object 'OS Version' | Sort-Object Name
$summary = foreach ($g in $byVersion) {
    $vname = if ($g.Name) { $g.Name } else { '(unknown)' }
    [pscustomobject]@{
        'OS Version'    = $vname
        'Total'         = $g.Count
        'OK'            = @($g.Group | Where-Object Flag -eq 'OK').Count
        'Yellow (>2mo)' = @($g.Group | Where-Object Flag -eq 'WARN').Count
        'Red (>6mo)'    = @($g.Group | Where-Object Flag -eq 'STALE').Count
    }
}
$summary = @($summary) + [pscustomobject]@{
    'OS Version'    = 'TOTAL'
    'Total'         = $rows.Count
    'OK'            = @($rows | Where-Object Flag -eq 'OK').Count
    'Yellow (>2mo)' = @($rows | Where-Object Flag -eq 'WARN').Count
    'Red (>6mo)'    = @($rows | Where-Object Flag -eq 'STALE').Count
}

if ($haveImportExcel) {
    Import-Module ImportExcel
    if ($OutputPath -notmatch '\.xlsx$') { $OutputPath = [IO.Path]::ChangeExtension($OutputPath, 'xlsx') }
    if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }

    $yellow = [System.Drawing.Color]::FromArgb(255, 255, 235, 156)  # soft yellow
    $red    = [System.Drawing.Color]::FromArgb(255, 255, 199, 206)  # soft red

    # --- Summary tab (written first so it lands as the left-most sheet) ---
    $excel = $summary |
        Export-Excel -Path $OutputPath -WorksheetName 'Summary' -AutoSize -BoldTopRow `
                     -PassThru
    $wsS = $excel.Workbook.Worksheets['Summary']
    $sEnd = $wsS.Dimension.End.Row
    # Bold + top-border the TOTAL row.
    $wsS.Cells[$sEnd, 1, $sEnd, 5].Style.Font.Bold = $true
    $wsS.Cells[$sEnd, 1, $sEnd, 5].Style.Border.Top.Style = 'Thin'
    # Tint the yellow/red count columns (D/E) where the count is non-zero.
    for ($i = 0; $i -lt $summary.Count; $i++) {
        $sr = $i + 2
        if ($summary[$i].'Yellow (>2mo)' -gt 0) {
            $wsS.Cells[$sr, 4].Style.Fill.PatternType = 'Solid'
            $wsS.Cells[$sr, 4].Style.Fill.BackgroundColor.SetColor($yellow)
        }
        if ($summary[$i].'Red (>6mo)' -gt 0) {
            $wsS.Cells[$sr, 5].Style.Fill.PatternType = 'Solid'
            $wsS.Cells[$sr, 5].Style.Fill.BackgroundColor.SetColor($red)
        }
    }

    # --- Detail tab ---
    $nCols = $detailCols.Count
    $excel = $rows | Select-Object $detailCols |
        Export-Excel -ExcelPackage $excel -WorksheetName 'KB Audit' -AutoSize -FreezeTopRow -BoldTopRow `
                     -AutoFilter -PassThru
    $ws = $excel.Workbook.Worksheets['KB Audit']
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $excelRow = $i + 2   # header is row 1
        $fill = switch ($rows[$i].Flag) { 'STALE' { $red } 'WARN' { $yellow } default { $null } }
        if ($fill) {
            $ws.Cells[$excelRow, 1, $excelRow, $nCols].Style.Fill.PatternType = 'Solid'
            $ws.Cells[$excelRow, 1, $excelRow, $nCols].Style.Fill.BackgroundColor.SetColor($fill)
        }
    }
    Close-ExcelPackage $excel
    $outResolved = (Resolve-Path $OutputPath).Path
    Write-Host "`nExcel written: $outResolved" -ForegroundColor Green
    Write-Host "  Sheets: 'Summary' (counts by OS version + flag) and 'KB Audit' (per-machine detail)." -ForegroundColor DarkGray
}
else {
    Write-Warning "ImportExcel module not found - writing CSV instead (no color coding, no summary tab)."
    Write-Warning "  To get the colored .xlsx:  Install-Module ImportExcel -Scope CurrentUser"
    if ($OutputPath -notmatch '\.csv$') { $OutputPath = [IO.Path]::ChangeExtension($OutputPath, 'csv') }
    # CSV keeps the Flag column (can't color) and always includes Group Tag for completeness.
    $csvCols = @($detailCols | Where-Object { $_ -ne 'Description' })
    if ($csvCols -notcontains 'Group Tag') { $csvCols += 'Group Tag' }
    $csvCols += 'Flag'
    $csvCols += 'Description'
    $rows | Select-Object $csvCols |
        Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    $outResolved = (Resolve-Path $OutputPath).Path
    Write-Host "`nCSV written: $outResolved" -ForegroundColor Green
    Write-Host "  Summary by OS version:" -ForegroundColor DarkGray
    $summary | Format-Table -AutoSize
}

$warnN  = @($rows | Where-Object Flag -eq 'WARN').Count
$staleN = @($rows | Where-Object Flag -eq 'STALE').Count
Write-Host ("Reported {0} host(s): {1} OK, {2} yellow (>{3} mo), {4} red (>{5} mo); {6} failure(s)." -f `
    $rows.Count, ($rows.Count - $warnN - $staleN), $warnN, $WarnMonths, $staleN, $StaleMonths, $failed.Count) -ForegroundColor Green

$rows | Select-Object ComputerName, IP, 'Latest KB', 'KB Install Date', Flag | Format-Table -AutoSize
if ($failed.Count -gt 0) {
    Write-Host "Not collected ($($failed.Count)):" -ForegroundColor Yellow
    $failed | Format-Table -AutoSize
}

#endregion
