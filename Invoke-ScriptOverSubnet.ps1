#Requires -Version 5.1
<#
.SYNOPSIS
    Runs any local .ps1 against every WinRM-reachable machine in an IP range and
    collects the combined output into a single .xlsx (or .csv).

.DESCRIPTION
    Generalized from Get-AutopilotHashes-Subnet.ps1 - same discovery pipeline,
    but the payload is whatever script you point it at instead of a hardcoded
    hardware-hash collector.

    1. Pings every IP in the range (in parallel) to find live hosts.
    2. Checks the WinRM port (default 5985) is reachable on each live host.
    3. Resolves hostnames via reverse DNS (Kerberos auth works by name; falls back to IP).
    4. Ships the contents of -ScriptPath to each machine and executes it via
       Invoke-Command, passing along -ArgumentList / -ScriptParameters.
    5. Flattens all returned objects into one table (union of every property seen)
       and writes an .xlsx with two sheets:
         Results - one row per object returned, tagged with ComputerName + SourceIP
         Status  - one row per live host: WinRM state, rows returned, error text

    The target script runs in a remote session, so:
      - It must be self-contained (no dot-sourcing local files, no local modules).
      - Anything it writes to the success stream is captured. Write-Host output is NOT.
      - Return [pscustomobject]s for clean columns. Plain strings land in an "Output" column.
      - Machines returning different property sets is fine - columns are unioned.

    Requirements:
      - Run from an admin PowerShell on a domain-joined machine.
      - WinRM enabled on targets (Enable-PSRemoting / GPO).
      - Account with local admin rights on targets (pass -Credential or run as domain admin).
      - If connecting by IP (no reverse DNS), the IP must be in the local TrustedHosts list:
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.0.1.*" -Concatenate

    No external modules required - the .xlsx is written with a built-in OOXML writer,
    so this works on locked-down boxes with no ImportExcel and no Excel installed.

.PARAMETER ScriptPath
    Path to the local .ps1 to execute on each remote machine. Its contents are read
    and re-created as a scriptblock remotely, so its own param() block works normally.

.PARAMETER ArgumentList
    Positional arguments passed to the target script's param() block.

.PARAMETER ScriptParameters
    Hashtable of named parameters splatted into the target script. Combine with
    -ArgumentList if you like; named wins where they overlap.

.EXAMPLE
    .\Invoke-ScriptOverSubnet.ps1 -ScriptPath .\customscript.ps1 -StartIP 10.0.1.10 -EndIP 10.0.1.250

.EXAMPLE
    .\Invoke-ScriptOverSubnet.ps1 -ScriptPath .\Get-DiskInfo.ps1 -StartIP 192.168.1.1 -EndIP 192.168.1.254 `
        -Credential (Get-Credential) -OutputPath C:\Temp\DiskAudit.xlsx -AlsoCsv

.EXAMPLE
    # Pass parameters through to the target script
    .\Invoke-ScriptOverSubnet.ps1 -ScriptPath .\Get-Service.ps1 -StartIP 10.0.1.1 -EndIP 10.0.1.254 `
        -ScriptParameters @{ ServiceName = 'Spooler'; IncludeStopped = $true }

.EXAMPLE
    # Skip the sweep and hit an explicit list instead
    .\Invoke-ScriptOverSubnet.ps1 -ScriptPath .\customscript.ps1 -ComputerName PC1,PC2,PC3
#>

[CmdletBinding(DefaultParameterSetName = 'Range')]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateScript({
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Script not found: $_" }
        if ([System.IO.Path]::GetExtension($_) -notin '.ps1', '.psm1') { throw "Not a PowerShell script: $_" }
        $true
    })]
    [string]$ScriptPath,

    [Parameter(Mandatory, ParameterSetName = 'Range')]
    [ValidateScript({ $null -ne ($_ -as [System.Net.IPAddress]) })]
    [string]$StartIP,

    [Parameter(Mandatory, ParameterSetName = 'Range')]
    [ValidateScript({ $null -ne ($_ -as [System.Net.IPAddress]) })]
    [string]$EndIP,

    [Parameter(Mandatory, ParameterSetName = 'Computers')]
    [string[]]$ComputerName,

    [string]$OutputPath = ".\ScriptResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx",

    [switch]$AlsoCsv,

    [object[]]$ArgumentList = @(),

    [hashtable]$ScriptParameters,

    [System.Management.Automation.PSCredential]$Credential,

    [int]$Port = 5985,

    [switch]$UseSSL,

    [int]$PingTimeoutMs = 1000,

    [int]$PortTimeoutMs = 2000,

    [int]$OpenTimeoutSec = 30,

    [int]$ThrottleLimit = 32
)

$ErrorActionPreference = 'Stop'

#region Helpers - IP math ----------------------------------------------------

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

function Invoke-OnTargets {
    <#
      Runs Invoke-Command against a set of targets and returns results + errors
      without ever letting one machine kill the run.

      A payload that calls `throw` raises a *terminating* error in the remote
      pipeline. -ErrorAction SilentlyContinue does not suppress terminating
      errors, so without the trap below a single bad machine aborts the whole
      sweep and discards everything already collected. Results are gathered
      through the pipeline (not a $x = @(...) assignment) so partial output
      survives if the pipeline does get torn down.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Computers,
        [Parameter(Mandatory)][hashtable]$IcmParams
    )

    $collected = [System.Collections.Generic.List[object]]::new()
    $errs      = [System.Collections.Generic.List[object]]::new()
    $ev        = $null

    # Function-scoped, so it reverts automatically on return.
    $ErrorActionPreference = 'Continue'

    try {
        Invoke-Command @IcmParams -ComputerName $Computers -ErrorVariable ev |
            ForEach-Object {
                # Read PSComputerName here, while the PSObject wrapper is still
                # intact, and carry it in an envelope. Handing a wrapped string to
                # List[object].Add() unwraps it and the note property is lost, so
                # string-returning payloads would otherwise arrive unattributable.
                $collected.Add([pscustomobject]@{
                    Value        = $_
                    ComputerName = [string]$_.PSComputerName
                })
            }
    }
    catch {
        $errs.Add($_)
    }

    foreach ($e in @($ev)) { if ($e) { $errs.Add($e) } }

    [pscustomobject]@{ Results = $collected; Errors = $errs }
}

#endregion

#region Helpers - minimal OOXML (.xlsx) writer -------------------------------
# Writes a valid multi-sheet workbook with no external dependencies.
# Strings use inlineStr (no shared-string table); numerics are written as <v>.

$script:XlsxMaxRows = 1048576
$script:XlsxMaxCols = 16384
$script:XlsxMaxCellChars = 32767

function Get-XlsxColumnLetter {
    param([int]$Index)   # 1-based
    $s = ''
    while ($Index -gt 0) {
        $rem = ($Index - 1) % 26
        $s = [char](65 + $rem) + $s
        $Index = [int](($Index - $rem - 1) / 26)
    }
    $s
}

function Get-XmlSafeString {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Text.Length -gt $script:XlsxMaxCellChars) {
        $Text = $Text.Substring(0, $script:XlsxMaxCellChars - 3) + '...'
    }
    $sb = [System.Text.StringBuilder]::new([int]($Text.Length * 1.1))
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        # Strip control chars Excel rejects (keep tab/LF/CR)
        if ($code -lt 0x20 -and $code -ne 9 -and $code -ne 10 -and $code -ne 13) { continue }
        if ($code -eq 0xFFFE -or $code -eq 0xFFFF) { continue }
        switch ($ch) {
            '&' { [void]$sb.Append('&amp;');  continue }
            '<' { [void]$sb.Append('&lt;');   continue }
            '>' { [void]$sb.Append('&gt;');   continue }
            '"' { [void]$sb.Append('&quot;'); continue }
            default { [void]$sb.Append($ch) }
        }
    }
    $sb.ToString()
}

function Test-IsNumericValue {
    param($Value)
    if ($null -eq $Value) { return $false }
    # Deliberately type-based, never string parsing - keeps "0012345" serials as text.
    return ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or
            $Value -is [decimal] -or $Value -is [single] -or $Value -is [byte] -or
            $Value -is [int16] -or $Value -is [uint16] -or $Value -is [uint32] -or
            $Value -is [uint64] -or $Value -is [sbyte])
}

function New-XlsxSheetXml {
    param(
        [string[]]$Headers,
        # Strongly typed so PowerShell can never flatten the nested row arrays
        [System.Collections.Generic.List[object[]]]$Rows,
        [int[]]$ColumnWidths
    )

    if ($null -eq $Rows) { $Rows = [System.Collections.Generic.List[object[]]]::new() }
    $colCount = [Math]::Min($Headers.Count, $script:XlsxMaxCols)
    $lastCol  = Get-XlsxColumnLetter $colCount
    $rowCount = [Math]::Min($Rows.Count + 1, $script:XlsxMaxRows)

    $sb = [System.Text.StringBuilder]::new(65536)
    [void]$sb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    [void]$sb.Append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
    [void]$sb.Append("<dimension ref=`"A1:$lastCol$rowCount`"/>")
    [void]$sb.Append('<sheetViews><sheetView workbookViewId="0">')
    [void]$sb.Append('<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>')
    [void]$sb.Append('</sheetView></sheetViews>')
    [void]$sb.Append('<sheetFormatPr defaultRowHeight="15"/>')

    if ($ColumnWidths) {
        [void]$sb.Append('<cols>')
        for ($c = 1; $c -le $colCount; $c++) {
            $w = if ($c -le $ColumnWidths.Count) { $ColumnWidths[$c - 1] } else { 18 }
            [void]$sb.Append("<col min=`"$c`" max=`"$c`" width=`"$w`" customWidth=`"1`"/>")
        }
        [void]$sb.Append('</cols>')
    }

    [void]$sb.Append('<sheetData>')

    # Header row (style 1 = bold)
    [void]$sb.Append('<row r="1">')
    for ($c = 1; $c -le $colCount; $c++) {
        $ref = (Get-XlsxColumnLetter $c) + '1'
        $val = Get-XmlSafeString ([string]$Headers[$c - 1])
        [void]$sb.Append("<c r=`"$ref`" s=`"1`" t=`"inlineStr`"><is><t xml:space=`"preserve`">$val</t></is></c>")
    }
    [void]$sb.Append('</row>')

    $r = 1
    foreach ($row in $Rows) {
        $r++
        if ($r -gt $script:XlsxMaxRows) { break }
        [void]$sb.Append("<row r=`"$r`">")
        for ($c = 1; $c -le $colCount; $c++) {
            $v = if ($c -le $row.Count) { $row[$c - 1] } else { $null }
            if ($null -eq $v -or ($v -is [string] -and $v -eq '')) { continue }  # skip empty cells
            $ref = (Get-XlsxColumnLetter $c) + $r
            if (Test-IsNumericValue $v) {
                $num = [System.Convert]::ToString($v, [System.Globalization.CultureInfo]::InvariantCulture)
                [void]$sb.Append("<c r=`"$ref`"><v>$num</v></c>")
            }
            elseif ($v -is [bool]) {
                $b = if ($v) { 1 } else { 0 }
                [void]$sb.Append("<c r=`"$ref`" t=`"b`"><v>$b</v></c>")
            }
            else {
                $val = Get-XmlSafeString ([string]$v)
                [void]$sb.Append("<c r=`"$ref`" t=`"inlineStr`"><is><t xml:space=`"preserve`">$val</t></is></c>")
            }
        }
        [void]$sb.Append('</row>')
    }

    [void]$sb.Append('</sheetData>')
    [void]$sb.Append("<autoFilter ref=`"A1:$lastCol$rowCount`"/>")
    [void]$sb.Append('</worksheet>')
    $sb.ToString()
}

function Export-Xlsx {
    <#
      Writes one .xlsx from an ordered list of sheet definitions.
      Each sheet: @{ Name = 'Results'; Headers = @(...); Rows = @(@(...),@(...)) }
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable[]]$Sheets
    )

    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $full = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine((Get-Location).ProviderPath, $Path))
    $dir = [System.IO.Path]::GetDirectoryName($full)
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    # ---- Build the package parts ----
    $ctypes = [System.Text.StringBuilder]::new()
    [void]$ctypes.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    [void]$ctypes.Append('<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">')
    [void]$ctypes.Append('<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>')
    [void]$ctypes.Append('<Default Extension="xml" ContentType="application/xml"/>')
    [void]$ctypes.Append('<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>')
    [void]$ctypes.Append('<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>')

    $wbSheets = [System.Text.StringBuilder]::new()
    $wbRels   = [System.Text.StringBuilder]::new()
    [void]$wbRels.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    [void]$wbRels.Append('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">')

    $sheetXml = @{}
    $i = 0
    foreach ($sheet in $Sheets) {
        $i++
        $rid  = "rId$i"
        $file = "sheet$i.xml"
        $name = Get-XmlSafeString ([string]$sheet.Name)

        [void]$ctypes.Append("<Override PartName=`"/xl/worksheets/$file`" ContentType=`"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml`"/>")
        [void]$wbSheets.Append("<sheet name=`"$name`" sheetId=`"$i`" r:id=`"$rid`"/>")
        [void]$wbRels.Append("<Relationship Id=`"$rid`" Type=`"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet`" Target=`"worksheets/$file`"/>")

        $sheetXml["xl/worksheets/$file"] = New-XlsxSheetXml `
            -Headers $sheet.Headers -Rows $sheet.Rows -ColumnWidths $sheet.ColumnWidths
    }

    # styles.xml relationship comes after the sheets
    $styleRid = "rId$($i + 1)"
    [void]$wbRels.Append("<Relationship Id=`"$styleRid`" Type=`"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles`" Target=`"styles.xml`"/>")
    [void]$wbRels.Append('</Relationships>')
    [void]$ctypes.Append('</Types>')

    $parts = [ordered]@{}
    $parts['[Content_Types].xml'] = $ctypes.ToString()

    $parts['_rels/.rels'] = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
        '</Relationships>'

    $parts['xl/workbook.xml'] = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ' +
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">' +
        '<sheets>' + $wbSheets.ToString() + '</sheets></workbook>'

    $parts['xl/_rels/workbook.xml.rels'] = $wbRels.ToString()

    $parts['xl/styles.xml'] = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
        '<fonts count="2">' +
        '<font><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/></font>' +
        '<font><b/><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/></font>' +
        '</fonts>' +
        '<fills count="2"><fill><patternFill patternType="none"/></fill>' +
        '<fill><patternFill patternType="gray125"/></fill></fills>' +
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>' +
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
        '<cellXfs count="2">' +
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' +
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>' +
        '</cellXfs>' +
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' +
        '</styleSheet>'

    foreach ($k in $sheetXml.Keys) { $parts[$k] = $sheetXml[$k] }

    # ---- Zip it (explicit '/' entry names; ZipFile::CreateFromDirectory is unsafe here) ----
    $fs = $null; $zip = $null
    try {
        $fs  = [System.IO.File]::Open($full, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        $zip = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create)
        $enc = [System.Text.UTF8Encoding]::new($false)   # no BOM
        foreach ($name in $parts.Keys) {
            $entry = $zip.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
            $stream = $entry.Open()
            try {
                $bytes = $enc.GetBytes([string]$parts[$name])
                $stream.Write($bytes, 0, $bytes.Length)
            } finally { $stream.Dispose() }
        }
    }
    finally {
        if ($zip) { $zip.Dispose() }
        if ($fs)  { $fs.Dispose() }
    }

    $full
}

#endregion

#region 1. Build target list -------------------------------------------------

$scriptText = Get-Content -LiteralPath $ScriptPath -Raw
if ([string]::IsNullOrWhiteSpace($scriptText)) { throw "$ScriptPath is empty." }
$scriptName = [System.IO.Path]::GetFileName($ScriptPath)

# Fail fast on a local syntax error rather than on 200 machines at once.
$parseTokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput(
    $scriptText, [ref]$parseTokens, [ref]$parseErrors)
if ($parseErrors -and $parseErrors.Count -gt 0) {
    Write-Warning "$scriptName has $($parseErrors.Count) parse error(s):"
    $parseErrors | Select-Object -First 5 | ForEach-Object {
        Write-Warning "  Line $($_.Extent.StartLineNumber): $($_.Message)"
    }
    throw "Refusing to deploy a script that does not parse."
}

$hostStatus = [System.Collections.Specialized.OrderedDictionary]::new()

if ($PSCmdlet.ParameterSetName -eq 'Computers') {
    Write-Host "Targeting $($ComputerName.Count) explicit host(s)..." -ForegroundColor Cyan
    $targets = foreach ($c in $ComputerName) {
        $hostStatus[$c] = [pscustomobject]@{
            IP = ''; Target = $c; Ping = 'skipped'; WinRM = 'assumed'
            Status = 'not attempted'; RowsReturned = 0; Error = ''
        }
        [pscustomobject]@{ IP = $c; Target = $c }
    }
    $liveCount    = @($targets).Count
    $scannedCount = @($targets).Count
}
else {
    #--- Expand IP range ---
    $start = ConvertTo-Int64FromIP $StartIP
    $end   = ConvertTo-Int64FromIP $EndIP
    if ($end -lt $start) { throw "EndIP ($EndIP) is lower than StartIP ($StartIP)." }

    $ipList = for ($i = $start; $i -le $end; $i++) { ConvertTo-IPFromInt64 $i }
    $scannedCount = $ipList.Count
    Write-Host "Scanning $scannedCount addresses ($StartIP - $EndIP)..." -ForegroundColor Cyan

    #--- Parallel ping sweep ---
    $pingTasks = foreach ($ip in $ipList) {
        $ping = [System.Net.NetworkInformation.Ping]::new()
        [pscustomobject]@{ IP = $ip; Task = $ping.SendPingAsync($ip, $PingTimeoutMs) }
    }
    try { [System.Threading.Tasks.Task]::WaitAll(@($pingTasks.Task)) } catch { } # faulted pings handled below

    $liveIPs = $pingTasks |
        Where-Object { $_.Task.Status -eq 'RanToCompletion' -and $_.Task.Result.Status -eq 'Success' } |
        Select-Object -ExpandProperty IP

    $liveCount = @($liveIPs).Count
    Write-Host "Live hosts: $liveCount" -ForegroundColor Green
    if (-not $liveIPs) { Write-Warning "No live hosts found. Exiting."; return }

    #--- Port check + hostname resolution ---
    $targets = foreach ($ip in $liveIPs) {
        $entry = [pscustomobject]@{
            IP = $ip; Target = ''; Ping = 'ok'; WinRM = 'closed'
            Status = 'skipped - WinRM unreachable'; RowsReturned = 0; Error = ''
        }
        $hostStatus[$ip] = $entry

        $client = [System.Net.Sockets.TcpClient]::new()
        $portOpen = $false
        try {
            $portOpen = $client.ConnectAsync($ip, $Port).Wait($PortTimeoutMs) -and $client.Connected
        } catch { } finally { $client.Dispose() }

        if (-not $portOpen) {
            Write-Warning "$ip : alive but WinRM ($Port) not reachable - skipping."
            continue
        }

        $entry.WinRM  = 'open'
        $entry.Status = 'not attempted'

        # Prefer DNS name (Kerberos); fall back to raw IP (needs TrustedHosts)
        $name = $ip
        try { $name = ([System.Net.Dns]::GetHostEntry($ip)).HostName } catch { }
        $entry.Target = $name

        [pscustomobject]@{ IP = $ip; Target = $name }
    }

    Write-Host "Targets with WinRM: $(@($targets).Count)" -ForegroundColor Green
    if (-not $targets) { Write-Warning "No WinRM-reachable hosts. Exiting."; return }
}

# Map any identity Invoke-Command may report (name or IP) back to the source IP
$ipByIdentity = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
$statusByIdentity = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($t in $targets) {
    $entry = $hostStatus[$t.IP]
    $identities = [System.Collections.Generic.List[string]]::new()
    if ($t.Target) { $identities.Add([string]$t.Target) }
    if ($t.IP)     { $identities.Add([string]$t.IP) }
    # Short NetBIOS-style name, but never the first octet of an IP (would collide)
    if ($t.Target -and ($null -eq ($t.Target -as [System.Net.IPAddress]))) {
        $short = ($t.Target -split '\.')[0]
        if ($short) { $identities.Add([string]$short) }
    }
    foreach ($id in $identities) {
        $ipByIdentity[$id] = $t.IP
        $statusByIdentity[$id] = $entry
    }
}

#endregion

#region 2. Run the script remotely -------------------------------------------

# Rebuilds the script remotely as a scriptblock so its own param() block binds
# normally, and both positional and named arguments work.
$runner = {
    param($Payload)
    $sb = [scriptblock]::Create([string]$Payload.ScriptText)
    $positional = @($Payload.Positional)
    if ($Payload.Named -and $Payload.Named.Count -gt 0) {
        $named = @{}
        foreach ($k in $Payload.Named.Keys) { $named[[string]$k] = $Payload.Named[$k] }
        & $sb @named @positional
    }
    else {
        & $sb @positional
    }
}

$payload = @{
    ScriptText = $scriptText
    Positional = @($ArgumentList)
    Named      = $ScriptParameters
}

$sessionOption = New-PSSessionOption -OpenTimeout ($OpenTimeoutSec * 1000)

$icmParams = @{
    ScriptBlock   = $runner
    ArgumentList  = @(, $payload)
    ThrottleLimit = $ThrottleLimit
    SessionOption = $sessionOption
    Port          = $Port
    ErrorAction   = 'SilentlyContinue'
}
if ($Credential) { $icmParams.Credential = $Credential }
if ($UseSSL)     { $icmParams.UseSSL = $true }

Write-Host "Running '$scriptName' on $(@($targets).Count) machine(s)..." -ForegroundColor Cyan
$run = Invoke-OnTargets -Computers @($targets.Target) -IcmParams $icmParams
$results   = @($run.Results)
$icmErrors = @($run.Errors)

# Retry failed hostname connections by raw IP (NTLM; IP must be in TrustedHosts).
# Only transport/connection failures are eligible. A payload that ran and threw
# must NOT be retried - it already executed, and re-running it by IP would
# double-execute anything with side effects.
$transportFailures = @($icmErrors | Where-Object {
    $_.Exception -is [System.Management.Automation.Remoting.PSRemotingTransportException]
})

$failedNames = @($transportFailures |
    ForEach-Object { $_.TargetObject; $_.OriginInfo.PSComputerName } |
    Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -Unique)

$retry = @($targets | Where-Object { $failedNames -contains $_.Target -and $_.Target -ne $_.IP })

if ($retry.Count -gt 0) {
    $trusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value
    if ([string]::IsNullOrWhiteSpace($trusted)) {
        Write-Warning "TrustedHosts is empty, so every IP retry below will be refused. To allow a range:"
        Write-Warning '  Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.0.0.*" -Concatenate'
    }
    else {
        Write-Warning "TrustedHosts is currently: $trusted"
        Write-Warning "  Retries for addresses not covered by that will be refused. To add a range:"
        Write-Warning '  Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.0.0.*" -Concatenate'
    }
    Write-Host "Retrying $($retry.Count) failed host(s) by IP address..." -ForegroundColor Yellow

    $retryRun = Invoke-OnTargets -Computers @($retry.IP) -IcmParams $icmParams
    $results += @($retryRun.Results)

    # Keep BOTH failures, not just the retry. The original by-name error explains
    # why Kerberos failed and is usually the more actionable of the two; discarding
    # it leaves you staring at a TrustedHosts message with no idea what came first.
    # Status still ends up correct: region 3 sets 'success' after this, so a host
    # that recovered on retry reads success while retaining the first error text.
    $icmErrors = @($retryRun.Errors) + @($icmErrors)
}

foreach ($e in $icmErrors) {
    # Work out which host this error belongs to. OriginInfo is authoritative for
    # errors raised inside the remote session. TargetObject holds the computer
    # name for connection failures, but for `throw "x"` it holds "x" - so only
    # trust either one when it matches a target we actually dispatched to.
    $failedHost = $null
    foreach ($candidate in @($e.OriginInfo.PSComputerName, $e.TargetObject)) {
        if ($candidate -and $statusByIdentity.ContainsKey([string]$candidate)) {
            $failedHost = [string]$candidate
            break
        }
    }
    # Single-target runs leave no ambiguity, so attribute anything unresolved.
    if (-not $failedHost -and @($targets).Count -eq 1) {
        $failedHost = [string](@($targets)[0].Target)
    }

    $label = if ($failedHost) { $failedHost } else { '<unattributed>' }
    Write-Warning "FAILED: $label - $($e.Exception.Message)"

    if ($failedHost -and $statusByIdentity.ContainsKey($failedHost)) {
        $st = $statusByIdentity[$failedHost]
        $st.Status = 'failed'
        $st.Error  = if ($st.Error) { "$($st.Error) | $($e.Exception.Message)" } else { $e.Exception.Message }
    }
}

#endregion

#region 3. Flatten results into a table --------------------------------------

$skipProps = @('RunspaceId', 'PSShowComputerName', 'PSSourceJobInstanceId')

function Format-CellValue {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ((Test-IsNumericValue $Value) -or ($Value -is [bool])) { return $Value }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    if ($Value -is [System.Collections.IDictionary]) {
        return (($Value.Keys | ForEach-Object { "$_=$($Value[$_])" }) -join '; ')
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return (@($Value) | ForEach-Object { "$_" }) -join '; '
    }
    return [string]$Value
}

$rows = [System.Collections.Generic.List[object]]::new()

foreach ($entry in $results) {
    if ($null -eq $entry) { continue }

    # Envelope from Invoke-OnTargets: Value = what the payload emitted,
    # ComputerName = identity captured before any PSObject unwrapping.
    $item = $entry.Value
    if ($null -eq $item) { continue }
    $computer = [string]$entry.ComputerName
    $ps = [psobject]$item

    $sourceIP = ''
    if ($computer -and $ipByIdentity.ContainsKey($computer)) { $sourceIP = $ipByIdentity[$computer] }

    if ($computer -and $statusByIdentity.ContainsKey($computer)) {
        $st = $statusByIdentity[$computer]
        $st.Status = 'success'
        $st.RowsReturned = [int]$st.RowsReturned + 1
    }

    $row = [ordered]@{
        ComputerName = $computer
        SourceIP     = $sourceIP
    }

    $isSimple = ($item -is [string]) -or ($item -is [datetime]) -or
                (Test-IsNumericValue $item) -or ($item -is [bool]) -or ($item -is [char])

    if ($isSimple) {
        $row['Output'] = Format-CellValue $item
    }
    else {
        foreach ($p in $ps.PSObject.Properties) {
            if ($p.Name -in $skipProps -or $p.Name -eq 'PSComputerName') { continue }
            # Never let a returned property clobber the connection identity
            $key = $p.Name
            if ($row.Contains($key)) { $key = "$($p.Name)_Remote" }
            $row[$key] = Format-CellValue $p.Value
        }
    }

    $rows.Add([pscustomobject]$row)
}

# Union of every column any machine returned, first-seen order
$columns = [System.Collections.Specialized.OrderedDictionary]::new()
foreach ($r in $rows) {
    foreach ($p in $r.PSObject.Properties) {
        if (-not $columns.Contains($p.Name)) { $columns[$p.Name] = $true }
    }
}
$headers = @($columns.Keys)
if (-not $headers) { $headers = @('ComputerName', 'SourceIP', 'Output') }

#endregion

#region 4. Export ------------------------------------------------------------

if ($rows.Count -eq 0) {
    Write-Warning "'$scriptName' returned no output from any target. Check that it writes objects to the success stream (Write-Host output is not captured)."
}

# Results sheet - built with an explicit list so every row stays column-aligned
$resultRows = [System.Collections.Generic.List[object[]]]::new()
foreach ($r in $rows) {
    $cells = [object[]]::new($headers.Count)
    for ($c = 0; $c -lt $headers.Count; $c++) {
        $p = $r.PSObject.Properties[$headers[$c]]
        $cells[$c] = if ($p) { $p.Value } else { $null }
    }
    $resultRows.Add($cells)
}

$resultWidths = [System.Collections.Generic.List[int]]::new()
foreach ($h in $headers) {
    # switch -Regex falls through without break, which would misalign the widths
    switch -Regex ($h) {
        'Hash|Data|Message|Error|Output|Path' { $resultWidths.Add(60); break }
        'Computer|Name'                       { $resultWidths.Add(24); break }
        default                               { $resultWidths.Add(18) }
    }
}

# Status sheet
$statusHeaders = @('IP', 'Target', 'Ping', 'WinRM', 'Status', 'RowsReturned', 'Error')
$statusRows = [System.Collections.Generic.List[object[]]]::new()
foreach ($k in @($hostStatus.Keys)) {
    $e = $hostStatus[$k]
    $statusRows.Add([object[]]@(
        $e.IP, $e.Target, $e.Ping, $e.WinRM, $e.Status, [int]$e.RowsReturned, $e.Error))
}

$sheets = @(
    @{ Name = 'Results'; Headers = $headers;       Rows = $resultRows; ColumnWidths = @($resultWidths) }
    @{ Name = 'Status';  Headers = $statusHeaders; Rows = $statusRows; ColumnWidths = @(16, 30, 10, 10, 14, 14, 60) }
)

if ([System.IO.Path]::GetExtension($OutputPath) -eq '') { $OutputPath += '.xlsx' }
$written = Export-Xlsx -Path $OutputPath -Sheets $sheets

$csvPath = $null
if ($AlsoCsv) {
    $csvPath = [System.IO.Path]::ChangeExtension($written, '.csv')
    $rows | Select-Object $headers | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
}

#endregion

#region 5. Summary -----------------------------------------------------------

$successHosts = @($hostStatus.Keys | Where-Object { $hostStatus[$_].Status -eq 'success' }).Count
$failedHosts  = @($hostStatus.Keys | Where-Object { $hostStatus[$_].Status -eq 'failed' }).Count

Write-Host ""
Write-Host ("Scanned {0} | live {1} | WinRM {2} | succeeded {3} | failed {4} | rows {5}" -f `
    $scannedCount, $liveCount, @($targets).Count, $successHosts, $failedHosts, $rows.Count) -ForegroundColor Green
Write-Host "Workbook: $written" -ForegroundColor Green
if ($csvPath) { Write-Host "CSV:      $csvPath" -ForegroundColor Green }
Write-Host ""

$rows | Select-Object -Property ComputerName, SourceIP -First 20 | Format-Table -AutoSize

#endregion
