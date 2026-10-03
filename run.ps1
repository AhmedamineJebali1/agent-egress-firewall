<#
.SYNOPSIS
  Egress firewall for AI agents - lab driver (Windows).

.DESCRIPTION
  Everything runs in containers. Docker Desktop is the only prerequisite.

    .\run.ps1              build, run the three-configuration experiment, report
    .\run.ps1 demo         the narrated prompt-injection demo, with and without
    .\run.ps1 up           start the stack and leave it running
    .\run.ps1 console      open the firewall's live console in a browser
    .\run.ps1 report       rebuild the report from evidence already collected
    .\run.ps1 test         self-test: verify the lab behaves as documented
    .\run.ps1 down         stop everything and remove the volumes
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('experiment', 'demo', 'up', 'console', 'report', 'test', 'down', 'build', 'logs')]
    [string]$Command = 'experiment'
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Write-Step { param([string]$Text) Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Write-Note { param([string]$Text) Write-Host "    $Text" -ForegroundColor DarkGray }

# Docker writes progress to stderr. Windows PowerShell turns that into error
# records, which would abort the script under ErrorActionPreference=Stop, so
# native output is merged and printed as plain text and only the exit code is
# treated as the result.
function Invoke-Checked {
    param([string[]]$Arguments, [switch]$AllowFailure, [switch]$Quiet)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & docker @Arguments 2>&1 | ForEach-Object {
            $line = if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_ }
            if (-not $Quiet) { Write-Host $line }
        }
    }
    finally { $ErrorActionPreference = $previous }

    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) {
        throw ("docker " + ($Arguments -join ' ') + " failed with exit code $LASTEXITCODE")
    }
}

function Test-Docker {
    Invoke-Checked @('version', '--format', '{{.Server.Version}}') -Quiet -AllowFailure
    if ($LASTEXITCODE -ne 0) {
        throw 'Docker is not running. Start Docker Desktop and try again.'
    }
}

function Build-Images {
    Write-Step 'Building images'
    Invoke-Checked @('compose', 'build')
}

function Start-Stack {
    Write-Step 'Starting the lab'
    New-Item -ItemType Directory -Force -Path './out' | Out-Null
    Invoke-Checked @('compose', 'up', '-d', 'labca', 'attacker', 'cdn', 'dnsguard', 'firewall')
    Invoke-Checked @('compose', 'run', '--rm', '-T', 'ctl', 'wait')
}

function Invoke-Ctl {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CtlArgs)
    Invoke-Checked (@('compose', 'run', '--rm', '-T', 'ctl') + $CtlArgs)
}

function Invoke-Configuration {
    param(
        [string]$Id,
        [string]$Mode,
        [string]$Label,
        [string]$Service
    )
    Write-Step "Configuration ${Id}: $Label"
    Invoke-Ctl 'mode' $Mode
    Invoke-Ctl 'reset'
    Invoke-Checked @(
        'compose', 'run', '--rm', '-T', $Service,
        'python', '-m', 'app.harness',
        '--config', $Id, '--label', $Label, '--mode', $Mode
    )
    Invoke-Ctl 'snapshot' $Id
}

function Invoke-Experiment {
    Build-Images
    Start-Stack
    Invoke-Configuration -Id 'A' -Mode 'off' `
        -Label 'no egress control' -Service 'agent-direct'
    Invoke-Configuration -Id 'B' -Mode 'allowlist' `
        -Label 'domain allowlist only' -Service 'agent-jailed'
    Invoke-Configuration -Id 'C' -Mode 'full' `
        -Label 'allowlist + TLS interception + DLP + DNS guard' -Service 'agent-jailed'

    Write-Step 'Building the report'
    Invoke-Ctl 'report'

    Write-Host ''
    Write-Host '  Report:        out\report.md' -ForegroundColor Green
    Write-Host '  Machine form:  out\report.json' -ForegroundColor Green
    Write-Host '  Live console:  http://localhost:9090' -ForegroundColor Green
    Write-Host '  Stop with:     .\run.ps1 down' -ForegroundColor DarkGray
    Write-Host ''
}

function Invoke-Demo {
    Build-Images
    Start-Stack

    Write-Step 'Demo 1 of 2: an agent with ordinary internet access'
    Invoke-Ctl 'mode' 'off'
    Invoke-Ctl 'reset'
    Invoke-Checked @('compose', 'run', '--rm', '-T', 'agent-direct',
        'python', '-m', 'app.demo', '--label', 'no egress control')
    Write-Note 'What the attacker collected:'
    Invoke-Ctl 'snapshot' 'demo-off'

    Write-Step 'Demo 2 of 2: the same agent behind the egress firewall'
    Invoke-Ctl 'mode' 'full'
    Invoke-Ctl 'reset'
    Invoke-Checked @('compose', 'run', '--rm', '-T', 'agent-jailed',
        'python', '-m', 'app.demo', '--label', 'full egress control')
    Invoke-Ctl 'snapshot' 'demo-full'

    Write-Host ''
    Write-Host '  Same agent, same injection, same obedience. Only the network changed.' -ForegroundColor Green
    Write-Host '  Live console: http://localhost:9090' -ForegroundColor Green
    Write-Host ''
}

function Invoke-SelfTest {
    Build-Images
    Start-Stack
    Write-Step 'Self-test'
    Invoke-Checked @('compose', 'run', '--rm', '-T', 'agent-jailed',
        'python', '-m', 'app.selftest')
}

Test-Docker

switch ($Command) {
    'experiment' { Invoke-Experiment }
    'demo'       { Invoke-Demo }
    'build'      { Build-Images }
    'up' {
        Build-Images
        Start-Stack
        Write-Host ''
        Write-Host '  Lab is up. Console: http://localhost:9090' -ForegroundColor Green
        Write-Host '  Poisoned page:      http://localhost:8081/article?s=b64_post_allowed' -ForegroundColor Green
        Write-Host '  Collector:          http://localhost:9091/hits' -ForegroundColor Green
        Write-Host ''
    }
    'console' {
        Start-Process 'http://localhost:9090'
        Write-Note 'Opened http://localhost:9090'
    }
    'report' { Invoke-Ctl 'report' }
    'test'   { Invoke-SelfTest }
    'logs'   { Invoke-Checked @('compose', 'logs', '-f', '--tail', '80') }
    'down' {
        Write-Step 'Stopping the lab'
        Invoke-Checked @('compose', 'down', '-v', '--remove-orphans') -AllowFailure
        Write-Note 'Stopped. Reports in .\out are kept.'
    }
}
