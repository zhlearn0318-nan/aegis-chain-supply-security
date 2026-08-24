function Resolve-AegisApplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Names,
        [string[]]$Candidates = @()
    )

    foreach ($name in $Names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command -and $command.Source) {
            return $command.Source
        }
    }

    foreach ($candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    return $null
}

function Resolve-AegisConfiguredApplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$EnvironmentVariable,
        [Parameter(Mandatory = $true)][string[]]$Names,
        [string[]]$Candidates = @()
    )

    $configured = [Environment]::GetEnvironmentVariable($EnvironmentVariable, "Process")
    if (-not [string]::IsNullOrWhiteSpace($configured)) {
        if (Test-Path -LiteralPath $configured -PathType Leaf) {
            return (Resolve-Path -LiteralPath $configured).Path
        }
        $configuredCommand = Get-Command $configured -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($configuredCommand -and $configuredCommand.Source) {
            return $configuredCommand.Source
        }
        throw "$EnvironmentVariable points to an unavailable executable: $configured"
    }

    return Resolve-AegisApplication -Names $Names -Candidates $Candidates
}

function Resolve-AegisPackageManager {
    [CmdletBinding()]
    param()

    $configured = Resolve-AegisConfiguredApplication `
        -EnvironmentVariable "AEGIS_PNPM_COMMAND" `
        -Names @("pnpm.cmd", "pnpm.exe", "pnpm")
    if ($configured) {
        return [pscustomobject]@{
            Command = $configured
            PrefixArguments = @()
            DisplayName = "pnpm"
            Discovery = if ([Environment]::GetEnvironmentVariable("AEGIS_PNPM_COMMAND", "Process")) { "AEGIS_PNPM_COMMAND" } else { "PATH" }
        }
    }

    $corepack = Resolve-AegisApplication -Names @("corepack.cmd", "corepack.exe", "corepack")
    if ($corepack) {
        return [pscustomobject]@{
            Command = $corepack
            PrefixArguments = @("pnpm")
            DisplayName = "corepack pnpm"
            Discovery = "PATH"
        }
    }

    return $null
}

function Invoke-AegisPackageManager {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Manager,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$FailureMessage = "Frontend package command failed."
    )

    $commandArguments = @($Manager.PrefixArguments) + $Arguments
    & $Manager.Command @commandArguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage Exit code: $LASTEXITCODE"
    }
}

function Resolve-AegisDockerCli {
    [CmdletBinding()]
    param()

    $candidates = @()
    if ($env:LOCALAPPDATA) {
        $candidates += Join-Path $env:LOCALAPPDATA "Programs\DockerDesktop\resources\bin\docker.exe"
    }
    if ($env:ProgramFiles) {
        $candidates += Join-Path $env:ProgramFiles "Docker\Docker\resources\bin\docker.exe"
    }

    return Resolve-AegisConfiguredApplication `
        -EnvironmentVariable "AEGIS_DOCKER_COMMAND" `
        -Names @("docker.exe", "docker") `
        -Candidates $candidates
}
