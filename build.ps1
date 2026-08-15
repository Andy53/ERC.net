<#
.SYNOPSIS
    Builds ERC.Net for x86, x64, or both.

.DESCRIPTION
    Unlike the x64dbg plugin that consumes this library, nothing here needs full
    MSBuild: there is no IL rewriting step, so the .NET SDK alone is enough.

    The project this replaces could not be built by anyone except its author. It
    referenced Fasm.NET, Reloaded.Assembler, Reloaded.Memory and
    Reloaded.Memory.Buffers by HintPath into
    "..\..\ConsoleApp1\ConsoleApp1\bin\Debug", a folder that exists on one machine,
    and excluded a file by absolute path under C:\Users\Andy. Those are now ordinary
    PackageReferences.

.EXAMPLE
    .\build.ps1
    Builds Release for both architectures.

.EXAMPLE
    .\build.ps1 -CleanPackages
    Restores into a throwaway package folder, so the build cannot quietly depend on
    something already sitting in the machine's NuGet cache.
#>
[CmdletBinding()]
param(
    [ValidateSet('x86', 'x64', 'both')]
    [string] $Platform = 'both',

    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',

    <#
      Restore into an empty package folder instead of the machine's own.

      Worth having on a library whose build was broken for everyone but its author
      for years: a warm package cache hides exactly that kind of problem.
    #>
    [switch] $CleanPackages
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = $PSScriptRoot
$solution = Join-Path $repoRoot 'ERC.Net.sln'

$cleanPackageFolder = $null
if ($CleanPackages) {
    $cleanPackageFolder = Join-Path ([System.IO.Path]::GetTempPath()) ("erc-packages-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $cleanPackageFolder | Out-Null
    $env:NUGET_PACKAGES = $cleanPackageFolder

    Write-Host "Restoring into a clean package folder: $cleanPackageFolder" -ForegroundColor Yellow

    # Stale obj folders carry a resolved dependency graph from the previous restore,
    # which would hide the problem this switch exists to expose.
    Get-ChildItem -Path $repoRoot -Recurse -Directory -Filter 'obj' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notlike '*\.git\*' } |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

$platforms = if ($Platform -eq 'both') { @('x86', 'x64') } else { @($Platform) }

foreach ($p in $platforms) {
    Write-Host ""
    Write-Host "==> Building $Configuration|$p" -ForegroundColor Cyan

    & dotnet build $solution -c $Configuration "-p:Platform=$p" --nologo -v minimal
    if ($LASTEXITCODE -ne 0) { throw "Build failed for $Configuration|$p." }

    foreach ($framework in @('net472', 'net8.0-windows')) {
        $assembly = Join-Path $repoRoot "ERC\bin\$p\$Configuration\$framework\ERC.Net.dll"
        if (-not (Test-Path $assembly)) { throw "Expected assembly was not produced: $assembly" }
        Write-Host "    $assembly" -ForegroundColor Green
    }
}

if ($cleanPackageFolder) {
    Remove-Item Env:\NUGET_PACKAGES -ErrorAction SilentlyContinue
    Remove-Item $cleanPackageFolder -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Build succeeded." -ForegroundColor Green
