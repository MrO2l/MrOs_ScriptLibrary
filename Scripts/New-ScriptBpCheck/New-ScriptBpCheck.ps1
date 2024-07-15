<#
.SYNOPSIS
    This script checks a PowerShell script (.ps1) for adherence to best practices and generates a report.

.DESCRIPTION
    This script analyzes a specified PowerShell script file and checks for compliance with various best practices.
    The report is output to the console, and optionally, an HTML report can also be generated. It also uses the PSScriptAnalyzer module to provide a detailed analysis.

.PARAMETER ScriptPath
    The path to the PowerShell script (.ps1) file to be analyzed.

.PARAMETER HtmlReport
    Switch parameter to generate an HTML report in addition to the console output.

.PARAMETER IncludeDetails
    Switch parameter to include detailed PSScriptAnalyzer results in the console output.

.EXAMPLE
    PS> .\Check-ScriptBestPractices.ps1 -ScriptPath "C:\Scripts\MyScript.ps1"
    Analyzes the script at the specified path and outputs a report to the console.

.EXAMPLE
    PS> .\Check-ScriptBestPractices.ps1 -ScriptPath "C:\Scripts\MyScript.ps1" -HtmlReport
    Analyzes the script at the specified path and outputs a report to the console and generates an HTML report.

.EXAMPLE
    PS> .\Check-ScriptBestPractices.ps1 -ScriptPath "C:\Scripts\MyScript.ps1" -IncludeDetails
    Analyzes the script at the specified path, outputs a report to the console, and includes detailed PSScriptAnalyzer results.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,

    [switch]$HtmlReport,

    [switch]$IncludeDetails
)

function Load-Checks {
    $json = Get-Content -Path ".\checks.json" -Raw | ConvertFrom-Json
    return $json
}

function Check-BestPractices {
    param (
        [string]$Content,
        [array]$Checks
    )

    $report = @()
    $functions = @()

    foreach ($check in $Checks) {
        if ($check.Part -eq "Comments and Documentation") {
            $commentLines = ($Content -split "`n" | Where-Object { $_ -match $check.Regex })
            if ($commentLines.Count -gt 10) {
                $report += [pscustomobject]@{ Part = $check.Part; Status = "Green"; Details = "Sufficient comments" }
            } elseif ($commentLines.Count -gt 0) {
                $report += [pscustomobject]@{ Part = $check.Part; Status = "Orange"; Details = "Insufficient comments" }
            } else {
                $report += [pscustomobject]@{ Part = $check.Part; Status = "Red"; Details = "No comments" }
            }
        } elseif ($check.Part -eq "Function Error Handling" -or $check.Part -eq "Function Parameter Validation") {
            $funcMatches = [regex]::Matches($Content, "function\s+(\w+)\s*\{.*?\}", [System.Text.RegularExpressions.RegexOptions]::Singleline)
            foreach ($funcMatch in $funcMatches) {
                $funcContent = $funcMatch.Value
                $funcName = $funcMatch.Groups[1].Value
                $functions += [pscustomobject]@{ Name = $funcName; Content = $funcContent }

                if ($funcContent -match "param\s*\(") {
                    if ($funcContent -match $check.Regex) {
                        $report += [pscustomobject]@{ Part = $check.Part; Status = "Green"; Details = "Present in function $funcName" }
                    } else {
                        $report += [pscustomobject]@{ Part = $check.Part; Status = "Red"; Details = "Missing in function $funcName" }
                    }
                } else {
                    if ($check.Part -eq "Function Error Handling") {
                        if ($funcContent -match $check.Regex) {
                            $report += [pscustomobject]@{ Part = $check.Part; Status = "Green"; Details = "Present in function $funcName" }
                        } else {
                            $report += [pscustomobject]@{ Part = $check.Part; Status = "Red"; Details = "Missing in function $funcName" }
                        }
                    }
                }
            }
        } else {
            if ($Content -match $check.Regex) {
                $report += [pscustomobject]@{ Part = $check.Part; Status = "Green"; Details = "Present" }
            } else {
                $report += [pscustomobject]@{ Part = $check.Part; Status = "Red"; Details = "Missing" }
            }
        }
    }

    return $report, $functions
}

function Analyze-ScriptWithPSScriptAnalyzer {
    param (
        [string]$ScriptPath
    )

    Import-Module PSScriptAnalyzer -ErrorAction Stop
    $analysisResults = Invoke-ScriptAnalyzer -Path $ScriptPath -Severity Warning,Error

    return $analysisResults
}

function Output-Report {
    param (
        [array]$Report,
        [array]$Functions,
        [array]$PSSAReport,
        [switch]$Html,
        [switch]$IncludeDetails
    )

    foreach ($item in $Report) {
        $color = switch ($item.Status) {
            "Green" { "Green" }
            "Orange" { "DarkYellow" }
            "Red" { "Red" }
        }
        Write-Host "$($item.Part): $($item.Details)" -ForegroundColor $color
    }

    if ($Functions.Count -gt 0) {
        Write-Host "`nFunctions:" -ForegroundColor Cyan
        foreach ($function in $Functions) {
            Write-Host "Function: $($function.Name)" -ForegroundColor Cyan
            $funcIssues = $Report | Where-Object { $_.Details -match "function $($function.Name)" }
            foreach ($issue in $funcIssues) {
                $color = switch ($issue.Status) {
                    "Green" { "Green" }
                    "Orange" { "DarkYellow" }
                    "Red" { "Red" }
                }
                Write-Host "  $($issue.Part): $($issue.Details)" -ForegroundColor $color
            }
        }
    }

    if ($IncludeDetails -and $PSSAReport.Count -gt 0) {
        Write-Host "`nDetailed PSScriptAnalyzer Report:" -ForegroundColor Cyan
        foreach ($result in $PSSAReport) {
            Write-Host "$($result.RuleName): $($result.Message)" -ForegroundColor Yellow
            Write-Host "Line $($result.Line): $($result.ScriptName)" -ForegroundColor Gray
        }
    }

    if ($Html) {
        $baseHtml = Get-Content -Path ".\Base.html" -Raw

        $bestPracticesReportHtml = ""
        foreach ($item in $Report) {
            $bestPracticesReportHtml += "<tr class='$($item.Status)'><td>$($item.Part)</td><td>$($item.Status)</td><td>$($item.Details)</td></tr>"
        }

        $functionsHtml = ""
        if ($Functions.Count -gt 0) {
            $functionsHtml += "<h2>Functions</h2>"
            foreach ($function in $Functions) {
                $functionsHtml += "<h3>Function: $($function.Name)</h3><ul>"
                $funcIssues = $Report | Where-Object { $_.Details -match "function $($function.Name)" }
                foreach ($issue in $funcIssues) {
                    $functionsHtml += "<li class='$($issue.Status)'>$($issue.Part): $($issue.Details)</li>"
                }
                $functionsHtml += "</ul>"
            }
        }

        $pssaReportHtml = ""
        if ($PSSAReport.Count -gt 0) {
            foreach ($result in $PSSAReport) {
                $pssaReportHtml += "<tr><td>$($result.RuleName)</td><td>$($result.Message)</td><td>$($result.Line)</td><td>$($result.ScriptName)</td></tr>"
            }
        }

        $htmlReport = $baseHtml -replace '<!-- BestPracticesReportPlaceholder -->', $bestPracticesReportHtml
        $htmlReport = $htmlReport -replace '<!-- PSSAReportPlaceholder -->', $pssaReportHtml
        $htmlReport = $htmlReport -replace '<!-- FunctionsPlaceholder -->', $functionsHtml

        $htmlPath = [System.IO.Path]::ChangeExtension($ScriptPath, ".html")
        $htmlReport | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Host "HTML report generated at $htmlPath" -ForegroundColor Green
    }
}

if (-not (Test-Path -Path $ScriptPath -PathType Leaf)) {
    Write-Host "The specified script file does not exist." -ForegroundColor Red
    exit 1
}

# Check if PSScriptAnalyzer is installed
if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
    Write-Host "The PSScriptAnalyzer module is not installed." -ForegroundColor Red
    $install = Read-Host "Do you want to install PSScriptAnalyzer now? (Y/N)"
    if ($install -eq 'Y' -or $install -eq 'y') {
        Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser
        if ($?) {
            Write-Host "PSScriptAnalyzer installed successfully. Please run the script again." -ForegroundColor Green
        } else {
            Write-Host "Failed to install PSScriptAnalyzer." -ForegroundColor Red
        }
        exit 0
    } else {
        Write-Host "PSScriptAnalyzer is required for this script to run. Exiting." -ForegroundColor Red
        exit 1
    }
}

$scriptContent = Get-Content -Path $ScriptPath -Raw
$checks = Load-Checks
$bestPracticesReport, $functions = Check-BestPractices -Content $scriptContent -Checks $checks
$pssaReport = Analyze-ScriptWithPSScriptAnalyzer -ScriptPath $ScriptPath

Output-Report -Report $bestPracticesReport -Functions $functions -PSSAReport $pssaReport -Html:$HtmlReport -IncludeDetails:$IncludeDetails
