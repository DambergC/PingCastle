<#
.SYNOPSIS
    Advanced HTML report generator for PingCastle security assessment data.

.DESCRIPTION
    This script generates rich HTML reports from PingCastle XML output, with features including:
    - Customizable theming and risk thresholds
    - Historical data comparison and trend analysis
    - Risk categorization and prioritization
    - Executive summary and action plan timeline
    - Optional PDF export and configuration templates

.PARAMETER XmlPath
    Path to the PingCastle XML output file.

.PARAMETER OutputPath
    Path where the HTML report will be saved.

.PARAMETER ThemeColor
    Hex color code for report theming.

.PARAMETER HighRiskThreshold
    Score threshold to classify issues as high risk.

.PARAMETER IncludeComparisonWithPrevious
    Include comparison with previous assessment results.

.PARAMETER ConfigPath
    Path to JSON configuration file for report settings.

.PARAMETER SaveTemplateAs
    Save current configuration as a template.

.NOTES
    Version:        1.0.0
    Author:         DambergC
    Creation Date:  2025-04-11
    Repository:     https://github.com/YourUsername/PingCastle
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$XmlPath = ".\ad_hc_int.vxops.se.xml",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "HealthcheckReport.html",
    
    [Parameter(Mandatory=$false)]
    [string]$ThemeColor = "#990AE3",
    
    [Parameter(Mandatory=$false)]
    [int]$HighRiskThreshold = 50,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeComparisonWithPrevious,
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = ".\PingCastleReportConfig.json",
    
    [Parameter(Mandatory=$false)]
    [string]$SaveTemplateAs
)

# Read from config file if it exists
if(Test-Path $ConfigPath) {
    try {
        $config = Get-Content $ConfigPath | ConvertFrom-Json
        # Use null-coalescing operator to only override parameters if they exist in config
        $XmlPath = $config.XmlPath ?? $XmlPath
        $OutputPath = $config.OutputPath ?? $OutputPath
        $ThemeColor = $config.ThemeColor ?? $ThemeColor
        $HighRiskThreshold = $config.HighRiskThreshold ?? $HighRiskThreshold
        
        # For boolean switch parameters, special handling needed
        if($null -ne $config.IncludeComparisonWithPrevious) {
            $IncludeComparisonWithPrevious = [System.Convert]::ToBoolean($config.IncludeComparisonWithPrevious)
        }
        if($null -ne $config.ExportPDF) {
            $ExportPDF = [System.Convert]::ToBoolean($config.ExportPDF)
        }
        
        Write-Host "Configuration loaded from $ConfigPath" -ForegroundColor Green
    } catch {
        Write-Warning "Error reading config file. Using default parameters: $_"
    }
}

$LogoBase64PingCastle = [Convert]::ToBase64String((Get-Content -Path .\Image\PingCastle.png -AsByteStream))
$LogoHTMLPingCastle = "<img src='data:image/png;base64,$LogoBase64Pingcastle' style='width: 150px; height: auto;'>"

$LogoBase64Company = [Convert]::ToBase64String((Get-Content -Path .\Image\TeliaCygate.png -AsByteStream))
$LogoHTMLCompany = "<img src='data:image/png;base64,$LogoBase64Company' style='width: 300px; height: auto;'>"


# Save current configuration as template if requested
if($SaveTemplateAs) {
    $template = @{
        XmlPath = $XmlPath
        OutputPath = $OutputPath
        ThemeColor = $ThemeColor
        HighRiskThreshold = $HighRiskThreshold
        IncludeComparisonWithPrevious = $IncludeComparisonWithPrevious.IsPresent
        ExportPDF = $ExportPDF.IsPresent
    }
    
    try {
        $template | ConvertTo-Json | Out-File $SaveTemplateAs
        Write-Output "Template saved successfully at $SaveTemplateAs"
    } catch {
        Write-Error "Failed to save template: $_"
        # Continue execution - this is not critical
    }
}

# Read the XML file
if(!(Test-Path $XmlPath)) {
    Write-Error "XML file not found: $XmlPath"
    exit 1
}

try {
    [xml]$data = Get-Content $XmlPath -ErrorAction Stop
    
    # Extract core domain information
    $domain = $data.HealthcheckData.DomainFQDN
        
    # Extract scores
    $globalScore = [int]$data.HealthcheckData.GlobalScore
    $StaleScore = [int]$data.HealthcheckData.StaleObjectsScore
    $PrivilegiedGroupScore = [int]$data.HealthcheckData.PrivilegiedGroupScore
    $trustscore = [int]$data.HealthcheckData.TrustScore
    $AnomalyScore = [int]$data.HealthcheckData.AnomalyScore
    
    # Extract risk data
    $healthcheckData = @()
    foreach($risk in $data.HealthcheckData.RiskRules.HealthcheckRiskRule) {
        $healthcheckData += [PSCustomObject]@{
            Category = $risk.Category
            RiskId = $risk.RiskId
            Model = $risk.Model
            Points = [int]$risk.Points
            Rationale = $risk.Rationale
        }
    }
    
} catch {
    Write-Error "Error processing XML data: $_"
    exit 1
}

# Ensure PSWriteHTML module is installed
if (!(Get-Module -ListAvailable -Name PSWriteHTML)) {
    Write-Host "PSWriteHTML module not found. Installing..." -ForegroundColor Yellow
    try {
        Install-Module -Name PSWriteHTML -Force -Scope CurrentUser -ErrorAction Stop
        Write-Host "PSWriteHTML module installed successfully." -ForegroundColor Green
    } catch {
        Write-Error "Failed to install PSWriteHTML module. Please install manually: Install-Module -Name PSWriteHTML -Force"
        exit 1
    }
}

# Import PSWriteHTML module
try {
    Import-Module PSWriteHTML -ErrorAction Stop
} catch {
    Write-Error "Failed to import PSWriteHTML module: $_"
    exit 1
}

# Helper function to determine score color - MODIFIED for 0=good, 100=bad scale
function Get-ScoreColor {
    param([int]$Score)
    
    if ($Score -lt 16) { return "green" }
    elseif ($Score -lt 31) { return "orange" }
    else { return "red" }
}

# Replace hardcoded values with dynamic ones
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$currentUser = $env:USERNAME
$reportDate = Get-Date -Format "yyyy-MM-dd"

# Historical tracking (if enabled)
$historyFile = ".\PingCastle_ScoreHistory.csv"
$showTrends = $false

if ($IncludeComparisonWithPrevious -and (Test-Path $historyFile)) {
    $scoreHistory = Import-Csv -Path $historyFile
    $previousEntry = $scoreHistory | Sort-Object -Property Date -Descending | Select-Object -First 1
    $showTrends = $true
}

# Save current scores for historical tracking
$newHistoryEntry = [PSCustomObject]@{
    Date = $reportDate
    Domain = $domain
    GlobalScore = $globalScore
    StaleScore = $StaleScore
    PrivilegiedGroupScore = $PrivilegiedGroupScore
    TrustScore = $trustscore
    AnomalyScore = $AnomalyScore
}

if ($IncludeComparisonWithPrevious) {
    if (Test-Path $historyFile) {
        $scoreHistory = Import-Csv -Path $historyFile
        $scoreHistory += $newHistoryEntry
        $scoreHistory | Export-Csv -Path $historyFile -NoTypeInformation
    } else {
        $newHistoryEntry | Export-Csv -Path $historyFile -NoTypeInformation
        Write-Host "Created new score history file at $historyFile" -ForegroundColor Green
    }
}

# Make styling more flexible by parameterizing colors and styles
New-HTML -TitleText "PingCastle Healthcheck Report - $domain" -Online -FilePath $OutputPath {
    
    New-HTMLHeader {
        New-HTMLSection -AlignContent center -HeaderTextAlignment center -HeaderText "PingCastle Security Assessment Report" -HeaderTextSize 50 -HeaderBackGroundColor $ThemeColor {
            
            New-HTMLText -Text $LogoHTMLCompany
            New-HTMLText -Text $LogoHTMLPingCastle


        }
        
        
        

            


    }
    New-HTMLSection -HeaderText "Global Score - $domain"-HeaderTextSize 40 -HeaderBackGroundColor $ThemeColor  {
        New-HTMLPanel {
            
            New-HTMLText -Text $globalScore -Color (Get-ScoreColor $globalScore) -FontSize 120 -Alignment center -FontWeight bolder
        }
    }

    New-HTMLSection -HeaderText "Section Score"-HeaderTextSize 24 -HeaderBackGroundColor $ThemeColor  {

        New-HTMLPanel {
            New-HTMLText -Text "Stale Objects" -Color $ThemeColor -FontSize 20 -FontWeight bold -Alignment center  
            New-HTMLText -Text $StaleScore -Color (Get-ScoreColor $StaleScore) -FontSize 80 -Alignment center -FontWeight bolder          
        }
        New-HTMLPanel {
            New-HTMLText -Text "Privileged Account" -Color $ThemeColor -FontSize 20 -FontWeight bold -Alignment center  
            New-HTMLText -Text $PrivilegiedGroupScore -Color (Get-ScoreColor $PrivilegiedGroupScore) -FontSize 80 -Alignment center -FontWeight bolder          
        }

        New-HTMLPanel {
            New-HTMLText -Text "Trust Relationships" -Color $ThemeColor -FontSize 20 -FontWeight bold -Alignment center
            New-HTMLText -Text $trustscore -Color (Get-ScoreColor $trustscore) -FontSize 80 -Alignment center -FontWeight bolder           
        }

        New-HTMLPanel {
            New-HTMLText -Text "Security Anomalies" -Color $ThemeColor -FontSize 20 -FontWeight bold -Alignment center  
            New-HTMLText -Text $AnomalyScore -Color (Get-ScoreColor $AnomalyScore) -FontSize 80 -Alignment center -FontWeight bolder          
        }

    }

    New-HTMLSection -HeaderBackGroundColor $ThemeColor -HeaderText "Summary and Recommendations" {
        New-HTMLPanel {
            New-HTMLText -Text "Summary Analysis" -Color $ThemeColor -FontSize 24 -FontWeight bold
            
            # Add logic to determine highest risk areas - MODIFIED for 0=good, 100=bad scale  
            $highestScore = @($globalScore, $StaleScore, $privilegedScore, $trustscore, $AnomalyScore) | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum
            
            # Better tracking of all high scores
            $thresholdForHighRisk = $HighRiskThreshold
            $highRiskAreas = @()
            
            if ($globalScore -gt $thresholdForHighRisk) { $highRiskAreas += "Overall Security" }
            if ($StaleScore -gt $thresholdForHighRisk) { $highRiskAreas += "Stale Objects" }
            if ($privilegedScore -gt $thresholdForHighRisk) { $highRiskAreas += "Privileged Access" }
            if ($trustscore -gt $thresholdForHighRisk) { $highRiskAreas += "Trust Relationships" }
            if ($AnomalyScore -gt $thresholdForHighRisk) { $highRiskAreas += "Security Anomalies" }
            
            $worstCategory = switch($highestScore) {
                $StaleScore { "Stale Objects" }
                $privilegedScore { "Privileged Access" }
                $trustscore { "Trust Relationships" }
                $AnomalyScore { "Security Anomalies" }
                default { "Overall Security" }
            }
            
            # Dynamic coloring based on score severity - MODIFIED for 0=good, 100=bad scale
            $priorityColor = if ($highestScore -gt 70) { "darkred" } elseif ($highestScore -gt 50) { "red" } elseif ($highestScore -gt 30) { "orange" } else { "green" }
            
            New-HTMLText -Text "Priority Focus Area: $worstCategory (Score: $highestScore)" -Color $priorityColor -FontSize 18 -FontWeight bold
            
            # Show all high risk areas if there are multiple
            if ($highRiskAreas.Count -gt 1) {
                New-HTMLText -Text "Additional High Risk Areas:" -Color $ThemeColor -FontSize 16
                New-HTMLList -Type Unordered {
                    foreach($area in $highRiskAreas | Where-Object {$_ -ne $worstCategory}) {
                        $areaScore = switch($area) {
                            "Stale Objects" { $StaleScore }
                            "Privileged Access" { $privilegedScore }
                            "Trust Relationships" { $trustscore }
                            "Security Anomalies" { $AnomalyScore }
                            default { $globalScore }
                        }
                        New-HTMLListItem -Text "$area (Score: $areaScore)"
                    }
                }
            }
            
            New-HTMLText -Text "Top Recommendations:" -Color $ThemeColor -FontSize 20
            
            # Get top issues by points, including remediation guidance
            $topIssues = $healthcheckData | Sort-Object -Property Points -Descending | Select-Object -First 5
            
            New-HTMLTable -DataTable $topIssues -HideButtons -DisablePaging -DisableSearch {
                New-TableHeader -Color White -BackGroundColor $ThemeColor
                New-TableCondition -Name "Points" -ComparisonType number -Operator gt -Value 30 -Color Red -Row
                New-TableCondition -Name "Points" -ComparisonType number -Operator gt -Value 20 -Color Orange -Row
                New-TableCondition -Name "Points" -ComparisonType number -Operator le -Value 20 -Color Green -Row
            }
            
            # Executive summary with progress tracking
            New-HTMLText -Text "Action Plan Timeline" -Color $ThemeColor -FontSize 18
            New-HTMLText -Text "Below is a recommended timeline to address the key findings:" -FontSize 14
            
            New-HTMLList -Type Ordered {
                New-HTMLListItem -Text "Immediate (0-30 days): Address priority focus area ($worstCategory)"
                New-HTMLListItem -Text "Short-term (30-60 days): Remediate top 3 issues by risk points"
                New-HTMLListItem -Text "Medium-term (60-90 days): Address additional high-risk areas"
                New-HTMLListItem -Text "Long-term: Implement regular security assessment cycles"
            }
        }
    }
    
    New-HTMLSection -HeaderBackGroundColor $ThemeColor -HeaderText "Detailed Risk Analysis" {
        New-HTMLPanel {
            New-HTMLTable -DataTable $healthcheckData -AllProperties -HideButtons -DisableSearch -DisablePaging {
                New-TableHeader -Color White -BackGroundColor $ThemeColor
                New-TableCondition -Name "Points" -ComparisonType number -Operator gt -Value 30 -Color Red -Row
                New-TableCondition -Name "Points" -ComparisonType number -Operator gt -Value 20 -Color Orange -Row
                New-TableCondition -Name "Points" -ComparisonType number -Operator le -Value 20 -Color Green -Row
            }
        }
    }
    
    New-HTMLFooter {
        New-HTMLText -Text "Report generated from PingCastle data on $currentDateTime by $currentUser" -Color gray -FontSize 10 -Alignment center
        New-HTMLText -Text "© $(Get-Date -Format yyyy) YourCompany - For internal use only" -Color gray -FontSize 10 -Alignment center
        New-HTMLText -Text "SCALE: 0 = GOOD, 100 = CRITICAL" -Color black -FontWeight bold -FontSize 12 -Alignment center
    }
}

Write-Output "Report generated successfully at $OutputPath"
