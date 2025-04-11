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
    [switch]$IncludeComparisonWithPrevious
)

# Read the XML file
if(!(Test-Path $XmlPath)) {
    Write-Error "XML file not found: $XmlPath"
    exit 1
}

try {
    [xml]$data = Get-Content $XmlPath -ErrorAction Stop
    
    # Extract core domain information
    $domain = $data.HealthcheckData.DomainFQDN
    $domainNetbios = $data.HealthcheckData.NetBIOSName
    $dcName = $data.HealthcheckData.DCName
    
    # Extract scores
    $globalScore = [int]$data.HealthcheckData.GlobalScore
    $StaleScore = [int]$data.HealthcheckData.StaleObjectsScore
    $privilegedScore = [int]$data.HealthcheckData.PrivilegedScore
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
            RecommendedFix = $risk.Documentation
        }
    }
    
} catch {
    Write-Error "Error processing XML data: $_"
    exit 1
}

# Ensure PSWriteHTML module is installed
if (!(Get-Module -ListAvailable -Name PSWriteHTML)) {
    Write-Error "PSWriteHTML module is required but not installed. Install it using: Install-Module -Name PSWriteHTML -Force"
    exit 1
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
    
    if ($Score -lt 20) { return "green" }
    elseif ($Score -lt 50) { return "orange" }
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
    PrivilegedScore = $privilegedScore
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
    }
}

# Make styling more flexible by parameterizing colors and styles
New-HTML -TitleText "PingCastle Healthcheck Report - $domain" -Online -FilePath $OutputPath {
    
    New-HTMLHeader {
        New-HTMLText -Text "PingCastle Security Assessment Report" -Color $ThemeColor -FontSize 24 -FontWeight bold
        New-HTMLText -Text "Domain: $domain ($domainNetbios)" -FontSize 14
        New-HTMLText -Text "Generated: $currentDateTime by $currentUser" -FontSize 12 -FontStyle italic
        New-HTMLText -Text "Domain Controller: $dcName" -FontSize 12
    }
    
    New-HTMLSection -HeaderText "Executive Dashboard" -HeaderBackGroundColor $ThemeColor -CanCollapse {
        New-HTMLPanel {
            New-HTMLText -Text "Domain Security Scores" -Color $ThemeColor -FontSize 20 -FontWeight bold
            New-HTMLText -Text "(Lower scores are better - 0 is perfect, 100 is critical)" -FontSize 14 -FontStyle italic
            
            # Create a grid layout for scores - using compatible parameter
            New-HTMLPanel {
                New-HTMLTable -DataTable @(
                    [PSCustomObject]@{
                        "Score Type" = "Global Score"
                        "Score" = $globalScore
                        "Status" = if ($globalScore -lt 20) { "Good" } elseif ($globalScore -lt 50) { "Warning" } else { "Critical" }
                        "Color" = Get-ScoreColor $globalScore
                    },
                    [PSCustomObject]@{
                        "Score Type" = "Stale Objects"
                        "Score" = $StaleScore
                        "Status" = if ($StaleScore -lt 20) { "Good" } elseif ($StaleScore -lt 50) { "Warning" } else { "Critical" }
                        "Color" = Get-ScoreColor $StaleScore
                    },
                    [PSCustomObject]@{
                        "Score Type" = "Privileged Access"
                        "Score" = $privilegedScore
                        "Status" = if ($privilegedScore -lt 20) { "Good" } elseif ($privilegedScore -lt 50) { "Warning" } else { "Critical" }
                        "Color" = Get-ScoreColor $privilegedScore
                    },
                    [PSCustomObject]@{
                        "Score Type" = "Trust Relationships"
                        "Score" = $trustscore
                        "Status" = if ($trustscore -lt 20) { "Good" } elseif ($trustscore -lt 50) { "Warning" } else { "Critical" }
                        "Color" = Get-ScoreColor $trustscore
                    },
                    [PSCustomObject]@{
                        "Score Type" = "Security Anomalies"
                        "Score" = $AnomalyScore
                        "Status" = if ($AnomalyScore -lt 20) { "Good" } elseif ($AnomalyScore -lt 50) { "Warning" } else { "Critical" }
                        "Color" = Get-ScoreColor $AnomalyScore
                    }
                ) {
                    New-TableHeader -Color White -BackGroundColor $ThemeColor
                    New-TableCondition -Name "Score" -ComparisonType number -Operator ge -Value 50 -Color "red" -Row
                    New-TableCondition -Name "Score" -ComparisonType number -Operator ge -Value 20 -Operator2 lt -Value2 50 -Color "orange" -Row
                    New-TableCondition -Name "Score" -ComparisonType number -Operator lt -Value 20 -Color "green" -Row
                }
            }
            
            # Show historical trends if enabled
            if ($showTrends) {
                New-HTMLText -Text "Score Trends" -Color $ThemeColor -FontSize 18 -FontWeight bold
                
                New-HTMLPanel {
                    New-HTMLTable -DataTable @(
                        [PSCustomObject]@{
                            "Score Type" = "Global Score"
                            "Previous" = [int]$previousEntry.GlobalScore
                            "Current" = $globalScore
                            "Change" = $globalScore - [int]$previousEntry.GlobalScore
                            "Trend" = if (($globalScore - [int]$previousEntry.GlobalScore) -lt 0) { "Improved" } elseif (($globalScore - [int]$previousEntry.GlobalScore) -gt 0) { "Degraded" } else { "No Change" }
                        },
                        [PSCustomObject]@{
                            "Score Type" = "Stale Objects"
                            "Previous" = [int]$previousEntry.StaleScore
                            "Current" = $StaleScore
                            "Change" = $StaleScore - [int]$previousEntry.StaleScore
                            "Trend" = if (($StaleScore - [int]$previousEntry.StaleScore) -lt 0) { "Improved" } elseif (($StaleScore - [int]$previousEntry.StaleScore) -gt 0) { "Degraded" } else { "No Change" }
                        },
                        [PSCustomObject]@{
                            "Score Type" = "Privileged Access"
                            "Previous" = [int]$previousEntry.PrivilegedScore
                            "Current" = $privilegedScore
                            "Change" = $privilegedScore - [int]$previousEntry.PrivilegedScore
                            "Trend" = if (($privilegedScore - [int]$previousEntry.PrivilegedScore) -lt 0) { "Improved" } elseif (($privilegedScore - [int]$previousEntry.PrivilegedScore) -gt 0) { "Degraded" } else { "No Change" }
                        },
                        [PSCustomObject]@{
                            "Score Type" = "Trust Relationships"
                            "Previous" = [int]$previousEntry.TrustScore
                            "Current" = $trustscore
                            "Change" = $trustscore - [int]$previousEntry.TrustScore
                            "Trend" = if (($trustscore - [int]$previousEntry.TrustScore) -lt 0) { "Improved" } elseif (($trustscore - [int]$previousEntry.TrustScore) -gt 0) { "Degraded" } else { "No Change" }
                        },
                        [PSCustomObject]@{
                            "Score Type" = "Security Anomalies"
                            "Previous" = [int]$previousEntry.AnomalyScore
                            "Current" = $AnomalyScore
                            "Change" = $AnomalyScore - [int]$previousEntry.AnomalyScore
                            "Trend" = if (($AnomalyScore - [int]$previousEntry.AnomalyScore) -lt 0) { "Improved" } elseif (($AnomalyScore - [int]$previousEntry.AnomalyScore) -gt 0) { "Degraded" } else { "No Change" }
                        }
                    ) {
                        New-TableHeader -Color White -BackGroundColor $ThemeColor
                        New-TableCondition -Name "Change" -ComparisonType number -Operator lt -Value 0 -Color "green" -Row
                        New-TableCondition -Name "Change" -ComparisonType number -Operator gt -Value 0 -Color "red" -Row
                    }
                }
            }
        }
    }

    New-HTMLSection -HeaderBackGroundColor $ThemeColor -HeaderText "Summary and Recommendations" -CanCollapse {
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
            
            New-HTMLTable -DataTable $topIssues -HideButtons {
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
    
    New-HTMLSection -HeaderBackGroundColor $ThemeColor -HeaderText "Detailed Risk Analysis" -CanCollapse {
        New-HTMLPanel {
            New-HTMLTable -DataTable $healthcheckData -AllProperties -HideButtons {
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