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

# Helper function to determine score color
function Get-ScoreColor {
    param([int]$Score)
    
    if ($Score -ge 17) { return "green" }
    elseif ($Score -ge 50) { return "orange" }
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
            
            # Create a grid layout for scores
            New-HTMLPanel -GridColumns 5 {
                # Global Score
                New-HTMLPanel {
                    New-HTMLText -Text "Global Score" -Color $ThemeColor -FontWeight bold -Alignment center
                    New-HTMLText -Text "$globalScore" -Color (Get-ScoreColor $globalScore) -Alignment center -FontSize 32 -FontWeight bold
                }
                
                # Stale Objects Score
                New-HTMLPanel {
                    New-HTMLText -Text "Stale Objects" -Color $ThemeColor -FontWeight bold -Alignment center
                    New-HTMLText -Text "$StaleScore" -Color (Get-ScoreColor $StaleScore) -Alignment center -FontSize 32 -FontWeight bold
                }
                
                # Privileged Score
                New-HTMLPanel {
                    New-HTMLText -Text "Privileged Access" -Color $ThemeColor -FontWeight bold -Alignment center
                    New-HTMLText -Text "$privilegedScore" -Color (Get-ScoreColor $privilegedScore) -Alignment center -FontSize 32 -FontWeight bold
                }
                
                # Trust Score
                New-HTMLPanel {
                    New-HTMLText -Text "Trust Relationships" -Color $ThemeColor -FontWeight bold -Alignment center
                    New-HTMLText -Text "$trustscore" -Color (Get-ScoreColor $trustscore) -Alignment center -FontSize 32 -FontWeight bold
                }
                
                # Anomaly Score
                New-HTMLPanel {
                    New-HTMLText -Text "Anomalies" -Color $ThemeColor -FontWeight bold -Alignment center
                    New-HTMLText -Text "$AnomalyScore" -Color (Get-ScoreColor $AnomalyScore) -Alignment center -FontSize 32 -FontWeight bold
                }
            }
            
            # Show historical trends if enabled
            if ($showTrends) {
                New-HTMLText -Text "Score Trends" -Color $ThemeColor -FontSize 18 -FontWeight bold
                
                New-HTMLPanel -GridColumns 5 {
                    # Global Score Trend
                    New-HTMLPanel {
                        $trend = [int]$globalScore - [int]$previousEntry.GlobalScore
                        $trendSymbol = if ($trend -gt 0) { "↑" } elseif ($trend -lt 0) { "↓" } else { "→" }
                        $trendColor = if ($trend -gt 0) { "green" } elseif ($trend -lt 0) { "red" } else { "gray" }
                        New-HTMLText -Text "$trendSymbol $trend" -Color $trendColor -Alignment center -FontSize 16 -FontWeight bold
                    }
                    
                    # Stale Objects Trend
                    New-HTMLPanel {
                        $trend = [int]$StaleScore - [int]$previousEntry.StaleScore
                        $trendSymbol = if ($trend -gt 0) { "↑" } elseif ($trend -lt 0) { "↓" } else { "→" }
                        $trendColor = if ($trend -gt 0) { "green" } elseif ($trend -lt 0) { "red" } else { "gray" }
                        New-HTMLText -Text "$trendSymbol $trend" -Color $trendColor -Alignment center -FontSize 16 -FontWeight bold
                    }
                    
                    # Privileged Score Trend
                    New-HTMLPanel {
                        $trend = [int]$privilegedScore - [int]$previousEntry.PrivilegedScore
                        $trendSymbol = if ($trend -gt 0) { "↑" } elseif ($trend -lt 0) { "↓" } else { "→" }
                        $trendColor = if ($trend -gt 0) { "green" } elseif ($trend -lt 0) { "red" } else { "gray" }
                        New-HTMLText -Text "$trendSymbol $trend" -Color $trendColor -Alignment center -FontSize 16 -FontWeight bold
                    }
                    
                    # Trust Score Trend
                    New-HTMLPanel {
                        $trend = [int]$trustscore - [int]$previousEntry.TrustScore
                        $trendSymbol = if ($trend -gt 0) { "↑" } elseif ($trend -lt 0) { "↓" } else { "→" }
                        $trendColor = if ($trend -gt 0) { "green" } elseif ($trend -lt 0) { "red" } else { "gray" }
                        New-HTMLText -Text "$trendSymbol $trend" -Color $trendColor -Alignment center -FontSize 16 -FontWeight bold
                    }
                    
                    # Anomaly Score Trend
                    New-HTMLPanel {
                        $trend = [int]$AnomalyScore - [int]$previousEntry.AnomalyScore
                        $trendSymbol = if ($trend -gt 0) { "↑" } elseif ($trend -lt 0) { "↓" } else { "→" }
                        $trendColor = if ($trend -gt 0) { "green" } elseif ($trend -lt 0) { "red" } else { "gray" }
                        New-HTMLText -Text "$trendSymbol $trend" -Color $trendColor -Alignment center -FontSize 16 -FontWeight bold
                    }
                }
            }
        }
    }

    New-HTMLSection -HeaderBackGroundColor $ThemeColor -HeaderText "Summary and Recommendations" -HeaderTextSize 40 {
        New-HTMLPanel {
            New-HTMLText -Text "Summary Analysis" -Color $ThemeColor -FontSize 24 -FontWeight bold
            
            # Add logic to determine highest risk areas
            $lowestScore = @($globalScore, $StaleScore, $privilegedScore, $trustscore, $AnomalyScore) | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum
            
            # Better tracking of all low scores (not just the minimum)
            $thresholdForHighRisk = $HighRiskThreshold
            $highRiskAreas = @()
            
            if ($globalScore -lt $thresholdForHighRisk) { $highRiskAreas += "Overall Security" }
            if ($StaleScore -lt $thresholdForHighRisk) { $highRiskAreas += "Stale Objects" }
            if ($privilegedScore -lt $thresholdForHighRisk) { $highRiskAreas += "Privileged Access" }
            if ($trustscore -lt $thresholdForHighRisk) { $highRiskAreas += "Trust Relationships" }
            if ($AnomalyScore -lt $thresholdForHighRisk) { $highRiskAreas += "Security Anomalies" }
            
            $worstCategory = switch($lowestScore) {
                $StaleScore { "Stale Objects" }
                $privilegedScore { "Privileged Access" }
                $trustscore { "Trust Relationships" }
                $AnomalyScore { "Security Anomalies" }
                default { "Overall Security" }
            }
            
            # Dynamic coloring based on score severity
            $priorityColor = if ($lowestScore -lt 30) { "darkred" } elseif ($lowestScore -lt 50) { "red" } elseif ($lowestScore -lt 70) { "orange" } else { "green" }
            
            New-HTMLText -Text "Priority Focus Area: $worstCategory (Score: $lowestScore)" -Color $priorityColor -FontSize 18 -FontWeight bold
            
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
    
    New-HTMLSection -HeaderBackGroundColor $ThemeColor -HeaderText "Detailed Risk Analysis" -HeaderTextSize 30 -CanCollapse {
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
    }
}

Write-Output "Report generated successfully at $OutputPath"