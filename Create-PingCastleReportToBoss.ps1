<#
.SYNOPSIS
    Generates PingCastle HTML security reports from XML exports.

.DESCRIPTION
    This script transforms PingCastle XML data exports into interactive HTML reports
    with security scores, risk analysis, and remediation recommendations.

.PARAMETER XmlPath
    Path to the PingCastle XML export file.

.PARAMETER OutputPath
    Path where the HTML report will be saved.

.PARAMETER ThemeColor
    Primary color theme for the report (hex code).

.PARAMETER HighRiskThreshold
    Score threshold for categorizing high-risk areas (default: 50).

.PARAMETER IncludeComparisonWithPrevious
    Switch to enable comparison with previous assessment data.

.PARAMETER ExportFormat
    Output format(s) for the report (HTML, PDF, CSV, JSON).

.EXAMPLE
    .\Generate-PingCastleReport.ps1 -XmlPath ".\ad_export.xml" -OutputPath "SecurityReport.html" -IncludeComparisonWithPrevious

.NOTES
    Author: DambergC
    Version: 2.0
    Last Updated: 2025-04-11
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$XmlPath = ".\ad_hc_int.vxops.se.xml",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "HealthcheckReport.html",
    
    [Parameter(Mandatory=$false)]
    [ValidatePattern("^#[0-9A-Fa-f]{6}$")]
    [string]$ThemeColor = "#990AE3",
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(0, 100)]
    [int]$HighRiskThreshold = 50,

    [Parameter(Mandatory=$false)]
    [ValidateRange(0, 100)]
    [int]$MediumRiskThreshold = 70,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeComparisonWithPrevious,

    [Parameter(Mandatory=$false)]
    [ValidateSet("HTML", "PDF", "CSV", "JSON")]
    [string[]]$ExportFormat = @("HTML")
)

<<<<<<< HEAD
# Read the XML file
if(!(Test-Path $XmlPath)) {
    Write-Error "XML file not found: $XmlPath"
    exit 1
=======
#region Functions

function Import-ReportConfig {
    param([string]$ConfigPath = ".\PingCastleReportConfig.json")
    
    if (Test-Path $ConfigPath) {
        $config = Get-Content $ConfigPath | ConvertFrom-Json
        Write-Verbose "Configuration loaded from $ConfigPath"
        return $config
    } else {
        # Default configuration
        Write-Verbose "No configuration file found, using defaults"
        return @{
            ThemeColor = $ThemeColor
            HighRiskThreshold = $HighRiskThreshold
            MediumRiskThreshold = $MediumRiskThreshold
            CompanyName = "YourCompany"
            LogoUrl = ""
            ReportTitle = "Active Directory Security Assessment"
        }
    }
>>>>>>> a69105d800f5d8918fe9e771090211e760e4db65
}

function Import-PingCastleData {
    param([string]$Path)
    
    Write-Verbose "Importing PingCastle data from $Path"
    try {
        [xml]$xmlData = Get-Content $Path -ErrorAction Stop
        
        # Validate XML structure
        if ($xmlData.HealthcheckData -eq $null) {
            throw "Invalid XML structure - missing HealthcheckData element"
        }

        $reportData = @{
            # Domain information
            Domain = $xmlData.HealthcheckData.DomainFQDN
            DomainNetbios = $xmlData.HealthcheckData.NetBIOSName
            DCName = $xmlData.HealthcheckData.DCName
            GenerationDate = $xmlData.HealthcheckData.GenerationDate
            
            # Scores
            Scores = @{
                Global = [int]$xmlData.HealthcheckData.GlobalScore
                StaleObjects = [int]$xmlData.HealthcheckData.StaleObjectsScore
                PrivilegedAccess = [int]$xmlData.HealthcheckData.PrivilegedScore
                Trust = [int]$xmlData.HealthcheckData.TrustScore
                Anomaly = [int]$xmlData.HealthcheckData.AnomalyScore
            }
            
            # Risk rules
            RiskRules = @(
                foreach($risk in $xmlData.HealthcheckData.RiskRules.HealthcheckRiskRule) {
                    [PSCustomObject]@{
                        Category = $risk.Category
                        RiskId = $risk.RiskId
                        Model = $risk.Model
                        Points = [int]$risk.Points
                        Rationale = $risk.Rationale
                        RecommendedFix = $risk.Documentation
                    }
                }
            )
        }
        
        return $reportData
    } 
    catch {
        Write-Error "Error processing XML data: $_"
        Write-Host "Please verify the XML file is a valid PingCastle health check export" -ForegroundColor Yellow
        exit 1
    }
}

function Get-ScoreColor {
    param(
        [int]$Score,
        [int]$HighThreshold = $config.MediumRiskThreshold,
        [int]$MediumThreshold = $config.HighRiskThreshold
    )
    
    if ($Score -ge $HighThreshold) { return "green" }
    elseif ($Score -ge $MediumThreshold) { return "orange" }
    else { return "red" }
}

function Get-ScoreTrend {
    param(
        [int]$CurrentScore,
        [int]$PreviousScore,
        [string]$MetricName
    )

    $trend = $CurrentScore - $PreviousScore
    $percentChange = if ($PreviousScore -ne 0) { [math]::Round(($trend / $PreviousScore) * 100, 1) } else { 0 }
    
    return @{
        Trend = $trend
        PercentChange = $percentChange
        Symbol = if ($trend -gt 0) { "↑" } elseif ($trend -lt 0) { "↓" } else { "→" }
        Color = if ($trend -gt 0) { "green" } elseif ($trend -lt 0) { "red" } else { "gray" }
        IsImprovement = $trend -gt 0  # Higher scores are better in PingCastle
        Description = if ($trend -gt 0) { "improved by $trend points ($percentChange%)" } elseif ($trend -lt 0) { "worsened by $($trend*-1) points ($($percentChange*-1)%)" } else { "unchanged" }
    }
}

function Get-RiskPriority {
    param(
        [array]$RiskRules
    )
    
    # Group risks by category and calculate total score impact
    $categoryRisks = $RiskRules | Group-Object -Property Category | ForEach-Object {
        $categoryScore = ($_.Group | Measure-Object -Property Points -Sum).Sum
        
        [PSCustomObject]@{
            Category = $_.Name
            TotalPoints = $categoryScore
            Count = $_.Count
            AveragePoints = [math]::Round($categoryScore / $_.Count, 1)
            HighestRisk = ($_.Group | Sort-Object Points -Descending | Select-Object -First 1)
        }
    }
    
    # Sort by total impact
    return $categoryRisks | Sort-Object TotalPoints -Descending
}

function Get-HistoricalData {
    param(
        [string]$HistoryFile,
        [hashtable]$CurrentData,
        [switch]$SaveCurrent = $true
    )
    
    Write-Verbose "Processing historical data from $HistoryFile"
    $historyExists = Test-Path $HistoryFile
    
    # Create new history entry
    $newHistoryEntry = [PSCustomObject]@{
        Date = Get-Date -Format "yyyy-MM-dd"
        Domain = $CurrentData.Domain
        GlobalScore = $CurrentData.Scores.Global
        StaleScore = $CurrentData.Scores.StaleObjects
        PrivilegedScore = $CurrentData.Scores.PrivilegedAccess
        TrustScore = $CurrentData.Scores.Trust
        AnomalyScore = $CurrentData.Scores.Anomaly
    }
    
    # Initialize result object
    $result = @{
        ShowTrends = $false
        PreviousEntry = $null
        History = @()
    }
    
    # Process existing history
    if ($historyExists) {
        try {
            $history = Import-Csv -Path $HistoryFile
            $result.History = $history
            if ($history.Count -gt 0) {
                $result.PreviousEntry = $history | Sort-Object -Property Date -Descending | Select-Object -First 1
                $result.ShowTrends = $true
            }
        }
        catch {
            Write-Warning "Error reading history file: $_"
        }
    }
    
    # Save current data to history
    if ($SaveCurrent) {
        try {
            if ($historyExists) {
                $updatedHistory = @($result.History) + @($newHistoryEntry)
                $updatedHistory | Export-Csv -Path $HistoryFile -NoTypeInformation
            } else {
                $newHistoryEntry | Export-Csv -Path $HistoryFile -NoTypeInformation
            }
            Write-Verbose "History updated with current results"
        }
        catch {
            Write-Warning "Error saving to history file: $_"
        }
    }
    
    return $result
}

function Save-EncryptedHistory {
    param(
        $HistoryData, 
        $FilePath,
        [switch]$UseEncryption = $false
    )
    
    if ($UseEncryption) {
        $secureString = ConvertTo-SecureString -String (ConvertTo-Json $HistoryData) -AsPlainText -Force
        $encrypted = ConvertFrom-SecureString -SecureString $secureString
        Set-Content -Path $FilePath -Value $encrypted
        Write-Verbose "Encrypted history saved to $FilePath"
    }
    else {
        $HistoryData | Export-Csv -Path $FilePath -NoTypeInformation
        Write-Verbose "History saved to $FilePath"
    }
}

function New-ExecutiveDashboard {
    param(
        $Data,
        $HistoricalData,
        $Config
    )
    
    New-HTMLSection -HeaderText "Executive Dashboard" -HeaderBackGroundColor $Config.ThemeColor -CanCollapse {
        New-HTMLPanel {
            New-HTMLText -Text "Domain Security Scores" -Color $Config.ThemeColor -FontSize 20 -FontWeight bold
            
            # Create a grid layout for scores
            New-HTMLPanel -GridColumns 5 {
                # Global Score
                New-HTMLPanel {
                    New-HTMLText -Text "Global Score" -Color $Config.ThemeColor -FontWeight bold -Alignment center
                    New-HTMLText -Text "$($Data.Scores.Global)" -Color (Get-ScoreColor -Score $Data.Scores.Global) -Alignment center -FontSize 32 -FontWeight bold
                }
                
                # Stale Objects Score
                New-HTMLPanel {
                    New-HTMLText -Text "Stale Objects" -Color $Config.ThemeColor -FontWeight bold -Alignment center
                    New-HTMLText -Text "$($Data.Scores.StaleObjects)" -Color (Get-ScoreColor -Score $Data.Scores.StaleObjects) -Alignment center -FontSize 32 -FontWeight bold
                }
                
                # Privileged Score
                New-HTMLPanel {
                    New-HTMLText -Text "Privileged Access" -Color $Config.ThemeColor -FontWeight bold -Alignment center
                    New-HTMLText -Text "$($Data.Scores.PrivilegedAccess)" -Color (Get-ScoreColor -Score $Data.Scores.PrivilegedAccess) -Alignment center -FontSize 32 -FontWeight bold
                }
                
                # Trust Score
                New-HTMLPanel {
                    New-HTMLText -Text "Trust Relationships" -Color $Config.ThemeColor -FontWeight bold -Alignment center
                    New-HTMLText -Text "$($Data.Scores.Trust)" -Color (Get-ScoreColor -Score $Data.Scores.Trust) -Alignment center -FontSize 32 -FontWeight bold
                }
                
                # Anomaly Score
                New-HTMLPanel {
                    New-HTMLText -Text "Anomalies" -Color $Config.ThemeColor -FontWeight bold -Alignment center
                    New-HTMLText -Text "$($Data.Scores.Anomaly)" -Color (Get-ScoreColor -Score $Data.Scores.Anomaly) -Alignment center -FontSize 32 -FontWeight bold
                }
            }
            
            # Show historical trends if enabled
            if ($HistoricalData.ShowTrends) {
                New-HTMLText -Text "Score Trends" -Color $Config.ThemeColor -FontSize 18 -FontWeight bold
                
                # Get trend data for each score
                $globalTrend = Get-ScoreTrend -CurrentScore $Data.Scores.Global -PreviousScore $HistoricalData.PreviousEntry.GlobalScore -MetricName "Global"
                $staleTrend = Get-ScoreTrend -CurrentScore $Data.Scores.StaleObjects -PreviousScore $HistoricalData.PreviousEntry.StaleScore -MetricName "StaleObjects"
                $privTrend = Get-ScoreTrend -CurrentScore $Data.Scores.PrivilegedAccess -PreviousScore $HistoricalData.PreviousEntry.PrivilegedScore -MetricName "PrivilegedAccess"
                $trustTrend = Get-ScoreTrend -CurrentScore $Data.Scores.Trust -PreviousScore $HistoricalData.PreviousEntry.TrustScore -MetricName "Trust"
                $anomalyTrend = Get-ScoreTrend -CurrentScore $Data.Scores.Anomaly -PreviousScore $HistoricalData.PreviousEntry.AnomalyScore -MetricName "Anomaly"
                
                New-HTMLPanel -GridColumns 5 {
                    # Global Score Trend
                    New-HTMLPanel {
                        New-HTMLText -Text "$($globalTrend.Symbol) $($globalTrend.Trend)" -Color $globalTrend.Color -Alignment center -FontSize 16 -FontWeight bold
                    }
                    
                    # Stale Objects Trend
                    New-HTMLPanel {
                        New-HTMLText -Text "$($staleTrend.Symbol) $($staleTrend.Trend)" -Color $staleTrend.Color -Alignment center -FontSize 16 -FontWeight bold
                    }
                    
                    # Privileged Score Trend
                    New-HTMLPanel {
                        New-HTMLText -Text "$($privTrend.Symbol) $($privTrend.Trend)" -Color $privTrend.Color -Alignment center -FontSize 16 -FontWeight bold
                    }
                    
                    # Trust Score Trend
                    New-HTMLPanel {
                        New-HTMLText -Text "$($trustTrend.Symbol) $($trustTrend.Trend)" -Color $trustTrend.Color -Alignment center -FontSize 16 -FontWeight bold
                    }
                    
                    # Anomaly Score Trend
                    New-HTMLPanel {
                        New-HTMLText -Text "$($anomalyTrend.Symbol) $($anomalyTrend.Trend)" -Color $anomalyTrend.Color -Alignment center -FontSize 16 -FontWeight bold
                    }
                }
                
                # Add score history chart if we have enough data points
                if ($HistoricalData.History.Count -ge 2) {
                    New-HTMLPanel {
                        $chartLabels = @($HistoricalData.History.Date)
                        
                        $chartData = @{
                            Labels = $chartLabels
                            Datasets = @(
                                @{
                                    Label = "Global Score"
                                    Data = @($HistoricalData.History.GlobalScore)
                                    BorderColor = $Config.ThemeColor
                                    BackgroundColor = "transparent"
                                    Fill = $false
                                    LineTension = 0.3
                                },
                                @{
                                    Label = "Stale Objects"
                                    Data = @($HistoricalData.History.StaleScore)
                                    BorderColor = "#1E90FF"
                                    BackgroundColor = "transparent"
                                    Fill = $false
                                    LineTension = 0.3
                                },
                                @{
                                    Label = "Privileged Access"
                                    Data = @($HistoricalData.History.PrivilegedScore)
                                    BorderColor = "#FF4500"
                                    BackgroundColor = "transparent"
                                    Fill = $false
                                    LineTension = 0.3
                                },
                                @{
                                    Label = "Trust Relationships"
                                    Data = @($HistoricalData.History.TrustScore)
                                    BorderColor = "#32CD32"
                                    BackgroundColor = "transparent"
                                    Fill = $false
                                    LineTension = 0.3
                                },
                                @{
                                    Label = "Anomalies"
                                    Data = @($HistoricalData.History.AnomalyScore)
                                    BorderColor = "#FFA500"
                                    BackgroundColor = "transparent"
                                    Fill = $false
                                    LineTension = 0.3
                                }
                            )
                        }
                        
                        New-HTMLChart -Type line -Data $chartData -Options @{
                            Title = @{
                                Display = $true
                                Text = "Security Score History"
                            }
                            Scales = @{
                                y = @{
                                    Ticks = @{
                                        BeginAtZero = $true
                                        Max = 100
                                    }
                                    Title = @{
                                        Display = $true
                                        Text = "Score"
                                    }
                                }
                            }
                            Elements = @{
                                Line = @{
                                    BorderWidth = 2
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

function New-SummaryAnalysis {
    param(
        $Data,
        $HistoricalData,
        $Config,
        $PrioritizedRisks
    )
    
    # Calculate high-risk areas
    $highRiskAreas = @()
    
    if ($Data.Scores.Global -lt $Config.HighRiskThreshold) { $highRiskAreas += "Overall Security" }
    if ($Data.Scores.StaleObjects -lt $Config.HighRiskThreshold) { $highRiskAreas += "Stale Objects" }
    if ($Data.Scores.PrivilegedAccess -lt $Config.HighRiskThreshold) { $highRiskAreas += "Privileged Access" }
    if ($Data.Scores.Trust -lt $Config.HighRiskThreshold) { $highRiskAreas += "Trust Relationships" }
    if ($Data.Scores.Anomaly -lt $Config.HighRiskThreshold) { $highRiskAreas += "Security Anomalies" }
    
    # Find lowest score for priority focus
    $scores = @($Data.Scores.Global, $Data.Scores.StaleObjects, $Data.Scores.PrivilegedAccess, $Data.Scores.Trust, $Data.Scores.Anomaly)
    $lowestScore = $scores | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum
    
    $worstCategory = switch($lowestScore) {
        $Data.Scores.StaleObjects { "Stale Objects" }
        $Data.Scores.PrivilegedAccess { "Privileged Access" }
        $Data.Scores.Trust { "Trust Relationships" }
        $Data.Scores.Anomaly { "Security Anomalies" }
        default { "Overall Security" }
    }
    
    # Dynamic coloring based on score severity
    $priorityColor = if ($lowestScore -lt 30) { "darkred" } elseif ($lowestScore -lt $Config.HighRiskThreshold) { "red" } elseif ($lowestScore -lt $Config.MediumRiskThreshold) { "orange" } else { "green" }
    
    # Get top issues by points, including remediation guidance
    $topIssues = $Data.RiskRules | Sort-Object -Property Points -Descending | Select-Object -First 5
    
    New-HTMLSection -HeaderBackGroundColor $Config.ThemeColor -HeaderText "Summary and Recommendations" -HeaderTextSize 40 {
        New-HTMLPanel {
            New-HTMLText -Text "Summary Analysis" -Color $Config.ThemeColor -FontSize 24 -FontWeight bold
            
            New-HTMLText -Text "Priority Focus Area: $worstCategory (Score: $lowestScore)" -Color $priorityColor -FontSize 18 -FontWeight bold
            
            # Show all high risk areas if there are multiple
            if ($highRiskAreas.Count -gt 1) {
                New-HTMLText -Text "Additional High Risk Areas:" -Color $Config.ThemeColor -FontSize 16
                New-HTMLList -Type Unordered {
                    foreach($area in $highRiskAreas | Where-Object {$_ -ne $worstCategory}) {
                        $areaScore = switch($area) {
                            "Stale Objects" { $Data.Scores.StaleObjects }
                            "Privileged Access" { $Data.Scores.PrivilegedAccess }
                            "Trust Relationships" { $Data.Scores.Trust }
                            "Security Anomalies" { $Data.Scores.Anomaly }
                            default { $Data.Scores.Global }
                        }
                        New-HTMLListItem -Text "$area (Score: $areaScore)"
                    }
                }
            }
            
            # Risk categories summary
            New-HTMLText -Text "Risk Category Summary" -Color $Config.ThemeColor -FontSize 18 -FontWeight bold
            
            # Show table with categorized risk impacts
            New-HTMLTable -DataTable $PrioritizedRisks -HideButtons {
                New-TableHeader -Color White -BackGroundColor $Config.ThemeColor
            }
            
            New-HTMLText -Text "Top Security Issues:" -Color $Config.ThemeColor -FontSize 20
            
            New-HTMLTable -DataTable $topIssues -HideButtons {
                New-TableHeader -Color White -BackGroundColor $Config.ThemeColor
                New-TableCondition -Name "Points" -ComparisonType number -Operator gt -Value 30 -Color Red -Row
                New-TableCondition -Name "Points" -ComparisonType number -Operator gt -Value 20 -Color Orange -Row
                New-TableCondition -Name "Points" -ComparisonType number -Operator le -Value 20 -Color Green -Row
            }
            
            # Executive summary with progress tracking
            New-HTMLText -Text "Action Plan Timeline" -Color $Config.ThemeColor -FontSize 18
            New-HTMLText -Text "Below is a recommended timeline to address the key findings:" -FontSize 14
            
            New-HTMLList -Type Ordered {
                New-HTMLListItem -Text "Immediate (0-30 days): Address priority focus area ($worstCategory)"
                New-HTMLListItem -Text "Short-term (30-60 days): Remediate top 3 issues by risk points"
                New-HTMLListItem -Text "Medium-term (60-90 days): Address additional high-risk areas"
                New-HTMLListItem -Text "Long-term: Implement regular security assessment cycles"
            }
            
            # Add improvement guidance based on comparing with previous assessment
            if ($HistoricalData.ShowTrends) {
                $globalTrend = Get-ScoreTrend -CurrentScore $Data.Scores.Global -PreviousScore $HistoricalData.PreviousEntry.GlobalScore -MetricName "Global"
                
                New-HTMLText -Text "Security Posture Trend:" -Color $Config.ThemeColor -FontSize 18
                New-HTMLText -Text "Since the last assessment, the overall security posture has $($globalTrend.Description)." -FontSize 14
                
                if ($globalTrend.Trend -lt 0) {
                    New-HTMLText -Text "Areas requiring immediate attention:" -Color "red" -FontSize 14 -FontWeight bold
                    
                    # Find areas that have worsened
                    $worseningAreas = @()
                    $staleTrend = Get-ScoreTrend -CurrentScore $Data.Scores.StaleObjects -PreviousScore $HistoricalData.PreviousEntry.StaleScore -MetricName "StaleObjects"
                    $privTrend = Get-ScoreTrend -CurrentScore $Data.Scores.PrivilegedAccess -PreviousScore $HistoricalData.PreviousEntry.PrivilegedScore -MetricName "PrivilegedAccess"
                    $trustTrend = Get-ScoreTrend -CurrentScore $Data.Scores.Trust -PreviousScore $HistoricalData.PreviousEntry.TrustScore -MetricName "Trust"
                    $anomalyTrend = Get-ScoreTrend -CurrentScore $Data.Scores.Anomaly -PreviousScore $HistoricalData.PreviousEntry.AnomalyScore -MetricName "Anomaly"
                    
                    if ($staleTrend.Trend -lt 0) { $worseningAreas += "Stale Objects ($($staleTrend.Description))" }
                    if ($privTrend.Trend -lt 0) { $worseningAreas += "Privileged Access ($($privTrend.Description))" }
                    if ($trustTrend.Trend -lt 0) { $worseningAreas += "Trust Relationships ($($trustTrend.Description))" }
                    if ($anomalyTrend.Trend -lt 0) { $worseningAreas += "Security Anomalies ($($anomalyTrend.Description))" }
                    
                    New-HTMLList -Type Unordered {
                        foreach ($area in $worseningAreas) {
                            New-HTMLListItem -Text $area -Color "red"
                        }
                    }
                } elseif ($globalTrend.Trend -gt 0) {
                    New-HTMLText -Text "Areas of improvement:" -Color "green" -FontSize 14 -FontWeight bold
                    
                    # Find areas that have improved
                    $improvedAreas = @()
                    $staleTrend = Get-ScoreTrend -CurrentScore $Data.Scores.StaleObjects -PreviousScore $HistoricalData.PreviousEntry.StaleScore -MetricName "StaleObjects"
                    $privTrend = Get-ScoreTrend -CurrentScore $Data.Scores.PrivilegedAccess -PreviousScore $HistoricalData.PreviousEntry.PrivilegedScore -MetricName "PrivilegedAccess"
                    $trustTrend = Get-ScoreTrend -CurrentScore $Data.Scores.Trust -PreviousScore $HistoricalData.PreviousEntry.TrustScore -MetricName "Trust"
                    $anomalyTrend = Get-ScoreTrend -CurrentScore $Data.Scores.Anomaly -PreviousScore $HistoricalData.PreviousEntry.AnomalyScore -MetricName "Anomaly"
                    
                    if ($staleTrend.Trend -gt 0) { $improvedAreas += "Stale Objects ($($staleTrend.Description))" }
                    if ($privTrend.Trend -gt 0) { $improvedAreas += "Privileged Access ($($privTrend.Description))" }
                    if ($trustTrend.Trend -gt 0) { $improvedAreas += "Trust Relationships ($($trustTrend.Description))" }
                    if ($anomalyTrend.Trend -gt 0) { $improvedAreas += "Security Anomalies ($($anomalyTrend.Description))" }
                    
                    New-HTMLList -Type Unordered {
                        foreach ($area in $improvedAreas) {
                            New-HTMLListItem -Text $area -Color "green"
                        }
                    }
                }
            }
        }
    }
}

#endregion Functions

#region Main Script

Write-Verbose "Starting PingCastle report generation"

# Load configuration
$config = Import-ReportConfig
# Override config with parameters if provided
if ($PSBoundParameters.ContainsKey('ThemeColor')) { $config.ThemeColor = $ThemeColor }
if ($PSBoundParameters.ContainsKey('HighRiskThreshold')) { $config.HighRiskThreshold = $HighRiskThreshold }
if ($PSBoundParameters.ContainsKey('MediumRiskThreshold')) { $config.MediumRiskThreshold = $MediumRiskThreshold }

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

<<<<<<< HEAD
# Helper function to determine score color - MODIFIED for 0=good, 100=bad scale
function Get-ScoreColor {
    param([int]$Score)
    
    if ($Score -lt 20) { return "green" }
    elseif ($Score -lt 50) { return "orange" }
    else { return "red" }
=======
# Import data
$data = Import-PingCastleData -Path $XmlPath

# Process historical data if enabled
$historyFile = ".\PingCastle_ScoreHistory.csv"
$history = @{
    ShowTrends = $false
    PreviousEntry = $null
    History = @()
>>>>>>> a69105d800f5d8918fe9e771090211e760e4db65
}

if ($IncludeComparisonWithPrevious) {
    $history = Get-HistoricalData -HistoryFile $historyFile -CurrentData $data -SaveCurrent
}

# Prepare metadata
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$currentUser = $env:USERNAME
$reportDate = Get-Date -Format "yyyy-MM-dd"

# Process and categorize risks
$prioritizedRisks = Get-RiskPriority -RiskRules $data.RiskRules

# Generate HTML report
New-HTML -TitleText "PingCastle Healthcheck Report - $($data.Domain)" -Online -FilePath $OutputPath {
    
    New-HTMLHeader {
        New-HTMLText -Text "PingCastle Security Assessment Report" -Color $config.ThemeColor -FontSize 24 -FontWeight bold
        New-HTMLText -Text "Domain: $($data.Domain) ($($data.DomainNetbios))" -FontSize 14
        New-HTMLText -Text "Generated: $currentDateTime by $currentUser" -FontSize 12 -FontStyle italic
        New-HTMLText -Text "Domain Controller: $($data.DCName)" -FontSize 12
    }
    
    # Executive Dashboard with scores
    New-ExecutiveDashboard -Data $data -HistoricalData $history -Config $config
    
    # Summary Analysis and Recommendations
    New-SummaryAnalysis -Data $data -HistoricalData $history -Config $config -PrioritizedRisks $prioritizedRisks
    
    # Detailed Risk Analysis
    New-HTMLSection -HeaderBackGroundColor $config.ThemeColor -HeaderText "Detailed Risk Analysis" -HeaderTextSize 30 -CanCollapse {
        New-HTMLPanel {
<<<<<<< HEAD
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
=======
            # Filter options and advanced dashboard
            New-HTMLTabStyle -BorderRadius 0px -TextTransform uppercase -FontWeight bold
            New-HTMLTab -Name 'By Category' -IconBrands hurricane {
                $categorizedRisks = $data.RiskRules | Group-Object Category
                
                foreach ($category in $categorizedRisks) {
                    New-HTMLSection -HeaderText $category.Name -CanCollapse {
                        New-HTMLTable -DataTable $category.Group -HideButtons {
                            New-TableHeader -Color White -BackGroundColor $config.ThemeColor
                            New-TableCondition -Name "Points" -ComparisonType number -Operator gt -Value 30 -Color Red -Row
                            New-TableCondition -Name "Points" -ComparisonType number -Operator gt -Value 20 -Color Orange -Row
                            New-TableCondition -Name "Points" -ComparisonType number -Operator le -Value 20 -Color Green -Row
>>>>>>> a69105d800f5d8918fe9e771090211e760e4db65
                        }
                    }
                }
            }
            
            New-HTMLTab -Name 'By Severity' -IconBrands gripfire {
                # High Risk Issues
                New-HTMLSection -HeaderText "High Risk Issues (30+ points)" -HeaderTextColor "White" -HeaderBackGroundColor "Red" -CanCollapse {
                    $highRiskIssues = $data.RiskRules | Where-Object { $_.Points -gt 30 }
                    
                    if ($highRiskIssues.Count -gt 0) {
                        New-HTMLTable -DataTable $highRiskIssues -HideButtons {
                            New-TableHeader -Color White -BackGroundColor "Red"
                        }
                    }
                    else {
                        New-HTMLText -Text "No high risk issues found!" -Color "green" -FontWeight bold
                    }
                }
                
                # Medium Risk Issues
                New-HTMLSection -HeaderText "Medium Risk Issues (20-30 points)" -HeaderTextColor "White" -HeaderBackGroundColor "Orange" -CanCollapse {
                    $mediumRiskIssues = $data.RiskRules | Where-Object { $_.Points -le 30 -and $_.Points -gt 20 }
                    
                    if ($mediumRiskIssues.Count -gt 0) {
                        New-HTMLTable -DataTable $mediumRiskIssues -HideButtons {
                            New-TableHeader -Color White -BackGroundColor "Orange"
                        }
                    }
                    else {
                        New-HTMLText -Text "No medium risk issues found!" -Color "green" -FontWeight bold
                    }
                }
                
                # Low Risk Issues
                New-HTMLSection -HeaderText "Low Risk Issues (≤ 20 points)" -HeaderTextColor "White" -HeaderBackGroundColor "Green" -CanCollapse {
                    $lowRiskIssues = $data.RiskRules | Where-Object { $_.Points -le 20 }
                    
                    if ($lowRiskIssues.Count -gt 0) {
                        New-HTMLTable -DataTable $lowRiskIssues -HideButtons {
                            New-TableHeader -Color White -BackGroundColor "Green"
                        }
                    }
                    else {
                        New-HTMLText -Text "No low risk issues found!" -Color "green" -FontWeight bold
                    }
                }
            }
            
            New-HTMLTab -Name 'All Issues' -IconBrands page4 {
                New-HTMLTable -DataTable $data.RiskRules -AllProperties -HideButtons {
                    New-TableHeader -Color White -BackGroundColor $config.ThemeColor
                    New-TableCondition -Name "Points" -ComparisonType number -Operator gt -Value 30 -Color Red -Row
                    New-TableCondition -Name "Points" -ComparisonType number -Operator gt -Value 20 -Color Orange -Row
                    New-TableCondition -Name "Points" -ComparisonType number -Operator le -Value 20 -Color Green -Row
                }
            }
        }
    }
    
<<<<<<< HEAD
    New-HTMLSection -HeaderBackGroundColor $ThemeColor -HeaderText "Detailed Risk Analysis" -CanCollapse {
=======
    # Add technical details section
    New-HTMLSection -HeaderBackGroundColor $config.ThemeColor -HeaderText "Technical Details" -HeaderTextSize 30 -CanCollapse {
>>>>>>> a69105d800f5d8918fe9e771090211e760e4db65
        New-HTMLPanel {
            New-HTMLTable -DataTable @(
                [PSCustomObject]@{
                    Property = "Domain FQDN"
                    Value = $data.Domain
                },
                [PSCustomObject]@{
                    Property = "NetBIOS Name"
                    Value = $data.DomainNetbios
                },
                [PSCustomObject]@{
                    Property = "Domain Controller"
                    Value = $data.DCName
                },
                [PSCustomObject]@{
                    Property = "Report Generated"
                    Value = $currentDateTime
                },
                [PSCustomObject]@{
                    Property = "Generated By"
                    Value = $currentUser
                },
                [PSCustomObject]@{
                    Property = "PingCastle Data Generated"
                    Value = $data.GenerationDate
                }
            ) -HideButtons {
                New-TableHeader -Color White -BackGroundColor $config.ThemeColor
            }
        }
    }
    
    New-HTMLFooter {
        New-HTMLText -Text "Report generated from PingCastle data on $currentDateTime by $currentUser" -Color gray -FontSize 10 -Alignment center
<<<<<<< HEAD
        New-HTMLText -Text "© $(Get-Date -Format yyyy) YourCompany - For internal use only" -Color gray -FontSize 10 -Alignment center
        New-HTMLText -Text "SCALE: 0 = GOOD, 100 = CRITICAL" -Color black -FontWeight bold -FontSize 12 -Alignment center
=======
        New-HTMLText -Text "© $(Get-Date -Format yyyy) $(if($config.CompanyName){$config.CompanyName}else{'YourCompany'}) - For internal use only" -Color gray -FontSize 10 -Alignment center
>>>>>>> a69105d800f5d8918fe9e771090211e760e4db65
    }
}

# Export data in additional formats if requested
if ($ExportFormat -contains "CSV") {
    $data.RiskRules | Export-Csv -Path "$($OutputPath -replace '\.html$','.csv')" -NoTypeInformation
    Write-Verbose "CSV report exported to $($OutputPath -replace '\.html$','.csv')"
}

if ($ExportFormat -contains "JSON") {
    $reportData = @{
        Domain = $data.Domain
        DomainNetbios = $data.DomainNetbios
        DCName = $data.DCName
        GenerationDate = $data.GenerationDate
        ReportDate = $reportDate
        Scores = $data.Scores
        RiskRules = $data.RiskRules
    }
    
    $reportData | ConvertTo-Json -Depth 4 | Out-File -FilePath "$($OutputPath -replace '\.html$','.json')"
    Write-Verbose "JSON report exported to $($OutputPath -replace '\.html$','.json')"
}

if ($ExportFormat -contains "PDF") {
    Write-Warning "PDF export requires additional modules. The HTML report can be printed to PDF from a browser."
}

Write-Output "Report generated successfully at $OutputPath"
Write-Output "Report shows $($data.RiskRules.Count) security findings across $($data.RiskRules | Select-Object -ExpandProperty Category -Unique | Measure-Object | Select-Object -ExpandProperty Count) categories."

if ($data.Scores.Global -lt $config.HighRiskThreshold) {
    Write-Host "ATTENTION: The domain has a HIGH RISK security score of $($data.Scores.Global)" -ForegroundColor Red
} elseif ($data.Scores.Global -lt $config.MediumRiskThreshold) {
    Write-Host "WARNING: The domain has a MEDIUM RISK security score of $($data.Scores.Global)" -ForegroundColor Yellow
} else {
    Write-Host "The domain has a LOW RISK security score of $($data.Scores.Global)" -ForegroundColor Green
}

#endregion Main Script