[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$XmlPath = ".\ad_hc_int.vxops.se.xml",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "HealthcheckReport.html",
    
    [Parameter(Mandatory=$false)]
    [string]$ThemeColor = "#990AE3"
)

# Read the XML file
if(!(Test-Path $XmlPath)) {
    Write-Error "XML file not found: $XmlPath"
    exit 1
}

[xml]$data = Get-Content $XmlPath

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
    
    if ($Score -ge 80) { return "green" }
    elseif ($Score -ge 50) { return "orange" }
    else { return "red" }
}

# Then use it in your HTML sections:
New-HTMLText -Text "$globalScore" -Color (Get-ScoreColor $globalScore) -Alignment center -FontSize 155 -FontWeight bold

# Replace hardcoded values with dynamic ones
$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$currentUser = $env:USERNAME

# Make styling more flexible by parameterizing colors and styles
New-HTML -TitleText "PingCastle Healthcheck Report - $domain" -Online -FilePath $OutputPath {
    # Your existing code with $ThemeColor parameter instead of hardcoded '#990AE3'

    New-HTMLSection -HeaderBackGroundColor $ThemeColor -HeaderText "Summary and Recommendations" -HeaderTextSize 40 {
        New-HTMLPanel {
            New-HTMLText -Text "Summary Analysis" -Color $ThemeColor -FontSize 24 -FontWeight bold
            
            # Add logic to determine highest risk areas
            $lowestScore = @($globalScore, $StaleScore, $privilegedScore, $trustscore, $AnomalyScore) | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum
            
            # Better tracking of all low scores (not just the minimum)
            $thresholdForHighRisk = 50
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
}

