<#
.SYNOPSIS
    Advanced HTML report generator for PingCastle security assessment data with email capability.

.DESCRIPTION
    This script generates rich HTML reports from PingCastle XML output, with features including:
    - Customizable theming and risk thresholds
    - Historical data comparison and trend analysis
    - Risk categorization and prioritization
    - Executive summary and action plan timeline
    - Optional PDF export and configuration templates
    - Email report distribution capability using MailKit

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

.PARAMETER ExportPDF
    Export the report as PDF in addition to HTML.

.PARAMETER SaveTemplateAs
    Save current configuration as a template.

.PARAMETER SendEmail
    Send the report via email after generation.

.PARAMETER EmailTo
    Recipient email addresses (comma-separated).

.PARAMETER EmailFrom
    Sender email address.

.PARAMETER SmtpServer
    SMTP server address for sending email.

.PARAMETER SmtpPort
    SMTP server port (default: 25).

.PARAMETER UseSSL
    Use SSL for SMTP connection.

.PARAMETER Credential
    PSCredential object for SMTP authentication.

.PARAMETER EmailSubject
    Custom subject for the email (default: "PingCastle Security Report - [DomainName]").

.NOTES
    Version:        1.0.0
    Author:         DambergC
    Creation Date:  2025-04-12
    Repository:     https://github.com/DambergC/PingCastle
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
    [switch]$ExportPDF,
    
    [Parameter(Mandatory=$false)]
    [string]$SaveTemplateAs,
    
    # Email parameters
    [Parameter(Mandatory=$false)]
    [switch]$SendEmail,
    
    [Parameter(Mandatory=$false)]
    [string[]]$EmailTo,
    
    [Parameter(Mandatory=$false)]
    [string]$EmailFrom,
    
    [Parameter(Mandatory=$false)]
    [string]$SmtpServer,
    
    [Parameter(Mandatory=$false)]
    [int]$SmtpPort = 25,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseSSL,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$EmailSubject
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
        
        # Email configuration from config file
        if($null -ne $config.SendEmail) {
            $SendEmail = [System.Convert]::ToBoolean($config.SendEmail)
        }
        $EmailTo = $config.EmailTo ?? $EmailTo
        $EmailFrom = $config.EmailFrom ?? $EmailFrom
        $SmtpServer = $config.SmtpServer ?? $SmtpServer
        $SmtpPort = $config.SmtpPort ?? $SmtpPort
        if($null -ne $config.UseSSL) {
            $UseSSL = [System.Convert]::ToBoolean($config.UseSSL)
        }
        $EmailSubject = $config.EmailSubject ?? $EmailSubject
        
        Write-Host "Configuration loaded from $ConfigPath" -ForegroundColor Green
    } catch {
        Write-Warning "Error reading config file. Using default parameters: $_"
    }
}

# Save current configuration as template if requested
if($SaveTemplateAs) {
    $template = @{
        XmlPath = $XmlPath
        OutputPath = $OutputPath
        ThemeColor = $ThemeColor
        HighRiskThreshold = $HighRiskThreshold
        IncludeComparisonWithPrevious = $IncludeComparisonWithPrevious.IsPresent
        ExportPDF = $ExportPDF.IsPresent
        SendEmail = $SendEmail.IsPresent
        EmailTo = $EmailTo
        EmailFrom = $EmailFrom
        SmtpServer = $SmtpServer
        SmtpPort = $SmtpPort
        UseSSL = $UseSSL.IsPresent
        EmailSubject = $EmailSubject
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
        Write-Host "Created new score history file at $historyFile" -ForegroundColor Green
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

# Export to PDF if requested
if ($ExportPDF) {
    try {
        # Check if the PSWritePDF module is available for PDF conversion
        if (!(Get-Module -ListAvailable -Name PSWritePDF)) {
            Write-Warning "PSWritePDF module not found. Attempting to install..."
            Install-Module -Name PSWritePDF -Force -Scope CurrentUser
        }
        
        Import-Module PSWritePDF
        
        # Convert HTML to PDF
        $PDFPath = $OutputPath -replace "\.html$", ".pdf"
        ConvertTo-PDF -Path (Get-Item $OutputPath).FullName -OutputPath $PDFPath -Encoding UTF8
        
        Write-Output "PDF report generated successfully at $PDFPath"
    } catch {
        Write-Error "Failed to generate PDF report: $_"
        Write-Warning "You may need to install the PSWritePDF module manually or use a third-party HTML-to-PDF converter."
    }
}

# Generate a QR code for the report if the module is available (additional feature)
try {
    if (Get-Module -ListAvailable -Name QRCodeGenerator) {
        $QRPath = $OutputPath -replace "\.html$", "_QR.png"
        $reportFullPath = (Get-Item $OutputPath).FullName
        
        Import-Module QRCodeGenerator
        New-QRCodeFile -Content "file://$reportFullPath" -OutPath $QRPath -Width 300 -Height 300
        Write-Output "QR code for report access generated at $QRPath"
    }
} catch {
    # Non-critical feature, just continue if it fails
    Write-Verbose "QR code generation skipped: QRCodeGenerator module not available or error occurred."
}

# Send email if requested - Using Send-MailKitMessage instead of Send-MailMessage
if ($SendEmail) {
    try {
        # Check if all required email parameters are provided
        $missingParams = @()
        if (!$EmailTo) { $missingParams += "EmailTo" }
        if (!$EmailFrom) { $missingParams += "EmailFrom" }
        if (!$SmtpServer) { $missingParams += "SmtpServer" }
        
        if ($missingParams.Count -gt 0) {
            Write-Error "Email cannot be sent. Missing required parameters: $($missingParams -join ', ')"
        } else {
            # Check if the PSMailKit module is available
            if (!(Get-Module -ListAvailable -Name PSMailKit)) {
                Write-Host "PSMailKit module not found. Installing..." -ForegroundColor Yellow
                try {
                    Install-Module -Name PSMailKit -Force -Scope CurrentUser -ErrorAction Stop
                    Write-Host "PSMailKit module installed successfully." -ForegroundColor Green
                } catch {
                    Write-Error "Failed to install PSMailKit module. Please install manually: Install-Module -Name PSMailKit -Force"
                    exit 1
                }
            }

            # Import PSMailKit module
            Import-Module PSMailKit -ErrorAction Stop
            
            # Set default email subject if not provided
            if (!$EmailSubject) {
                $EmailSubject = "PingCastle Security Report - $domain"
            }
            
            # Create a summary of key findings for email body
            $emailBody = @"
<html>
<head>
    <style>
        body { font-family: Arial, Helvetica, sans-serif; }
        h1 { color: $ThemeColor; }
        .highlight { color: red; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: $ThemeColor; color: white; }
        .score-good { background-color: #dff0d8; }
        .score-warning { background-color: #fcf8e3; }
        .score-critical { background-color: #f2dede; }
    </style>
</head>
<body>
    <h1>PingCastle Security Assessment Report</h1>
    <p>Domain: <strong>$domain</strong> ($domainNetbios)</p>
    <p>Generated: $currentDateTime</p>
    
    <h2>Security Score Summary</h2>
    <table>
        <tr>
            <th>Score Type</th>
            <th>Score</th>
            <th>Status</th>
        </tr>
        <tr class="score-$(if ($globalScore -lt 20) { 'good' } elseif ($globalScore -lt 50) { 'warning' } else { 'critical' })">
            <td>Global Score</td>
            <td>$globalScore</td>
            <td>$(if ($globalScore -lt 20) { 'Good' } elseif ($globalScore -lt 50) { 'Warning' } else { 'Critical' })</td>
        </tr>
        <tr class="score-$(if ($StaleScore -lt 20) { 'good' } elseif ($StaleScore -lt 50) { 'warning' } else { 'critical' })">
            <td>Stale Objects</td>
            <td>$StaleScore</td>
            <td>$(if ($StaleScore -lt 20) { 'Good' } elseif ($StaleScore -lt 50) { 'Warning' } else { 'Critical' })</td>
        </tr>
        <tr class="score-$(if ($privilegedScore -lt 20) { 'good' } elseif ($privilegedScore -lt 50) { 'warning' } else { 'critical' })">
            <td>Privileged Access</td>
            <td>$privilegedScore</td>
            <td>$(if ($privilegedScore -lt 20) { 'Good' } elseif ($privilegedScore -lt 50) { 'Warning' } else { 'Critical' })</td>
        </tr>
        <tr class="score-$(if ($trustscore -lt 20) { 'good' } elseif ($trustscore -lt 50) { 'warning' } else { 'critical' })">
            <td>Trust Relationships</td>
            <td>$trustscore</td>
            <td>$(if ($trustscore -lt 20) { 'Good' } elseif ($trustscore -lt 50) { 'Warning' } else { 'Critical' })</td>
        </tr>
        <tr class="score-$(if ($AnomalyScore -lt 20) { 'good' } elseif ($AnomalyScore -lt 50) { 'warning' } else { 'critical' })">
            <td>Security Anomalies</td>
            <td>$AnomalyScore</td>
            <td>$(if ($AnomalyScore -lt 20) { 'Good' } elseif ($AnomalyScore -lt 50) { 'Warning' } else { 'Critical' })</td>
        </tr>
    </table>
    
    <h2>Priority Focus Area</h2>
    <p>$worstCategory (Score: $highestScore)</p>
    
    <p>The full report is attached to this email.</p>
    <p><em>Note: This is an automatically generated report. Please refer to the attached file for complete details.</em></p>
</body>
</html>
"@
            
            # Prepare attachments
            $attachments = @()
            if (Test-Path $OutputPath) {
                $attachments += $OutputPath
            }
            if ($ExportPDF) {
                $PDFPath = $OutputPath -replace "\.html$", ".pdf"
                if (Test-Path $PDFPath) {
                    $attachments += $PDFPath
                }
            }
            
            # Prepare email parameters for Send-MailKitMessage
            $mailKitParams = @{
                From = $EmailFrom
                To = $EmailTo
                Subject = $EmailSubject
                BodyHtml = $emailBody
                SmtpServer = $SmtpServer
                Port = $SmtpPort
                Attachments = $attachments
            }
            
            # Add optional parameters if specified
            if ($UseSSL) {
                $mailKitParams.Add("UseSsl", $true)
            }
            
            if ($null -ne $Credential) {
                $mailKitParams.Add("Credential", $Credential)
            }
            
            # Send the email using MailKit
            Send-MailKitMessage @mailKitParams
            Write-Output "Email sent successfully to $($EmailTo -join ', ')"
        }
    } catch {
        Write-Error "Failed to send email: $_"
    }
}