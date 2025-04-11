# Error handling for module import
try {
    Import-Module PSWriteHTML -ErrorAction Stop
} catch {
    Write-Error "Failed to import PSWriteHTML module: $_"
    exit 1
}

# Error handling for XML loading
try {
    [xml]$data = Get-Content .\ad_hc_int.vxops.se.xml -ErrorAction Stop
} catch {
    Write-Error "Failed to load XML file: $_"
    exit 1
}

# Data extraction with null checks
$domain = if ($data.HealthcheckData.DomainFQDN) { $data.HealthcheckData.DomainFQDN } else { "Domain Not Found" }
$reportdate = $data.HealthcheckData.GenerationDate

# Score extraction with validation
$globalScore = [math]::Max(0, [math]::Min(100, [int]$(if ($data.HealthcheckData.GlobalScore) { $data.HealthcheckData.GlobalScore } else { 0 })))
$StaleScore = [math]::Max(0, [math]::Min(100, [int]$(if ($data.HealthcheckData.StaleObjectsScore) { $data.HealthcheckData.StaleObjectsScore } else { 0 })))
$privilegedScore = [math]::Max(0, [math]::Min(100, [int]$(if ($data.HealthcheckData.PrivilegiedGroupScore) { $data.HealthcheckData.PrivilegiedGroupScore } else { 0 })))
$trustscore = [math]::Max(0, [math]::Min(100, [int]$(if ($data.HealthcheckData.TrustScore) { $data.HealthcheckData.TrustScore } else { 0 })))
$AnomalyScore = [math]::Max(0, [math]::Min(100, [int]$(if ($data.HealthcheckData.AnomalyScore) { $data.HealthcheckData.AnomalyScore } else { 0 })))

# Function to determine score color
function Get-ScoreColor {
    param([int]$score)
    switch ($score) {
        {$_ -ge 90} { return '#E74C3C' } # Red
        {$_ -ge 50} { return '#F1C40F' } # Yellow
        default { return '#2ECC71' }      # Green
    }
}

# Create PSCustomObjects from XML data with enhanced error handling
$healthcheckData = @()
try {
    $healthcheckData = $data.SelectNodes("//HealthcheckRiskRule") | ForEach-Object {
        [PSCustomObject]@{
            Points = [int]$(if ($_.Points) { $_.Points } else { 0 })
            Category = if ($_.Category) { $_.Category } else { "Uncategorized" }
            Model = if ($_.Model) { $_.Model } else { "Unknown" }
            Rationale = if ($_.Rationale) { $_.Rationale } else { "No rationale provided" }
        }
    }
} catch {
    Write-Warning "Error processing health check data: $_"
}

# Calculate enhanced summary statistics
$categoryStats = $healthcheckData | Group-Object Category | Select-Object @{
    Name = 'Category'
    Expression = {$_.Name}
}, @{
    Name = 'Count'
    Expression = {$_.Count}
}, @{
    Name = 'TotalPoints'
    Expression = {($_.Group | Measure-Object -Property Points -Sum).Sum}
}

$currentDateTime = "2025-04-10 14:20:40"
$currentUser = "DambergC"
$exportPath = "HealthcheckReport_$(Get-Date $currentDateTime -Format 'yyyyMMdd')"

New-HTML -TitleText "Healthcheck Risk Rules Report" -Online -FilePath "$exportPath.html" {
    
    New-HTMLHeader {
        New-HTMLText -Text "Healthcheck Risk Rules Analysis - $domain" -Color '#990AE3' -Alignment center -FontSize 40
    }
    
    New-HTMLSection -HeaderText 'GlobalScore' -HeaderBackGroundColor '#990AE3' -HeaderTextColor White -HeaderTextSize 40 -HeaderTextAlignment center {
        New-HTMLPanel {
            New-HTMLText -Text "$globalScore" -Color (Get-ScoreColor $globalScore) -Alignment center -FontSize 155 -FontWeight bold
            New-HTMLText -Text "/100" -Color '#990AE3' -Alignment center -FontSize 36
        }
    }

    New-HTMLSection -HeaderBackGroundColor '#990AE3' {
        New-HTMLPanel {
            New-HTMLText -Text 'Stale' -Color '#990AE3' -Alignment center -FontSize 40
            New-HTMLText -Text "$StaleScore" -Color (Get-ScoreColor $StaleScore) -Alignment center -FontSize 72 -FontWeight bold
            New-HTMLText -Text "/100" -Color '#990AE3' -Alignment center -FontSize 36
        }
        New-HTMLPanel {
            New-HTMLText -Text 'Privileged' -Color '#990AE3' -Alignment center -FontSize 40
            New-HTMLText -Text "$privilegedScore" -Color (Get-ScoreColor $privilegedScore) -Alignment center -FontSize 72 -FontWeight bold
            New-HTMLText -Text "/100" -Color '#990AE3' -Alignment center -FontSize 36
        }
        New-HTMLPanel {
            New-HTMLText -Text 'Trust' -Color '#990AE3' -Alignment center -FontSize 40
            New-HTMLText -Text "$trustscore" -Color (Get-ScoreColor $trustscore) -Alignment center -FontSize 72 -FontWeight bold
            New-HTMLText -Text "/100" -Color '#990AE3' -Alignment center -FontSize 36
        }
        New-HTMLPanel {
            New-HTMLText -Text 'Anomaly' -Color '#990AE3' -Alignment center -FontSize 40
            New-HTMLText -Text "$AnomalyScore" -Color (Get-ScoreColor $AnomalyScore) -Alignment center -FontSize 72 -FontWeight bold
            New-HTMLText -Text "/100" -Color '#990AE3' -Alignment center -FontSize 36
        }
    }

    New-HTMLSection -HeaderBackGroundColor '#990AE3' -HeaderText "Category Summary" -HeaderTextSize 40 {
        New-HTMLTable -DataTable $categoryStats -HideFooter -HideButtons {
            New-TableHeader -Color White -BackgroundColor '#990AE3'
        }
    }

    New-HTMLSection -HeaderBackGroundColor '#990AE3' -HeaderText "Detailed Risk Rules" -HeaderTextSize 40 {
        New-HTMLTable -DataTable $healthcheckData -HideFooter -SearchBuilder -FixedHeader -PagingLength $healthcheckData.Count {
            New-TableHeader -Color White -BackgroundColor '#990AE3'
        } -Buttons @('copyHtml5', 'excelHtml5', 'csvHtml5', 'pdfHtml5') -DisablePaging
    }

    New-HTMLSection -HeaderBackGroundColor '#990AE3' -HeaderText "Report Information" {
        New-HTMLPanel {
            New-HTMLList -Type Ordered {
                New-HTMLListItem -Text "Report generated on: $currentDateTime (UTC)"
                New-HTMLListItem -Text "Generated by: $currentUser"
                New-HTMLListItem -Text "Total records analyzed: $($healthcheckData.Count)"
                New-HTMLListItem -Text "Domain: $domain"
            }
        }
    }
} -ShowHTML

Write-Host "Report generated successfully at: $exportPath.html"