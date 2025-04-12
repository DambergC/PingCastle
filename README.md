# Enhanced PingCastle HTML Report Generator

This script generates comprehensive HTML reports from PingCastle security assessment data, with advanced features including historical comparisons, risk prioritization, and PDF export.

## Features

- Customizable theme colors and risk thresholds
- Historical data comparison with trend analysis
- Executive summary with action planning timeline
- Detailed risk analysis with remediation guidance
- PDF export capability
- Configuration templates
- QR code generation for quick report access

## Requirements

- PowerShell 7
- PingCastle XML output file
- PSWriteHTML module (auto-installed if missing)
- Optional: PSWritePDF module for PDF export
- Optional: QRCodeGenerator module for QR code generation

## Usage

## Parameters
|           Parameter           	|                     Description                     	|         Default Value         	| Required 	|
|:-----------------------------:	|:---------------------------------------------------:	|:-----------------------------:	|:--------:	|
| XmlPath                       	| Path to the PingCastle XML output file              	| .\ad_hc_int.vxops.se.xml      	| No       	|
| OutputPath                    	| Path where the HTML report will be saved            	| HealthcheckReport.html        	| No       	|
| ThemeColor                    	| Hex color code for report theming                   	| #990AE3                       	| No       	|
| HighRiskThreshold             	| Score threshold to classify issues as high risk     	| 50                            	| No       	|
| IncludeComparisonWithPrevious 	| Include comparison with previous assessment results 	| False                         	| No       	|
| ConfigPath                    	| Path to JSON configuration file for report settings 	| .\PingCastleReportConfig.json 	| No       	|
| ExportPDF                     	| Export the report as PDF in addition to HTML        	| False                         	| No       	|
| SaveTemplateAs                	| Save current configuration as a template            	| None                          	| No       	|
## Notes

- Version: 1.0.0
- Generated on: 2025-04-11
- Author: DambergC
- This tool is designed to enhance PingCastle output visualization and make security findings more actionable
- Report scoring uses a 0-100 scale where 0 is good and 100 is critical
- Historical data is stored in PingCastle_ScoreHistory.csv in the same directory as the script
- For PDF export functionality, the PSWritePDF module will be automatically installed if missing
- For questions or issues, please open an issue in the GitHub repository

## Basic usage:
```powershell
.\Enhanced-PingCastleReport.ps1 -XmlPath ".\your-pingcastle-export.xml"

With historical comparison:
.\Enhanced-PingCastleReport.ps1 -XmlPath ".\your-pingcastle-export.xml" -IncludeComparisonWithPrevious

Customized report:
.\Enhanced-PingCastleReport.ps1 -XmlPath ".\your-pingcastle-export.xml" -ThemeColor "#336699" -HighRiskThreshold 40 -ExportPDF

Save and use configuration template:
# Save current settings as template
.\Enhanced-PingCastleReport.ps1 -SaveTemplateAs "MyReportTemplate.json" -ThemeColor "#336699"

# Use saved template
.\Enhanced-PingCastleReport.ps1 -ConfigPath "MyReportTemplate.json"
