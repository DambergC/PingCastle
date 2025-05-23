<#
.SYNOPSIS
    Management tool for Active Directory Managed Service Accounts (MSAs and gMSAs).

.DESCRIPTION
    Comprehensive functions for managing Managed Service Accounts in Active Directory, 
    including creation, modification, deletion, installation, listing, and assignment management.

.PARAMETER NonInteractive
    Run in non-interactive mode for scripted operations.

.PARAMETER Action
    The action to perform (Create, Modify, Delete, Install, List).

.PARAMETER MSAName
    The name of the MSA to operate on.

.PARAMETER ComputerName
    The name of the computer to associate with the MSA or where to install the MSA.

.PARAMETER MSAType
    The type of MSA to create (1 for sMSA, 2 for gMSA).

.EXAMPLE
    .\MSACMDManager.ps1
    Runs the script in interactive menu mode.

.EXAMPLE
    .\MSACMDManager.ps1 -NonInteractive -Action Create -MSAName "WebAppService" -MSAType "2"
    Creates a new gMSA named WebAppService in non-interactive mode.

.NOTES
    Author: DambergC
    Date Created: 2025-05-14
    Last Updated: 2025-05-20
#>

[CmdletBinding()]
param(
    [switch]$NonInteractive,
    [ValidateSet('Create', 'Modify', 'Delete', 'Install', 'List', 'Test', 'Export', 'Import')]
    [string]$Action,
    [string]$MSAName,
    [string]$ComputerName,
    [ValidateSet('1', '2')]
    [string]$MSAType,
    [string]$LogPath = "$env:TEMP\MSA-Manager.log",
    [string]$ExportPath,
    [string]$ImportPath
)

# =================== Helper Functions ===================

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO',
        [string]$LogPath = $script:LogPath
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        'ERROR' { Write-Host $logLine -ForegroundColor Red }
        'WARN'  { Write-Host $logLine -ForegroundColor Yellow }
        default { Write-Host $logLine }
    }
    Add-Content -Path $LogPath -Value $logLine -ErrorAction SilentlyContinue
}

function MaybeClearHost {
    if (-not $NonInteractive) { Clear-Host }
}

function Test-ADModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "Active Directory module not found. Installing..." -Level 'WARN'
        Try {
            Install-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop
            Import-Module ActiveDirectory
            Write-Log "Active Directory module installed successfully." -Level 'INFO'
        }
        Catch {
            Write-Log "Error installing Active Directory module. Please install RSAT tools manually." -Level 'ERROR'
            Write-Log $_.Exception.Message -Level 'ERROR'
            return $false
        }
    } else {
        Import-Module ActiveDirectory
    }
    return $true
}

function Test-ADObjectExists {
    param(
        [Parameter(Mandatory)][ValidateSet('ServiceAccount', 'Computer', 'Group')]$Type,
        [Parameter(Mandatory)][string]$Name
    )
    switch ($Type.ToLower()) {
        'serviceaccount' { return (Get-ADServiceAccount -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue) }
        'computer'       { return (Get-ADComputer -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue) }
        'group'          { return (Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue) }
        default          { return $null }
    }
}

function Select-MSA {
    param([string]$Prompt = "Select a Managed Service Account:")
    $msaList = Get-ADServiceAccount -Filter * | Select-Object Name
    if (-not $msaList) {
        Write-Host "No MSAs found." -ForegroundColor Yellow
        return $null
    }
    $msaList = @($msaList)
    for ($i = 0; $i -lt $msaList.Count; $i++) {
        Write-Host "[$i] $($msaList[$i].Name)"
    }
    $selection = Read-Host "$Prompt (number or 'c' to cancel)"
    if ($selection -eq 'c') { return $null }
    if ([int]::TryParse($selection, [ref]$null) -and $selection -ge 0 -and $selection -lt $msaList.Count) {
        return $msaList[$selection].Name
    }
    Write-Host "Invalid selection." -ForegroundColor Red
    return $null
}

# =================== MSA Management Functions ===================

function New-ManagedServiceAccount {
    [CmdletBinding()]
    param (
        [string]$MSAName,
        [ValidateSet('1', '2')][string]$MSAType
    )
    try {
        Clear-Host
        Write-Host "=== Create New Managed Service Account ===" -ForegroundColor Cyan
        Write-Log "Starting MSA creation process" -Level 'INFO'

        if ([string]::IsNullOrWhiteSpace($MSAName)) {
            $MSAName = Read-Host "Enter the name for the new Managed Service Account"
            if ([string]::IsNullOrWhiteSpace($MSAName) -or $MSAName -match '\s') {
                Write-Log "Invalid MSA name. Name cannot be empty or contain spaces." -Level 'ERROR'
                return
            }
        }
        if (Test-ADObjectExists -Type ServiceAccount -Name $MSAName) {
            Write-Log "An MSA with name '$MSAName' already exists." -Level 'ERROR'
            Write-Host "An MSA with name '$MSAName' already exists." -ForegroundColor Red
            return
        }
        if ([string]::IsNullOrWhiteSpace($MSAType)) {
            $MSAType = Read-Host "Create as: (1) sMSA (standalone) or (2) gMSA (group)"
            if ($MSAType -ne '1' -and $MSAType -ne '2') {
                Write-Log "Invalid MSA type. Must be '1' for sMSA or '2' for gMSA." -Level 'ERROR'
                return
            }
        }

        if ($MSAType -eq '1') {
            Write-Log "Creating standalone MSA (sMSA) '$MSAName'..." -Level 'INFO'
            New-ADServiceAccount -Name $MSAName -RestrictToSingleComputer -ErrorAction Stop
            Write-Host "Standalone MSA '$MSAName' created successfully." -ForegroundColor Green

            $computerName = Read-Host "Enter the computer name to bind this sMSA to"
            if (-not [string]::IsNullOrWhiteSpace($computerName)) {
                if (-not (Test-ADObjectExists -Type Computer -Name $computerName)) {
                    Write-Log "Computer '$computerName' not found in Active Directory." -Level 'ERROR'
                    Write-Host "Computer '$computerName' not found in Active Directory." -ForegroundColor Red
                    return
                }
                $msaDN = (Get-ADServiceAccount -Identity $MSAName).DistinguishedName
                $assignedComputers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount | Where-Object {
                    $_."msDS-HostServiceAccount" -contains $msaDN
                }
                if ($assignedComputers.Count -gt 0) {
                    Write-Host "Warning: This sMSA is already assigned to: $($assignedComputers.Name -join ', ')" -ForegroundColor Yellow
                    $choice = Read-Host "Remove the sMSA from those computers and assign to $computerName? (yes/no)"
                    if ($choice.ToLower() -eq "yes") {
                        foreach ($c in $assignedComputers) {
                            Remove-ADComputerServiceAccount -Identity $c.Name -ServiceAccount $MSAName
                            Write-Log "Removed sMSA '$MSAName' from computer '$($c.Name)'" -Level 'INFO'
                        }
                        Add-ADComputerServiceAccount -Identity $computerName -ServiceAccount $MSAName -ErrorAction Stop
                        Write-Log "Computer '$computerName' allowed to use MSA '$MSAName'." -Level 'INFO'
                        Write-Host "Computer '$computerName' allowed to use MSA '$MSAName'." -ForegroundColor Green

                        # Ensure only one assignment
                        $assignedComputers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount | Where-Object {
                            $_."msDS-HostServiceAccount" -contains $msaDN
                        }
                        if ($assignedComputers.Count -ne 1) {
                            Write-Host "WARNING: There are $($assignedComputers.Count) computers assigned to this sMSA! Only one is allowed." -ForegroundColor Red
                            $toRemove = $assignedComputers | Where-Object { $_.Name -ne $computerName }
                            foreach ($comp in $toRemove) {
                                Remove-ADComputerServiceAccount -Identity $comp.Name -ServiceAccount $MSAName
                                Write-Host "Removed $($comp.Name) from the sMSA." -ForegroundColor Yellow
                                Write-Log "Removed computer '$($comp.Name)' from sMSA '$MSAName'." -Level 'INFO'
                            }
                        }
                        # Ensure no group principals
                        $msaObject = Get-ADServiceAccount -Identity $MSAName -Properties objectClass, PrincipalsAllowedToRetrieveManagedPassword
                        if ($msaObject.objectClass -eq "msDS-ManagedServiceAccount" -and $msaObject.PrincipalsAllowedToRetrieveManagedPassword) {
                            Set-ADServiceAccount -Identity $MSAName -PrincipalsAllowedToRetrieveManagedPassword $null
                            Write-Host "Cleared group principals for sMSA $MSAName." -ForegroundColor Yellow
                            Write-Log "Cleared group principals for sMSA $MSAName." -Level 'INFO'
                        }
                    } else {
                        Write-Host "Operation canceled. sMSA not reassigned." -ForegroundColor Red
                        Write-Log "User canceled sMSA reassignment." -Level 'WARN'
                        return
                    }
                } else {
                    Add-ADComputerServiceAccount -Identity $computerName -ServiceAccount $MSAName -ErrorAction Stop
                    Write-Log "Computer '$computerName' allowed to use MSA '$MSAName'." -Level 'INFO'
                    Write-Host "Computer '$computerName' allowed to use MSA '$MSAName'." -ForegroundColor Green
                }
            }
        } else {
            # gMSA
            $isAdGroupCreated = Read-Host "Is the AD group created? (yes/no)"
            if ($isAdGroupCreated.ToLower() -eq "yes") {
                $adGroupName = Read-Host "Please provide the AD group name"
                if (-not (Test-ADObjectExists -Type Group -Name $adGroupName)) {
                    Write-Log "AD group '$adGroupName' not found in Active Directory." -Level 'ERROR'
                    Write-Host "AD group '$adGroupName' not found in Active Directory." -ForegroundColor Red
                    return
                }
                Write-Log "Creating group MSA (gMSA) '$MSAName' associated with AD group '$adGroupName'..." -Level 'INFO'
                if (-not (Get-KdsRootKey)) {
                    Write-Log "No KDS Root Key found. Creating one..." -Level 'WARN'
                    Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
                    Write-Log "KDS Root Key created. Waiting for replication..." -Level 'INFO'
                    Start-Sleep -Seconds 5
                }
                New-ADServiceAccount -Name $MSAName -PrincipalsAllowedToRetrieveManagedPassword $adGroupName -ErrorAction Stop
                Write-Log "Group MSA '$MSAName' created successfully." -Level 'INFO'
                Write-Host "Group MSA '$MSAName' created successfully." -ForegroundColor Green
            } elseif ($isAdGroupCreated.ToLower() -eq "no") {
                Write-Host "Would you like to create one now? (yes/no)" -ForegroundColor Yellow
                $createGroup = Read-Host
                if ($createGroup.ToLower() -eq "yes") {
                    $groupName = Read-Host "Enter a name for the new AD group"
                    New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security
                    Write-Log "AD group '$groupName' created successfully." -Level 'INFO'
                    Write-Host "AD group '$groupName' created. Now you can create the gMSA." -ForegroundColor Green
                }
                return
            } else {
                Write-Log "Invalid input. Please respond with 'yes' or 'no'." -Level 'ERROR'
                Write-Host "Invalid input. Please respond with 'yes' or 'no'." -ForegroundColor Red
                return
            }
        }
    } catch {
        Write-Log "Error creating MSA: $_" -Level 'ERROR'
        Write-Host "Error creating MSA: $_" -ForegroundColor Red
    } finally {
        if (-not $NonInteractive) { Read-Host "Press Enter to continue" }
    }
}

function List-ManagedServiceAccounts {
    [CmdletBinding()]
    param()
    try {
        MaybeClearHost
        Write-Host "=== List of Managed Service Accounts (MSAs and gMSAs) ===" -ForegroundColor Cyan
        $msaList = Get-ADServiceAccount -Filter * -Properties *
        if (-not $msaList -or $msaList.Count -eq 0) {
            Write-Host "No Managed Service Accounts found." -ForegroundColor Yellow
            return
        }
        foreach ($item in $msaList) {
            $msaObject = Get-ADServiceAccount -Identity $item.Name -Properties *
            Write-Host ""
            Write-Host "Name: $($msaObject.Name)" -ForegroundColor White
            switch ($msaObject.objectClass) {
                "msDS-ManagedServiceAccount"         { Write-Host "  Type: sMSA (Standalone Managed Service Account)" }
                "msDS-GroupManagedServiceAccount"    { Write-Host "  Type: gMSA (Group Managed Service Account)" }
                default                             { Write-Host "  Type: Unknown" }
            }
            Write-Host "  Enabled: $($msaObject.Enabled)"
            Write-Host "  Description: $($msaObject.Description)"
            Write-Host "  Created: $($msaObject.Created)"
            Write-Host "  Modified: $($msaObject.Modified)"

            $assignedComputers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount | Where-Object {
                $_."msDS-HostServiceAccount" -contains $msaObject.DistinguishedName
            }
            $assignedComputersList = $assignedComputers | Select-Object -ExpandProperty Name
            if ($msaObject.objectClass -eq "msDS-ManagedServiceAccount") {
                if ($assignedComputersList.Count -gt 1) {
                    Write-Host "  WARNING: sMSA assigned to multiple computers! Only one assignment is allowed." -ForegroundColor Red
                    Write-Host "  Assigned Computers: $($assignedComputersList -join ', ')" -ForegroundColor Red
                    $autofix = Read-Host "  Do you want to automatically remove all but one assignment for this sMSA? (yes/no)"
                    if ($autofix.ToLower() -eq "yes") {
                        $toRemove = $assignedComputers | Select-Object -Skip 1
                        foreach ($comp in $toRemove) {
                            Remove-ADComputerServiceAccount -Identity $comp.Name -ServiceAccount $msaObject.Name
                            Write-Host "    Removed sMSA $($msaObject.Name) from $($comp.Name)" -ForegroundColor Yellow
                        }
                        $finalComputer = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount | Where-Object {
                            $_."msDS-HostServiceAccount" -contains $msaObject.DistinguishedName
                        } | Select-Object -ExpandProperty Name
                        Write-Host "  Final Assigned Computer: $finalComputer" -ForegroundColor Green
                    }
                } else {
                    Write-Host "  Assigned Computer: $($assignedComputersList -join ', ')"
                }
            } else {
                Write-Host "  Assigned Computers: $($assignedComputersList -join ', ')"
            }
            if ($msaObject.objectClass -eq "msDS-GroupManagedServiceAccount" -and $msaObject.PrincipalsAllowedToRetrieveManagedPassword) {
                Write-Host "  Principals Allowed (Groups):"
                foreach ($dn in $msaObject.PrincipalsAllowedToRetrieveManagedPassword) {
                    try {
                        $grp = Get-ADGroup -Identity $dn -Properties Name
                        Write-Host "    - $($grp.Name)"
                    } catch {
                        Write-Host "    - $dn"
                    }
                }
            }
        }
    } catch {
        Write-Host "Error listing MSAs: $_" -ForegroundColor Red
    } finally {
        if (-not $NonInteractive) { Read-Host "Press Enter to continue" }
    }
}


# Better function to find computers that have permission to use an MSA
function Get-MSAPrincipals {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$MSAName
    )

    $principalsList = @()

    try {
        Write-Log "Getting principals for MSA '$MSAName'..." -Level 'INFO'
        
        # Get the MSA object with all necessary properties
        $msaObject = Get-ADServiceAccount -Identity $MSAName -Properties PrincipalsAllowedToRetrieveManagedPassword

        # Check PrincipalsAllowedToRetrieveManagedPassword property
        if ($msaObject.PrincipalsAllowedToRetrieveManagedPassword) {
            foreach ($principalDN in $msaObject.PrincipalsAllowedToRetrieveManagedPassword) {
                try {
                    $principal = Get-ADObject -Identity $principalDN -Properties Name, ObjectClass, sAMAccountName
                    $principalInfo = [PSCustomObject]@{
                        Name               = $principal.Name
                        Type               = $principal.ObjectClass
                        SAMAccountName     = $principal.sAMAccountName
                        DistinguishedName  = $principalDN
                    }
                    $principalsList += $principalInfo
                }
                catch {
                    # If we can't get the object details, at least store the DN
                    $principalInfo = [PSCustomObject]@{
                        Name               = ($principalDN -split ',')[0] -replace 'CN=',''
                        Type               = "Unknown"
                        SAMAccountName     = ""
                        DistinguishedName  = $principalDN
                    }
                    $principalsList += $principalInfo
                }
            }
        }

        # Validate against msDS-HostServiceAccount attribute - FIX the bug in the string comparison
        $computers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount
        foreach ($computer in $computers) {
            if ($computer.'msDS-HostServiceAccount' -contains $msaObject.DistinguishedName) {
                $principalInfo = [PSCustomObject]@{
                    Name               = $computer.Name
                    Type               = "Computer"
                    SAMAccountName     = $computer.sAMAccountName
                    DistinguishedName  = $computer.DistinguishedName
                }
                $principalsList += $principalInfo
            }
        }

        return $principalsList
    }
    catch {
        Write-Log "Error getting MSA principals: $_" -Level 'ERROR'
        return @()
    }
}

# Function to view MSA computer principals
function Show-MSAPrincipals {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$MSAName
    )
    
    try {
        Clear-Host
        Write-Host "=== Principals for $MSAName ===" -ForegroundColor Cyan
        Write-Log "Viewing principals for MSA '$MSAName'..." -Level 'INFO'
        
        # Get principals using our enhanced function
        $principals = Get-MSAPrincipals -MSAName $MSAName
        
        # Filter computers
        $computers = $principals | Where-Object { $_.Type -eq "computer" }
        
        if ($computers.Count -gt 0) {
            Write-Host "`nComputers with permission to use this MSA:" -ForegroundColor Yellow
            foreach ($computer in $computers) {
                Write-Host "  - $($computer.Name)" -ForegroundColor White
            }
        } else {
            Write-Host "`nNo computers have permission to use this MSA." -ForegroundColor Yellow
            
            # Try an alternative way to check permissions
            Write-Host "`nAttempting alternative permission check..." -ForegroundColor Yellow
            
            $msaObject = Get-ADServiceAccount -Identity $MSAName -Properties *
            
            # Display raw permission data to help troubleshoot
            Write-Host "`nRaw Permission Data:" -ForegroundColor Yellow
            
            if ($msaObject.PrincipalsAllowedToRetrieveManagedPassword) {
                Write-Host "  PrincipalsAllowedToRetrieveManagedPassword:" -ForegroundColor White
                foreach ($principal in $msaObject.PrincipalsAllowedToRetrieveManagedPassword) {
                    Write-Host "  - $principal" -ForegroundColor Gray
                }
            } else {
                Write-Host "  PrincipalsAllowedToRetrieveManagedPassword: None" -ForegroundColor Gray
            }
            
            # Check Security Descriptor
            if ($msaObject.nTSecurityDescriptor) {
                Write-Host "`n  Security Descriptor Access Rules:" -ForegroundColor White
                foreach ($ace in $msaObject.nTSecurityDescriptor.Access) {
                    $identity = $ace.IdentityReference.ToString()
                    $rights = $ace.ActiveDirectoryRights.ToString()
                    Write-Host "  - $identity : $rights" -ForegroundColor Gray
                }
            }
        }
        
        # Filter groups
        $groups = $principals | Where-Object { $_.Type -eq "group" }
        
        if ($groups.Count -gt 0) {
            Write-Host "`nGroups with permission to use this MSA:" -ForegroundColor Yellow
            foreach ($group in $groups) {
                Write-Host "  - $($group.Name)" -ForegroundColor White
                
                # Get computers in this group
                try {
                    $groupMembers = Get-ADGroupMember -Identity $group.DistinguishedName | Where-Object { $_.objectClass -eq "computer" }
                    if ($groupMembers.Count -gt 0) {
                        Write-Host "    Computers in this group:" -ForegroundColor Gray
                        foreach ($member in $groupMembers) {
                            Write-Host "    - $($member.Name)" -ForegroundColor Gray
                        }
                    }
                }
                catch {
                    Write-Host "    Error getting group members: $_" -ForegroundColor Red
                }
            }
        }
        
        # Get other types of principals
        $others = $principals | Where-Object { $_.Type -ne "computer" -and $_.Type -ne "group" }
        
        if ($others.Count -gt 0) {
            Write-Host "`nOther principals with permission to this MSA:" -ForegroundColor Yellow
            foreach ($other in $others) {
                Write-Host "  - $($other.Name) (Type: $($other.Type))" -ForegroundColor White
            }
        }
        
        # Show information about how to manually add a computer
        Write-Host "`nTo manually add a computer to this MSA, use:" -ForegroundColor Cyan
        Write-Host "Add-ADComputerServiceAccount -Identity <ComputerName> -ServiceAccount $MSAName" -ForegroundColor White
    }
    catch {
        Write-Log "Error displaying MSA principals: $_" -Level 'ERROR'
    }
    finally {
        if (-not $NonInteractive) {
            Read-Host "`nPress Enter to continue"
        }
    }
}

# Implementation of Remove-AllMSAReferences function
function Remove-AllMSAReferences {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$MSAName
    )
    
    Write-Host "Removing all computer assignments from MSA '$MSAName'..." -ForegroundColor Yellow
    Write-Log "Removing all computer assignments from MSA '$MSAName'..." -Level 'INFO'
    
    try {
        # Get all computers that have this MSA assigned
        $msaObject = Get-ADServiceAccount -Identity $MSAName -ErrorAction Stop
        
        $computers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount |
                    Where-Object { $_.'msDS-HostServiceAccount' -contains $msaObject.DistinguishedName }
        
        if ($computers.Count -eq 0) {
            Write-Host "No computers found with MSA '$MSAName' assigned." -ForegroundColor Green
            Write-Log "No computers found with MSA '$MSAName' assigned." -Level 'INFO'
            return
        }
        
        foreach ($computer in $computers) {
            try {
                Write-Host "Removing MSA '$MSAName' from computer '$($computer.Name)'..." -ForegroundColor Yellow
                Remove-ADComputerServiceAccount -Identity $computer.Name -ServiceAccount $MSAName
                Write-Host "Successfully removed MSA from '$($computer.Name)'." -ForegroundColor Green
                Write-Log "Successfully removed MSA '$MSAName' from computer '$($computer.Name)'." -Level 'INFO'
            }
            catch {
                Write-Host "Failed to remove MSA from '$($computer.Name)': $_" -ForegroundColor Red
                Write-Log "Failed to remove MSA '$MSAName' from computer '$($computer.Name)': $_" -Level 'ERROR'
            }
        }
        
        Write-Host "Completed removing MSA assignments." -ForegroundColor Green
        Write-Log "Completed removing MSA assignments for '$MSAName'." -Level 'INFO'
    }
    catch {
        Write-Host "Error removing MSA references: $_" -ForegroundColor Red
        Write-Log "Error removing MSA references for '$MSAName': $_" -Level 'ERROR'
    }
}

# Function to modify MSA with improved computer principal view
function Set-MSAProperties {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$MSAName,
        [Parameter(Mandatory=$false)]
        [string]$Operation,
        [Parameter(Mandatory=$false)]
        [string]$ComputerName,
        [Parameter(Mandatory=$false)]
        [string]$GroupName,
        [Parameter(Mandatory=$false)]
        [string]$Description
    )

    try {
        Clear-Host
        Write-Host "=== Modify Managed Service Account ===" -ForegroundColor Cyan
        Write-Log "Starting MSA modification process" -Level 'INFO'

        # List available MSAs for selection if MSAName not provided
        if ([string]::IsNullOrWhiteSpace($MSAName)) {
            Write-Host "Available Managed Service Accounts:" -ForegroundColor Yellow
            try {
                $msaList = Get-ADServiceAccount -Filter * | Select-Object Name, DistinguishedName, objectClass, PrincipalsAllowedToRetrieveManagedPassword
                if ($msaList -eq $null -or ($msaList -is [array] -and $msaList.Count -eq 0)) {
                    Write-Host "No Managed Service Accounts found." -ForegroundColor Yellow
                    Write-Log "No Managed Service Accounts found." -Level 'WARN'
                    return
                }
                if (-not ($msaList -is [array])) { $msaList = @($msaList) }
                for ($i = 0; $i -lt $msaList.Count; $i++) {
                    Write-Host "[$i] $($msaList[$i].Name)"
                }
                $selection = Read-Host "Enter the number of the MSA to modify (or 'c' to cancel)"
                if ($selection -eq 'c') { return }
                if ([int]::TryParse($selection, [ref]$null) -and $selection -ge 0 -and $selection -lt $msaList.Count) {
                    $selectedMSA = $msaList[$selection]
                    $MSAName = $selectedMSA.Name
                } else {
                    Write-Host "Invalid selection. Please enter a valid number from the list." -ForegroundColor Red
                    Write-Log "Invalid MSA selection number." -Level 'ERROR'
                    return
                }
            } catch {
                Write-Log "Error retrieving MSA list: $_" -Level 'ERROR'
                return
            }
        } else {
            # Verify the MSA exists
            try {
                $selectedMSA = Get-ADServiceAccount -Identity $MSAName -Properties objectClass, PrincipalsAllowedToRetrieveManagedPassword
            } catch {
                Write-Log "MSA '$MSAName' not found in Active Directory." -Level 'ERROR'
                Write-Host "MSA '$MSAName' not found in Active Directory." -ForegroundColor Red
                return
            }
        }

        # If operation not provided, show menu
        if ([string]::IsNullOrWhiteSpace($Operation)) {
            Write-Host "What would you like to modify for $MSAName?" -ForegroundColor Yellow
            Write-Host "1. Change assigned computer (MSA only)"
            Write-Host "2. Assign AD group (gMSA only)"
            Write-Host "3. Set description"
            Write-Host "4. View assigned computers/principals"
            Write-Host "5. Remove all assigned computers"
            Write-Host "6. Exit"
            $Operation = Read-Host "Select an option"
        }

        switch ($Operation) {
           "1" {
    # Change assigned computer (sMSA only)
    if ($selectedMSA.objectClass -contains "msDS-GroupManagedServiceAccount") {
        Write-Host "You cannot assign computers to a gMSA. Please assign an AD group instead." -ForegroundColor Red
        Write-Log "Attempted to assign a computer directly to a gMSA '$MSAName', which is not supported." -Level 'ERROR'
        return
    }
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        $ComputerName = Read-Host "Enter the new computer name to assign to this MSA"
    }
    if (-not (Get-ADComputer -Filter "Name -eq '$ComputerName'" -ErrorAction SilentlyContinue)) {
        Write-Host "Computer '$ComputerName' not found in Active Directory." -ForegroundColor Red
        Write-Log "Computer '$ComputerName' not found in Active Directory." -Level 'ERROR'
        return
    }

    # Find all computers currently assigned to this sMSA
    $assignedComputers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount | Where-Object {
        $_."msDS-HostServiceAccount" -contains $selectedMSA.DistinguishedName
    }

    # Remove sMSA from all old computers (except the new one, if somehow it was already there)
    foreach ($c in $assignedComputers) {
        if ($c.Name -ne $ComputerName) {
            Remove-ADComputerServiceAccount -Identity $c.Name -ServiceAccount $MSAName
            Write-Log "Removed sMSA '$MSAName' from computer '$($c.Name)'" -Level 'INFO'
            Write-Host "Removed sMSA '$MSAName' from computer '$($c.Name)'" -ForegroundColor Yellow
        }
    }

    # (Re)assign the sMSA to the new computer
    Add-ADComputerServiceAccount -Identity $ComputerName -ServiceAccount $MSAName -ErrorAction Stop
    Write-Log "Computer '$ComputerName' allowed to use MSA '$MSAName'." -Level 'INFO'
    Write-Host "Computer '$ComputerName' allowed to use MSA '$MSAName'." -ForegroundColor Green

    # Ensure only one assignment exists (for safety, repeat check)
    $assignedComputers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount | Where-Object {
        $_."msDS-HostServiceAccount" -contains $selectedMSA.DistinguishedName
    }
    if ($assignedComputers.Count -ne 1) {
        Write-Host "WARNING: There are $($assignedComputers.Count) computers assigned to this sMSA! Only one is allowed." -ForegroundColor Red
        $toRemove = $assignedComputers | Where-Object { $_.Name -ne $ComputerName }
        foreach ($comp in $toRemove) {
            Remove-ADComputerServiceAccount -Identity $comp.Name -ServiceAccount $MSAName
            Write-Host "Removed $($comp.Name) from the sMSA." -ForegroundColor Yellow
            Write-Log "Removed computer '$($comp.Name)' from sMSA '$MSAName'." -Level 'INFO'
        }
    }

    # Ensure no group principals
    $msaObject = Get-ADServiceAccount -Identity $MSAName -Properties objectClass, PrincipalsAllowedToRetrieveManagedPassword
    if ($msaObject.objectClass -eq "msDS-ManagedServiceAccount" -and $msaObject.PrincipalsAllowedToRetrieveManagedPassword) {
        Set-ADServiceAccount -Identity $MSAName -PrincipalsAllowedToRetrieveManagedPassword $null
        Write-Host "Cleared group principals for sMSA $MSAName." -ForegroundColor Yellow
        Write-Log "Cleared group principals for sMSA $MSAName." -Level 'INFO'
    }
}

"2" {
    # Assign AD group (gMSA only)
    if ($selectedMSA.objectClass -notcontains "msDS-GroupManagedServiceAccount") {
        Write-Host "You can only assign groups to a gMSA." -ForegroundColor Red
        Write-Log "Attempted to assign a group to a non-gMSA '$MSAName'." -Level 'ERROR'
        return
    }
    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        $GroupName = Read-Host "Enter the AD group name to assign to this gMSA"
    }
    $group = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue
    if (-not $group) {
        Write-Host "Group '$GroupName' not found in Active Directory." -ForegroundColor Red
        Write-Log "Group '$GroupName' not found in Active Directory." -Level 'ERROR'
        return
    }
    Set-ADServiceAccount -Identity $MSAName -PrincipalsAllowedToRetrieveManagedPassword $GroupName
    Write-Log "Set gMSA '$MSAName' principals to group '$GroupName'." -Level 'INFO'
    Write-Host "gMSA '$MSAName' now assigned to group '$GroupName'." -ForegroundColor Green
}


"3" {
    if ([string]::IsNullOrWhiteSpace($Description)) {
        $Description = Read-Host "Enter the new description for $MSAName"
    }
    Set-ADServiceAccount -Identity $MSAName -Description $Description
    Write-Log "Updated description for '$MSAName' to '$Description'." -Level 'INFO'
    Write-Host "Description updated for '$MSAName'." -ForegroundColor Green
}


"4" {
    Write-Host "Assigned principals/computers for ($MSAName):" -ForegroundColor Yellow
    if ($selectedMSA.objectClass -contains "msDS-GroupManagedServiceAccount") {
        # gMSA: show groups allowed to retrieve password
        $principals = $selectedMSA.PrincipalsAllowedToRetrieveManagedPassword
        if ($principals) {
            foreach ($p in $principals) {
                Write-Host "- $p"
            }
        } else {
            Write-Host "No groups assigned." -ForegroundColor Yellow
        }
    } else {
        # sMSA: show assigned computer(s)
        $assignedComputers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount | Where-Object {
            $_."msDS-HostServiceAccount" -contains $selectedMSA.DistinguishedName
        }
        if ($assignedComputers.Count -gt 0) {
            foreach ($c in $assignedComputers) {
                Write-Host "- $($c.Name)"
            }
        } else {
            Write-Host "No computers assigned." -ForegroundColor Yellow
        }
    }
    Write-Log "Listed assigned principals/computers for '$MSAName'." -Level 'INFO'
}

"5" {
    # Remove all computers from sMSA
    if ($selectedMSA.objectClass -contains "msDS-GroupManagedServiceAccount") {
        Write-Host "gMSA does not have direct computer assignments." -ForegroundColor Red
        Write-Log "Attempted to remove computers from gMSA '$MSAName'." -Level 'ERROR'
        return
    }
    $assignedComputers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount | Where-Object {
        $_."msDS-HostServiceAccount" -contains $selectedMSA.DistinguishedName
    }
    if ($assignedComputers.Count -eq 0) {
        Write-Host "No computers assigned to this sMSA." -ForegroundColor Yellow
        Write-Log "No computers to remove from sMSA '$MSAName'." -Level 'WARN'
        return
    }
    foreach ($c in $assignedComputers) {
        Remove-ADComputerServiceAccount -Identity $c.Name -ServiceAccount $MSAName
        Write-Host "Removed sMSA '$MSAName' from computer '$($c.Name)'." -ForegroundColor Yellow
        Write-Log "Removed sMSA '$MSAName' from computer '$($c.Name)'." -Level 'INFO'
    }
    Write-Host "All computers removed from sMSA '$MSAName'." -ForegroundColor Green
    Write-Log "All computers removed from sMSA '$MSAName'." -Level 'INFO'
}





            "6" {
                Write-Host "Exiting modification menu." -ForegroundColor Cyan
                return
            }
            default {
                Write-Host "Invalid option selected." -ForegroundColor Red
                Write-Log "Invalid option selected for MSA modification: '$Operation'." -Level 'ERROR'
            }
        }
    } catch {
        Write-Host "Error modifying MSA: $_" -ForegroundColor Red
        Write-Log "Unexpected error in Set-MSAProperties: $_" -Level 'ERROR'
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level 'ERROR'
    } finally {
        if (-not $NonInteractive) {
            Read-Host "Press Enter to continue"
        }
    }
}

# Function to delete MSA
function Remove-ManagedServiceAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$MSAName
    )
    
    try {
        Clear-Host
        Write-Host "=== Delete Managed Service Account ===" -ForegroundColor Cyan
        Write-Log "Starting MSA deletion process" -Level 'INFO'
        
        # List available MSAs for selection if MSAName not provided
        if ([string]::IsNullOrWhiteSpace($MSAName)) {
            Write-Host "Available Managed Service Accounts:" -ForegroundColor Yellow
            try {
                $msaList = Get-ADServiceAccount -Filter * | Select-Object Name
                if ($msaList -eq $null -or ($msaList -is [array] -and $msaList.Count -eq 0)) {
                    Write-Host "No Managed Service Accounts found." -ForegroundColor Yellow
                    Write-Log "No Managed Service Accounts found for deletion." -Level 'WARN'
                    return
                }
                
                # Force into array if single item
                if (-not ($msaList -is [array])) {
                    $msaList = @($msaList)
                }
                
                for ($i=0; $i -lt $msaList.Count; $i++) {
                    Write-Host "[$i] $($msaList[$i].Name)"
                }
                
                $selection = Read-Host "Enter the number of the MSA to delete (or 'c' to cancel)"
                if ($selection -eq 'c') { return }
                
                if ([int]::TryParse($selection, [ref]$null)) {
                    $idx = [int]$selection
                    if ($idx -ge 0 -and $idx -lt $msaList.Count) {
                        $MSAName = $msaList[$idx].Name
                    } else {
                        Write-Host "Invalid selection number." -ForegroundColor Red
                        Write-Log "Invalid MSA selection number for deletion." -Level 'ERROR'
                        return
                    }
                } else {
                    Write-Host "Invalid input." -ForegroundColor Red
                    Write-Log "Invalid input for MSA selection." -Level 'ERROR'
                    return
                }
            }
            catch {
                Write-Log "Error retrieving MSA list for deletion: $_" -Level 'ERROR'
                return
            }
        }
        else {
            # Verify the MSA exists
            if (-not (Get-ADServiceAccount -Filter "Name -eq '$MSAName'" -ErrorAction SilentlyContinue)) {
                Write-Host "MSA '$MSAName' not found in Active Directory." -ForegroundColor Red
                Write-Log "MSA '$MSAName' not found in Active Directory for deletion." -Level 'ERROR'
                return
            }
        }
        
        # Confirm deletion
        $confirm = Read-Host "Are you sure you want to delete $MSAName? This cannot be undone. (yes/no)"
        if ($confirm.ToLower() -eq "yes") {
            # Check for any system dependencies before deletion
            try {
                $dependencies = Get-MSAPrincipals -MSAName $MSAName
                if ($dependencies.Count -gt 0) {
                    Write-Host "Warning: This MSA has $($dependencies.Count) dependencies. Removing it may affect these systems." -ForegroundColor Yellow
                    $forceDelete = Read-Host "Do you want to proceed with deletion anyway? (yes/no)"
                    if ($forceDelete.ToLower() -ne "yes") {
                        Write-Host "Deletion canceled." -ForegroundColor Yellow
                        Write-Log "MSA '$MSAName' deletion canceled due to dependencies." -Level 'INFO'
                        return
                    }
                }
                
                Remove-ADServiceAccount -Identity $MSAName -Confirm:$false
                Write-Host "Managed Service Account '$MSAName' has been deleted." -ForegroundColor Green
                Write-Log "Managed Service Account '$MSAName' has been deleted." -Level 'INFO'
            }
            catch {
                Write-Host "Error deleting MSA: $_" -ForegroundColor Red
                Write-Log "Error deleting MSA '$MSAName': $_" -Level 'ERROR'
            }
        } else {
            Write-Host "Deletion canceled." -ForegroundColor Yellow
            Write-Log "MSA '$MSAName' deletion canceled by user." -Level 'INFO'
        }
    }
    catch {
        Write-Host "Unexpected error in Remove-ManagedServiceAccount: $_" -ForegroundColor Red
        Write-Log "Unexpected error in Remove-ManagedServiceAccount: $_" -Level 'ERROR'
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level 'ERROR'
    }
    finally {
        if (-not $NonInteractive) {
            Read-Host "Press Enter to continue"
        }
    }
}

# Function to install MSA on a computer
function Install-ManagedServiceAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$MSAName,
        
        [Parameter(Mandatory=$false)]
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    try {
        Clear-Host
        Write-Host "=== Install Managed Service Account on Computer ===" -ForegroundColor Cyan
        Write-Log "Starting MSA installation process" -Level 'INFO'
        
        # List available MSAs for selection if MSAName not provided
        if ([string]::IsNullOrWhiteSpace($MSAName)) {
            Write-Host "Available Managed Service Accounts:" -ForegroundColor Yellow
            try {
                $progressParams = @{
                    Activity = "Retrieving MSA accounts"
                    Status = "Getting accounts from Active Directory"
                    PercentComplete = 20
                }
                Write-Progress @progressParams
                
                $msaList = Get-ADServiceAccount -Filter * | Select-Object Name, DistinguishedName
                
                # Update progress
                $progressParams.PercentComplete = 40
                $progressParams.Status = "Processing accounts"
                Write-Progress @progressParams
                
                if ($msaList -eq $null -or ($msaList -is [array] -and $msaList.Count -eq 0)) {
                    Write-Host "No Managed Service Accounts found." -ForegroundColor Yellow
                    Write-Log "No Managed Service Accounts found for installation." -Level 'WARN'
                    
                    # Complete progress
                    $progressParams.PercentComplete = 100
                    $progressParams.Completed = $true
                    Write-Progress @progressParams
                    
                    return
                }
                
                # Complete progress
                $progressParams.PercentComplete = 100
                $progressParams.Completed = $true
                Write-Progress @progressParams
                
                # Force into array if single item
                if (-not ($msaList -is [array])) {
                    $msaList = @($msaList)
                }
                
                for ($i=0; $i -lt $msaList.Count; $i++) {
                    Write-Host "[$i] $($msaList[$i].Name)"
                }
                
                $selection = Read-Host "Enter the number of the MSA to install (or 'c' to cancel)"
                if ($selection -eq 'c') { return }
                
                if ([int]::TryParse($selection, [ref]$null)) {
                    $idx = [int]$selection
                    if ($idx -ge 0 -and $idx -lt $msaList.Count) {
                        $selectedMSA = $msaList[$idx]
                        $MSAName = $selectedMSA.Name
                    } else {
                        Write-Host "Invalid selection number." -ForegroundColor Red
                        Write-Log "Invalid MSA selection number for installation." -Level 'ERROR'
                        return
                    }
                } else {
                    Write-Host "Invalid input." -ForegroundColor Red
                    Write-Log "Invalid input for MSA selection." -Level 'ERROR'
                    return
                }
            }
            catch {
                Write-Log "Error retrieving MSA list for installation: $_" -Level 'ERROR'
                return
            }
        }
        else {
            # Verify the MSA exists
            if (-not (Get-ADServiceAccount -Identity $MSAName -ErrorAction SilentlyContinue)) {
                Write-Host "MSA '$MSAName' not found in Active Directory." -ForegroundColor Red
                Write-Log "MSA '$MSAName' not found in Active Directory for installation." -Level 'ERROR'
                return
            }
            
            $selectedMSA = Get-ADServiceAccount -Identity $MSAName
        }
        
        # Get the computer name if not provided
        if ([string]::IsNullOrWhiteSpace($ComputerName)) {
            $ComputerName = Read-Host "Enter the computer name where you want to install the MSA (or press Enter for local computer)"
            
            if ([string]::IsNullOrWhiteSpace($ComputerName)) {
                $ComputerName = $env:COMPUTERNAME
            }
        }
        
        # Check permission using our improved method
        Write-Host "Checking permissions for $ComputerName on MSA $MSAName..." -ForegroundColor Yellow
        $principals = Get-MSAPrincipals -MSAName $MSAName
        $computerPrincipals = $principals | Where-Object { $_.Type -eq "Computer" }
        $hasPermission = $false
        
        foreach ($comp in $computerPrincipals) {
            if ($comp.Name -eq $ComputerName) {
                $hasPermission = $true
                break
            }
        }
        
        # Also check if computer is member of groups with permission
        if (-not $hasPermission) {
            $groupPrincipals = $principals | Where-Object { $_.Type -eq "group" }
            
            foreach ($group in $groupPrincipals) {
                try {
                    $groupMembers = Get-ADGroupMember -Identity $group.DistinguishedName | Where-Object { $_.objectClass -eq "computer" }
                    foreach ($member in $groupMembers) {
                        if ($member.Name -eq $ComputerName) {
                            $hasPermission = $true
                            Write-Host "Computer '$ComputerName' has permission via group membership in '$($group.Name)'." -ForegroundColor Green
                            break
                        }
                    }
                    
                    if ($hasPermission) { break }
                }
                catch {
                    Write-Log "Error checking group membership for '$($group.Name)': $_" -Level 'ERROR'
                }
            }
        }
        
        if (-not $hasPermission) {
            $addPermission = Read-Host "Computer '$ComputerName' doesn't have permission to use this MSA. Add permission? (y/n)"
            if ($addPermission.ToLower() -eq "y") {
                try {
                    Add-ADComputerServiceAccount -Identity $ComputerName -ServiceAccount $MSAName
                    Write-Host "Added permission for '$ComputerName' to use MSA '$MSAName'." -ForegroundColor Green
                    Write-Log "Added permission for computer '$ComputerName' to use MSA '$MSAName'." -Level 'INFO'
                }
                catch {
                    Write-Host "Failed to add permission: $_" -ForegroundColor Red
                    Write-Log "Failed to add permission for computer '$ComputerName' to use MSA '$MSAName': $_" -Level 'ERROR'
                    return
                }
            }
            else {
                Write-Host "Installation canceled. The computer needs permission to use the MSA." -ForegroundColor Red
                Write-Log "MSA installation canceled due to insufficient permissions." -Level 'WARN'
                return
            }
        }
        
        # Check if remote or local
        $isLocal = ($ComputerName -eq $env:COMPUTERNAME) -or ($ComputerName -eq "localhost")
        
        if ($isLocal) {
            # Install locally
            try {
                Write-Host "Installing MSA '$MSAName' locally..." -ForegroundColor Yellow
                Install-ADServiceAccount -Identity $MSAName -ErrorAction Stop
                Write-Host "MSA '$MSAName' installed successfully on local computer." -ForegroundColor Green
                Write-Log "MSA '$MSAName' installed successfully on local computer." -Level 'INFO'
            }
            catch {
                Write-Host "Failed to install MSA locally: $_" -ForegroundColor Red
                Write-Log "Failed to install MSA '$MSAName' locally: $_" -Level 'ERROR'
                Write-Host "`nTroubleshooting tips:" -ForegroundColor Cyan
                Write-Host "1. Make sure you have local administrative privileges." -ForegroundColor White
                Write-Host "2. Verify that the computer has been correctly added to the MSA's allowed principals." -ForegroundColor White
                Write-Host "3. Try restarting the computer to ensure group membership changes are applied." -ForegroundColor White
                Write-Host "4. Check if the KDS Root Key is available and properly replicated." -ForegroundColor White
            }
        } else {
            # Install remotely using Invoke-Command
            Write-Host "Installing MSA '$MSAName' on remote computer '$ComputerName'..." -ForegroundColor Yellow
            
            $scriptBlock = {
                param($msaName)
                try {
                    Import-Module ActiveDirectory -ErrorAction Stop
                    Install-ADServiceAccount -Identity $msaName -ErrorAction Stop
                    return "MSA '$msaName' installed successfully."
                } catch {
                    return "Error installing MSA: $_"
                }
            }
            
            try {
                $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $MSAName -ErrorAction Stop
                Write-Host $result -ForegroundColor Green
                Write-Log "Remote installation of MSA '$MSAName' on computer '$ComputerName': $result" -Level 'INFO'
            } catch {
                Write-Host "Failed to connect to remote computer: $ComputerName" -ForegroundColor Red
                Write-Host "Error: $_" -ForegroundColor Red
                Write-Log "Failed to connect to remote computer '$ComputerName': $_" -Level 'ERROR'
                Write-Host "`nTroubleshooting tips:" -ForegroundColor Cyan
                Write-Host "1. Make sure the computer is online and accessible via network." -ForegroundColor White
                Write-Host "2. Verify that you have administrative privileges on the remote computer." -ForegroundColor White
                Write-Host "3. Check if PowerShell remoting is enabled (run 'Enable-PSRemoting' on the remote computer)." -ForegroundColor White
                Write-Host "4. Verify that WinRM service is running on the remote computer." -ForegroundColor White
            }
        }
    }
    catch {
        Write-Host "Unexpected error in Install-ManagedServiceAccount: $_" -ForegroundColor Red
        Write-Log "Unexpected error in Install-ManagedServiceAccount: $_" -Level 'ERROR'
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level 'ERROR'
    }
    finally {
        if (-not $NonInteractive) {
            Read-Host "Press Enter to continue"
        }
    }
}

# Function to test MSA installation and functionality
function Test-MSAInstallation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$MSAName,
        
        [Parameter(Mandatory=$false)]
        [string]$ComputerName = $env:COMPUTERNAME
    )
    
    try {
        Clear-Host
        Write-Host "=== Testing MSA Installation ===" -ForegroundColor Cyan
        Write-Log "Starting MSA installation test process" -Level 'INFO'
        
        # List available MSAs for selection if MSAName not provided
        if ([string]::IsNullOrWhiteSpace($MSAName)) {
            Write-Host "Available Managed Service Accounts:" -ForegroundColor Yellow
            try {
                $msaList = Get-ADServiceAccount -Filter * | Select-Object Name
                if ($msaList -eq $null -or ($msaList -is [array] -and $msaList.Count -eq 0)) {
                    Write-Host "No Managed Service Accounts found." -ForegroundColor Yellow
                    Write-Log "No Managed Service Accounts found for testing." -Level 'WARN'
                    return
                }
                
                # Force into array if single item
                if (-not ($msaList -is [array])) {
                    $msaList = @($msaList)
                }
                
                for ($i=0; $i -lt $msaList.Count; $i++) {
                    Write-Host "[$i] $($msaList[$i].Name)"
                }
                
                $selection = Read-Host "Enter the number of the MSA to test (or 'c' to cancel)"
                if ($selection -eq 'c') { return }
                
                if ([int]::TryParse($selection, [ref]$null)) {
                    $idx = [int]$selection
                    if ($idx -ge 0 -and $idx -lt $msaList.Count) {
                        $MSAName = $msaList[$idx].Name
                    } else {
                        Write-Host "Invalid selection number." -ForegroundColor Red
                        Write-Log "Invalid MSA selection number for testing." -Level 'ERROR'
                        return
                    }
                } else {
                    Write-Host "Invalid input." -ForegroundColor Red
                    Write-Log "Invalid input for MSA selection." -Level 'ERROR'
                    return
                }
            }
            catch {
                Write-Log "Error retrieving MSA list for testing: $_" -Level 'ERROR'
                return
            }
        }
        
        # Get the computer name if not provided
        if ([string]::IsNullOrWhiteSpace($ComputerName)) {
            $ComputerName = Read-Host "Enter the computer name to test (or press Enter for local computer)"
            
            if ([string]::IsNullOrWhiteSpace($ComputerName)) {
                $ComputerName = $env:COMPUTERNAME
            }
        }
        
        # Check if MSA exists in AD
        $msaExists = Get-ADServiceAccount -Filter "Name -eq '$MSAName'" -ErrorAction SilentlyContinue
        if (-not $msaExists) {
            Write-Host "MSA '$MSAName' does not exist in Active Directory." -ForegroundColor Red
            Write-Log "MSA '$MSAName' does not exist in Active Directory (test failed)." -Level 'ERROR'
            return $false
        }
        
        Write-Host "Testing MSA '$MSAName' on computer '$ComputerName'..." -ForegroundColor Yellow
        
        # Test if MSA is installed on the target computer
        $scriptBlock = {
            param($msaName)
            try {
                $result = Test-ADServiceAccount -Identity $msaName
                
                # Get additional information if installed
                if ($result) {
                    $additionalInfo = @{
                        IsInstalled = $result
                        SID = (Get-ADServiceAccount -Identity $msaName -Properties ObjectSID).ObjectSID.Value
                        AccountExists = $null -ne (Get-ADServiceAccount -Identity $msaName -ErrorAction SilentlyContinue)
                    }
                    return $additionalInfo
                }
                return @{ IsInstalled = $result }
            }
            catch {
                return @{ 
                    IsInstalled = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        if ($ComputerName -eq $env:COMPUTERNAME) {
            $testResult = Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $MSAName
        }
        else {
            try {
                $testResult = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $MSAName -ErrorAction Stop
            }
            catch {
                Write-Host "Failed to connect to computer '$ComputerName': $_" -ForegroundColor Red
                Write-Log "Failed to connect to computer '$ComputerName' for MSA testing: $_" -Level 'ERROR'
                return $false
            }
        }
        
        if ($testResult.IsInstalled) {
            Write-Host "`nMSA '$MSAName' is properly installed and functional on '$ComputerName'." -ForegroundColor Green
            Write-Log "MSA '$MSAName' is properly installed and functional on '$ComputerName'." -Level 'INFO'
            
            # Display additional MSA information
            Write-Host "`nMSA Details:" -ForegroundColor Cyan
            if ($testResult.SID) {
                Write-Host "SID: $($testResult.SID)" -ForegroundColor White
            }
            
            # List permissions
            $principals = Get-MSAPrincipals -MSAName $MSAName
            $computerPrincipals = $principals | Where-Object { $_.Type -eq "Computer" }
            
            Write-Host "`nComputers with permission to use this MSA:" -ForegroundColor Cyan
            if ($computerPrincipals.Count -gt 0) {
                foreach ($comp in $computerPrincipals) {
                    if ($comp.Name -eq $ComputerName) {
                        Write-Host "  - $($comp.Name) (Current Computer)" -ForegroundColor Green
                    } else {
                        Write-Host "  - $($comp.Name)" -ForegroundColor White
                    }
                }
            } else {
                Write-Host "  None directly assigned" -ForegroundColor Yellow
            }
            
            # Check group memberships
            $groupPrincipals = $principals | Where-Object { $_.Type -eq "group" }
            
            Write-Host "`nGroups with permission to use this MSA:" -ForegroundColor Cyan
            if ($groupPrincipals.Count -gt 0) {
                foreach ($group in $groupPrincipals) {
                    Write-Host "  - $($group.Name)" -ForegroundColor White
                }
            } else {
                Write-Host "  None" -ForegroundColor Yellow
            }
            
            return $true
        }
        else {
            Write-Host "`nMSA '$MSAName' is NOT properly installed on '$ComputerName'." -ForegroundColor Red
            Write-Log "MSA '$MSAName' is NOT properly installed on '$ComputerName'." -Level 'ERROR'
            
            if ($testResult.Error) {
                Write-Host "Error details: $($testResult.Error)" -ForegroundColor Red
            }
            
            # Check if computer has permission
            $principals = Get-MSAPrincipals -MSAName $MSAName
            $computerHasDirectPermission = $principals | Where-Object { $_.Type -eq "Computer" -and $_.Name -eq $ComputerName }
            
            if (-not $computerHasDirectPermission) {
                Write-Host "`nIssue detected: Computer '$ComputerName' does not have direct permission to use this MSA." -ForegroundColor Yellow
                
                # Check group memberships
                $groupPrincipals = $principals | Where-Object { $_.Type -eq "group" }
                $computerInGroup = $false
                
                foreach ($group in $groupPrincipals) {
                    try {
                        $groupMembers = Get-ADGroupMember -Identity $group.DistinguishedName | Where-Object { $_.objectClass -eq "computer" }
                        foreach ($member in $groupMembers) {
                            if ($member.Name -eq $ComputerName) {
                                $computerInGroup = $true
                                Write-Host "Computer is a member of group '$($group.Name)' which has permission to use the MSA." -ForegroundColor Yellow
                                break
                            }
                        }
                        
                        if ($computerInGroup) { break }
                    }
                    catch {
                        Write-Log "Error checking group membership: $_" -Level 'ERROR'
                    }
                }
                
                if (-not $computerInGroup) {
                    Write-Host "Computer is not a member of any group that has permission to use this MSA." -ForegroundColor Red
                    Write-Host "`nRecommendation: Add the computer to the allowed principals using:" -ForegroundColor Cyan
                    Write-Host "Add-ADComputerServiceAccount -Identity $ComputerName -ServiceAccount $MSAName" -ForegroundColor White
                }
            }
            
            Write-Host "`nTroubleshooting steps:" -ForegroundColor Cyan
            Write-Host "1. Verify the computer has permission to use the MSA" -ForegroundColor White
            Write-Host "2. Run 'Install-ADServiceAccount -Identity $MSAName' on the target computer" -ForegroundColor White
            Write-Host "3. Check if the KDS Root Key is properly configured" -ForegroundColor White
            Write-Host "4. Ensure the computer can contact a domain controller" -ForegroundColor White
            Write-Host "5. Verify Active Directory replication is working correctly" -ForegroundColor White
            
            return $false
        }
    }
    catch {
        Write-Host "Error testing MSA installation: $_" -ForegroundColor Red
        Write-Log "Error testing MSA installation: $_" -Level 'ERROR'
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level 'ERROR'
        return $false
    }
    finally {
        if (-not $NonInteractive) {
            Read-Host "`nPress Enter to continue"
        }
    }
}

# Function to list MSAs - Enhanced detailed version with progress indicator
function Get-ManagedServiceAccounts {
    [CmdletBinding()]
    param ()

    try {
        Clear-Host
        Write-Host "=== List Managed Service Accounts ===" -ForegroundColor Cyan
        Write-Log "Retrieving MSA accounts" -Level 'INFO'

        # Initialize progress bar
        $progressParams = @{
            Activity = "Retrieving MSA accounts"
            Status = "Getting accounts from Active Directory"
            PercentComplete = 20
        }
        Write-Progress @progressParams

        # Get MSAs with important properties
        $msaAccounts = Get-ADServiceAccount -Filter * -Properties Name, DNSHostName, Enabled, Description,
                      Created, Modified, ServicePrincipalNames, PrincipalsAllowedToRetrieveManagedPassword, objectClass

        # Update progress
        $progressParams.PercentComplete = 50
        $progressParams.Status = "Processing accounts"
        Write-Progress @progressParams

        if ($msaAccounts -eq $null -or ($msaAccounts -is [array] -and $msaAccounts.Count -eq 0)) {
            # Complete progress
            $progressParams.PercentComplete = 100
            $progressParams.Completed = $true
            Write-Progress @progressParams
            
            Write-Host "No Managed Service Accounts found." -ForegroundColor Yellow
            Write-Log "No Managed Service Accounts found." -Level 'WARN'
            return
        }

        # Force into array if single item
        if (-not ($msaAccounts -is [array])) {
            $msaAccounts = @($msaAccounts)
        }

        # Update progress
        $progressParams.PercentComplete = 70
        $progressParams.Status = "Analyzing account details"
        Write-Progress @progressParams

        Write-Host "Found $($msaAccounts.Count) Managed Service Account(s):" -ForegroundColor Yellow
        Write-Host

        $counter = 0
        $total = $msaAccounts.Count
        foreach ($msa in $msaAccounts) {
            # Update progress for each MSA
            $counter++
            $progressParams.PercentComplete = 70 + (30 * $counter / $total)
            $progressParams.Status = "Processing account $counter of $total"
            Write-Progress @progressParams
            
            # Determine if this is an sMSA or gMSA based on objectClass
            $msaType = "gMSA (Group Managed Service Account)"
            if ($msa.objectClass -contains "msDS-ManagedServiceAccount") {
                $msaType = "sMSA (Standalone Managed Service Account)"
            }

            # Basic info
            Write-Host "Name: $($msa.Name)" -ForegroundColor Cyan
            Write-Host "  Type: $msaType" -ForegroundColor White
            Write-Host "  Enabled: $($msa.Enabled)" -ForegroundColor White
            Write-Host "  Description: $($msa.Description)" -ForegroundColor White
            Write-Host "  Created: $($msa.Created)" -ForegroundColor White
            Write-Host "  Modified: $($msa.Modified)" -ForegroundColor White

            # Assigned Computers
            $assignedComputers = @()
            foreach ($computer in Get-ADComputer -Filter * -Properties msDS-HostServiceAccount) {
                # FIXED: Ensure the msDS-HostServiceAccount property is treated properly
                if ($computer.'msDS-HostServiceAccount' -contains $msa.DistinguishedName) {
                    $assignedComputers += $computer.Name
                }
            }

            if ($assignedComputers.Count -gt 0) {
                Write-Host "  Assigned Computers: $($assignedComputers -join ', ')" -ForegroundColor Green
            } else {
                Write-Host "  Assigned Computers: None" -ForegroundColor Yellow
            }

            Write-Host
        }
        
        # Complete progress
        $progressParams.PercentComplete = 100
        $progressParams.Completed = $true
        Write-Progress @progressParams
    }
    catch {
        Write-Host "Error retrieving MSAs: $_" -ForegroundColor Red
        Write-Log "Error retrieving MSAs: $_" -Level 'ERROR'
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level 'ERROR'
    }
    finally {
        if (-not $NonInteractive) {
            Read-Host "Press Enter to continue"
        }
    }
}

# Function to get current username from whoami
function Get-CurrentUsername {
    try {
        $whoami = whoami
        # Extract just the username part, removing domain if present
        $username = ($whoami -split '\\')[-1]
        return $username
    }
    catch {
        # Fallback to environment variable if whoami fails
        return $env:USERNAME
    }
}

# =================== Main Logic ===================

if (-not (Test-ADModule)) {
    Write-Host "Active Directory module could not be loaded. Exiting." -ForegroundColor Red
    exit 1
}

if (-not $NonInteractive -and -not $Action) {
    while ($true) {
        MaybeClearHost
        Write-Host "=== Managed Service Account Manager ===" -ForegroundColor Cyan
        Write-Host "1. Create Managed Service Account"
        Write-Host "2. Modify Managed Service Account"
        Write-Host "3. Delete Managed Service Account"
        Write-Host "4. Install Managed Service Account"
        Write-Host "5. List Managed Service Accounts"
        Write-Host "6. Exit"
        $choice = Read-Host "Select an option [1-6]"
        switch ($choice) {
            "1" { New-ManagedServiceAccount }
            "2" { Set-MSAProperties }
            "3" { Remove-ManagedServiceAccount }
            "4" { Install-ManagedServiceAccount }
            "5" { List-ManagedServiceAccounts }
            "6" { exit }
            default { Write-Host "Invalid selection." -ForegroundColor Red; Start-Sleep 2 }
        }
    }
} elseif ($Action) {
    switch ($Action) {
        "Create" { New-ManagedServiceAccount -MSAName $MSAName -MSAType $MSAType }
        "Modify" { Set-MSAProperties -MSAName $MSAName }
        "Delete" { Remove-ManagedServiceAccount -MSAName $MSAName }
        "Install" { Install-ManagedServiceAccount -MSAName $MSAName -ComputerName $ComputerName }
        "List" { List-ManagedServiceAccounts }
        default { Write-Host "Unknown action: $Action" -ForegroundColor Red }
    }
}
