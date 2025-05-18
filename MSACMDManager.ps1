<#
.SYNOPSIS
    Management tool for Active Directory Managed Service Accounts (MSAs and gMSAs).

.DESCRIPTION
    This script provides a comprehensive set of functions for managing Managed Service Accounts
    in Active Directory, including creating, modifying, deleting, installing, and listing MSAs.

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
    .\MSA-gMSA-Manager.ps1
    Runs the script in interactive menu mode.

.EXAMPLE
    .\MSA-gMSA-Manager.ps1 -NonInteractive -Action Create -MSAName "WebAppService" -MSAType "2"
    Creates a new gMSA named WebAppService in non-interactive mode.

.NOTES
    Author: DambergC
    Date Created: 2025-05-14
    Last Updated: 2025-05-18
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$NonInteractive,
    
    [Parameter()]
    [ValidateSet('Create', 'Modify', 'Delete', 'Install', 'List', 'Test', 'Export', 'Import')]
    [string]$Action,
    
    [Parameter()]
    [string]$MSAName,
    
    [Parameter()]
    [string]$ComputerName,
    
    [Parameter()]
    [ValidateSet('1', '2')]
    [string]$MSAType,

    [Parameter()]
    [string]$LogPath = "$env:TEMP\MSA-Manager.log",

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [string]$ImportPath
)

# Function for logging
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Level = 'INFO',
        
        [Parameter()]
        [string]$LogPath = $script:LogPath
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$Level] $Message"
    
    if ($Level -eq 'ERROR') {
        Write-Host $logLine -ForegroundColor Red
    } elseif ($Level -eq 'WARN') {
        Write-Host $logLine -ForegroundColor Yellow
    } else {
        Write-Host $logLine
    }
    
    Add-Content -Path $LogPath -Value $logLine -ErrorAction SilentlyContinue
}

# Ensure Active Directory module is available
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
    }
    else {
        Import-Module ActiveDirectory
    }
    return $true
}

# Function to create a new MSA - Enhanced with validation and logging
function New-ManagedServiceAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [string]$MSAName,

        [Parameter(Mandatory=$false)]
        [ValidateSet('1', '2')]
        [string]$MSAType
    )

    try {
        Clear-Host
        Write-Host "=== Create New Managed Service Account ===" -ForegroundColor Cyan
        Write-Log "Starting MSA creation process" -Level 'INFO'
        
        # Get MSA name if not provided
        if ([string]::IsNullOrWhiteSpace($MSAName)) {
            $MSAName = Read-Host "Enter the name for the new Managed Service Account"
            
            # Validate MSA name
            if ([string]::IsNullOrWhiteSpace($MSAName) -or $MSAName -match '\s') {
                Write-Log "Invalid MSA name. Name cannot be empty or contain spaces." -Level 'ERROR'
                return
            }
        }
        
        # Check if MSA already exists
        if (Get-ADServiceAccount -Filter "Name -eq '$MSAName'" -ErrorAction SilentlyContinue) {
            Write-Log "An MSA with name '$MSAName' already exists." -Level 'ERROR'
            return
        }
        
        # Get MSA type if not provided
        if ([string]::IsNullOrWhiteSpace($MSAType)) {
            $MSAType = Read-Host "Create as: (1) sMSA (standalone) or (2) gMSA (group)"
            
            # Validate MSA type
            if ($MSAType -ne '1' -and $MSAType -ne '2') {
                Write-Log "Invalid MSA type. Must be '1' for sMSA or '2' for gMSA." -Level 'ERROR'
                return
            }
        }
        
        try {
            if ($MSAType -eq '1') {
                # Create standalone MSA (sMSA)
                Write-Log "Creating standalone MSA (sMSA) '$MSAName'..." -Level 'INFO'
                
                New-ADServiceAccount -Name $MSAName -RestrictToSingleComputer -ErrorAction Stop
                
                Write-Log "Standalone MSA '$MSAName' created successfully." -Level 'INFO'
                Write-Host "Standalone MSA '$MSAName' created successfully." -ForegroundColor Green
                
                # Ask for the computer to bind this MSA to
                $computerName = Read-Host "Enter the computer name to bind this sMSA to"
                
                if (-not [string]::IsNullOrWhiteSpace($computerName)) {
                    # Verify the computer exists in AD
                    if (-not (Get-ADComputer -Filter "Name -eq '$computerName'" -ErrorAction SilentlyContinue)) {
                        Write-Log "Computer '$computerName' not found in Active Directory." -Level 'ERROR'
                        return
                    }
                    
                    # Add the computer to the allowed principals for this MSA
                    Add-ADComputerServiceAccount -Identity $computerName -ServiceAccount $MSAName -ErrorAction Stop
                    Write-Log "Computer '$computerName' allowed to use MSA '$MSAName'." -Level 'INFO'
                    Write-Host "Computer '$computerName' allowed to use MSA '$MSAName'." -ForegroundColor Green
                }
            } 
            else {
                # Check if AD group is created
                $isAdGroupCreated = Read-Host "Is the AD group created? (yes/no)"
                if ($isAdGroupCreated.ToLower() -eq "yes") {
                    $adGroupName = Read-Host "Please provide the AD group name"
                    
                    # Verify the group exists
                    if (-not (Get-ADGroup -Filter "Name -eq '$adGroupName'" -ErrorAction SilentlyContinue)) {
                        Write-Log "AD group '$adGroupName' not found in Active Directory." -Level 'ERROR'
                        return
                    }
                    
                    Write-Log "Creating group MSA (gMSA) '$MSAName' associated with AD group '$adGroupName'..." -Level 'INFO'
                    
                    # Check for KDS Root Key
                    $kdsRootKeys = Get-KdsRootKey
                    if ($null -eq $kdsRootKeys) {
                        Write-Log "No KDS Root Key found. Creating one..." -Level 'WARN'
                        Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
                        Write-Log "KDS Root Key created. Waiting for replication..." -Level 'INFO'
                        Start-Sleep -Seconds 5  # Brief pause
                    }
                    
                    # Create the group MSA
                    New-ADServiceAccount -Name $MSAName -PrincipalsAllowedToRetrieveManagedPassword $adGroupName -ErrorAction Stop
                    
                    Write-Log "Group MSA '$MSAName' created successfully." -Level 'INFO'
                    Write-Host "Group MSA '$MSAName' created successfully." -ForegroundColor Green
                }
                elseif ($isAdGroupCreated.ToLower() -eq "no") {
                    Write-Log "AD group is not created. Stopping gMSA creation." -Level 'WARN'
                    Write-Host "AD group is not created. Would you like to create one now? (yes/no)" -ForegroundColor Yellow
                    $createGroup = Read-Host
                    
                    if ($createGroup.ToLower() -eq "yes") {
                        $groupName = Read-Host "Enter a name for the new AD group"
                        try {
                            New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security
                            Write-Log "AD group '$groupName' created successfully." -Level 'INFO'
                            Write-Host "AD group '$groupName' created successfully. Now you can create the gMSA." -ForegroundColor Green
                        }
                        catch {
                            Write-Log "Error creating AD group: $_" -Level 'ERROR'
                        }
                    }
                    return
                }
                else {
                    Write-Log "Invalid input. Please respond with 'yes' or 'no'." -Level 'ERROR'
                    return
                }
            }
        }
        catch {
            Write-Log "Error creating MSA: $_" -Level 'ERROR'
            
            $errorMsg = $_.Exception.Message
            
            # Provide specific guidance based on the error message
            if ($errorMsg -like "*Parameter set cannot be resolved*") {
                Write-Log "Your Active Directory version might require different parameter combinations." -Level 'WARN'
                Write-Host "`nYour Active Directory version might require different parameter combinations." -ForegroundColor Yellow
                Write-Host "Please try one of these commands manually in a PowerShell window:" -ForegroundColor Yellow
                
                if ($MSAType -eq '1') {
                    Write-Host "`nFor standalone MSA (sMSA):" -ForegroundColor Cyan
                    Write-Host "New-ADServiceAccount -Name $MSAName -RestrictToSingleComputer" -ForegroundColor White
                    Write-Host "-- OR --" -ForegroundColor Cyan
                    Write-Host "New-ADServiceAccount -Name $MSAName -SAMAccountName $MSAName`$ -RestrictToSingleComputer" -ForegroundColor White
                } else {
                    Write-Host "`nFor group MSA (gMSA):" -ForegroundColor Cyan
                    Write-Host "New-ADServiceAccount -Name $MSAName" -ForegroundColor White
                    Write-Host "-- OR --" -ForegroundColor Cyan
                    Write-Host "New-ADServiceAccount -Name $MSAName -SAMAccountName $MSAName`$" -ForegroundColor White
                    Write-Host "-- OR --" -ForegroundColor Cyan
                    Write-Host "New-ADServiceAccount -Name $MSAName -DNSHostName $MSAName.$((Get-ADDomain).DNSRoot)" -ForegroundColor White
                }
            }
        }
    }
    catch {
        Write-Log "Unexpected error in New-ManagedServiceAccount: $_" -Level 'ERROR'
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level 'ERROR'
    }
    finally {
        if (-not $NonInteractive) {
            Read-Host "Press Enter to continue"
        }
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

                # Force into array if single item
                if (-not ($msaList -is [array])) {
                    $msaList = @($msaList)
                }

                for ($i = 0; $i -lt $msaList.Count; $i++) {
                    Write-Host "[$i] $($msaList[$i].Name)"
                }

                $selection = Read-Host "Enter the number of the MSA to modify (or 'c' to cancel)"
                if ($selection -eq 'c') { return }

                # Validate selection
                if ([int]::TryParse($selection, [ref]$null) -and $selection -ge 0 -and $selection -lt $msaList.Count) {
                    $selectedMSA = $msaList[$selection]
                    $MSAName = $selectedMSA.Name
                } else {
                    Write-Host "Invalid selection. Please enter a valid number from the list." -ForegroundColor Red
                    Write-Log "Invalid MSA selection number." -Level 'ERROR'
                    return
                }
            }
            catch {
                Write-Log "Error retrieving MSA list: $_" -Level 'ERROR'
                return
            }
        }
        else {
            # Verify the MSA exists
            try {
                $selectedMSA = Get-ADServiceAccount -Identity $MSAName -Properties objectClass
            }
            catch {
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
            $Operation = Read-Host "Select an option"
        }

        switch ($Operation) {
            "1" {
                # Logic for changing assigned computer (MSA only)
                if ($selectedMSA.objectClass -contains "msDS-GroupManagedServiceAccount") {
                    Write-Host "You cannot assign computers to a gMSA. Please assign an AD group instead." -ForegroundColor Red
                    Write-Log "Attempted to assign a computer directly to a gMSA '$MSAName', which is not supported." -Level 'ERROR'
                    return
                }

                # Get the new computer to assign
                if ([string]::IsNullOrWhiteSpace($ComputerName)) {
                    $ComputerName = Read-Host "Enter the new computer name to assign to this MSA"
                }

                # Verify the computer exists
                if (-not (Get-ADComputer -Filter "Name -eq '$ComputerName'" -ErrorAction SilentlyContinue)) {
                    Write-Host "Computer '$ComputerName' not found in Active Directory." -ForegroundColor Red
                    Write-Log "Computer '$ComputerName' not found in Active Directory." -Level 'ERROR'
                    return
                }

                # Check for existing assignments
                $assignedComputers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount |
                                     Where-Object { $_."msDS-HostServiceAccount" -contains $selectedMSA.DistinguishedName }

                # Remove existing assignments
                if ($assignedComputers.Count -gt 0) {
                    foreach ($computerToRemove in $assignedComputers) {
                        try {
                            Remove-ADComputerServiceAccount -Identity $computerToRemove.Name -ServiceAccount $MSAName
                            Write-Host "Removed $($computerToRemove.Name) from the MSA." -ForegroundColor Yellow
                            Write-Log "Removed computer '$($computerToRemove.Name)' from MSA '$MSAName'." -Level 'INFO'
                        } catch {
                            Write-Host "Failed to remove $($computerToRemove.Name) from the MSA. Error: $_" -ForegroundColor Red
                            Write-Log "Failed to remove computer '$($computerToRemove.Name)' from MSA '$MSAName': $_" -Level 'ERROR'
                        }
                    }
                }

                # Add the new computer to the MSA
                try {
                    Add-ADComputerServiceAccount -Identity $ComputerName -ServiceAccount $MSAName
                    Write-Host "$ComputerName now has exclusive permission to use $MSAName." -ForegroundColor Green
                    Write-Log "Computer '$ComputerName' now has exclusive permission to use MSA '$MSAName'." -Level 'INFO'
                } catch {
                    Write-Host "Failed to add $ComputerName to MSA. Error: $_" -ForegroundColor Red
                    Write-Log "Failed to add computer '$ComputerName' to MSA '$MSAName': $_" -Level 'ERROR'
                }
            }
            "2" {
                # Logic for assigning AD groups (gMSA only)
                if ($selectedMSA.objectClass -contains "msDS-GroupManagedServiceAccount") {
                    if ([string]::IsNullOrWhiteSpace($GroupName)) {
                        $GroupName = Read-Host "Enter the AD group name to assign to this gMSA"
                    }
                    
                    # Verify the group exists
                    if (-not (Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue)) {
                        Write-Host "AD group '$GroupName' not found in Active Directory." -ForegroundColor Red
                        Write-Log "AD group '$GroupName' not found in Active Directory." -Level 'ERROR'
                        return
                    }
                    
                    try {
                        Set-ADServiceAccount -Identity $MSAName -PrincipalsAllowedToRetrieveManagedPassword $GroupName
                        Write-Host "Assigned AD group '$GroupName' to gMSA '$MSAName'." -ForegroundColor Green
                        Write-Log "Assigned AD group '$GroupName' to gMSA '$MSAName'." -Level 'INFO'
                    } catch {
                        Write-Host "Failed to assign AD group to gMSA. Error: $_" -ForegroundColor Red
                        Write-Log "Failed to assign AD group '$GroupName' to gMSA '$MSAName': $_" -Level 'ERROR'
                    }
                } else {
                    Write-Host "You can only assign AD groups to a gMSA. This is not a gMSA." -ForegroundColor Red
                    Write-Log "Attempted to assign AD group to non-gMSA account '$MSAName'." -Level 'ERROR'
                }
            }
            "3" {
                if ([string]::IsNullOrWhiteSpace($Description)) {
                    $Description = Read-Host "Enter new description"
                }
                
                try {
                    Set-ADServiceAccount -Identity $MSAName -Description $Description
                    Write-Host "Description updated for '$MSAName'." -ForegroundColor Green
                    Write-Log "Description updated for MSA '$MSAName'." -Level 'INFO'
                }
                catch {
                    Write-Host "Failed to update description. Error: $_" -ForegroundColor Red
                    Write-Log "Failed to update description for MSA '$MSAName': $_" -Level 'ERROR'
                }
            }
            "4" {
                try {
                    Show-MSAPrincipals -MSAName $MSAName
                } catch {
                    Write-Host "Error viewing principals for ($MSAName): $_" -ForegroundColor Red
                    Write-Log "Error viewing principals for MSA '$MSAName': $_" -Level 'ERROR'
                }
            }
            "5" {
                $confirm = Read-Host "Are you sure you want to remove all computer assignments from '$MSAName'? (yes/no)"
                if ($confirm.ToLower() -eq "yes") {
                    Remove-AllMSAReferences -MSAName $MSAName
                }
                else {
                    Write-Host "Operation cancelled." -ForegroundColor Yellow
                }
            }
            default {
                Write-Host "Invalid option selected." -ForegroundColor Red
                Write-Log "Invalid option selected for MSA modification: '$Operation'." -Level 'ERROR'
            }
        }
    } 
    catch {
        Write-Host "Error modifying MSA: $_" -ForegroundColor Red
        Write-Log "Unexpected error in Set-MSAProperties: $_" -Level 'ERROR'
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level 'ERROR'
    }
    finally {
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

# Function to export MSA configuration
function Export-MSAConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$FilePath
    )
    
    try {
        Clear-Host
        Write-Host "=== Export MSA Configuration ===" -ForegroundColor Cyan
        Write-Log "Starting MSA configuration export process" -Level 'INFO'
        
        if ([string]::IsNullOrWhiteSpace($FilePath)) {
            $defaultPath = "$env:USERPROFILE\Documents\MSAConfig_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $FilePath = Read-Host "Enter export file path (default: $defaultPath)"
            
            if ([string]::IsNullOrWhiteSpace($FilePath)) {
                $FilePath = $defaultPath
            }
        }
        
        # Initialize progress bar
        $progressParams = @{
            Activity = "Exporting MSA Configuration"
            Status = "Getting MSA accounts"
            PercentComplete = 10
        }
        Write-Progress @progressParams
        
               $msaList = Get-ADServiceAccount -Filter * -Properties Name, DNSHostName, Enabled, Description, 
                  Created, Modified, PrincipalsAllowedToRetrieveManagedPassword, objectClass
        
        # Update progress
        $progressParams.PercentComplete = 30
        $progressParams.Status = "Processing MSA details"
        Write-Progress @progressParams
        
        if ($msaList -eq $null -or ($msaList -is [array] -and $msaList.Count -eq 0)) {
            Write-Host "No Managed Service Accounts found to export." -ForegroundColor Yellow
            Write-Log "No MSA accounts found to export." -Level 'WARN'
            return
        }
        
        # Force into array if single item
        if (-not ($msaList -is [array])) {
            $msaList = @($msaList)
        }
        
        $exportData = @()
        $counter = 0
        $total = $msaList.Count
        
        foreach ($msa in $msaList) {
            # Update progress for each MSA
            $counter++
            $progressParams.PercentComplete = 30 + (60 * $counter / $total)
            $progressParams.Status = "Processing MSA $counter of ($total): $($msa.Name)"
            Write-Progress @progressParams
            
            $principals = Get-MSAPrincipals -MSAName $msa.Name
            
            # Determine MSA type
            $msaType = "gMSA"
            if ($msa.objectClass -contains "msDS-ManagedServiceAccount") {
                $msaType = "sMSA"
            }
            
            $exportData += [PSCustomObject]@{
                Name = $msa.Name
                Type = $msaType
                Description = $msa.Description
                Enabled = $msa.Enabled
                DNSHostName = $msa.DNSHostName
                Created = $msa.Created.ToString('yyyy-MM-dd HH:mm:ss')
                Modified = $msa.Modified.ToString('yyyy-MM-dd HH:mm:ss')
                Principals = $principals | Select-Object Name, Type, SAMAccountName, DistinguishedName
            }
        }
        
        # Update progress
        $progressParams.PercentComplete = 90
        $progressParams.Status = "Saving configuration to file"
        Write-Progress @progressParams
        
        # Create directory if it doesn't exist
        $directory = Split-Path -Path $FilePath -Parent
        if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path $directory)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
        
        $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $FilePath -Force
        
        # Complete progress
        $progressParams.PercentComplete = 100
        $progressParams.Completed = $true
        Write-Progress @progressParams
        
        Write-Host "MSA configuration exported to $FilePath" -ForegroundColor Green
        Write-Log "MSA configuration exported to $FilePath" -Level 'INFO'
    }
    catch {
        Write-Host "Error exporting MSA configuration: $_" -ForegroundColor Red
        Write-Log "Error exporting MSA configuration: $_" -Level 'ERROR'
        Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level 'ERROR'
    }
    finally {
        if (-not $NonInteractive) {
            Read-Host "Press Enter to continue"
        }
    }
}

# Function to import MSA configuration
function Import-MSAConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$FilePath
    )
    
    try {
        Clear-Host
        Write-Host "=== Import MSA Configuration ===" -ForegroundColor Cyan
        Write-Log "Starting MSA configuration import process" -Level 'INFO'
        
        if ([string]::IsNullOrWhiteSpace($FilePath)) {
            $FilePath = Read-Host "Enter the path to the MSA configuration JSON file"
            
            if ([string]::IsNullOrWhiteSpace($FilePath) -or -not (Test-Path $FilePath)) {
                Write-Host "File not found or invalid path specified." -ForegroundColor Red
                Write-Log "Invalid file path specified for import: $FilePath" -Level 'ERROR'
                return
            }
        }
        
        # Initialize progress bar
        $progressParams = @{
            Activity = "Importing MSA Configuration"
            Status = "Reading configuration file"
            PercentComplete = 10
        }
        Write-Progress @progressParams
        
        # Read and parse configuration file
        $importData = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        
        # Update progress
        $progressParams.PercentComplete = 30
        $progressParams.Status = "Analyzing configuration"
        Write-Progress @progressParams
        
        if ($importData -eq $null) {
            Write-Host "No valid configuration data found in file." -ForegroundColor Red
            Write-Log "No valid MSA configuration data found in import file." -Level 'ERROR'
            return
        }
        
        # Display import summary
        Write-Host "`nFound $($importData.Count) MSA configurations to import:" -ForegroundColor Yellow
        foreach ($msa in $importData) {
            Write-Host "- $($msa.Name) (Type: $($msa.Type))" -ForegroundColor White
        }
        
        # Confirm import
        $confirm = Read-Host "`nDo you want to import these configurations? This is a READ-ONLY VIEW and will not create MSAs. (yes/no)"
        if ($confirm.ToLower() -ne "yes") {
            Write-Host "Import operation canceled." -ForegroundColor Yellow
            Write-Log "MSA configuration import canceled by user." -Level 'INFO'
            return
        }
        
        # Process configurations
        Write-Host "`nProcessing MSA configurations (READ-ONLY MODE):" -ForegroundColor Cyan
        $counter = 0
        $total = $importData.Count
        
        foreach ($msa in $importData) {
            $counter++
            $progressParams.PercentComplete = 30 + (60 * $counter / $total)
            $progressParams.Status = "Processing MSA $counter of ($total): $($msa.Name)"
            Write-Progress @progressParams
            
            Write-Host "`n[$counter/$total] Processing $($msa.Name):" -ForegroundColor Cyan
            
            # Check if MSA exists
            $existingMSA = Get-ADServiceAccount -Filter "Name -eq '$($msa.Name)'" -ErrorAction SilentlyContinue
            if ($existingMSA) {
                Write-Host "  MSA $($msa.Name) already exists in Active Directory." -ForegroundColor Yellow
                Write-Host "  Created: $($msa.Created)"
                Write-Host "  Description: $($msa.Description)"
                
                # Show principals
                if ($msa.Principals -and $msa.Principals.Count -gt 0) {
                    Write-Host "  Principals:" -ForegroundColor White
                    foreach ($principal in $msa.Principals) {
                        Write-Host "    - $($principal.Name) (Type: $($principal.Type))" -ForegroundColor Gray
                    }
                }
            }
            else {
                Write-Host "  MSA $($msa.Name) does not exist in Active Directory." -ForegroundColor White
                Write-Host "  Type: $($msa.Type)"
                Write-Host "  Description: $($msa.Description)"
                Write-Host "  Created: $($msa.Created)"
                
                # Show creation command
                Write-Host "  To create this MSA, you would use:" -ForegroundColor White
                if ($msa.Type -eq "sMSA") {
                    Write-Host "  New-ADServiceAccount -Name $($msa.Name) -RestrictToSingleComputer" -ForegroundColor Gray
                } 
                else {
                    $groupPrincipals = $msa.Principals | Where-Object { $_.Type -eq "group" }
                    if ($groupPrincipals -and $groupPrincipals.Count -gt 0) {
                        $groupName = $groupPrincipals[0].Name
                        Write-Host "  New-ADServiceAccount -Name $($msa.Name) -PrincipalsAllowedToRetrieveManagedPassword $groupName" -ForegroundColor Gray
                    }
                    else {
                        Write-Host "  New-ADServiceAccount -Name $($msa.Name)" -ForegroundColor Gray
                    }
                }
            }
        }
        
        # Complete progress
        $progressParams.PercentComplete = 100
        $progressParams.Completed = $true
        Write-Progress @progressParams
        
        Write-Host "`nMSA configuration import preview completed successfully." -ForegroundColor Green
        Write-Host "This was a READ-ONLY operation. No MSAs were created or modified." -ForegroundColor Yellow
        Write-Log "MSA configuration import preview completed." -Level 'INFO'
    }
    catch {
        Write-Host "Error importing MSA configuration: $_" -ForegroundColor Red
        Write-Log "Error importing MSA configuration: $_" -Level 'ERROR'
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

# Main menu function
function Show-MainMenu {
    $continue = $true
    
    while ($continue) {
        # Get actual current date/time in the required format
        $currentDateTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        
        # Get current username from whoami
        $currentUsername = Get-CurrentUsername
        
        Clear-Host
        Write-Host "===================================" -ForegroundColor Blue
        Write-Host "       MSA MANAGEMENT SYSTEM       " -ForegroundColor Cyan
        Write-Host "===================================" -ForegroundColor Blue
        Write-Host
        Write-Host "Current Date and Time (UTC - YYYY-MM-DD HH:MM:SS formatted): $currentDateTime" -ForegroundColor Gray
        Write-Host "Current User's Login: $currentUsername" -ForegroundColor Gray
        Write-Host
        Write-Host "1. Create new MSA" -ForegroundColor Yellow
        Write-Host "2. Modify existing MSA" -ForegroundColor Yellow
        Write-Host "3. Delete MSA" -ForegroundColor Yellow
        Write-Host "4. Install MSA on a computer" -ForegroundColor Yellow
        Write-Host "5. List all MSAs" -ForegroundColor Yellow
        Write-Host "6. Test MSA installation" -ForegroundColor Yellow
        Write-Host "7. Export MSA configuration" -ForegroundColor Yellow
        Write-Host "8. Import MSA configuration" -ForegroundColor Yellow
        Write-Host "0. Exit" -ForegroundColor Yellow
        Write-Host
        
        $choice = Read-Host "Enter your choice"
        
        switch ($choice) {
            "1" { New-ManagedServiceAccount }
            "2" { Set-MSAProperties }
            "3" { Remove-ManagedServiceAccount }
            "4" { Install-ManagedServiceAccount }
            "5" { Get-ManagedServiceAccounts }
            "6" { Test-MSAInstallation }
            "7" { Export-MSAConfiguration }
            "8" { Import-MSAConfiguration }
            "0" { $continue = $false }
            default { 
                Write-Host "Invalid selection. Press Enter to continue..." -ForegroundColor Red
                Read-Host
            }
        }
    }
}

# Handle non-interactive mode
if ($NonInteractive) {
    Write-Log "Starting script in non-interactive mode" -Level 'INFO'
    
    switch ($Action) {
        "Create" { New-ManagedServiceAccount -MSAName $MSAName -MSAType $MSAType }
        "Modify" { Set-MSAProperties -MSAName $MSAName -ComputerName $ComputerName }
        "Delete" { Remove-ManagedServiceAccount -MSAName $MSAName }
        "Install" { Install-ManagedServiceAccount -MSAName $MSAName -ComputerName $ComputerName }
        "List" { Get-ManagedServiceAccounts }
        "Test" { Test-MSAInstallation -MSAName $MSAName -ComputerName $ComputerName }
        "Export" { Export-MSAConfiguration -FilePath $ExportPath }
        "Import" { Import-MSAConfiguration -FilePath $ImportPath }
        default { 
            Write-Log "No valid action specified for non-interactive mode." -Level 'ERROR'
            Write-Host "Error: No valid action specified for non-interactive mode." -ForegroundColor Red
            Write-Host "Valid actions: Create, Modify, Delete, Install, List, Test, Export, Import" -ForegroundColor Yellow
        }
    }
    
    exit
}

# Main script execution
Clear-Host
Write-Host "Welcome to the MSA Management System" -ForegroundColor Green
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

if (Test-ADModule) {
    Show-MainMenu
} else {
    Write-Host "Unable to proceed without the Active Directory module." -ForegroundColor Red
    Read-Host "Press Enter to exit"
}
