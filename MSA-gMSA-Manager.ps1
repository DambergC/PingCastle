# ================================================
# Script Name: MSA-gMSA-Manager.ps1
# Description: PowerShell script for managing Managed Service Accounts (MSA) 
#              and Group Managed Service Accounts (gMSA).
# Version: 1.0.0
# Last Updated: 2025-05-15
# Author: DambergC (Christian Damberg)
# GitHub Repository: https://github.com/DambergC/PingCastle
# 
# Changelog:
# Version 1.0.0 - 2025-05-15
#   - Initial release with functions for creating, modifying, deleting, 
#     and managing MSAs and gMSAs.
# ================================================

# Function to check if the script is running as administrator
function Check-IsAdministrator {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentUser)

    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "The script must be run as an administrator by the logged-on user." -ForegroundColor Red
        Write-Host "Please restart the script with elevated privileges."
        Read-Host "Press Enter to exit"
        exit
    }
}

# Function to get the current logged-on user's username
function Get-CurrentUsername {
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        return $currentUser
    } catch {
        Write-Host "Error fetching logged-on user: $_" -ForegroundColor Red
        return "Unknown"
    }
}

# Main script execution starts here
# Perform checks for administrator privileges and display the current user
Check-IsAdministrator
$currentUsername = Get-CurrentUsername
Write-Host "Script is running as Administrator." -ForegroundColor Green
Write-Host "Current logged-on user: $currentUsername" -ForegroundColor Yellow


# Ensure Active Directory module is available
function Check-ADModule {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Host "Active Directory module not found. Installing..." -ForegroundColor Yellow
        Try {
            Install-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop
            Import-Module ActiveDirectory
            Write-Host "Active Directory module installed successfully." -ForegroundColor Green
        }
        Catch {
            Write-Host "Error installing Active Directory module. Please install RSAT tools manually." -ForegroundColor Red
            Write-Host $_.Exception.Message
            return $false
        }
    }
    else {
        Import-Module ActiveDirectoryview
    }
    return $true
}

function Remove-AllMSAReferences {
    param (
        [Parameter(Mandatory=$true)]
        [string]$MSAName
    )
    
    try {
        $msaDistinguishedName = (Get-ADServiceAccount -Identity $MSAName).DistinguishedName
        $assignedComputers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount |
                             Where-Object { $_."msDS-HostServiceAccount" -contains $msaDistinguishedName }

        if ($assignedComputers.Count -eq 0) {
            Write-Host "No computers are currently assigned to the MSA '$MSAName'." -ForegroundColor Yellow
            return
        }

        foreach ($computer in $assignedComputers) {
            try {
                Remove-ADComputerServiceAccount -Identity $computer.Name -ServiceAccount $MSAName
                Write-Host "Successfully removed MSA from computer: $($computer.Name)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove MSA from computer: $($computer.Name)" -ForegroundColor Red
                Write-Host "Error: $_" -ForegroundColor Red
            }
        }

        Write-Host "All references to the MSA '$MSAName' have been removed." -ForegroundColor Green
    } catch {
        Write-Host "Error removing MSA references: $_" -ForegroundColor Red
    }
}

function Remove-MSAGroupPrincipal {
    param (
        [Parameter(Mandatory=$true)]
        [string]$MSAName,
        [Parameter(Mandatory=$true)]
        [string]$GroupName
    )
    
    try {
        $msaObject = Get-ADServiceAccount -Identity $MSAName -Properties PrincipalsAllowedToRetrieveManagedPassword
        if (-not $msaObject.PrincipalsAllowedToRetrieveManagedPassword) {
            Write-Host "No principals are currently assigned to the MSA '$MSAName'." -ForegroundColor Yellow
            return
        }

        # Remove the specified group from the PrincipalsAllowedToRetrieveManagedPassword
        $updatedPrincipals = $msaObject.PrincipalsAllowedToRetrieveManagedPassword | Where-Object { $_ -ne (Get-ADGroup -Identity $GroupName).DistinguishedName }
        Set-ADServiceAccount -Identity $MSAName -PrincipalsAllowedToRetrieveManagedPassword $updatedPrincipals

        Write-Host "Successfully removed the group '$GroupName' from the MSA '$MSAName'." -ForegroundColor Green
    } catch {
        Write-Host "Error removing principal: $_" -ForegroundColor Red
    }
}

# Function to create a new MSA - ULTRA MINIMAL VERSION
function Create-MSA {
    Clear-Host
    Write-Host "=== Create New Managed Service Account ===" -ForegroundColor Cyan
    
    $msaName = Read-Host "Enter the name for the new Managed Service Account"
    
    # Ask if this MSA should be a standalone MSA (sMSA) or group MSA (gMSA)
    $msaType = Read-Host "Create as: (1) sMSA (standalone) or (2) gMSA (group)"
    
    try {
        if ($msaType -eq '1') {
            # Create standalone MSA (sMSA)
            Write-Host "Creating standalone MSA (sMSA)..." -ForegroundColor Yellow
            New-ADServiceAccount -Name $msaName -RestrictToSingleComputer
            Write-Host "Standalone MSA '$msaName' created successfully." -ForegroundColor Green
        } else {
            # Check if AD group is created
            $isAdGroupCreated = Read-Host "Is the AD group created? (yes/no)"
            if ($isAdGroupCreated -eq "yes") {
                $adGroupName = Read-Host "Please provide the AD group name"
                Write-Host "Creating group MSA (gMSA) associated with AD group '$adGroupName'..." -ForegroundColor Yellow
                
                # Check for KDS Root Key
                $kdsRootKeys = Get-KdsRootKey
                if ($null -eq $kdsRootKeys) {
                    Write-Host "No KDS Root Key found. Creating one..." -ForegroundColor Yellow
                    Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
                    Write-Host "KDS Root Key created. Waiting for replication..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 5
                }
                
                # Create group MSA
                New-ADServiceAccount -Name $msaName -PrincipalsAllowedToRetrieveManagedPassword $adGroupName
                Write-Host "Group MSA '$msaName' created successfully." -ForegroundColor Green
            } elseif ($isAdGroupCreated -eq "no") {
                Write-Host "AD group is not created. Stopping gMSA creation." -ForegroundColor Red
                return
            } else {
                Write-Host "Invalid input. Please respond with 'yes' or 'no'." -ForegroundColor Red
                return
            }
        }
    } catch {
        Write-Host "Error creating MSA: $_" -ForegroundColor Red
    }
    
    Read-Host "Press Enter to continue"
}

# Better function to find computers that have permission to use an MSA
function Get-MSAPrincipals {
    param(
        [Parameter(Mandatory=$true)]
        [string]$MSAName
    )

    $principalsList = @()

    try {
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

        # Validate against msDS-HostServiceAccount attribute
        $computers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount
        foreach ($computer in $computers) {
            if ("$computer.msDS-HostServiceAccount" -contains $msaObject.DistinguishedName) {
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
        Write-Host "Error getting MSA principals: $_" -ForegroundColor Red
        return @()
    }
}

# Function to view MSA computer principals
function View-MSAPrincipals {
    param(
        [Parameter(Mandatory=$true)]
        [string]$MSAName
    )
    
    Clear-Host
    Write-Host "=== Principals for $MSAName ===" -ForegroundColor Cyan
    
    try {
        # Get the MSA object with all necessary properties
        $msaObject = Get-ADServiceAccount -Identity $MSAName -Properties *
        
        if ($msaObject -eq $null) {
            Write-Host "No Managed Service Account found with the name '$MSAName'." -ForegroundColor Red
            return
        }
        
        # For standalone MSAs (sMSAs)
        if ($msaObject.ObjectClass -contains "msDS-ManagedServiceAccount") {
            Write-Host "`nStandalone Managed Service Account (sMSA) detected." -ForegroundColor Yellow
            
            # Find computers where this sMSA is assigned
            $assignedComputers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount | Where-Object {
                $_."msDS-HostServiceAccount" -contains $msaObject.DistinguishedName
            }
            
            if ($assignedComputers.Count -gt 0) {
                Write-Host "`nComputers assigned to this sMSA:" -ForegroundColor Yellow
                foreach ($computer in $assignedComputers) {
                    Write-Host "  - $($computer.Name)" -ForegroundColor White
                }
            } else {
                Write-Host "`nNo computers are currently assigned to this sMSA." -ForegroundColor Yellow
            }
        }
        
        # For group MSAs (gMSAs)
        elseif ($msaObject.ObjectClass -contains "msDS-GroupManagedServiceAccount") {
            Write-Host "`nGroup Managed Service Account (gMSA) detected." -ForegroundColor Yellow
            
            # Check PrincipalsAllowedToRetrieveManagedPassword property
            if ($msaObject.PrincipalsAllowedToRetrieveManagedPassword) {
                Write-Host "`nAssociated AD Group(s):" -ForegroundColor Yellow
                foreach ($principalDN in $msaObject.PrincipalsAllowedToRetrieveManagedPassword) {
                    try {
                        $principal = Get-ADObject -Identity $principalDN -Properties Name
                        Write-Host "  - $($principal.Name)" -ForegroundColor White
                    } catch {
                        Write-Host "  - $principalDN (could not resolve)" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "`nNo associated AD group found for this gMSA." -ForegroundColor Yellow
            }
        }
        
        # Handle unexpected MSA types
        else {
            Write-Host "Unknown MSA type. Please verify the MSA configuration." -ForegroundColor Red
        }
        
    } catch {
        Write-Host "Error retrieving MSA principals: $_" -ForegroundColor Red
    }
    
    Read-Host "`nPress Enter to continue"
}

# Function to modify MSA with improved computer principal view
function Modify-MSA {
    Clear-Host
    Write-Host "=== Modify Managed Service Account ===" -ForegroundColor Cyan

    # List available MSAs for selection
    Write-Host "Available Managed Service Accounts:" -ForegroundColor Yellow
    try {
        $msaList = Get-ADServiceAccount -Filter * | Select-Object Name, DistinguishedName, objectClass, PrincipalsAllowedToRetrieveManagedPassword
        if ($msaList -eq $null -or ($msaList -is [array] -and $msaList.Count -eq 0)) {
            Write-Host "No Managed Service Accounts found." -ForegroundColor Yellow
            Read-Host "Press Enter to continue"
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
        } else {
            Write-Host "Invalid selection. Please enter a valid number from the list." -ForegroundColor Red
            Read-Host "Press Enter to continue"
            return
        }

        Write-Host "What would you like to modify for $($selectedMSA.Name)?" -ForegroundColor Yellow
        Write-Host "1. Add computer principals"
        Write-Host "2. Remove computer principals"
        Write-Host "3. Set description"
        Write-Host "4. View assigned computers/principals"
        Write-Host "5. Remove all assigned computers"

        $modOption = Read-Host "Select an option"

        switch ($modOption) {
            "1" {
                # Logic for adding computer principals
                ...
            }
            "2" {
                # Logic for removing computer principals
                ...
            }
            "3" {
                $description = Read-Host "Enter new description"
                Set-ADServiceAccount -Identity $selectedMSA.Name -Description $description
                Write-Host "Description updated." -ForegroundColor Green
            }
            "4" {
                try {
                    View-MSAPrincipals -MSAName $selectedMSA.Name
                } catch {
                    Write-Host "Error viewing principals for $($selectedMSA.Name): $_" -ForegroundColor Red
                }
            }
            "5" {
                Remove-AllMSAReferences -MSAName $selectedMSA.Name
            }
            default {
                Write-Host "Invalid option selected." -ForegroundColor Red
                Read-Host "Press Enter to continue"
            }
        }
    } catch {
        Write-Host "Error modifying MSA: $_" -ForegroundColor Red
    }

    Read-Host "Press Enter to continue"
}

# Function to delete MSA
function Delete-MSA {
    Clear-Host
    Write-Host "=== Delete Managed Service Account ===" -ForegroundColor Cyan
    
    # List available MSAs for selection
    Write-Host "Available Managed Service Accounts:" -ForegroundColor Yellow
    try {
        $msaList = Get-ADServiceAccount -Filter * | Select-Object Name
        if ($msaList -eq $null -or ($msaList -is [array] -and $msaList.Count -eq 0)) {
            Write-Host "No Managed Service Accounts found." -ForegroundColor Yellow
            Read-Host "Press Enter to continue"
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
                $selectedMSA = $msaList[$idx].Name
                
                # Confirm deletion
                $confirm = Read-Host "Are you sure you want to delete $selectedMSA? This cannot be undone. (yes/no)"
                if ($confirm -eq "yes") {
                    Remove-ADServiceAccount -Identity $selectedMSA -Confirm:$false
                    Write-Host "Managed Service Account '$selectedMSA' has been deleted." -ForegroundColor Green
                } else {
                    Write-Host "Deletion canceled." -ForegroundColor Yellow
                }
            } else {
                Write-Host "Invalid selection number." -ForegroundColor Red
            }
        } else {
            Write-Host "Invalid input." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Error deleting MSA: $_" -ForegroundColor Red
    }
    
    Read-Host "Press Enter to continue"
}

function Install-MSA {
    Clear-Host
    Write-Host "=== Install Managed Service Account on Computer ===" -ForegroundColor Cyan

    Write-Host "Available Managed Service Accounts:" -ForegroundColor Yellow
    try {
        $msaList = Get-ADServiceAccount -Filter * | Select-Object Name, DistinguishedName, objectClass, PrincipalsAllowedToRetrieveManagedPassword
        if (-not $msaList) {
            Write-Host "No Managed Service Accounts found." -ForegroundColor Yellow
            return
        }

        for ($i = 0; $i -lt $msaList.Count; $i++) {
            Write-Host "[$i] $($msaList[$i].Name)"
        }

        $selection = Read-Host "Enter the number of the MSA to install (or 'c' to cancel)"
        if ($selection -eq 'c') { return }

        $selectedMSA = $msaList[$selection]
        $computerName = Read-Host "Enter the computer name where you want to install the MSA"

        if ($selectedMSA.objectClass -contains "msDS-ManagedServiceAccount") {
            # sMSA: Ensure only one machine is assigned
            $assignedComputers = Get-ADComputer -Filter * -Properties msDS-HostServiceAccount |
                                 Where-Object { $_."msDS-HostServiceAccount" -contains $selectedMSA.DistinguishedName }

            if ($assignedComputers.Count -gt 0) {
                Write-Host "This standalone MSA is already assigned to: $($assignedComputers.Name -join ', ')" -ForegroundColor Yellow
                Write-Host "Reassigning the sMSA to the new computer and removing previous assignments..." -ForegroundColor Yellow

                # Remove all existing assignments
                foreach ($computerToRemove in $assignedComputers) {
                    try {
                        Remove-ADComputerServiceAccount -Identity $computerToRemove.Name -ServiceAccount $selectedMSA.Name
                        Write-Host "Removed $($computerToRemove.Name) from the MSA." -ForegroundColor Green
                    } catch {
                        Write-Host "Failed to remove $($computerToRemove.Name) from the MSA. Error: $_" -ForegroundColor Red
                    }
                }
            }

            # Assign the new computer
            try {
                Add-ADComputerServiceAccount -Identity $computerName -ServiceAccount $selectedMSA.Name
                Write-Host "MSA '$($selectedMSA.Name)' assigned to computer '$computerName' successfully." -ForegroundColor Green
            } catch {
                Write-Host "Failed to assign MSA to computer. Error: $_" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "Error during MSA installation: $_" -ForegroundColor Red
    }
}

# Function to list MSAs - IMPROVED DETAILED VERSION
function List-MSA {
    Clear-Host
    Write-Host "=== List Managed Service Accounts ===" -ForegroundColor Cyan

    try {
        # Get MSAs with important properties
        $msaAccounts = Get-ADServiceAccount -Filter * -Properties Name, DNSHostName, Enabled, Description,
                      Created, Modified, ServicePrincipalNames, PrincipalsAllowedToRetrieveManagedPassword, objectClass

        if ($msaAccounts -eq $null -or ($msaAccounts -is [array] -and $msaAccounts.Count -eq 0)) {
            Write-Host "No Managed Service Accounts found." -ForegroundColor Yellow
            Read-Host "Press Enter to continue"
            return
        }

        # Force into array if single item
        if (-not ($msaAccounts -is [array])) {
            $msaAccounts = @($msaAccounts)
        }

        Write-Host "Found $($msaAccounts.Count) Managed Service Account(s):" -ForegroundColor Yellow
        Write-Host

        foreach ($msa in $msaAccounts) {
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

            # If gMSA, show associated AD group(s)
            if ($msaType -eq "gMSA (Group Managed Service Account)") {
                if ($msa.PrincipalsAllowedToRetrieveManagedPassword) {
                    Write-Host "  Associated AD Group(s):" -ForegroundColor Green
                    foreach ($principalDN in $msa.PrincipalsAllowedToRetrieveManagedPassword) {
                        try {
                            $principal = Get-ADObject -Identity $principalDN -Properties Name
                            Write-Host "    - $($principal.Name)" -ForegroundColor White
                        } catch {
                            Write-Host "    - $principalDN (could not resolve)" -ForegroundColor Yellow
                        }
                    }
                } else {
                    Write-Host "  Associated AD Group(s): None" -ForegroundColor Yellow
                }
            }

            # Assigned Computers
            $assignedComputers = @()
            foreach ($computer in Get-ADComputer -Filter * -Properties msDS-HostServiceAccount) {
                # Ensure the msDS-HostServiceAccount property is treated properly as an array
                if ($computer."msDS-HostServiceAccount" -contains $msa.DistinguishedName) {
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
    }
    catch {
        Write-Host "Error retrieving MSAs: $_" -ForegroundColor Red
    }

    Read-Host "Press Enter to continue"
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
        Write-Host "0. Exit" -ForegroundColor Yellow
        Write-Host
        
        $choice = Read-Host "Enter your choice"
        
        switch ($choice) {
            "1" { Create-MSA }
            "2" { Modify-MSA }
            "3" { Delete-MSA }
            "4" { Install-MSA }
            "5" { List-MSA }
            "0" { $continue = $false }
            default { 
                Write-Host "Invalid selection. Press Enter to continue..." -ForegroundColor Red
                Read-Host
            }
        }
    }
}

# Main script execution
Clear-Host
Write-Host "Welcome to the MSA Management System" -ForegroundColor Green
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

if (Check-ADModule) {
    Show-MainMenu
} else {
    Write-Host "Unable to proceed without the Active Directory module." -ForegroundColor Red
    Read-Host "Press Enter to exit"
}
