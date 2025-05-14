# MSA Manager - PowerShell Script for Managing Managed Service Accounts
# Created: 2025-05-14

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
        Import-Module ActiveDirectory
    }
    return $true
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
            # Create standalone MSA (sMSA) with absolute minimum parameters
            Write-Host "Creating standalone MSA (sMSA)..." -ForegroundColor Yellow
            
            # Try the most basic command possible
            New-ADServiceAccount -Name $msaName -RestrictToSingleComputer
            
            Write-Host "Standalone MSA '$msaName' created successfully." -ForegroundColor Green
            
            # Ask for the computer to bind this MSA to
            $computerName = Read-Host "Enter the computer name to bind this sMSA to"
            
            # Add the computer to the allowed principals for this MSA
            Add-ADComputerServiceAccount -Identity $computerName -ServiceAccount $msaName
            Write-Host "Computer '$computerName' allowed to use MSA '$msaName'." -ForegroundColor Green
        } 
        else {
            # Create group MSA (gMSA) with absolute minimum parameters
            Write-Host "Creating group MSA (gMSA)..." -ForegroundColor Yellow
            
            # Check for KDS Root Key
            $kdsRootKeys = Get-KdsRootKey
            if ($null -eq $kdsRootKeys) {
                Write-Host "No KDS Root Key found. Creating one..." -ForegroundColor Yellow
                Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
                Write-Host "KDS Root Key created. Waiting for replication..." -ForegroundColor Yellow
                Start-Sleep -Seconds 5  # Brief pause
            }
            
            # Try the most basic command possible
            New-ADServiceAccount -Name $msaName
            
            Write-Host "Group MSA '$msaName' created successfully." -ForegroundColor Green
            
            # Ask if want to add computers to this gMSA now
            $addPrincipals = Read-Host "Do you want to add computers to this gMSA now? (y/n)"
            
            if ($addPrincipals -eq 'y') {
                $continue = $true
                while ($continue) {
                    $computerName = Read-Host "Enter computer name to add (or press Enter to finish)"
                    
                    if ([string]::IsNullOrEmpty($computerName)) {
                        $continue = $false
                    } else {
                        try {
                            Add-ADComputerServiceAccount -Identity $computerName -ServiceAccount $msaName
                            Write-Host "Computer '$computerName' added successfully to gMSA '$msaName'." -ForegroundColor Green
                        }
                        catch {
                            Write-Host "Error adding computer: $_" -ForegroundColor Red
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Error creating MSA: $_" -ForegroundColor Red
        
        $errorMsg = $_.Exception.Message
        
        # Provide specific guidance based on the error message
        if ($errorMsg -like "*Parameter set cannot be resolved*") {
            Write-Host "`nYour Active Directory version might require different parameter combinations." -ForegroundColor Yellow
            Write-Host "Please try one of these commands manually in a PowerShell window:" -ForegroundColor Yellow
            
            if ($msaType -eq '1') {
                Write-Host "`nFor standalone MSA (sMSA):" -ForegroundColor Cyan
                Write-Host "New-ADServiceAccount -Name $msaName -RestrictToSingleComputer" -ForegroundColor White
                Write-Host "-- OR --" -ForegroundColor Cyan
                Write-Host "New-ADServiceAccount -Name $msaName -SAMAccountName $msaName`$ -RestrictToSingleComputer" -ForegroundColor White
            } else {
                Write-Host "`nFor group MSA (gMSA):" -ForegroundColor Cyan
                Write-Host "New-ADServiceAccount -Name $msaName" -ForegroundColor White
                Write-Host "-- OR --" -ForegroundColor Cyan
                Write-Host "New-ADServiceAccount -Name $msaName -SAMAccountName $msaName`$" -ForegroundColor White
                Write-Host "-- OR --" -ForegroundColor Cyan
                Write-Host "New-ADServiceAccount -Name $msaName -DNSHostName $msaName.$((Get-ADDomain).DNSRoot)" -ForegroundColor White
            }
        }
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
            if ($computer.msDS-HostServiceAccount -contains $msaObject.DistinguishedName) {
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
        Write-Host "Error getting MSA principals: $_" -ForegroundColor Red
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
        $msaList = Get-ADServiceAccount -Filter * | Select-Object Name, DistinguishedName
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
        
        $selection = Read-Host "Enter the number of the MSA to modify (or 'c' to cancel)"
        if ($selection -eq 'c') { return }
        
        if ([int]::TryParse($selection, [ref]$null)) {
            $idx = [int]$selection
            if ($idx -ge 0 -and $idx -lt $msaList.Count) {
                $selectedMSA = $msaList[$idx]
                
                Write-Host "What would you like to modify for $($selectedMSA.Name)?" -ForegroundColor Yellow
                Write-Host "1. Add computer principals"
                Write-Host "2. Remove computer principals"
                Write-Host "3. Set description"
                Write-Host "4. View assigned computers/principals"
                
                $modOption = Read-Host "Select an option"
                
                switch ($modOption) {
                    "1" {
                        $computer = Read-Host "Enter computer name to add permission for"
                        Add-ADComputerServiceAccount -Identity $computer -ServiceAccount $selectedMSA.Name
                        Write-Host "$computer now has permission to use $($selectedMSA.Name)" -ForegroundColor Green
                    }
                    "2" {
                        # Find computers with permissions to this MSA using our improved function
                        $principals = Get-MSAPrincipals -MSAName $selectedMSA.Name
                        $computers = $principals | Where-Object { $_.Type -eq "computer" } | Select-Object -ExpandProperty Name
                        
                        if ($computers.Count -eq 0) {
                            Write-Host "No computers have permission to use this MSA." -ForegroundColor Yellow
                        } else {
                            Write-Host "Computers with permission to use this MSA:" -ForegroundColor Yellow
                            for ($i=0; $i -lt $computers.Count; $i++) {
                                Write-Host "[$i] $($computers[$i])"
                            }
                            
                            $computerIndex = Read-Host "Enter the number of the computer to remove (or 'c' to cancel)"
                            if ($computerIndex -eq 'c') { break }
                            
                            if ([int]::TryParse($computerIndex, [ref]$null)) {
                                $compIdx = [int]$computerIndex
                                if ($compIdx -ge 0 -and $compIdx -lt $computers.Count) {
                                    $selectedComputer = $computers[$compIdx]
                                    Remove-ADComputerServiceAccount -Identity $selectedComputer -ServiceAccount $selectedMSA.Name
                                    Write-Host "Permission for $selectedComputer removed from $($selectedMSA.Name)" -ForegroundColor Green
                                } else {
                                    Write-Host "Invalid selection number." -ForegroundColor Red
                                }
                            } else {
                                Write-Host "Invalid input." -ForegroundColor Red
                            }
                        }
                    }
                    "3" {
                        $description = Read-Host "Enter new description"
                        Set-ADServiceAccount -Identity $selectedMSA.Name -Description $description
                        Write-Host "Description updated." -ForegroundColor Green
                    }
                    "4" {
                        # Show detailed view of principals/computers
                        View-MSAPrincipals -MSAName $selectedMSA.Name
                    }
                    default {
                        Write-Host "Invalid option selected." -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "Invalid selection number." -ForegroundColor Red
            }
        } else {
            Write-Host "Invalid input." -ForegroundColor Red
        }
    }
    catch {
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

# Function to install MSA on a computer
function Install-MSA {
    Clear-Host
    Write-Host "=== Install Managed Service Account on Computer ===" -ForegroundColor Cyan
    
    # List available MSAs for selection
    Write-Host "Available Managed Service Accounts:" -ForegroundColor Yellow
    try {
        $msaList = Get-ADServiceAccount -Filter * | Select-Object Name, DistinguishedName
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
        
        $selection = Read-Host "Enter the number of the MSA to install (or 'c' to cancel)"
        if ($selection -eq 'c') { return }
        
        if ([int]::TryParse($selection, [ref]$null)) {
            $idx = [int]$selection
            if ($idx -ge 0 -and $idx -lt $msaList.Count) {
                $selectedMSA = $msaList[$idx]
                
                $computerName = Read-Host "Enter the computer name where you want to install the MSA"
                
                # Check permission using our improved method
                $principals = Get-MSAPrincipals -MSAName $selectedMSA.Name
                $computerPrincipals = $principals | Where-Object { $_.Type -eq "computer" }
                $hasPermission = $false
                
                foreach ($comp in $computerPrincipals) {
                    if ($comp.Name -eq $computerName) {
                        $hasPermission = $true
                        break
                    }
                }
                
                if (-not $hasPermission) {
                    $addPermission = Read-Host "Computer '$computerName' doesn't have permission to use this MSA. Add permission? (y/n)"
                    if ($addPermission -eq "y") {
                        Add-ADComputerServiceAccount -Identity $computerName -ServiceAccount $selectedMSA.Name
                        Write-Host "Added permission for '$computerName' to use MSA '$($selectedMSA.Name)'." -ForegroundColor Green
                    }
                }
                
                # Check if remote or local
                $isLocal = ($computerName -eq $env:COMPUTERNAME) -or ($computerName -eq "localhost")
                
                if ($isLocal) {
                    # Install locally
                    Install-ADServiceAccount -Identity $selectedMSA.Name
                    Write-Host "MSA '$($selectedMSA.Name)' installed successfully on local computer." -ForegroundColor Green
                } else {
                    # Install remotely using Invoke-Command
                    Write-Host "Installing MSA '$($selectedMSA.Name)' on remote computer '$computerName'..." -ForegroundColor Yellow
                    
                    $scriptBlock = {
                        param($msaName)
                        try {
                            Import-Module ActiveDirectory
                            Install-ADServiceAccount -Identity $msaName
                            return "MSA '$msaName' installed successfully."
                        } catch {
                            return "Error installing MSA: $_"
                        }
                    }
                    
                    try {
                        $result = Invoke-Command -ComputerName $computerName -ScriptBlock $scriptBlock -ArgumentList $selectedMSA.Name -ErrorAction Stop
                        Write-Host $result -ForegroundColor Green
                    } catch {
                        Write-Host "Failed to connect to remote computer: $computerName" -ForegroundColor Red
                        Write-Host "Error: $_" -ForegroundColor Red
                        Write-Host "Make sure the computer is online and that you have permission to connect to it." -ForegroundColor Yellow
                    }
                }
            } else {
                Write-Host "Invalid selection number." -ForegroundColor Red
            }
        } else {
            Write-Host "Invalid input." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Error installing MSA: $_" -ForegroundColor Red
    }
    
    Read-Host "Press Enter to continue"
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

            # Assigned Computers
            $assignedComputers = @()
            foreach ($computer in Get-ADComputer -Filter * -Properties msDS-HostServiceAccount) {
                if ($computer.msDS-HostServiceAccount -contains $msa.DistinguishedName) {
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
