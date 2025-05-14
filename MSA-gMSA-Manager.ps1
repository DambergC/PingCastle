<#
.SYNOPSIS
	Complete GUI application for managing both Managed Service Accounts (MSAs) and Group Managed Service Accounts (gMSAs).
.DESCRIPTION
	This script provides a comprehensive graphical interface for creating, modifying, and managing both 
	MSAs and gMSAs with separate tabs for each account type.
.NOTES
	Created with PowerShell Studio from SAPIEN Technologies
	Requires the Active Directory module
	Requires Windows Server 2012 or later for gMSA support
#>

# Import required assemblies for GUI
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')

# Import Active Directory module
Import-Module ActiveDirectory

# Create the main form
$formAccountManager = New-Object System.Windows.Forms.Form
$formAccountManager.Text = 'Service Account Manager (MSA & gMSA)'
$formAccountManager.Size = New-Object System.Drawing.Size(800, 600)
$formAccountManager.StartPosition = 'CenterScreen'
$formAccountManager.FormBorderStyle = 'FixedDialog'
$formAccountManager.MaximizeBox = $false

# Create TabControl for MSA and gMSA
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$tabControl.Size = New-Object System.Drawing.Size(770, 540)

# Create tab pages
$tabMSA = New-Object System.Windows.Forms.TabPage
$tabMSA.Text = "Managed Service Accounts (MSA)"
$tabgMSA = New-Object System.Windows.Forms.TabPage
$tabgMSA.Text = "Group Managed Service Accounts (gMSA)"

# Add tab pages to tab control
$tabControl.Controls.Add($tabMSA)
$tabControl.Controls.Add($tabgMSA)
$formAccountManager.Controls.Add($tabControl)

#=============================================================================
# MSA TAB CONTENT
#=============================================================================

# Create account name label and textbox
$labelMSAAccountName = New-Object System.Windows.Forms.Label
$labelMSAAccountName.Location = New-Object System.Drawing.Point(20, 20)
$labelMSAAccountName.Size = New-Object System.Drawing.Size(150, 23)
$labelMSAAccountName.Text = 'MSA Account Name:'
$tabMSA.Controls.Add($labelMSAAccountName)

$textBoxMSAAccountName = New-Object System.Windows.Forms.TextBox
$textBoxMSAAccountName.Location = New-Object System.Drawing.Point(180, 20)
$textBoxMSAAccountName.Size = New-Object System.Drawing.Size(250, 23)
$tabMSA.Controls.Add($textBoxMSAAccountName)

# Create domain label and textbox
$labelMSADomain = New-Object System.Windows.Forms.Label
$labelMSADomain.Location = New-Object System.Drawing.Point(20, 60)
$labelMSADomain.Size = New-Object System.Drawing.Size(150, 23)
$labelMSADomain.Text = 'Domain:'
$tabMSA.Controls.Add($labelMSADomain)

$textBoxMSADomain = New-Object System.Windows.Forms.TextBox
$textBoxMSADomain.Location = New-Object System.Drawing.Point(180, 60)
$textBoxMSADomain.Size = New-Object System.Drawing.Size(250, 23)
$textBoxMSADomain.Text = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
$tabMSA.Controls.Add($textBoxMSADomain)

# Create groupbox for MSA actions
$groupBoxMSAActions = New-Object System.Windows.Forms.GroupBox
$groupBoxMSAActions.Location = New-Object System.Drawing.Point(20, 100)
$groupBoxMSAActions.Size = New-Object System.Drawing.Size(730, 100)
$groupBoxMSAActions.Text = 'MSA Actions'
$tabMSA.Controls.Add($groupBoxMSAActions)

# Create buttons for MSA actions
$buttonCreateMSA = New-Object System.Windows.Forms.Button
$buttonCreateMSA.Location = New-Object System.Drawing.Point(20, 30)
$buttonCreateMSA.Size = New-Object System.Drawing.Size(120, 50)
$buttonCreateMSA.Text = 'Create New MSA'
# Create New MSA Button Event Handler

# Create New MSA Button Event Handler
# Create New MSA Button Event Handler
$buttonCreateMSA.Add_Click({
    if ($textBoxMSAAccountName.Text -ne '') {
        try {
            # Explicitly create an MSA with -Type Standalone
            New-ADServiceAccount -Name $textBoxMSAAccountName.Text -Type Standalone
            
            [System.Windows.Forms.MessageBox]::Show(
                "Managed Service Account $($textBoxMSAAccountName.Text) created successfully.",
                "Success",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
            RefreshMSAList
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to create Managed Service Account: $_",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show(
            "Account name is required.",
            "Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})


$groupBoxMSAActions.Controls.Add($buttonCreateMSA)

$buttonAssociateMSA = New-Object System.Windows.Forms.Button
$buttonAssociateMSA.Location = New-Object System.Drawing.Point(150, 30)
$buttonAssociateMSA.Size = New-Object System.Drawing.Size(120, 50)
$buttonAssociateMSA.Text = 'Associate MSA'
$buttonAssociateMSA.Add_Click({
    if ($textBoxMSAAccountName.Text -ne '') {
        try {
            Install-ADServiceAccount -Identity $textBoxMSAAccountName.Text
            [System.Windows.Forms.MessageBox]::Show("Managed Service Account $($textBoxMSAAccountName.Text) associated successfully with this computer.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to associate Managed Service Account: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Account name is required.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$groupBoxMSAActions.Controls.Add($buttonAssociateMSA)

$buttonResetMSAPassword = New-Object System.Windows.Forms.Button
$buttonResetMSAPassword.Location = New-Object System.Drawing.Point(280, 30)
$buttonResetMSAPassword.Size = New-Object System.Drawing.Size(120, 50)
$buttonResetMSAPassword.Text = 'Reset Password'
$buttonResetMSAPassword.Add_Click({
    if ($textBoxMSAAccountName.Text -ne '') {
        try {
            Reset-ADServiceAccountPassword -Identity $textBoxMSAAccountName.Text
            [System.Windows.Forms.MessageBox]::Show("Password for Managed Service Account $($textBoxMSAAccountName.Text) reset successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to reset password for Managed Service Account: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Account name is required.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$groupBoxMSAActions.Controls.Add($buttonResetMSAPassword)

$buttonVerifyMSA = New-Object System.Windows.Forms.Button
$buttonVerifyMSA.Location = New-Object System.Drawing.Point(410, 30)
$buttonVerifyMSA.Size = New-Object System.Drawing.Size(120, 50)
$buttonVerifyMSA.Text = 'Verify MSA'
$buttonVerifyMSA.Add_Click({
    if ($textBoxMSAAccountName.Text -ne '') {
        try {
            $result = Test-ADServiceAccount -Identity $textBoxMSAAccountName.Text
            if ($result -eq $true) {
                [System.Windows.Forms.MessageBox]::Show("Managed Service Account $($textBoxMSAAccountName.Text) is valid and properly associated.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } else {
                [System.Windows.Forms.MessageBox]::Show("Managed Service Account $($textBoxMSAAccountName.Text) is not valid or not properly associated.", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to verify Managed Service Account: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Account name is required.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$groupBoxMSAActions.Controls.Add($buttonVerifyMSA)

$buttonModifyMSA = New-Object System.Windows.Forms.Button
$buttonModifyMSA.Location = New-Object System.Drawing.Point(540, 30)
$buttonModifyMSA.Size = New-Object System.Drawing.Size(120, 50)
$buttonModifyMSA.Text = 'Modify MSA'
$buttonModifyMSA.Add_Click({
    if ($textBoxMSAAccountName.Text -ne '') {
        try {
            # Create modify MSA form
            $formModifyMSA = New-Object System.Windows.Forms.Form
            $formModifyMSA.Text = "Modify MSA: $($textBoxMSAAccountName.Text)"
            $formModifyMSA.Size = New-Object System.Drawing.Size(500, 400)
            $formModifyMSA.StartPosition = 'CenterParent'
            $formModifyMSA.FormBorderStyle = 'FixedDialog'
            $formModifyMSA.MaximizeBox = $false
            
            # Get current MSA properties
            $msa = Get-ADServiceAccount -Identity $textBoxMSAAccountName.Text -Properties *
            
            # DNS hostname
            $labelDNS = New-Object System.Windows.Forms.Label
            $labelDNS.Location = New-Object System.Drawing.Point(20, 20)
            $labelDNS.Size = New-Object System.Drawing.Size(150, 23)
            $labelDNS.Text = 'DNS Hostname:'
            $formModifyMSA.Controls.Add($labelDNS)
            
            $textBoxDNS = New-Object System.Windows.Forms.TextBox
            $textBoxDNS.Location = New-Object System.Drawing.Point(180, 20)
            $textBoxDNS.Size = New-Object System.Drawing.Size(250, 23)
            $textBoxDNS.Text = $msa.DNSHostName
            $formModifyMSA.Controls.Add($textBoxDNS)
            
            # Description
            $labelDesc = New-Object System.Windows.Forms.Label
            $labelDesc.Location = New-Object System.Drawing.Point(20, 60)
            $labelDesc.Size = New-Object System.Drawing.Size(150, 23)
            $labelDesc.Text = 'Description:'
            $formModifyMSA.Controls.Add($labelDesc)
            
            $textBoxDesc = New-Object System.Windows.Forms.TextBox
            $textBoxDesc.Location = New-Object System.Drawing.Point(180, 60)
            $textBoxDesc.Size = New-Object System.Drawing.Size(250, 23)
            $textBoxDesc.Text = $msa.Description
            $formModifyMSA.Controls.Add($textBoxDesc)
            
            # Enabled status
            $checkBoxEnabled = New-Object System.Windows.Forms.CheckBox
            $checkBoxEnabled.Location = New-Object System.Drawing.Point(20, 100)
            $checkBoxEnabled.Size = New-Object System.Drawing.Size(250, 23)
            $checkBoxEnabled.Text = 'Account Enabled'
            if ($msa.Enabled -ne $null) {
                $checkBoxEnabled.Checked = $msa.Enabled
            } else {
                $checkBoxEnabled.Checked = -not ($msa.UserAccountControl -band 0x0002)
            }
            $formModifyMSA.Controls.Add($checkBoxEnabled)
            
            # Save button
            $buttonSave = New-Object System.Windows.Forms.Button
            $buttonSave.Location = New-Object System.Drawing.Point(200, 320)
            $buttonSave.Size = New-Object System.Drawing.Size(100, 30)
            $buttonSave.Text = 'Save Changes'
            $buttonSave.Add_Click({
                try {
                    # Update description
                    if ($msa.Description -ne $textBoxDesc.Text) {
                        Set-ADServiceAccount -Identity $textBoxMSAAccountName.Text -Description $textBoxDesc.Text
                    }
                    
                    # Update DNS hostname
                    if ($msa.DNSHostName -ne $textBoxDNS.Text) {
                        Set-ADServiceAccount -Identity $textBoxMSAAccountName.Text -DNSHostName $textBoxDNS.Text
                    }
                    
                    # Update enabled status
                    $isCurrentlyEnabled = $msa.Enabled -eq $true -or ($msa.UserAccountControl -band 0x0002) -eq 0
                    if ($checkBoxEnabled.Checked -and -not $isCurrentlyEnabled) {
                        Enable-ADAccount -Identity $textBoxMSAAccountName.Text
                    } elseif (-not $checkBoxEnabled.Checked -and $isCurrentlyEnabled) {
                        Disable-ADAccount -Identity $textBoxMSAAccountName.Text
                    }
                    
                    [System.Windows.Forms.MessageBox]::Show("Managed Service Account $($textBoxMSAAccountName.Text) modified successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                    $formModifyMSA.Close()
                    RefreshMSAList
                } catch {
                    [System.Windows.Forms.MessageBox]::Show("Failed to modify Managed Service Account: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                }
            })
            $formModifyMSA.Controls.Add($buttonSave)
            
            # Cancel button
            $buttonCancel = New-Object System.Windows.Forms.Button
            $buttonCancel.Location = New-Object System.Drawing.Point(310, 320)
            $buttonCancel.Size = New-Object System.Drawing.Size(100, 30)
            $buttonCancel.Text = 'Cancel'
            $buttonCancel.Add_Click({ $formModifyMSA.Close() })
            $formModifyMSA.Controls.Add($buttonCancel)
            
            $formModifyMSA.ShowDialog()
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to retrieve MSA details: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Account name is required.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$groupBoxMSAActions.Controls.Add($buttonModifyMSA)

# Create groupbox for MSA List
$groupBoxMSAList = New-Object System.Windows.Forms.GroupBox
$groupBoxMSAList.Location = New-Object System.Drawing.Point(20, 210)
$groupBoxMSAList.Size = New-Object System.Drawing.Size(730, 250)
$groupBoxMSAList.Text = 'Existing MSA Accounts'
$tabMSA.Controls.Add($groupBoxMSAList)

# Create ListView for MSAs
$listViewMSAs = New-Object System.Windows.Forms.ListView
$listViewMSAs.Location = New-Object System.Drawing.Point(10, 20)
$listViewMSAs.Size = New-Object System.Drawing.Size(710, 180)
$listViewMSAs.View = [System.Windows.Forms.View]::Details
$listViewMSAs.FullRowSelect = $true
$listViewMSAs.GridLines = $true
$listViewMSAs.Columns.Add("Name", 150) | Out-Null
$listViewMSAs.Columns.Add("DNS Host Name", 200) | Out-Null
$listViewMSAs.Columns.Add("Created Date", 150) | Out-Null
$listViewMSAs.Columns.Add("Status", 100) | Out-Null
$listViewMSAs.Columns.Add("Description", 200) | Out-Null
$groupBoxMSAList.Controls.Add($listViewMSAs)

# Add event handler for list view selection
$listViewMSAs.Add_SelectedIndexChanged({
    if ($listViewMSAs.SelectedItems.Count -gt 0) {
        $textBoxMSAAccountName.Text = $listViewMSAs.SelectedItems[0].Text
    }
})

# Create refresh button for MSA tab
$buttonRefreshMSA = New-Object System.Windows.Forms.Button
$buttonRefreshMSA.Location = New-Object System.Drawing.Point(650, 470)
$buttonRefreshMSA.Size = New-Object System.Drawing.Size(100, 30)
$buttonRefreshMSA.Text = 'Refresh List'
$buttonRefreshMSA.Add_Click({
    RefreshMSAList
})
$tabMSA.Controls.Add($buttonRefreshMSA)

# Create delete button for MSA tab
$buttonDeleteMSA = New-Object System.Windows.Forms.Button
$buttonDeleteMSA.Location = New-Object System.Drawing.Point(540, 470)
$buttonDeleteMSA.Size = New-Object System.Drawing.Size(100, 30)
$buttonDeleteMSA.Text = 'Delete MSA'
$buttonDeleteMSA.ForeColor = [System.Drawing.Color]::Red
$buttonDeleteMSA.Add_Click({
    if ($textBoxMSAAccountName.Text -ne '') {
        $confirmResult = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to delete the MSA '$($textBoxMSAAccountName.Text)'? This action cannot be undone.", "Confirm Delete", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($confirmResult -eq [System.Windows.Forms.DialogResult]::Yes) {
            try {
                Remove-ADServiceAccount -Identity $textBoxMSAAccountName.Text -Confirm:$false
                [System.Windows.Forms.MessageBox]::Show("Managed Service Account $($textBoxMSAAccountName.Text) deleted successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                $textBoxMSAAccountName.Text = ""
                RefreshMSAList
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to delete Managed Service Account: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Please select an account to delete.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$tabMSA.Controls.Add($buttonDeleteMSA)

# Function to refresh MSA list
function RefreshMSAList {
    $listViewMSAs.Items.Clear()
    
    try {
        # Get all managed service accounts - simplified filter approach to catch all MSAs
        # Instead of filtering by type, we'll get all service accounts and filter in-memory
        $allServiceAccounts = Get-ADServiceAccount -Filter * -Properties DNSHostName, Created, Description, UserAccountControl, Enabled, msDS-GroupMSAMembership
        
        # Filter to standalone MSAs (non-group)
        $msas = $allServiceAccounts | Where-Object { -not ($_.PSObject.Properties.Match('msDS-GroupMSAMembership').Count) }
        
        # Check if any MSAs were found
        if ($msas) {
            # Handle both single object and array results
            if ($msas -is [array]) {
                foreach ($msa in $msas) {
                    $item = New-Object System.Windows.Forms.ListViewItem($msa.Name)
                    
                    # Add DNS Host Name
                    if ($msa.DNSHostName) {
                        $item.SubItems.Add($msa.DNSHostName)
                    } else {
                        $item.SubItems.Add("N/A")
                    }
                    
                    # Add Created Date
                    if ($msa.Created) {
                        $item.SubItems.Add($msa.Created.ToString("yyyy-MM-dd HH:mm:ss"))
                    } else {
                        $item.SubItems.Add("N/A")
                    }
                    
                    # Add Status - Check if account is enabled
                    $isEnabled = $true
                    if ($msa.Enabled -ne $null) {
                        $isEnabled = $msa.Enabled -eq $true
                    } elseif ($msa.UserAccountControl -ne $null) {
                        # Check if the "ACCOUNTDISABLE" flag (0x0002) is set
                        $isEnabled = -not ($msa.UserAccountControl -band 0x0002)
                    }
                    
                    if ($isEnabled) {
                        $item.SubItems.Add("Enabled")
                    } else {
                        $item.SubItems.Add("Disabled")
                    }
                    
                    # Add Description
                    if ($msa.Description) {
                        $item.SubItems.Add($msa.Description)
                    } else {
                        $item.SubItems.Add("")
                    }
                    
                    $listViewMSAs.Items.Add($item)
                }
            } else {
                # Handle single MSA result
                $item = New-Object System.Windows.Forms.ListViewItem($msas.Name)
                
                # Add DNS Host Name
                if ($msas.DNSHostName) {
                    $item.SubItems.Add($msas.DNSHostName)
                } else {
                    $item.SubItems.Add("N/A")
                }
                
                # Add Created Date
                if ($msas.Created) {
                    $item.SubItems.Add($msas.Created.ToString("yyyy-MM-dd HH:mm:ss"))
                } else {
                    $item.SubItems.Add("N/A")
                }
                
                # Add Status - Check if account is enabled
                $isEnabled = $true
                if ($msas.Enabled -ne $null) {
                    $isEnabled = $msas.Enabled -eq $true
                } elseif ($msas.UserAccountControl -ne $null) {
                    # Check if the "ACCOUNTDISABLE" flag (0x0002) is set
                    $isEnabled = -not ($msas.UserAccountControl -band 0x0002)
                }
                
                if ($isEnabled) {
                    $item.SubItems.Add("Enabled")
                } else {
                    $item.SubItems.Add("Disabled")
                }
                
                # Add Description
                if ($msas.Description) {
                    $item.SubItems.Add($msas.Description)
                } else {
                    $item.SubItems.Add("")
                }
                
                $listViewMSAs.Items.Add($item)
            }
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to retrieve MSA list: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

#=============================================================================
# gMSA TAB CONTENT
#=============================================================================

# Create account name label and textbox for gMSA
$labelgMSAAccountName = New-Object System.Windows.Forms.Label
$labelgMSAAccountName.Location = New-Object System.Drawing.Point(20, 20)
$labelgMSAAccountName.Size = New-Object System.Drawing.Size(150, 23)
$labelgMSAAccountName.Text = 'gMSA Account Name:'
$tabgMSA.Controls.Add($labelgMSAAccountName)

$textBoxgMSAAccountName = New-Object System.Windows.Forms.TextBox
$textBoxgMSAAccountName.Location = New-Object System.Drawing.Point(180, 20)
$textBoxgMSAAccountName.Size = New-Object System.Drawing.Size(250, 23)
$tabgMSA.Controls.Add($textBoxgMSAAccountName)

# Create domain label and textbox for gMSA
$labelgMSADomain = New-Object System.Windows.Forms.Label
$labelgMSADomain.Location = New-Object System.Drawing.Point(20, 60)
$labelgMSADomain.Size = New-Object System.Drawing.Size(150, 23)
$labelgMSADomain.Text = 'Domain:'
$tabgMSA.Controls.Add($labelgMSADomain)

$textBoxgMSADomain = New-Object System.Windows.Forms.TextBox
$textBoxgMSADomain.Location = New-Object System.Drawing.Point(180, 60)
$textBoxgMSADomain.Size = New-Object System.Drawing.Size(250, 23)
$textBoxgMSADomain.Text = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
$tabgMSA.Controls.Add($textBoxgMSADomain)

# Create groupbox for principals allowed to retrieve password
$groupBoxPrincipals = New-Object System.Windows.Forms.GroupBox
$groupBoxPrincipals.Location = New-Object System.Drawing.Point(440, 20)
$groupBoxPrincipals.Size = New-Object System.Drawing.Size(310, 80)
$groupBoxPrincipals.Text = 'Principals Allowed to Retrieve Password'
$tabgMSA.Controls.Add($groupBoxPrincipals)

$textBoxPrincipals = New-Object System.Windows.Forms.TextBox
$textBoxPrincipals.Location = New-Object System.Drawing.Point(10, 20)
$textBoxPrincipals.Size = New-Object System.Drawing.Size(290, 40)
$textBoxPrincipals.Multiline = $true
$textBoxPrincipals.Text = "Domain Computers"
$groupBoxPrincipals.Controls.Add($textBoxPrincipals)

# Create groupbox for gMSA actions
$groupBoxgMSAActions = New-Object System.Windows.Forms.GroupBox
$groupBoxgMSAActions.Location = New-Object System.Drawing.Point(20, 110)
$groupBoxgMSAActions.Size = New-Object System.Drawing.Size(730, 100)
$groupBoxgMSAActions.Text = 'gMSA Actions'
$tabgMSA.Controls.Add($groupBoxgMSAActions)

# Create buttons for gMSA actions
$buttonCreategMSA = New-Object System.Windows.Forms.Button
$buttonCreategMSA.Location = New-Object System.Drawing.Point(20, 30)
$buttonCreategMSA.Size = New-Object System.Drawing.Size(120, 50)
$buttonCreategMSA.Text = 'Create New gMSA'
$buttonCreategMSA.Add_Click({
    if (($textBoxgMSAAccountName.Text -ne '') -and ($textBoxgMSADomain.Text -ne '') -and ($textBoxPrincipals.Text -ne '')) {
        try {
            # Split the principals string by commas, semicolons or line breaks
            $principals = $textBoxPrincipals.Text -split "[,;\r\n]+" | Where-Object { $_ -ne "" } | ForEach-Object { $_.Trim() }
            
            New-ADServiceAccount -Name $textBoxgMSAAccountName.Text -DNSHostName "$($textBoxgMSAAccountName.Text).$($textBoxgMSADomain.Text)" -PrincipalsAllowedToRetrieveManagedPassword $principals -GroupManagedServiceAccount
            [System.Windows.Forms.MessageBox]::Show("Group Managed Service Account $($textBoxgMSAAccountName.Text) created successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            RefreshgMSAList
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to create Group Managed Service Account: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Account name, domain, and principals are required.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$groupBoxgMSAActions.Controls.Add($buttonCreategMSA)

$buttonInstallgMSA = New-Object System.Windows.Forms.Button
$buttonInstallgMSA.Location = New-Object System.Drawing.Point(150, 30)
$buttonInstallgMSA.Size = New-Object System.Drawing.Size(120, 50)
$buttonInstallgMSA.Text = 'Install gMSA'
$buttonInstallgMSA.Add_Click({
    if ($textBoxgMSAAccountName.Text -ne '') {
        try {
            Install-ADServiceAccount -Identity $textBoxgMSAAccountName.Text
            [System.Windows.Forms.MessageBox]::Show("Group Managed Service Account $($textBoxgMSAAccountName.Text) installed successfully on this computer.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to install Group Managed Service Account: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Account name is required.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$groupBoxgMSAActions.Controls.Add($buttonInstallgMSA)

$buttonVerifygMSA = New-Object System.Windows.Forms.Button
$buttonVerifygMSA.Location = New-Object System.Drawing.Point(280, 30)
$buttonVerifygMSA.Size = New-Object System.Drawing.Size(120, 50)
$buttonVerifygMSA.Text = 'Verify gMSA'
$buttonVerifygMSA.Add_Click({
    if ($textBoxgMSAAccountName.Text -ne '') {
        try {
            $result = Test-ADServiceAccount -Identity $textBoxgMSAAccountName.Text
            if ($result -eq $true) {
                [System.Windows.Forms.MessageBox]::Show("Group Managed Service Account $($textBoxgMSAAccountName.Text) is valid and properly associated.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } else {
                [System.Windows.Forms.MessageBox]::Show("Group Managed Service Account $($textBoxgMSAAccountName.Text) is not valid or not properly associated.", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to verify Group Managed Service Account: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Account name is required.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$groupBoxgMSAActions.Controls.Add($buttonVerifygMSA)

$buttonModifygMSA = New-Object System.Windows.Forms.Button
$buttonModifygMSA.Location = New-Object System.Drawing.Point(410, 30)
$buttonModifygMSA.Size = New-Object System.Drawing.Size(140, 50)
$buttonModifygMSA.Text = 'Modify gMSA'
$buttonModifygMSA.Add_Click({
    if ($textBoxgMSAAccountName.Text -ne '') {
        try {
            # Create modify gMSA form
            $formModifygMSA = New-Object System.Windows.Forms.Form
            $formModifygMSA.Text = "Modify gMSA: $($textBoxgMSAAccountName.Text)"
            $formModifygMSA.Size = New-Object System.Drawing.Size(500, 500)
            $formModifygMSA.StartPosition = 'CenterParent'
            $formModifygMSA.FormBorderStyle = 'FixedDialog'
            $formModifygMSA.MaximizeBox = $false
            
            # Get current gMSA properties
            $gmsa = Get-ADServiceAccount -Identity $textBoxgMSAAccountName.Text -Properties *
            
            # DNS hostname
            $labelDNS = New-Object System.Windows.Forms.Label
            $labelDNS.Location = New-Object System.Drawing.Point(20, 20)
            $labelDNS.Size = New-Object System.Drawing.Size(150, 23)
            $labelDNS.Text = 'DNS Hostname:'
            $formModifygMSA.Controls.Add($labelDNS)
            
            $textBoxDNS = New-Object System.Windows.Forms.TextBox
            $textBoxDNS.Location = New-Object System.Drawing.Point(180, 20)
            $textBoxDNS.Size = New-Object System.Drawing.Size(250, 23)
            $textBoxDNS.Text = $gmsa.DNSHostName
            $formModifygMSA.Controls.Add($textBoxDNS)
            
            # Description
            $labelDesc = New-Object System.Windows.Forms.Label
            $labelDesc.Location = New-Object System.Drawing.Point(20, 60)
            $labelDesc.Size = New-Object System.Drawing.Size(150, 23)
            $labelDesc.Text = 'Description:'
            $formModifygMSA.Controls.Add($labelDesc)
            
            $textBoxDesc = New-Object System.Windows.Forms.TextBox
            $textBoxDesc.Location = New-Object System.Drawing.Point(180, 60)
            $textBoxDesc.Size = New-Object System.Drawing.Size(250, 23)
            $textBoxDesc.Text = $gmsa.Description
            $formModifygMSA.Controls.Add($textBoxDesc)
            
            # Enabled status
            $checkBoxEnabled = New-Object System.Windows.Forms.CheckBox
            $checkBoxEnabled.Location = New-Object System.Drawing.Point(20, 100)
            $checkBoxEnabled.Size = New-Object System.Drawing.Size(250, 23)
            $checkBoxEnabled.Text = 'Account Enabled'
            if ($gmsa.Enabled -ne $null) {
                $checkBoxEnabled.Checked = $gmsa.Enabled
            } else {
                $checkBoxEnabled.Checked = -not ($gmsa.UserAccountControl -band 0x0002)
            }
            $formModifygMSA.Controls.Add($checkBoxEnabled)
            
            # Principals allowed
            $labelPrincipals = New-Object System.Windows.Forms.Label
            $labelPrincipals.Location = New-Object System.Drawing.Point(20, 140)
            $labelPrincipals.Size = New-Object System.Drawing.Size(410, 23)
            $labelPrincipals.Text = 'Principals Allowed to Retrieve Password (one per line):'
            $formModifygMSA.Controls.Add($labelPrincipals)
            
            $textBoxModPrincipals = New-Object System.Windows.Forms.TextBox
            $textBoxModPrincipals.Location = New-Object System.Drawing.Point(20, 170)
            $textBoxModPrincipals.Size = New-Object System.Drawing.Size(410, 100)
            $textBoxModPrincipals.Multiline = $true
            $textBoxModPrincipals.ScrollBars = "Vertical"
            # Get current principals and join them with line breaks
            try {
                $currentPrincipals = $gmsa.PrincipalsAllowedToRetrieveManagedPassword | ForEach-Object { $_.ToString() }
                $textBoxModPrincipals.Text = [string]::Join("`r`n", $currentPrincipals)
            } catch {
                $textBoxModPrincipals.Text = "Domain Computers"
            }
            $formModifygMSA.Controls.Add($textBoxModPrincipals)
            
            # Save button
            $buttonSave = New-Object System.Windows.Forms.Button
            $buttonSave.Location = New-Object System.Drawing.Point(200, 420)
            $buttonSave.Size = New-Object System.Drawing.Size(100, 30)
            $buttonSave.Text = 'Save Changes'
            $buttonSave.Add_Click({
                try {
                    # Update description
                    if ($gmsa.Description -ne $textBoxDesc.Text) {
                        Set-ADServiceAccount -Identity $textBoxgMSAAccountName.Text -Description $textBoxDesc.Text
                    }
                    
                    # Update DNS hostname
                    if ($gmsa.DNSHostName -ne $textBoxDNS.Text) {
                        Set-ADServiceAccount -Identity $textBoxgMSAAccountName.Text -DNSHostName $textBoxDNS.Text
                    }
                    
                    # Update enabled status
                    $isCurrentlyEnabled = $gmsa.Enabled -eq $true -or ($gmsa.UserAccountControl -band 0x0002) -eq 0
                    if ($checkBoxEnabled.Checked -and -not $isCurrentlyEnabled) {
                        Enable-ADAccount -Identity $textBoxgMSAAccountName.Text
                    } elseif (-not $checkBoxEnabled.Checked -and $isCurrentlyEnabled) {
                        Disable-ADAccount -Identity $textBoxgMSAAccountName.Text
                    }
                    
                    # Update principals
                    $newPrincipals = $textBoxModPrincipals.Text -split "[,;\r\n]+" | Where-Object { $_ -ne "" } | ForEach-Object { $_.Trim() }
                    Set-ADServiceAccount -Identity $textBoxgMSAAccountName.Text -PrincipalsAllowedToRetrieveManagedPassword $newPrincipals
                    
                    [System.Windows.Forms.MessageBox]::Show("Group Managed Service Account $($textBoxgMSAAccountName.Text) modified successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                    $formModifygMSA.Close()
                    RefreshgMSAList
                } catch {
                    [System.Windows.Forms.MessageBox]::Show("Failed to modify Group Managed Service Account: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                }
            })
            $formModifygMSA.Controls.Add($buttonSave)
            
            # Cancel button
            $buttonCancel = New-Object System.Windows.Forms.Button
            $buttonCancel.Location = New-Object System.Drawing.Point(310, 420)
            $buttonCancel.Size = New-Object System.Drawing.Size(100, 30)
            $buttonCancel.Text = 'Cancel'
            $buttonCancel.Add_Click({ $formModifygMSA.Close() })
            $formModifygMSA.Controls.Add($buttonCancel)
            
            $formModifygMSA.ShowDialog()
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to retrieve gMSA details: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Account name is required.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$groupBoxgMSAActions.Controls.Add($buttonModifygMSA)

$buttonUpdateKDS = New-Object System.Windows.Forms.Button
$buttonUpdateKDS.Location = New-Object System.Drawing.Point(560, 30)
$buttonUpdateKDS.Size = New-Object System.Drawing.Size(140, 50)
$buttonUpdateKDS.Text = 'Update KDS Root Key'
$buttonUpdateKDS.Add_Click({
    try {
        $confirmResult = [System.Windows.Forms.MessageBox]::Show("Do you want to check if a KDS Root Key exists and create one if needed? This is required for gMSA.", "Confirm KDS Root Key Check", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
        if ($confirmResult -eq [System.Windows.Forms.DialogResult]::Yes) {
            $kdsRootKeys = Get-KdsRootKey
            if (-not $kdsRootKeys) {
                $effectiveTime = (Get-Date).AddHours(-10)
                Add-KdsRootKey -EffectiveTime $effectiveTime
                [System.Windows.Forms.MessageBox]::Show("KDS Root Key created successfully with an effective time of 10 hours ago.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } else {
                [System.Windows.Forms.MessageBox]::Show("KDS Root Key already exists. No action needed.", "Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to update KDS Root Key: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$groupBoxgMSAActions.Controls.Add($buttonUpdateKDS)

# Create groupbox for gMSA List
$groupBoxgMSAList = New-Object System.Windows.Forms.GroupBox
$groupBoxgMSAList.Location = New-Object System.Drawing.Point(20, 220)
$groupBoxgMSAList.Size = New-Object System.Drawing.Size(730, 240)
$groupBoxgMSAList.Text = 'Existing gMSA Accounts'
$tabgMSA.Controls.Add($groupBoxgMSAList)

# Create ListView for gMSAs
$listViewgMSAs = New-Object System.Windows.Forms.ListView
$listViewgMSAs.Location = New-Object System.Drawing.Point(10, 20)
$listViewgMSAs.Size = New-Object System.Drawing.Size(710, 170)
$listViewgMSAs.View = [System.Windows.Forms.View]::Details
$listViewgMSAs.FullRowSelect = $true
$listViewgMSAs.GridLines = $true
$listViewgMSAs.Columns.Add("Name", 150) | Out-Null
$listViewgMSAs.Columns.Add("DNS Host Name", 200) | Out-Null
$listViewgMSAs.Columns.Add("Created Date", 150) | Out-Null
$listViewgMSAs.Columns.Add("Status", 100) | Out-Null
$listViewgMSAs.Columns.Add("Description", 200) | Out-Null
$groupBoxgMSAList.Controls.Add($listViewgMSAs)

# Add event handler for list view selection
$listViewgMSAs.Add_SelectedIndexChanged({
    if ($listViewgMSAs.SelectedItems.Count -gt 0) {
        $textBoxgMSAAccountName.Text = $listViewgMSAs.SelectedItems[0].Text
    }
})

# Create refresh button for gMSA tab
$buttonRefreshgMSA = New-Object System.Windows.Forms.Button
$buttonRefreshgMSA.Location = New-Object System.Drawing.Point(650, 470)
$buttonRefreshgMSA.Size = New-Object System.Drawing.Size(100, 30)
$buttonRefreshgMSA.Text = 'Refresh List'
$buttonRefreshgMSA.Add_Click({
    RefreshgMSAList
})
$tabgMSA.Controls.Add($buttonRefreshgMSA)

# Create delete button for gMSA tab
$buttonDeletegMSA = New-Object System.Windows.Forms.Button
$buttonDeletegMSA.Location = New-Object System.Drawing.Point(540, 470)
$buttonDeletegMSA.Size = New-Object System.Drawing.Size(100, 30)
$buttonDeletegMSA.Text = 'Delete gMSA'
$buttonDeletegMSA.ForeColor = [System.Drawing.Color]::Red
$buttonDeletegMSA.Add_Click({
    if ($textBoxgMSAAccountName.Text -ne '') {
        $confirmResult = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to delete the gMSA '$($textBoxgMSAAccountName.Text)'? This action cannot be undone.", "Confirm Delete", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($confirmResult -eq [System.Windows.Forms.DialogResult]::Yes) {
            try {
                Remove-ADServiceAccount -Identity $textBoxgMSAAccountName.Text -Confirm:$false
                [System.Windows.Forms.MessageBox]::Show("Group Managed Service Account $($textBoxgMSAAccountName.Text) deleted successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                $textBoxgMSAAccountName.Text = ""
                RefreshgMSAList
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to delete Group Managed Service Account: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Please select an account to delete.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$tabgMSA.Controls.Add($buttonDeletegMSA)

# Function to refresh gMSA list
function RefreshgMSAList {
    $listViewgMSAs.Items.Clear()
    
    try {
        # Get all service accounts
        $allServiceAccounts = Get-ADServiceAccount -Filter * -Properties DNSHostName, Created, Description, UserAccountControl, Enabled, msDS-GroupMSAMembership
        
        # Filter to gMSAs (with the group membership attribute)
        $gmsas = $allServiceAccounts | Where-Object { $_.PSObject.Properties.Match('msDS-GroupMSAMembership').Count }
        
        # Check if any gMSAs were found
        if ($gmsas) {
            # Handle both single object and array results
            if ($gmsas -is [array]) {
                foreach ($gmsa in $gmsas) {
                    $item = New-Object System.Windows.Forms.ListViewItem($gmsa.Name)
                    
                    # Add DNS Host Name
                    if ($gmsa.DNSHostName) {
                        $item.SubItems.Add($gmsa.DNSHostName)
                    } else {
                        $item.SubItems.Add("N/A")
                    }
                    
                    # Add Created Date
                    if ($gmsa.Created) {
                        $item.SubItems.Add($gmsa.Created.ToString("yyyy-MM-dd HH:mm:ss"))
                    } else {
                        $item.SubItems.Add("N/A")
                    }
                    
                    # Add Status - Check if account is enabled
                    $isEnabled = $true
                    if ($gmsa.Enabled -ne $null) {
                        $isEnabled = $gmsa.Enabled -eq $true
                    } elseif ($gmsa.UserAccountControl -ne $null) {
                        # Check if the "ACCOUNTDISABLE" flag (0x0002) is set
                        $isEnabled = -not ($gmsa.UserAccountControl -band 0x0002)
                    }
                    
                    if ($isEnabled) {
                        $item.SubItems.Add("Enabled")
                    } else {
                        $item.SubItems.Add("Disabled")
                    }
                    
                    # Add Description
                    if ($gmsa.Description) {
                        $item.SubItems.Add($gmsa.Description)
                    } else {
                        $item.SubItems.Add("")
                    }
                    
                    $listViewgMSAs.Items.Add($item)
                }
            } else {
                # Handle single gMSA result
                $item = New-Object System.Windows.Forms.ListViewItem($gmsas.Name)
                
                # Add DNS Host Name
                if ($gmsas.DNSHostName) {
                    $item.SubItems.Add($gmsas.DNSHostName)
                } else {
                    $item.SubItems.Add("N/A")
                }
                
                # Add Created Date
                if ($gmsas.Created) {
                    $item.SubItems.Add($gmsas.Created.ToString("yyyy-MM-dd HH:mm:ss"))
                } else {
                    $item.SubItems.Add("N/A")
                }
                
                # Add Status - Check if account is enabled
                $isEnabled = $true
                if ($gmsas.Enabled -ne $null) {
                    $isEnabled = $gmsas.Enabled -eq $true
                } elseif ($gmsas.UserAccountControl -ne $null) {
                    # Check if the "ACCOUNTDISABLE" flag (0x0002) is set
                    $isEnabled = -not ($gmsas.UserAccountControl -band 0x0002)
                }
                
                if ($isEnabled) {
                    $item.SubItems.Add("Enabled")
                } else {
                    $item.SubItems.Add("Disabled")
                }
                
                # Add Description
                if ($gmsas.Description) {
                    $item.SubItems.Add($gmsas.Description)
                } else {
                    $item.SubItems.Add("")
                }
                
                $listViewgMSAs.Items.Add($item)
            }
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to retrieve gMSA list: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# Initialize lists
try {
    RefreshMSAList
} catch {
    [System.Windows.Forms.MessageBox]::Show("Failed to initialize MSA list: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
}

try {
    RefreshgMSAList
} catch {
    [System.Windows.Forms.MessageBox]::Show("Failed to initialize gMSA list: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
}

# Show the form
$formAccountManager.Add_Shown({
    $formAccountManager.Activate()
})

[void]$formAccountManager.ShowDialog()
