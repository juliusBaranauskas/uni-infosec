using namespace System.Security.AccessControl;

$sysAdminGroup = "sysadmin"
$bossGroup = "director"
$administrationGroup = "administration"
$managerGroup = "manager"
$employeeGroup = "employee"

#region helper Methods
function defaultACL {
    param([string]$path)
    $resAcl = Get-Acl -Path $path

    $sysEntry = fullControlACL -user "NT AUTHORITY\SYSTEM"
    $adminsEntry = fullControlACL -user "BUILTIN\Administrators"
    $ownerEntry = fullControlACL -user "CREATOR OWNER"

    $resAcl.AddAccessRule($sysEntry)
    $resAcl.AddAccessRule($adminsEntry)
    $resAcl.AddAccessRule($ownerEntry)

    return $resAcl
}

function addUser {
    param (
        [string]$username,
        [string[]]$groups
    )

    $Password = ConvertTo-SecureString $username -AsPlainText -Force
    $user = New-LocalUser -Name $username -Password $Password
    Add-LocalGroupMember -Group $(Get-LocalGroup -Name "Users") -Member $user | Out-Null 

    foreach($group in $groups) 
    {
        $group = Get-LocalGroup -Name $group
        Add-LocalGroupMember -Group $group -Member $user | Out-Null
    }
}

function fullControlACL {
    param([string]$user)
    
    $rule = New-Object FileSystemAccessRule(
            $user,
            [FileSystemRights]::FullControl,
            ([InheritanceFlags]::ContainerInherit + [InheritanceFlags]::ObjectInherit),
            [PropagationFlags]::None,
            [AccessControlType]::Allow)
    return $rule
}

function rxACL {
    param([string]$user)
    
    $rule = New-Object FileSystemAccessRule(
            $user,
            [FileSystemRights]::ReadAndExecute,
            ([InheritanceFlags]::ContainerInherit + [InheritanceFlags]::ObjectInherit),
            [PropagationFlags]::None,
            [AccessControlType]::Allow)
    return $rule
}

function rwxACL {
    param([string]$user)
    
    $rule = New-Object FileSystemAccessRule(
            $user,
            ([FileSystemRights]::ReadAndExecute + [FileSystemRights]::Write),
            ([InheritanceFlags]::ContainerInherit + [InheritanceFlags]::ObjectInherit),
            [PropagationFlags]::None,
            [AccessControlType]::Allow)
    return $rule
}

function clearInheritance {
    param([string]$path)
    
    $currACL = Get-Acl -Path $path
    $currACL.SetAccessRuleProtection($true, $false)
    Set-Acl -Path $path -AclObject $currACL
}
#endregion

#region cleanup
Remove-LocalUser -Name SystemAdmin
Remove-LocalUser -Name BossPerson
Remove-LocalUser -Name Fin1
Remove-LocalUser -Name Fin2
Remove-LocalUser -Name Man1
Remove-LocalUser -Name Man2
Remove-LocalUser -Name Supreme

Remove-LocalGroup -Name $sysAdminGroup
Remove-LocalGroup -Name $bossGroup
Remove-LocalGroup -Name $administrationGroup
Remove-LocalGroup -Name $managerGroup
Remove-LocalGroup -Name $employeeGroup

Remove-Item -Recurse -Path "C:\bendrove"
#endregion

New-LocalGroup -Name $sysAdminGroup
New-LocalGroup -Name $bossGroup
New-LocalGroup -Name $administrationGroup
New-LocalGroup -Name $managerGroup
New-LocalGroup -Name $employeeGroup

addUser -username "SystemAdmin" -groups $employeeGroup, $sysAdminGroup, "Administrators"
addUser -username "BossPerson" -groups $employeeGroup, $bossGroup
addUser -username "Fin1" -groups $employeeGroup, $administrationGroup
addUser -username "Fin2" -groups $employeeGroup, $administrationGroup
addUser -username "Man1" -groups $employeeGroup, $managerGroup
addUser -username "Man2" -groups $employeeGroup, $managerGroup
addUser -username "Supreme" -groups $employeeGroup


#region bendrove
$bendrovePath = "C:\bendrove"
New-Item -Path $bendrovePath -ItemType "Directory" 

# Clear inheritance
clearInheritance -path $bendrovePath

$aclObject = defaultACL -Path $bendrovePath

$sysadminEntry = fullControlACL -user $sysAdminGroup
$bossEntry = fullControlACL -user $bossGroup
$employeeEntry = rxACL -user $employeeGroup

$aclObject.AddAccessRule($sysadminEntry)
$aclObject.AddAccessRule($bossEntry)
$aclObject.AddAccessRule($employeeEntry)
Set-Acl -Path $bendrovePath -AclObject $aclObject
#endregion


#region BOSS
$bossPath = "C:\bendrove\boss"
New-Item -Path $bossPath -ItemType "Directory"

# Clear inheritance
clearInheritance -path $bossPath

$aclObject = defaultACL -Path $bossPath

$sysadminEntry = fullControlACL -user $sysAdminGroup
$bossEntry = fullControlACL -user $bossGroup
$administrationMemberEntry = rwxACL -user "Fin1"

$aclObject.AddAccessRule($sysadminEntry)
$aclObject.AddAccessRule($bossEntry)
$aclObject.AddAccessRule($administrationMemberEntry)
Set-Acl -Path $bossPath -AclObject $aclObject
#endregion


#region Administration
$administrationPath = "C:\bendrove\administracija"
New-Item -Path $administrationPath -ItemType "Directory"

# Clear inheritance
clearInheritance -path $administrationPath

$aclObject = defaultACL -Path $administrationPath

$sysadminEntry = fullControlACL -user $sysAdminGroup
$bossEntry = fullControlACL -user $bossGroup
$administrationEntry = rxACL -user $administrationGroup

$aclObject.AddAccessRule($sysadminEntry)
$aclObject.AddAccessRule($bossEntry)
$aclObject.AddAccessRule($administrationEntry)
Set-Acl -Path $administrationPath -AclObject $aclObject
#endregion


#region Fin1
$admin1Path = "C:\bendrove\administracija\fin1"
New-Item -Path $admin1Path -ItemType "Directory"

# Clear inheritance
# clearInheritance -path $admin1Path

$aclObject = defaultACL -Path $admin1Path

$sysadminEntry = fullControlACL -user $sysAdminGroup
$bossEntry = fullControlACL -user $bossGroup
$admin1Entry = rwxACL -user "Fin1"

# $aclObject.AddAccessRule($sysadminEntry)
# $aclObject.AddAccessRule($bossEntry)
$aclObject.AddAccessRule($admin1Entry)
Set-Acl -Path $admin1Path -AclObject $aclObject
#endregion


#region Fin2
$admin2Path = "C:\bendrove\administracija\fin2"
New-Item -Path $admin2Path -ItemType "Directory"

# Clear inheritance
# clearInheritance -path $admin2Path

$aclObject = defaultACL -Path $admin2Path

$sysadminEntry = fullControlACL -user $sysAdminGroup
$bossEntry = fullControlACL -user $bossGroup
$admin2Entry = rwxACL -user "Fin2"

# $aclObject.AddAccessRule($sysadminEntry)
# $aclObject.AddAccessRule($bossEntry)
$aclObject.AddAccessRule($admin2Entry)
Set-Acl -Path $admin2Path -AclObject $aclObject
#endregion


#region Managers
$managerPath = "C:\bendrove\vadovai"
New-Item -Path $managerPath -ItemType "Directory"

# Clear inheritance
clearInheritance -path $managerPath

$aclObject = defaultACL -Path $managerPath

$sysadminEntry = fullControlACL -user $sysAdminGroup
$bossEntry = fullControlACL -user $bossGroup
$managerEntry = rxACL -user $managerGroup

$aclObject.AddAccessRule($sysadminEntry)
$aclObject.AddAccessRule($bossEntry)
$aclObject.AddAccessRule($managerEntry)
Set-Acl -Path $managerPath -AclObject $aclObject
#endregion


#region Man1
$manager1Path = "C:\bendrove\vadovai\man1"
New-Item -Path $manager1Path -ItemType "Directory"

# Clear inheritance
# clearInheritance -path $manager1Path

$aclObject = defaultACL -Path $manager1Path

$sysadminEntry = fullControlACL -user $sysAdminGroup
$bossEntry = fullControlACL -user $bossGroup
$manager1Entry = rwxACL -user "Man1"


# $aclObject.AddAccessRule($sysadminEntry)
# $aclObject.AddAccessRule($bossEntry)
$aclObject.AddAccessRule($manager1Entry)
# $aclObject.AddAccessRule($managerEntry)
Set-Acl -Path $manager1Path -AclObject $aclObject
#endregion


#region Man2
$manager2Path = "C:\bendrove\vadovai\man2"
New-Item -Path $manager2Path -ItemType "Directory"

# Clear inheritance
# clearInheritance -path $manager2Path

$aclObject = defaultACL -Path $manager2Path

$sysadminEntry = fullControlACL -user $sysAdminGroup
$bossEntry = fullControlACL -user $bossGroup
$manager2Entry = rwxACL -user "Man2"


# $aclObject.AddAccessRule($sysadminEntry)
# $aclObject.AddAccessRule($bossEntry)
$aclObject.AddAccessRule($manager2Entry)
# $aclObject.AddAccessRule($managerEntry)
Set-Acl -Path $manager2Path -AclObject $aclObject
#endregion


#region Chaoso_kambarys
$chaosasPath = "C:\bendrove\chaoso_kambarelis"
New-Item -Path $chaosasPath -ItemType "Directory"

# Clear inheritance
# clearInheritance -path $chaosasPath

# $sysadminEntry = fullControlACL -user $sysAdminGroup
# $bossEntry = fullControlACL -user $bossGroup
$employeeEntry = fullControlACL -user $employeeGroup

# $aclObject.AddAccessRule($sysadminEntry)
# $aclObject.AddAccessRule($bossEntry)
$aclObject = defaultACL -Path $chaosasPath
$aclObject.AddAccessRule($employeeEntry)
Set-Acl -Path $chaosasPath -AclObject $aclObject
#endregion


#region meme_club
$memeClubPath = "C:\bendrove\meme_club"
New-Item -Path $memeClubPath -ItemType "Directory"

# Clear inheritance
clearInheritance -path $memeClubPath

$aclObject = defaultACL -Path $memeClubPath

$sysadminEntry = fullControlACL -user $sysAdminGroup
$bossEntry = fullControlACL -user $bossGroup
$manager2Entry = rwxACL -user "Man2"
$fin1Entry = rwxACL -user "Fin1"


$aclObject.AddAccessRule($sysadminEntry)
$aclObject.AddAccessRule($bossEntry)
$aclObject.AddAccessRule($manager2Entry)
$aclObject.AddAccessRule($fin1Entry)
Set-Acl -Path $memeClubPath -AclObject $aclObject
#endregion

# Task#3
net accounts /maxpwage:210
net accounts /minpwage:20
net accounts /minpwlen:10
net accounts /lockoutduration:30
net accounts /lockoutthreshold:6
# Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $True

# Task#4
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Force -Type "DWord" -Name "NoDispCPL" -Value 1

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Force -Type "DWord" -Name "NoChangingWallPaper" -Value 1

New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows" -Name "RemovableStorageDevices" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices" -Force -Type "DWord" -Name "Deny_All" -Value 1

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force -Type "DWord" -Name "HidePowerOptions" -Value 1
# try to forbid executing shutdown.exe

# Task#5
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Security state change" /success:enable /failure:enable
auditpol /set /subcategory:"Audit policy change" /success:enable /failure:enable

# Task#6
# create dir_to_chown as user x by running another powershell with `RunAs user`
# ps1 file that takes as a param path to create a file and runs in another users name
$username = 'Fin1'
$password = $username

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword

$testFilename="testChown.test"
$currentPath=(Get-Location).Path.ToString()
$createFileScriptPath = $currentPath + "\createFile.ps1"
$args= $createFileScriptPath + " " + $chaosasPath + " " + $testFilename
Start-Process powershell.exe -Credential $credential -ArgumentList ("-file $args")

$testFilePath = $chaosasPath + $testFilename
takeown /f $testFilePath

# Task#8
auditpol /set /category:"Privilege Use" /success:enable /failure:enable