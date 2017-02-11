param
(
     [Parameter(Mandatory=$true)]
     [String]$account
      
)
     
Set-StrictMode -Version 2
<# addCSharpObjectTemplate Read C# file and make available to Powershell #>
function addCSharpObjectTemplate($file)
{
     
    $fileFullPath = resolve-path $file;
     
    $Source = [System.IO.File]::ReadAllText($file);
      
    $strLog = "Importing Files :- fileFullPath: {0}"  -f $fileFullPath
     
    Write-Host $strLog
     
    Add-Type -TypeDefinition $Source -Language CSharpVersion3;
 
}
 
 
<# addCSharpObject Invokes addCSharpObjectTemplate for the listed files #>
function addCSharpObject
{
	
	$file = "LsaSecurity.cs";
    addCSharpObjectTemplate($file);

 
}

#Add C# Objects
addCSharpObject

<# CHAR #>
$CHAR_TAB = "`t";
$CHAR_YES = "Y";
$CHAR_NO = "N";


$listofRights = @(
					  'SeManageVolumePrivilege'
					, 'SeLockMemoryPrivilege'
				)

#$rights = "SeManageVolumePrivilege"


[LsaSecurity.LsaWrapperCaller]::computer = $null;

<#
	[LsaSecurity.LsaWrapperCaller]::GetUsersWithPrivilege($rights)
	[LsaSecurity.LsaWrapperCaller]::AddPrivileges($account, $rights)
	[LsaSecurity.LsaWrapperCaller]::RemovePrivileges($account, $rights)
#>

$log = "Adding Local Security Policy Privilges for {0} ..." -f $account
Write-Host $log

# For each right, grant to account
foreach ($rights in $listofRights) {

    $log = "`tWorking on {0} ..." -f $rights
	
	Write-Host $log
	
	[LsaSecurity.LsaWrapperCaller]::AddPrivileges($account, $rights)
}
