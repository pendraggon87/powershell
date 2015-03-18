######################################################################
# Title: AD_User_Audit_v1											 #
# Author: Aaron J. Katz												 #
# Description: Obtain AD information about users in selected domains #
# Version: 1.0.1													 #
# Changelog:														 #
#	* Added IsServiceAccount column. Determine if service account by #
#		checking if the phrase "service account" is in the desc.	 #
######################################################################

import-module activedirectory

$servers = "" # Comma-separated list of domain controllers, one per domain

$output = @()

foreach($server in $servers){
    $output += Get-ADUser -Properties * -Filter * -Server $server | Select @{Name='Server';Expression={$server}}, @{Name='Domain';Expression={(Get-ADDomain (($_.DistinguishedName.Split(",") | ? {$_ -like "DC=*"}) -join ",")).NetBIOSName}}, 
        ‘Name’,’DisplayName’,’SamAccountName’,'Enabled','PasswordLastSet','PasswordNeverExpires',
        @{Name='IsServiceAccount';Expression={$_.Description -like "*service account*"}},
        @{Name='IsDomainOrEnterpriseOrSchemaAdmin';Expression={[string]::join(";",($_.MemberOf)) -match "(Domain Admins|Enterprise Admins|Schema Admins)"}}, 
        @{Name=’MemberOf';Expression={$_.MemberOf -join ';'}}
}
$output | export-csv -NoTypeInformation .\adoutput.csv
