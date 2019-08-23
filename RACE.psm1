<#
Import this module to load all the functions in RACE toolkit in the current PowerShell session.
PS > Import-Module C:\RACE-master\RACE.psm1
#>


if(!$PSScriptRoot)
{ 
    $PSScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
}
$PSScriptRoot
Get-ChildItem -Recurse $PSScriptRoot *.ps1  | ForEach-Object  {. $_.FullName}
