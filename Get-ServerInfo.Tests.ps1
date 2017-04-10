<#
invoke-Pester -Script @{ Path = './Get-ServerInfo.Tests.ps1'; verbose = [System.Management.Automation.ActionPreference]::Continue }

Rudimentary Pester
#>
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'
. "$here\$sut"

Describe "Get-ServerInfo" {
    It "Should Get servers from pipeline" {
        @('localhost','Flores') | get-serverinfo -verbose
    }

    It "Should Get LOCALHOST info on command line"{
      get-serverinfo 'LOCALHOST' -verbose
      }
}
