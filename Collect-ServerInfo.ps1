<#
  .SYNOPSIS
    Collect-ServerInfo.ps1 - PowerShell script to collect information about Windows servers

  .DESCRIPTION
    This PowerShell script runs a series of WMI and other queries to collect information
    about Windows servers.

  .PARAMETER ComputerName
    The remote computer.

  .PARAMETER skipSofware
    Skip software

  .PARAMETER -Verbose
    See more detailed progress as the script is running.

  .EXAMPLE
    .\Collect-ServerInfo.ps1 SERVER1
    Collect information about a single server.

  .EXAMPLE
    "SERVER1","SERVER2","SERVER3" | .\Collect-ServerInfo.ps1
    Collect information about multiple servers.

  .EXAMPLE
    Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} | %{.\Collect-ServerInfo.ps1 $_.DNSHostName}
    Collects information about all servers in Active Directory.

  .OUTPUTS
    Each server's results are output to HTML.

  .NOTES
    Written by: Paul Cunningham

    Find me on:

    * My Blog:	http://paulcunningham.me
    * Twitter:	https://twitter.com/paulcunningham
    * LinkedIn:	http://au.linkedin.com/in/cunninghamp/
    * Github:	https://github.com/cunninghamp

    License:

    The MIT License (MIT)

    Copyright (c) 2015 Paul Cunningham

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

    Change Log:
    V1.00, 20/04/2015 - First release
    V1.01, 01/05/2015 - Updated with better error handling
    V2.00, 2016-02-07 - Added Share section
                      - Added CSS
                      - Added Powershell section
                      - Added Oracle Software Section
                      - Added regions
    2016-07-21        - Wrapped WMI calls in Invoke-Command. These failed because of Server hardening
    2016-08-03        - Added Smallworld image section
#>
[CmdletBinding()]
param
(
  [Parameter(ValueFromPipeline = $true,
             Position = 1)]
  [string]
  $ComputerName = $env:COMPUTERNAME,
  [string]$CssPath = $(Join-Path $PSScriptRoot "Collect-ServerInfo.css"),
  [switch]$skipSoftware,
  [switch]$skipOracle,
  [switch]$skipChocolatey
)

Begin
{
    #Initialize
    Write-Verbose "Initializing"

}

Process
{

    #---------------------------------------------------------------------
    # Process each ComputerName
    #---------------------------------------------------------------------

    if (!($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent))
    {
        Write-Host "Processing $ComputerName"
    }

    Write-Verbose "=====> Processing $ComputerName <====="

    $htmlreport = @()
    $htmlbody = @()
    $htmlfile = "$($ComputerName).html"
    $spacer = "<br />"

  #region nslookupTest
  #---------------------------------------------------------------------
  # Collect DNS details to HTML fragment
  # As on Windows 7 can't use Get-NetTCPConnection,Get-NetIPConfiguration
  #---------------------------------------------------------------------
  Write-Verbose "Collecting DNS Details"

  $subhead = @"
  <p><a name="computer-dns-details"></a></p><h3 id="computer-dns-details">DNS Details<a href="#TOC">^</a></h3>
"@
  $htmlbody += $subhead

  try
  {
    $dnsInfo= nslookup.exe $ComputerName | out-string
    $htmlbody += "<pre>" +$dnsInfo +"</pre>"
    $htmlbody += $spacer
  }
  catch
  {
    Write-Warning $_.Exception.Message
    $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
    $htmlbody += $spacer
  }

  #endregion nslookupTest
  #region IpConfig
  #---------------------------------------------------------------------
  # Collect computer IP config
  # As on Windows 7 can't use Get-NetTCPConnection,Get-NetIPConfiguration
  #---------------------------------------------------------------------
  Write-Verbose "Collecting Windows IP Configuration"

  $subhead = @"
  <p><a name="computer-windows-ip-configuration"></a></p><h3 id="computer-windows-ip-configuration">Windows IP Configuration<a href="#TOC">^</a></h3>
"@

  $htmlbody += $subhead

  try
  {
    $ipConfigInfo = Invoke-Command -Computer $ComputerName  -ScriptBlock { & ipconfig.exe /all | out-string}

    $htmlbody += "<pre>" + $ipConfigInfo + "</pre>"
    $htmlbody += $spacer

  }
  catch
  {
    Write-Warning $_.Exception.Message
    $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
    $htmlbody += $spacer
  }
  #endregion IpConfig
  #region CompSystem
    #---------------------------------------------------------------------
    # Collect computer system information and convert to HTML fragment
    #---------------------------------------------------------------------

    Write-Verbose "Collecting computer system information"

    $subhead = @"
    <p><a name="Computer-System-Information"></a></p><h3 id="computer-system-information">Computer System Information<a href="#TOC">^</a></h3>
"@
    $htmlbody += $subhead

    try
    {
    $csinfo = Invoke-Command -computer $ComputerName -ScriptBlock { Get-WmiObject Win32_ComputerSystem -ErrorAction STOP } |
      Select-Object Name, Manufacturer, Model,
                    @{ Name = 'Physical Processors'; Expression = { $_.NumberOfProcessors } },
                    @{ Name = 'Logical Processors'; Expression = { $_.NumberOfLogicalProcessors } },
                    @{
        Name = 'Total Physical Memory (Gb)'; Expression = {
          $tpm = $_.TotalPhysicalMemory/1GB;
          "{0:F0}" -f $tpm
        }
      },
                    DnsHostName, Domain

      $htmlbody += $csinfo | ConvertTo-Html -Fragment
      $htmlbody += $spacer

    }
    catch
    {
      Write-Warning $_.Exception.Message
      $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
      $htmlbody += $spacer
    }

    #endregion  CompSystem
    #region OperatingSystem

    #---------------------------------------------------------------------
    # Collect operating system information and convert to HTML fragment
    #---------------------------------------------------------------------
    Write-Verbose "Collecting operating system information"

    $subhead = "<h3>Operating System Information</h3>"
    $subhead = @"
    <p><a name="Operating-System-Information"></a></p><h3 id="Operating-System-Information">Operating System Information<a href="#TOC">^</a></h3>
"@

    $htmlbody += $subhead

    try
    {
    $osinfo = Invoke-Command -computer $ComputerName -ScriptBlock { Get-WmiObject Win32_OperatingSystem -ErrorAction STOP} |
    Select-Object @{ Name = 'Operating System'; Expression = { $_.Caption } },
                    @{ Name = 'Architecture'; Expression = { $_.OSArchitecture } },
                    Version, Organization,
                    @{
        Name = 'Install Date'; Expression = {
          $installdate = [datetime]::ParseExact($_.InstallDate.SubString(0, 8), "yyyyMMdd", $null);
          $installdate.ToShortDateString()
        }
      },
                    WindowsDirectory

      $htmlbody += $osinfo | ConvertTo-Html -Fragment
      $htmlbody += $spacer
    }
    catch
    {
      Write-Warning $_.Exception.Message
      $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
      $htmlbody += $spacer
    }

    #endregion
    #region PowershellInfo
    #---------------------------------------------------------------------
    # Collect Powershell Info information and convert to HTML fragment
    #---------------------------------------------------------------------

    Write-Verbose "Collecting Powershell Information"
    $subhead = @"
    <p><a name="Powershell-Information"></a></p><h3 id="Powershell-Information">Powershell Information<a href="#TOC">^</a></h3>
"@
    $htmlbody += $subhead

    try
    {
      $poshInfo = Invoke-Command -ScriptBlock { [PSCustomObject]$PSVersionTable } -computername $ComputerName
      $poshCompatibleVersions = [PSCustomObject] $poshInfo | Select-Object PSCompatibleVersions
      $poshVersions = $poshInfo | Select-Object PSVersion, WSManStackVersion, SerializationVersion, CLRVersion, BuildVersion, PSRemotingProtocolVersion
      $compverNum=@()
      foreach ($i in $poshCompatibleVersions.pscompatibleVersions)
      {
        $compverNum += "{0}.{1}" -f $i.major,$i.minor
      }
      $poshVersions | Add-Member NoteProperty -Name "PSCompatibleVersions" -Value $($compverNum -join ',')
      $htmlbody += $poshVersions | convertto-html -Fragment | Out-String
      $htmlbody += $spacer
    }
    catch
    {
      Write-Warning $_.Exception.Message
      $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
      $htmlbody += $spacer
    }

    #endregion PowershellInfo
    #region PhysicalMemory
    #---------------------------------------------------------------------
    # Collect physical memory information and convert to HTML fragment
    #---------------------------------------------------------------------

    Write-Verbose "Collecting physical memory information"

    $subhead = "<h3>Physical Memory Information</h3>"
    $subhead = @"
    <p><a name="Physical-Memory-Information"></a></p><h3 id="Physical-Memory-Information">Physical Memory Information<a href="#TOC">^</a></h3>
"@

    $htmlbody += $subhead

    try
    {
      $memorybanks = @()
      $physicalmemoryinfo = @(Invoke-Command -computer $ComputerName -ScriptBlock { Get-WmiObject Win32_PhysicalMemory -ErrorAction STOP } |
      Select-Object DeviceLocator, Manufacturer, Speed, Capacity)

      foreach ($bank in $physicalmemoryinfo)
      {
        $memObject = New-Object PSObject
        $memObject | Add-Member NoteProperty -Name "Device Locator" -Value $bank.DeviceLocator
        $memObject | Add-Member NoteProperty -Name "Manufacturer" -Value $bank.Manufacturer
        $memObject | Add-Member NoteProperty -Name "Speed" -Value $bank.Speed
        $memObject | Add-Member NoteProperty -Name "Capacity (GB)" -Value ("{0:F0}" -f $bank.Capacity/1GB)

        $memorybanks += $memObject
      }

      $htmlbody += $memorybanks | ConvertTo-Html -Fragment
      $htmlbody += $spacer
    }
    catch
    {
      Write-Warning $_.Exception.Message
      $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
      $htmlbody += $spacer
    }

    #endregion PhysicalMemory
    #region PageFile
    #---------------------------------------------------------------------
    # Collect pagefile information and convert to HTML fragment
    #---------------------------------------------------------------------

    $subhead = "<h3>PageFile Information</h3>"
    $subhead = @"
    <p><a name="PageFile-Information"></a></p><h3 id="PageFile-Information">PageFile Information<a href="#TOC">^</a></h3>
"@

    $htmlbody += $subhead

    Write-Verbose "Collecting pagefile information"

    try
    {
      $pagefileinfo = Invoke-Command -computer $ComputerName -ScriptBlock { Get-WmiObject Win32_PageFileUsage -ErrorAction STOP } |
      Select-Object @{ Name = 'Pagefile Name'; Expression = { $_.Name } },
                    @{ Name = 'Allocated Size (Mb)'; Expression = { $_.AllocatedBaseSize } }

      $htmlbody += $pagefileinfo | ConvertTo-Html -Fragment
      $htmlbody += $spacer
    }
    catch
    {
      Write-Warning $_.Exception.Message
      $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
      $htmlbody += $spacer
    }

    #endregion PageFile
    #region BIOS
    #---------------------------------------------------------------------
    # Collect BIOS information and convert to HTML fragment
    #---------------------------------------------------------------------

    $subhead = "<h3>BIOS Information</h3>"
    $subhead = @"
    <p><a name="BIOS-Information"></a></p><h3 id="BIOS-Information">BIOS Information<a href="#TOC">^</a></h3>
"@

    $htmlbody += $subhead

    Write-Verbose "Collecting BIOS information"

    try
    {
      $biosinfo = Invoke-Command -computer $ComputerName -ScriptBlock { Get-WmiObject Win32_Bios -ErrorAction STOP } |
      Select-Object Status, Version, Manufacturer,
                    @{
        Name = 'Release Date'; Expression = {
          $releasedate = [datetime]::ParseExact($_.ReleaseDate.SubString(0, 8), "yyyyMMdd", $null);
          $releasedate.ToShortDateString()
        }
      },
                    @{ Name = 'Serial Number'; Expression = { $_.SerialNumber } }

      $htmlbody += $biosinfo | ConvertTo-Html -Fragment
      $htmlbody += $spacer
    }
    catch
    {
      Write-Warning $_.Exception.Message
      $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
      $htmlbody += $spacer
    }

    #endregion BIOS
    #region LogicalDisk
    #---------------------------------------------------------------------
    # Collect logical disk information and convert to HTML fragment
    #---------------------------------------------------------------------

    $subhead = "<h3>Logical Disk Information</h3>"
    $subhead = @"
    <p><a name="Logical-Disk-Information"></a></p><h3 id="Logical-Disk-Information">Logical Disk Information<a href="#TOC">^</a></h3>
"@

    $htmlbody += $subhead

    Write-Verbose "Collecting logical disk information"

    try
    {
      $diskinfo = Invoke-Command -computer $ComputerName -ScriptBlock { Get-WmiObject Win32_LogicalDisk -ErrorAction STOP } |
      Select-Object DeviceID, FileSystem, VolumeName,
                    @{ Expression = { $_.Size /1Gb -as [int] }; Label = "Total Size (GB)" },
                    @{ Expression = { $_.Freespace / 1Gb -as [int] }; Label = "Free Space (GB)" }

      $htmlbody += $diskinfo | ConvertTo-Html -Fragment
      $htmlbody += $spacer
    }
    catch
    {
      Write-Warning $_.Exception.Message
      $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
      $htmlbody += $spacer
    }

    #endregion LogicalDisk
    #region VolumeInfo
    #---------------------------------------------------------------------
    # Collect volume information and convert to HTML fragment
    #---------------------------------------------------------------------

    $subhead = "<h3>Volume Information</h3>"
    $subhead = @"
    <p><a name="Volume-Information"></a></p><h3 id="Volume-Information">Volume Information<a href="#TOC">^</a></h3>
"@

    $htmlbody += $subhead

    Write-Verbose "Collecting volume information"

    try
    {
      $volinfo = Invoke-Command -computer $ComputerName -ScriptBlock { Get-WmiObject Win32_Volume -ErrorAction STOP } |
      Select-Object Label, Name, DeviceID, SystemVolume,
                    @{ Expression = { $_.Capacity /1Gb -as [int] }; Label = "Total Size (GB)" },
                    @{ Expression = { $_.Freespace / 1Gb -as [int] }; Label = "Free Space (GB)" }

      $htmlbody += $volinfo | ConvertTo-Html -Fragment
      $htmlbody += $spacer
    }
    catch
    {
      Write-Warning $_.Exception.Message
      $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
      $htmlbody += $spacer
    }

    #endregion VolumeInfo
    #region NetworkInterface
    #---------------------------------------------------------------------
    # Collect network interface information and convert to HTML fragment
    #---------------------------------------------------------------------

    $subhead = "<h3>Network Interface Information</h3>"
    $subhead = @"
    <p><a name="Network-Interface-Information"></a></p><h3 id="Network-Interface-Information">Network Interface Information<a href="#TOC">^</a></h3>
"@

    $htmlbody += $subhead

    Write-Verbose "Collecting network interface information"

    try
    {
      $nics = @()
      $nicinfo = @(Invoke-Command -computer $ComputerName -ScriptBlock { Get-WmiObject Win32_NetworkAdapter -ErrorAction STOP } | Where { $_.PhysicalAdapter } |
      Select-Object Name, AdapterType, MACAddress,
                    @{ Name = 'ConnectionName'; Expression = { $_.NetConnectionID } },
                    @{ Name = 'Enabled'; Expression = { $_.NetEnabled } },
                    @{ Name = 'Speed'; Expression = { $_.Speed/1000000 } })

      $nwinfo = Invoke-Command -computer $ComputerName -ScriptBlock { Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction STOP } |
      Select-Object Description, DHCPServer,
                    @{ Name = 'IpAddress'; Expression = { $_.IpAddress -join '; ' } },
                    @{ Name = 'IpSubnet'; Expression = { $_.IpSubnet -join '; ' } },
                    @{ Name = 'DefaultIPgateway'; Expression = { $_.DefaultIPgateway -join '; ' } },
                    @{ Name = 'DNSServerSearchOrder'; Expression = { $_.DNSServerSearchOrder -join '; ' } }

      foreach ($nic in $nicinfo)
      {
        $nicObject = New-Object PSObject
        $nicObject | Add-Member NoteProperty -Name "Connection Name" -Value $nic.connectionname
        $nicObject | Add-Member NoteProperty -Name "Adapter Name" -Value $nic.Name
        $nicObject | Add-Member NoteProperty -Name "Type" -Value $nic.AdapterType
        $nicObject | Add-Member NoteProperty -Name "MAC" -Value $nic.MACAddress
        $nicObject | Add-Member NoteProperty -Name "Enabled" -Value $nic.Enabled
        $nicObject | Add-Member NoteProperty -Name "Speed (Mbps)" -Value $nic.Speed

        $ipaddress = ($nwinfo | Where { $_.Description -eq $nic.Name }).IpAddress
        $nicObject | Add-Member NoteProperty -Name "IPAddress" -Value $ipaddress

        $nics += $nicObject
      }

      $htmlbody += $nics | ConvertTo-Html -Fragment
      $htmlbody += $spacer
    }
    catch
    {
      Write-Warning $_.Exception.Message
      $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
      $htmlbody += $spacer
    }

    #endregion NetworkInterface
    #region SoftwareInfo
    #---------------------------------------------------------------------
    # Collect software information and convert to HTML fragment
    #---------------------------------------------------------------------
      $subhead = "<h3>Software Information</h3>"
      $subhead = @"
    <p><a name="Software-Information"></a></p><h3 id="Software-Information">Software Information<a href="#TOC">^</a></h3>
"@
    $htmlbody += $subhead
    if (!$skipSoftware)
    {
      Write-Verbose "Collecting software information"
      try
      {
      $software = Invoke-Command -computer $ComputerName -ScriptBlock { Get-ItemProperty @("HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*") | Sort-Object -Property "DisplayName" } | Select-Object DisplayName, Publisher, DisplayVersion, InstallDate
      $htmlbody += $software | select * -ExcludeProperty RunspaceId, PSComputerName, PSShowComputerName | ConvertTo-Html -Fragment
        $htmlbody += $spacer
      }
      catch
      {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
      }
    }
    else
    {
      $htmlbody += "<p>Skipped</p>"
    }
  #endregion SoftwareInfo
  #region doNetFramework
  #---------------------------------------------------------------------
  # Collect information and convert to HTML fragment
  #---------------------------------------------------------------------
  $Title = ".NET Framework versions"
  $subhead = @"
    <p><a name="#NET-Framework-versions"></a></p><h3 id="#NET-Framework-versions">$Title<a href="#TOC">^</a></h3>
"@
  $htmlbody += $subhead

  try
  {
    if (!$skipSoftware)
    {
      Write-Verbose "Collecting $Title"
      $software = Invoke-Command -computer $ComputerName -ScriptBlock {
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse |
        Get-ItemProperty -name Version, Release -EA 0 |
        Where { $_.PSChildName -match '^(?!S)\p{L}' } |
        Select PSChildName, Version, Release, @{
          name = "Product"
          expression = {
            switch ($_.Release)
            {
              378389 { [Version]"4.5" }
              378675 { [Version]"4.5.1" }
              378758 { [Version]"4.5.1" }
              379893 { [Version]"4.5.2" }
              393295 { [Version]"4.6" }
              393297 { [Version]"4.6" }
              394254 { [Version]"4.6.1" }
              394271 { [Version]"4.6.1" }
              394747 { [Version]"4.6.2" }
              394748 { [Version]"4.6.2" }
            }
          }
        }
      }
      $htmlbody += $software | select * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName | ConvertTo-Html -Fragment
      $htmlbody += $spacer
    }
    else
    {
      $htmlbody += "<p>Skipped</p>"
    }
  }
  catch
  {
    Write-Warning $_.Exception.Message
    $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
    $htmlbody += $spacer
  }

  #endregion doNetFramework
  #region ChocoConfig
  #---------------------------------------------------------------------
  # Collect Chocolatey software config and convert to HTML fragment
  #---------------------------------------------------------------------
  $Title = "Chocolatey Configuration"
  $subhead = "<h3>$Title</h3>"
  $subhead = @"
    <p><a name="Chocolatey-Configuration"></a></p><h3 id="Chocolatey-Configuration">$Title<a href="#TOC">^</a></h3>
"@
  $htmlbody += $subhead

  if (!$skipChocolatey)
  {
    Write-Verbose "Collecting $Title"

    try
    {

      $htmlbody += "<h4>Chocolatey Source</h4>"
      $software = Invoke-Command -ScriptBlock { choco.exe source --limitoutput } -ComputerName $ComputerName

      $rv = @()
      $software | %{
        $row = New-Object PSObject
        $tmp = $_ -split ("\|")
        $row | Add-Member NoteProperty -Name "Name" -value $tmp[0]
        $row | Add-Member NoteProperty -Name "Priority" -value $tmp[1]
        $rv += $row
      }
      $htmlbody += $rv | ConvertTo-Html -Fragment
      $htmlbody += $spacer

      # Get Source
      $htmlbody += "<h4>Chocolatey Features</h4>"
      $software = Invoke-Command -ScriptBlock { choco.exe features --limitoutput } -ComputerName $ComputerName

      $rv = @()
      $software | %{
        $row = New-Object PSObject
        $tmp = $_ -split ("\|")
        $row | Add-Member NoteProperty -Name "Name" -value $tmp[0]
        $row | Add-Member NoteProperty -Name "Description" -value $tmp[1]
        $rv += $row
      }
      $htmlbody += $rv | ConvertTo-Html -Fragment
      $htmlbody += $spacer
    }
    catch
    {
      Write-Warning $_.Exception.Message
      $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
      $htmlbody += $spacer
    }
  }
  else
  {
    $htmlbody += "<p>Skipped</p>"
  }

  #endregion ChocoConfig
  #region ChocoInfo
  #---------------------------------------------------------------------
  # Collect Chocolatey software information and convert to HTML fragment
  #---------------------------------------------------------------------
  $subhead = "<h3>Chocolatey Software Information</h3>"
  $subhead = @"
    <p><a name="Chocolatey-Software-Information"></a></p><h3 id="Chocolatey-Software-Information">Chocolatey Software Information<a href="#TOC">^</a></h3>
"@
  $htmlbody += $subhead
  if (!$skipChocolatey)
  {

    Write-Verbose "Collecting Chocolatey software information"

    try
    {
      $software = Invoke-Command -ScriptBlock { clist.exe --localonly --limitoutput } -ComputerName $ComputerName
      $rv = @()
      $software | %{
        $row = New-Object PSObject
        $tmp = $_ -split ("\|")
        $row | Add-Member NoteProperty -Name "Name" -value $tmp[0]
        $row | Add-Member NoteProperty -Name "Version" -value $tmp[1]
        $rv += $row
      }
      $htmlbody += $rv | ConvertTo-Html -Fragment
      $htmlbody += $spacer
    }
    catch
    {
      Write-Warning $_.Exception.Message
      $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
      $htmlbody += $spacer
    }
  }
  else
  {
    $htmlbody += "<p>Skipped</p>"
  }
    #endregion ChocoInfo
    #region smallworld_images
    #---------------------------------------------------------------------
    # Collect smallworld_images versions and name and convert to HTML fragment
    #---------------------------------------------------------------------
    $Title = "Smallworld Images"
    Write-Verbose "Collecting $Title information"
    $subhead = @"
    <p><a name="#smallworld_images"></a></p><h3 id="#smallworld_images">$Title<a href="#TOC">^</a></h3>
"@
    
    $htmlbody += $subhead
    
    try
    {
        $csinfo = Invoke-Command -computer $ComputerName -ScriptBlock {
            resolve-path "d:\smallworld\ched_*\images\*.msf" -ErrorAction SilentlyContinue | %{
                $info = @(Get-Content $_.path | Select-Object -skip 1 | % { $_.split("/.") });
                $fileinfo = [System.io.Fileinfo]$_.Path
                $imgObject = New-Object PSObject
                $imgObject | Add-Member NoteProperty -Name "Image Name" -Value $info[1]
                $imgObject | Add-Member NoteProperty -Name "Image sha" -Value $info[0]
                $imgObject | Add-Member NoteProperty -Name "Mod Date" -Value $fileinfo.LastWriteTime
                $imgObject
            }
        }
        $htmlbody += $csinfo | select * -ExcludeProperty RunspaceId, PSComputerName, PSShowComputerName | ConvertTo-Html -Fragment
        $htmlbody += $spacer
    }
    catch
    {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
    }
    #endregion smallworld_images
    #region ChocoOutdated
    #---------------------------------------------------------------------
    # Collect Chocolatey software information and convert to HTML fragment
    #---------------------------------------------------------------------
    $subhead = "<h3>Chocolatey Outdated Packages</h3>"
    $subhead = @"
    <p><a name="Chocolatey-Outdated-Packages"></a></p><h3 id="Chocolatey-Outdated-Packages">Chocolatey Outdated Packages<a href="#TOC">^</a></h3>
"@
    $htmlbody += $subhead
    if (!$skipChocolatey)
    {

    Write-Verbose "Collecting Chocolatey Outdated Packages"

    try
    {
        $software = Invoke-Command -ScriptBlock { choco.exe outdated --limitoutput } -ComputerName $ComputerName
        $rv = @()
        $software | %{
          $row = New-Object PSObject
          if ($_ -notlike "OutDated*" -and $_ -notlike " Output is*" -and $_ -notlike "")
          {
          $tmp = $_ -split ("\|")
          if ($tmp[1] -ne $tmp[2]) #fix for outdated over PS Remoting returning
          {
            $row | Add-Member NoteProperty -Name "Name" -value $tmp[0]
            $row | Add-Member NoteProperty -Name "Version" -value $tmp[1]
            $row | Add-Member NoteProperty -Name "VersionAvailable" -value $tmp[2]
            $row | Add-Member NoteProperty -Name "pinned" -value $tmp[3]
          }
        }
        $rv += $row
        }
        $htmlbody += $rv | ConvertTo-Html -Fragment
        $htmlbody += $spacer
      }
      catch
      {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
      }
    }
    else
    {
      $htmlbody += "<p>Skipped</p>"
    }
    #endregion ChocoOutdated
    #region OracleInfo
    #---------------------------------------------------------------------
    # Collect Oracle software information and convert to HTML fragment
    #---------------------------------------------------------------------
      $subhead = "<h3>Oracle Software Information</h3>"
      $subhead = @"
    <p><a name="Oracle-Software-Information"></a></p><h3 id="Oracle Software Information">Oracle Software Information<a href="#TOC">^</a></h3>
"@
    $htmlbody += $subhead
    if (! $skipOracle)
    {
      Write-Verbose "Collecting Oracle Software Information"
      try
      {
        $htmlbody += $spacer
        $OracleInfo = Invoke-Command -ScriptBlock {
          Get-ChildItem -Path "c:\oracle" -Filter "opatch.bat" -recurse | % {
            "<b>" + $_.fullname + "</b>"
            "<pre>"
            & $_.fullname lsinventory -detail
            "</pre>"
          }
        } -ComputerName $ComputerName
        $htmlbody += $OracleInfo | Out-String

      }
      catch
      {
        Write-Warning $_.Exception.Message
        $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
        $htmlbody += $spacer
      }
    }
    else
    {
      $htmlbody += "<p>Skipped</p>"
    }
    #endregion OracleInfo
    #region ShareInfo
    #---------------------------------------------------------------------
    # Collect Share information and convert to HTML fragment
    #---------------------------------------------------------------------

    $subhead = "<h3>Share Information</h3>"
    $subhead = @"
    <p><a name="Share-Information"></a></p><h3 id="Share-Information">Share Information<a href="#TOC">^</a></h3>
"@

    $htmlbody += $subhead

    Write-Verbose "Collecting share information"

    try
  {
      $shareinfo = Invoke-Command -computer $ComputerName -ScriptBlock { Get-WmiObject Win32_Share -ErrorAction STOP } |
      Select-Object Name, Path, Description
      $htmlbody += $shareinfo | ConvertTo-Html -Fragment
      $htmlbody += $spacer
    }
    catch
    {
      Write-Warning $_.Exception.Message
      $htmlbody += "<p>An error was encountered. $($_.Exception.Message)</p>"
      $htmlbody += $spacer
    }


    #endregion ShareInfo
    #region Collate
    #---------------------------------------------------------------------
    # Generate the HTML report and output to file
    #---------------------------------------------------------------------

    Write-Verbose "Producing HTML report"

    $reportime = Get-Date

    #Common HTML head and styles
    $htmlhead_template =@"

				    <body>
				    <h1 >Server Info: <b>$ComputerName</b></h1>
				    <p >Generated: <em>$reportime</em></h3>


<p><a name="TOC"></a></p>
<h2 id="table-of-contents">Table of Contents</h2>
<ul>
  <li><a href="#computer-dns-details">DNS Details</a></li>
  <li><a href="#computer-windows-ip-configuration">Windows IP Configuration</a></li>
  <li><a href="#computer-system-information">Computer System Information</a></li>
  <li><a href="#Operating-System-Information">Operating System Information</a></li>
  <li><a href="#Powershell-Information">Powershell Information</a></li>
  <li><a href="#Physical-Memory-Information">Physical Memory Information</a></li>
  <li><a href="#computer-system-information">Computer System Information</a></li>
  <li><a href="#PageFile-Information">PageFile Information</a></li>
  <li><a href="#BIOS-Information">BIOS Information</a></li>
  <li><a href="#Logical-Disk-Information">Logical Disk Information</a></li>
  <li><a href="#Volume-Information">Volume Information</a></li>
  <li><a href="#Network-Interface-Information">Network Interface Information</a></li>
  <li><a href="#Software-Information">Software Information</a></li>
  <li><a href="#NET-Framework-versions"</a>.NET Framework versions</li>
  <li><a href="#Chocolatey-Configuration"</a>Chocolatey Configuration</li>
  <li><a href="#Chocolatey-Software-Information">Chocolatey Software Information</a></li>
  <li><a href="#smallworld_images"</a>Smallworld Images</li>
  <li><a href="#Chocolatey-Outdated-Packages">Chocolatey Outdated Packages</a></li>
  <li><a href="#Oracle-Software-Information">Oracle Software Information</a></li>
  <li><a href="#Share-Information">Share Information</a></li>
</ul>
<p></p>
"@
    $htmltail = "</body> </html>"
    $htmlhead = "<html>" + $(Get-Content $CssPath) + $htmlhead_template
    $htmlreport = $htmlhead + $htmlbody + $htmltail
    $htmlreport | Out-File $htmlfile -Encoding Utf8
    #endregion Collate

}

End
{
    #Wrap it up
  Write-Verbose "=====> Finished  $ComputerName <====="
}
