<#
Template for adding to Collect-ServerInfo
#>

#---------------------------------------------------------------------
# Collect computer system information and convert to HTML fragment
#---------------------------------------------------------------------

Write-Verbose "Collecting computer system information"

$subhead = "<h3>Computer System Information</h3>"
$htmlbody += $subhead

try
{
  $csinfo = Get-WmiObject Win32_ComputerSystem -ComputerName $ComputerName -ErrorAction STOP |
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

