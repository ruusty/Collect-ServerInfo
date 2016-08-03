<#
Template for adding to Collect-ServerInfo
#>

#region __xyz__
#---------------------------------------------------------------------
# Collect __xyz__ information and convert to HTML fragment
#---------------------------------------------------------------------
$Title = "__xyz__"
Write-Verbose "Collecting __xyz__ information"
$subhead = @"
    <p><a name="#__xyz__"></a></p><h3 id="#__xyz__">$Title<a href="#TOC">^</a></h3>
"@

$htmlbody += $subhead

try
{
    $csinfo = Invoke-Command -computer $ComputerName -ScriptBlock { Get-WmiObject Win32_ComputerSystem -ErrorAction STOP } |
  Select-Object Name, Manufacturer, Model,
                @{ Name = 'Physical Processors'; Expression = { $_.NumberOfProcessors } },
                @{ Name = 'Logical Processors'; Expression = { $_.NumberOfLogicalProcessors } },
                @{ Name = 'Total Physical Memory (Gb)'; Expression = {      $tpm = $_.TotalPhysicalMemory/1GB;"{0:F0}" -f $tpm }},
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

#endregion __xyz__

and in the Collate region
<li><a href="#__xyz__"</a>__xyz__</li>