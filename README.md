# KITS_AMS_SNIPEAGENT

chocolateyInstall.ps1:
```
$packageName = 'snipeagent-lab8'
$url = 'http://192.168.3.15:88/snipeagent-lab8.zip' #Public Web Directory 
$zipDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$extractedDir = Join-Path $zipDir "$packageName"
$checksum = "D9037FA2D6841BE02F1325D20EC18A450F4E4E9770E4512F6E709E4ABADE7B8F"
$packageArgs = @{
  packageName    = $packageName
  unzipLocation  = $extractedDir
  fileType       = 'zip'
  url            = $url
  checksum       = $checksum
  checksumType   = 'sha256'  # Adjust the checksum type as necessary
}

Install-ChocolateyZipPackage @packageArgs

if ($?) {
  $ps1Command = "Powershell.exe -Command ""$extractedDir\AssetSelfReport.ps1"" -ConfigFile ""$extractedDir\selfReportConfig.json"""

  Write-Host "Running PowerShell command: $ps1Command"
  Invoke-Expression $ps1Command
} else {
  Write-Error "Checksum verification failed. The downloaded file may be corrupted."
}
```
