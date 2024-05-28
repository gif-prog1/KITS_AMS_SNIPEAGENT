param (
    [Object]$ConfigFile=''
)
Clear-Host;
$art = @"
______     ______   ______        ______     __    __     ______   
/\  ___\   /\__  _\ /\  ___\      /\  __ \   /\ "-./  \   /\  ___\  
\ \ \____  \/_/\ \/ \ \ \____     \ \  __ \  \ \ \-./\ \  \ \___  \ 
 \ \_____\    \ \_\  \ \_____\     \ \_\ \_\  \ \_\ \ \_\  \/\_____\
  \/_____/     \/_/   \/_____/      \/_/\/_/   \/_/  \/_/   \/_____/                                                                                                                                                                                                                                                                                                                 

Running the script to add/update the system to the Asset Inventory...
"@

Write-host $art;

#To run the script
#Powershell.exe -Command "C:\Users\KIDS*\Desktop\Asset-Self-Reporting-Tool-for-SnipeIT-main\Asset-Self-Reporting-Tool-for-SnipeIT-main\AssetSelfReport.ps1" -ConfigFile "C:\Users\KIDS*\Desktop\Asset-Self-Reporting-Tool-for-SnipeIT-main\Asset-Self-Reporting-Tool-for-SnipeIT-main\selfReportConfig.json"



########################################################################################################################################################################################################
# Remove Stale Variables 
########################################################################################################################################################################################################
Remove-Variable -Name DataHashTable -ErrorAction 'SilentlyContinue';
Remove-Variable -Name DataObject -ErrorAction 'SilentlyContinue';
Remove-Variable -Name Record -ErrorAction 'SilentlyContinue';
Remove-Variable -Name EmailParams -ErrorAction 'SilentlyContinue';
Remove-Variable -Name Config -ErrorAction 'SilentlyContinue';


########################################################################################################################################################################################################
# Static Variables 
########################################################################################################################################################################################################
Write-host "Assigning variables..."

If (!$ConfigFile) { Exit 1; }
$Config = (Get-Content $ConfigFile) | ConvertFrom-Json;

$Snipe = $Config.Snipe;


$StartTime = Get-Date;

$DeviceName = hostname;
[HashTable]$DataHashTable = @{};
$Win32_BIOS = Get-WMIObject -Class Win32_BIOS;
$Win32_BaseBoard = Get-WmiObject -Class Win32_BaseBoard;

$RandomNumber = (Get-Random -Minimum 0 -Maximum 8)*15;

########################################################################################################################################################################################################
# Static Variables 
########################################################################################################################################################################################################
$SerialNumber = (Get-WmiObject -class win32_bios).SerialNumber
$DataHashTable.Add('SerialNumber', $SerialNumber);
$Win32_ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem;
$CustomValues = @{};
########################################################################################################################################################################################################
# Functions
########################################################################################################################################################################################################

Function GetHRSize {
    param( [INT64] $bytes )
    Process {
        If ( $bytes -gt 1pb ) { "{0:N1}PB" -f ($bytes / 1pb) }
        ElseIf ( $bytes -gt 1tb ) { "{0:N1}TB" -f ($bytes / 1tb) }
        ElseIf ( $bytes -gt 1gb ) { "{0:N1}GB" -f ($bytes / 1gb) }
        ElseIf ( $bytes -gt 1mb ) { "{0:N1}MB" -f ($bytes / 1mb) }
        ElseIf ( $bytes -gt 1kb ) { "{0:N1}KB" -f ($bytes / 1kb) }
        Else   { "{0:N} Bytes" -f $bytes }
    }
}

########################################################################################################################################################################################################
# Package Requirements 
########################################################################################################################################################################################################
'NuGet' | ForEach-Object {
        If (-NOT (Get-PackageProvider -ListAvailable -Name $_ -ErrorAction SilentlyContinue)) {
        Install-PackageProvider $_ -Confirm:$false -Force:$true;
    } Else {
        $Installed = [String](Get-PackageProvider -ListAvailable -Name $_ | Select-Object -First 1).Version;
        $Latest = [String](Find-PackageProvider -Name $_ | Sort-Object Version -Descending| Select-Object -First 1).version;
        If ([System.Version]$Latest -gt [System.Version]$Installed) {
            Install-PackageProvider $_ -Confirm:$false -Force:$true;
        }
    }
}


########################################################################################################################################################################################################
# Modules Requirements 
########################################################################################################################################################################################################

If ($Win32_ComputerSystem.Manufacturer -eq "Dell") { 
    $RequiredModules = 'SnipeitPS', 'DellBIOSProvider', 'ActiveDirectory', 'PSWindowsUpdate'; 
} Else {
    $RequiredModules = 'SnipeitPS', 'PSWindowsUpdate', 'ActiveDirectory';
}
$RequiredModules | ForEach-Object {
    Try {
        $Mdle = $_;
        If (!(Get-Module -ListAvailable -Name $Mdle)) {
            If ($Mdle -eq 'ActiveDirectory') {
                Try {
                    Install-WindowsFeature RSAT-AD-PowerShell;
                } Catch {
                    Add-WindowsCapability –Online –Name “Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0”;
                }
            } Else { Install-Module -Name $Mdle -Force; }
        } ElseIf ($Mdle -ne 'ActiveDirectory') {
            $Latest = [String](Find-Module -Name $Mdle | Sort-Object Version -Descending)[0].version;
            $Installed = [String](Get-Module -ListAvailable $Mdle | Select-Object -First 1).version;
            If ([System.Version]$Latest -gt [System.Version]$Installed) {
                Update-Module -Name $Mdle -Force;
            }
        }
        Try { Import-Module -Name $Mdle -Force; }
        Catch {
            
        }
    } Catch {  }
}

########################################################################################################################################################################################################
# General Device Information
########################################################################################################################################################################################################
Write-host "Gathering General information..."
#$Location = "$(($DeviceName).Split("-")[0])-$(($DeviceName).Split("-")[1])";
$DataHashTable.Add('Location', $Snipe.Location);
$DataHashTable.Add('DeviceName', $($DeviceName));
$DataHashTable.Add('LastReported', (Get-Date));
$DataHashTable.Add('LastReportedUnix', ([Math]::Round((Get-Date -UFormat %s),0)));
If ($Win32_ComputerSystem.Model -eq "System Product Name") {
    $DataHashTable.Add('Model', $Win32_BaseBoard.Product);
} Else { $DataHashTable.Add('Model', $Win32_ComputerSystem.Model); }
$DataHashTable.Add('Manufacturer', "$($Win32_ComputerSystem.Manufacturer -replace " Inc.", '')");
$DataHashTable.Add('Bios', $Win32_BIOS.SMBIOSBIOSVersion);

########################################################################################################################################################################################################
# Operating System Information
########################################################################################################################################################################################################
Write-host "Gathering OS information..."
$Win32_OperatingSystem = Get-WmiObject -Class Win32_OperatingSystem;
$DataHashTable.Add('OS', ($Win32_OperatingSystem.Name).Split("|")[0]);
$DataHashTable.Add('Build', $Win32_OperatingSystem.Version);
If ($DataHashTable['OS'] -Contains "Server") { $ModelCatID = $Snipe.ServerCatID; }

########################################################################################################################################################################################################
# Network Adapter Configurations
########################################################################################################################################################################################################
Write-host "Gathering NIC (IP,MAC) information..."
$MacAddress = @();
$IpAddress = @();
$NetworkAdapters = @();
Get-NetAdapter | Where-Object { $_.Name -NotLike "*bluetooth*" } | ForEach-Object {
    $IfcDesc = $_.InterfaceDescription -replace "\([^\)]+\)",'' -replace '  ',' ';
    $NetworkAdapters += "[$($_.ifIndex)] $($_.LinkSpeed) - $($IfcDesc)";
    $MacAddress += "$($_.MacAddress -replace '-',':') [$($_.ifIndex)]";
    If ($_.Status -eq 'Up') {
        $InterfaceAlias = "$($_.Name)";
        $IpAddress += "$((Get-NetIpAddress | Where-Object { $_.AddressFamily -Like "IPv4" -and $_.InterfaceAlias -eq $InterfaceAlias; }).IPAddress) [$($_.ifIndex)]";
    }
}
$MacAddress = $MacAddress -join "`n";
$IpAddress = $IpAddress -join "`n";
$NetworkAdapters = $NetworkAdapters -join "`n";
$DataHashTable.Add('IpAddress', $IpAddress);
$DataHashTable.Add('MacAddress', $MacAddress);
$DataHashTable.Add('NetworkAdapters', $NetworkAdapters);
Switch ((Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Sort-Object -Property Index | Where-Object { $_.IPAddress } | Select-Object -First 1).DHCPEnabled) {
    "True" { $DataHashTable.Add('DHCP', "Enabled"); Break; }
    "False" { $DataHashTable.Add('DHCP', "Disabled"); Break; }
}


########################################################################################################################################################################################################
# Group Access
########################################################################################################################################################################################################
$LocalAdministrators = Get-LocalGroupMember -Group "Administrators";
$DataHashTable.Add('LocalAdmins', ($LocalAdministrators).Name -join "`n");
$RemoteDesktopUsers = Get-LocalGroupMember -Group "Remote Desktop Users";
$DataHashTable.Add('RemoteUsers', ($RemoteDesktopUsers).Name -join "`n");

########################################################################################################################################################################################################
# Drive Configuration Collection 
########################################################################################################################################################################################################
Write-host "Gathering Internal and External Drive Information...";
Remove-Variable -Name InternalMedia -ErrorAction SilentlyContinue;
Remove-Variable -Name RemovableMedia -ErrorAction SilentlyContinue;
$DiskDrives = Get-WmiObject Win32_DiskDrive -Property * | Sort-Object DeviceID;
$DiskVolumes = Get-Volume | Sort-Object Index;
$PhysicalDisks = Get-PhysicalDisk;
$InternalDisks = @();
$InternalMedia = @();
$RemovableMedia = @();
$UnhealthyDisks = @();
$LowSpaceDrives = @();
ForEach ($Disk in $DiskDrives) {
    Remove-Variable -Name DiskInfo -ErrorAction SilentlyContinue;
    Remove-Variable -Name DriveType -ErrorAction SilentlyContinue;
    $PhysicalDisk = ($PhysicalDisks | Where-Object { $_.DeviceID -eq (($Disk.DeviceID).substring((($Disk.DeviceID).Length)-1)) });
    Switch ($PhysicalDisk.MediaType) {
        'Unspecified' { $Disk.MediaType = 'USB'; Break; }
        'External hard disk media' { $Disk.MediaType = 'HDD'; Break; }
        default { $Disk.MediaType = $PhysicalDisk.MediaType; }
    }
    If ($PhysicalDisk.BusType -eq $Disk.MediaType) { $DiskType = $PhysicalDisk.BusType; }
    If ($PhysicalDisk.HealthStatus -ne 'Healthy') { $UnhealthyDisks += $PhysicalDisk; }
    Else { $DiskType = "$($Disk.MediaType)-$($PhysicalDisk.BusType)"; }
    $DiskInfo = "Disk$($Disk.Index): [$($DiskType)] $($Disk.Model) ($(GetHRSize $Disk.size))`n";
    $PartitionQuery = 'ASSOCIATORS OF {Win32_DiskDrive.DeviceID="'+$($Disk.DeviceID.replace('\','\\'))+'"} WHERE AssocClass=Win32_DiskDriveToDiskPartition';
    $WmiPartitions = @(Get-WmiObject -Query $PartitionQuery | Sort-Object StartingOffset);
    ForEach ($Partition in $WmiPartitions) {
        $DiskInfo += "---- Part$($Partition.Index): $(GetHRSize $Partition.Size) $($Partition.Type)`n";
        $VolumeQuery = 'ASSOCIATORS OF {Win32_DiskPartition.DeviceID="'+$Partition.DeviceID+'"} WHERE AssocClass=Win32_LogicalDiskToPartition';
        $WmiVolumes   = @(Get-WmiObject -Query $VolumeQuery);
        ForEach ($Volume in $WmiVolumes) {
            $VolumeData = "$($Volume.name) [$($Volume.FileSystem)] $((GetHRSize ($Volume.Size - $Volume.FreeSpace)) -replace "GB",'')/$(GetHRSize $Volume.Size) ($(GetHRSize ($Volume.FreeSpace)) Free)"
            If ($Volume.name -eq 'C:') {
                $DataHashTable.Add('BootDrive', "$($Volume.name) [$($DiskType)] $((GetHRSize ($Volume.Size - $Volume.FreeSpace)) -replace "GB",'')/$(GetHRSize $Volume.Size) ($(GetHRSize ($Volume.FreeSpace)) Free)");
                $DataHashTable.Add('HasSSD', ('Yes','No')[($Disk.MediaType -ne 'SSD')]);
            }
            $DiskVolume = ($DiskVolumes | Where-Object { $_.Driveletter -eq ($Volume.DeviceID -replace ":",'') });
            $DriveType = @($DiskVolume.DriveType,'Removable')[($PhysicalDisk.BusType -eq 'USB')]
            $DiskInfo += "--------- $VolumeData`n";
            If ($DriveType -ne 'Removable' -AND (($DiskVolume.SizeRemaining / $DiskVolume.Size) -lt .1)) {
                $LowSpaceDrives += [PSCustomObject]@{
                    Drive = $DiskVolume.DriveLetter;
                    SpaceAvailable = $DiskVolume.SizeRemaining;
                    TotalSize = $DiskVolume.Size;
                } 
            }
        }
    }
    Switch ($DriveType) {
        "Removable" { $RemovableMedia += $DiskInfo.Trim(); Break; }
        default { 
            $InternalDisks += "[$($Disk.MediaType)] $($Disk.Model) ($(GetHRSize $Disk.size))";
            $InternalMedia += $DiskInfo.Trim(); Break; 
        }
    }
}
$DataHashTable.Add('Drives', $InternalDisks -join "`n");
$DataHashTable.Add('InternalMedia', $InternalMedia -join "`n");
$DataHashTable.Add('RemovableMedia', $RemovableMedia -join "`n");
If ($LowSpaceDrives.Count -gt 0) { 
    $LastStorageAlert = Get-Content $StorageAlertLog | ConvertFrom-Json;
    $TimeSinceLastStorageAlert = New-TimeSpan -Start (Get-Date -Date $LastStorageAlert.Last_Notified) -End (Get-Date);
    $StorageNotification = [PSCustomObject]@{
        'Drives' = $LowSpaceDrives;
        'Last_Notified' = (Get-Date).DateTime;
    }
    If (!$TimeSinceLastStorageAlert -OR (($StorageNotification.Drives).Drive | Out-String) -ne (($LastStorageAlert.Drives).Drive | Out-String) -OR $TimeSinceLastStorageAlert.TotalDays -gt 30) {
        Set-Content -Path $StorageAlertLog -Value ($StorageNotification | ConvertTo-Json)
    }
}
If ($UnhealthyDisks.Count -gt 0) { EmailAlert -Subject "Unhealthy Drive(s) Detected" -Body "$($UnhealthyDisks | Format-List | Out-String)"; }

########################################################################################################################################################################################################
# GPU IdentIfication
########################################################################################################################################################################################################
Write-host "Gathering GPU Information..."
$GraphicsCard = (Get-PnpDevice | Where-Object {$_.Class -eq "Display" -AND $_.Status -eq 'OK'} | 
                    Get-PnpDeviceProperty | Where-Object { $_.Keyname -eq "DEVPKEY_NAME" } | 
                    Where-Object { $_.Data -ne "Microsoft Remote Display Adapter" } | 
                    Sort-Object -Property Data).Data -join "`n";
Switch ($true) {
    ($null -ne $GraphicsCard) { $DataHashTable.Add('Graphics', "$($GraphicsCard)"); Break; } 
    default { $DataHashTable.Add('Graphics', ''); }
}


########################################################################################################################################################################################################
# RAM/Memory
########################################################################################################################################################################################################
Write-host "Gathering RAM Information..."
$Memory = Get-WmiObject -Class Win32_PhysicalMemory | Select-Object * -First 1;
$MemoryVoltage = $Memory.ConfiguredVoltage;
If (-NOT ($MemorySpeed)) { $MemorySpeed = "$($Memory.Speed)MHz"; }
If (-NOT ($MemoryType)) { 
    Switch ($MemoryVoltage) { 
        '1200' { $MemoryType = "DDR4"; } 
        '1500' { $MemoryType = "DDR3"; } 
        default { $MemoryType = ''; } 
    }
}
$Memory = Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum;

$MemoryAvailable = [math]::Round(($Win32_OperatingSystem.FreePhysicalMemory / 1MB),1);
$MemoryUsed = [math]::Round((($Memory.Sum / 1gb)-($Win32_OperatingSystem.FreePhysicalMemory / 1MB)),1);
$MemoryInstalled = "$($Memory.Sum / 1gb)GB";

$DataHashTable.Add('RAM', "$($MemoryUsed)/$($MemoryInstalled) [$($Memory.Count)] $($MemorySpeed) $($MemoryType)");
$DataHashTable.Add('RAM_Installed', "$($MemoryInstalled) [$($Memory.Count)]");

If ([int]$MemoryAvailable -lt 1 -AND $DataHashTable['Model'] -ne "Virtual Machine") {
    $LastRamAlert = Get-Content $RamAlertLog | ConvertFrom-Json;
    $TimeSinceLastRamAlert = New-TimeSpan -Start (Get-Date -Date $LastRamAlert.Last_Notified) -End (Get-Date);
    If (!$TimeSinceLastRamAlert -OR $TimeSinceLastRamAlert.TotalDays -gt 30) {
        $RamNotification = [PSCustomObject]@{
            'RAM_Installed' = "$($MemoryInstalled) [$($Memory.Count)]";
            'RAM_Available' = "$($MemoryAvailable)Gb";
            'Last_Notified' = (Get-Date).DateTime;
            'Previous_Notification' = $LastRamAlert.Last_Notified;
        }
        #EmailAlert -Subject "Low RAM Availability" -Body "$($RamNotification | Format-List | Out-String)";
        Set-Content -Path $RamAlertLog -Value ($RamNotification | ConvertTo-Json)
    }
}


########################################################################################################################################################################################################
# CPU/Processor
########################################################################################################################################################################################################
Write-host "Gathering CPU Information..."
$Win32_Processor = (Get-WmiObject Win32_Processor | Select-Object *);
If ($Win32_Processor.Count -gt 1) { 
    $Win32_Processor = $Win32_Processor[0]; 
    $Win32_Processor.Name = "[2] $($Win32_Processor.Name)"; 
}
If ($Win32_Processor.Name -like "AMD*") {
    $AssetProcessor = ($Win32_Processor.Name -replace '16-Core Processor|12-Core Processor','').Trim();
    $AssetProcessor = $AssetProcessor += " $($Win32_Processor.NumberOfCores)c/$($Win32_Processor.NumberOfLogicalProcessors)t";
    $AssetProcessor = $AssetProcessor += " $([math]::Round(($Win32_Processor.CurrentClockSpeed/1000),2))GHz";
    $DataHashTable.Add('CPU', $AssetProcessor);
} ElseIf ($Win32_Processor.Name -like "Intel*") {
    $AssetProcessor = ($Win32_Processor.Name -replace '\(TM\)|\(R\)','');
    $AssetProcessor = ($AssetProcessor -replace '@',"$($Win32_Processor.NumberOfCores)c/$($Win32_Processor.NumberOfLogicalProcessors)t");
    $AssetProcessor = ($AssetProcessor -replace '  | 0 ',' ');
    $DataHashTable.Add('CPU', $AssetProcessor);
} Else { $DataHashTable.Add('CPU', $Win32_Processor.Name); }


########################################################################################################################################################################################################
# Update SnipeIT 
########################################################################################################################################################################################################
Start-Sleep -Seconds $RandomNumber;
Connect-SnipeitPS -URL $Snipe.Url -apiKey $Snipe.Token;
$SnipeAsset = Get-SnipeItAsset -asset_serial $DataHashTable['SerialNumber'];
If ($SnipeAsset.StatusCode -eq 'InternalServerError') {
    $SnipeAsset = Get-SnipeItAsset -asset_serial $DataHashTable['SerialNumber'];
    If ($SnipeAsset.StatusCode -eq 'InternalServerError') {
        Exit 0;
    }
}

$CustomValues.Add('_snipeit_mac_address_7', $DataHashTable['MacAddress']);
$CustomValues.Add('_snipeit_cpu_8', $DataHashTable['CPU']);
$CustomValues.Add('_snipeit_ram_9', $DataHashTable['RAM']);
$CustomValues.Add('_snipeit_os_10', $DataHashTable['OS']);
$CustomValues.Add('_snipeit_ip_address_6', $DataHashTable['IpAddress']);
$CustomValues.Add('_snipeit_bios_12', $DataHashTable['Bios']);
$CustomValues.Add('_snipeit_graphics_13', $DataHashTable['Graphics']);
$CustomValues.Add('_snipeit_boot_drive_14', $DataHashTable['BootDrive']);
$CustomValues.Add('_snipeit_internal_media_15', $DataHashTable['InternalMedia']);
$CustomValues.Add('_snipeit_network_adapters_19', $DataHashTable['NetworkAdapters']);
$NextAuditDate = Get-Date;
If ($NextAuditDate.Month -ne 1) {
    $NextAuditDate = New-Object DateTime(($NextAuditDate.Year+1), 1, [DateTime]::DaysInMonth($NextAuditDate.Year, $NextAuditDate.Month))
    $Diff = ([int] [DayOfWeek]::Friday) - ([int]$lastDay.DayOfWeek);
    $NextAuditDate = @((Get-Date -Date $NextAuditDate.AddDays($Diff)),(Get-Date -Date $NextAuditDate.AddDays(- (7-$Diff))))[($Diff -ge 0)];
    $CustomValues.Add('next_audit_date', ($NextAuditDate | Get-Date -UFormat "%Y-%m-%d"));
}
If (!$SnipeAsset) {
    Try {
        Try {
            $Manufacturer = Get-SnipeItManufacturer -search $DataHashTable['Manufacturer'];
            If (!$Manufacturer) { $Manufacturer = New-SnipeItManufacturer -name $DataHashTable['Manufacturer']; }
            $ManufacturerID = $Manufacturer.id;
        } Catch { Write-host "[SnipeIT] [ERROR] Unable to obtain Manufacturer ID."; }
        Try {
            $Model = Get-SnipeItModel -all | Where-Object { $_.name -eq "$($DataHashTable['Model'])" };
            If (!$Model) {
                If ($DataHashTable['OS'] -Contains "Server") { $ModelCatID = $Snipe.ServerCatID; } 
                Else { $ModelCatID = $Snipe.WorkstationCatID; }
                $Model = New-SnipeItModel -name $DataHashTable['Model'] -manufacturer_id $ManufacturerID -fieldset_id $Snipe.FieldSetID -category_id $ModelCatID;
            } Else {
                $ModelData = $Model.notes -replace "&quot;",'"' | ConvertFrom-Json;
                If ($ModelData.LatestBios -gt $DataHashTable['Bios']) {
                    ##########################################
                }
            }
            
        } Catch { write-host "[SnipeIT] [ERROR] Unable to obtain Model ID." ; }
        $SnipeAsset = New-SnipeItAsset -name $DataHashTable['DeviceName'] -status_id 2 -model_id $Model.id -serial $DataHashTable['SerialNumber'] -asset_tag $DataHashTable['SerialNumber'] -customfields $CustomValues;
        write-host "[SnipeIT] Created a new Asset in SnipeIT.";
    } Catch { write-host "[SnipeIT] [ERROR] Unable to Create new Asset."; }
} ElseIf ($SnipeAsset.Count -gt 1) {
    Write-Host "[ERROR] Multiple Assets with Identical Serial Numbers Found in SnipeIT.";
} Else {
    $UserAssigned = $SnipeAsset.assigned_to.username;
    $RemoteUsers = ($RemoteDesktopUsers | Where-Object { $_.ObjectClass -ne 'Group' } | Select-Object -Property @{ Name="Name"; Expression={ ($_.Name).Split("\")[1] } }).Name;
    If ($RemoteUsers -NotContains $UserAssigned) {
        Write-Host "Adding $($UserAssigned) to local Remote Desktop Users Group...";
        Add-LocalGroupMember -Group "Remote Desktop Users" -Member $UserAssigned;
        $DataHashTable['RemoteUsers'] = (Get-LocalGroupMember -Group "Remote Desktop Users").Name -join "`n";
    }
    If ($RemoteUsers.Count -gt 1) {
        write-host "Found more than one user assigned to the local Remote Desktop Users Group...";
        $UnauthorizedRemoteUsers = $RemoteUsers | Where-Object { $_ -ne $UserAssigned }
        $UnauthorizedRemoteUsers | Get-ADUser | ForEach-Object {
            Write-Host "Removed $($_.SamAccountName) from the local Remote Desktop Users Group...";
            Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $_.SamAccountName;
            $DataHashTable['RemoteUsers'] = (Get-LocalGroupMember -Group "Remote Desktop Users").Name -join "`n";
        }
    }
    # Check Asset Tag
    If ($SnipeAsset.asset_tag) { $DataHashTable.Add('AssetTag', $SnipeAsset.asset_tag); }


    # Check License Software
    Write-host "Checking Installed Software against Inventory...";
    $AssetData = $($SnipeAsset | Select-Object @{N='Name';E={$_.name}},@{N='AssetTag';E={$_.asset_tag}},@{N='Serial';E={$_.serial}},@{N='AssignedTo'; E={$_.assigned_to.username}} | Format-List | Out-String);
    If ($null -ne $InstalledSoftware) {
        $InstalledSoftware | ForEach-Object {
            $SW = ($_).Split('-')[0].Trim();
        }
    }
    # Audit Assigned Licenses
    $AssignedLicenses = Get-SnipeItLicense -asset_id $SnipeAsset.id;
    If ($AssignedLicenses) {

    }
    # Update Asset
    Try {
        $UpdatedAsset = Set-SnipeItAsset -name $DataHashTable['DeviceName'] -id $SnipeAsset.id -status_id $Snipe.DefStatusID -rtd_location_id $Snipe.Location -customfields $CustomValues;
        Write-Host "[SnipeIT] Updated an Asset in SnipeIT.";
        $SnipeAsset = $UpdatedAsset;
    } Catch { Write-host "[ERROR] Unable to Update SnipeIT Asset."; }
}

#########################################
# Th-th-th-th-that's all folks! 
#########################################
Write-Host "Script Completed in $([math]::Round((New-TimeSpan -Start $StartTime -End (Get-Date)).TotalSeconds, 1)) Seconds";
#exit 0;
#[Environment]::Exit(0);
