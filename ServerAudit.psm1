# ServerAudit.psm1

function DHCPCredentials {
    try {
        $DHCPCredentials = Get-DhcpServerDnsCredential -ErrorAction SilentlyContinue
        if ($DHCPCredentials.UserName) {
            return "$($DHCPCredentials.DomainName)\$($DHCPCredentials.UserName)"
        }
        else {
            return 'N/A'
        }
    }
    catch {
        return 'N/A'
    }
}

function ShadowCopy {
    $volumes = @{}
    $allvolumes = Get-CimInstance win32_volume -ComputerName $env:COMPUTERNAME -Property DeviceID, Name
    foreach ($v in $allvolumes) {
        $volumes.add($v.DeviceID, $v.Name)
    }

    $shadows = Get-CimInstance -Class "Win32_ShadowCopy"
    $shadowcopy = "Drive,Date`n"

    foreach ($copy in $shadows) {
        $date = $copy.InstallDate
        $shadowcopy += "$($volumes.Item($copy.VolumeName)),$date`n"
    }

    $result = $shadowcopy | ConvertFrom-Csv | Sort-Object -Property date -Descending | Sort-Object -Property drive -Unique
    
    return $result
}

function StaticIP {
    $NAC = Get-NetAdapter -Physical | Where-Object { $_.MediaConnectionState -eq 'Connected' } | Select-Object ifIndex, MacAddress
    $DHCP = Get-NetIPInterface -ifindex $NAC.ifIndex -AddressFamily IPv4
    $IP = Get-NetIPAddress -InterfaceIndex $NAC.ifIndex -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress
    
    if ($DHCP.Dhcp -eq "Disabled") {
        $IsStatic = $true
    }
    else {
        $IsStatic = $false
    }

    $result = @{
        IsStatic   = $IsStatic
        IPAddress  = $IP
        MacAddress = $NAC.MacAddress
    }

    [PSCustomObject]$result
}

function DuplicatesDNS {
    $Zone = try { Get-DnsServerResourceRecord -ZoneName $Env:USERDNSDOMAIN -RRType A } catch { $false }
    if ($Zone -ne $false) {

        $DNSTable = foreach ($Record in $Zone) {
            [pscustomobject]@{
                Hostname  = $Record.hostname
                Timestamp = $Record.Timestamp
                IPAddress = $([system.version]($Record.RecordData.ipv4address.IPAddressToString))
            }    
        }
    
        $Duplicates = @()
        $DNSUnique = $DNSTable | Sort-Object Timestamp | Sort-Object -Unique IPAddress
        foreach ($ip in $DNSTable) {
            if ($ip.Hostname -notin $DNSUnique.Hostname -and $ip.IPAddress -notin (Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress)) { $Duplicates += $ip }
        }
    }

    return $(if ($Duplicates.count -gt 0) {$true} else {$false})
}

function EventLog_System {
    $StartTime = (Get-Date).AddDays(-7)

    $Logs = (Get-WinEvent -LogName 'System' | Where-Object { $_.LevelDisplayName -eq 'Error' -and $_.TimeCreated -gt $StartTime -or $_.LevelDisplayName -eq 'Critical' -and $_.TimeCreated -gt $StartTime }) 2>$null

    try { $ID = ([string]($Logs.id | Sort-Object -Unique)).Replace(" ", ",") } catch {}

    if ($ID) {
        $ID
    }
    else {
        return 'N/A'
    }
}

function EventLog_Security {
    $StartTime = (Get-Date).AddDays(-7)

    $Logs = (Get-WinEvent -LogName 'Security' | Where-Object { $_.LevelDisplayName -eq 'Error' -and $_.TimeCreated -gt $StartTime -or $_.LevelDisplayName -eq 'Critical' -and $_.TimeCreated -gt $StartTime }) 2>$null

    try { $ID = ([string]($Logs.id | Sort-Object -Unique)).Replace(" ", ",") } catch {}

    if ($ID) {
        return $ID
    }
    else {
        return 'N/A'
    }
}

function ReplicationLog {
    $StartTime = (Get-Date).AddDays(-7)

    $Logs = Get-WinEvent -ProviderName *dfs* | Where-Object { $_.LevelDisplayName -eq 'Error' -and $_.TimeCreated -gt $StartTime -or $_.LevelDisplayName -eq 'Critical' -and $_.TimeCreated -gt $StartTime -or $_.LevelDisplayName -eq 'Warning' -and $_.TimeCreated -lt $StartTime }

    try { $ID = ([string]($Logs.id | Sort-Object -Unique)).Replace(" ", ",") } catch {}

    if ($ID) {
        $ID
    }
    else {
        return 'N/A'
    }
}

function UPS {
    $UpsDevice = get-pnpDevice -FriendlyName *battery*
    if ($UpsDevice.Status -match 'OK') {
        return $true
    }
    else {
        return $false
    }
}

function Get-MachineType {
    $VM = $false
    $Platform = ''

    $ComputerSystemInfo = Get-CimInstance -Class Win32_ComputerSystem
    switch ($ComputerSystemInfo.Model) { 

        "VMware Virtual Platform" { 
            $Platform = "VMware"
            $VM = $true
            Break 
        } 

        "VirtualBox" { 
            $Platform = "Oracle - VirtualBox"
            $VM = $true
            Break 
        } 
        default { 

            switch ($ComputerSystemInfo.Manufacturer) {

                "Xen" {
                    $Platform = "Xen"
                    $VM = $true
                    Break
                }

                "VMware, Inc." {
                    $Platform = "VMware"
                    $VM = $true
                    Break
                }

                "QEMU" {
                    $Platform = "KVM"
                    $VM = $true
                    Break
                }
                "Microsoft Corporation" { 
                    if (get-service WindowsAzureGuestAgent -ErrorAction SilentlyContinue) {
                        $Platform = "Azure"
                    }
                    else {
                        $Platform = "Hyper-V"
                    }
                    $VM = $true
                    Break
                }
                "Google" {
                    $Platform = "Google Cloud"
                    $VM = $true
                    Break
                }

                default { 
                    if ((((Get-CimInstance -query "select uuid from Win32_ComputerSystemProduct" | Select-Object UUID).UUID).substring(0, 3) ) -match "EC2") {
                        $Platform = "AWS"
                        $VM = $true
                    }
                    else {
                        $Platform = "Physical"
                        $VM = $false
                    }
                } 
            }                  
        } 
    } 
    return "{IsVM: '$VM', Platform: '$Platform'}" | ConvertFrom-Json
}

function HyperV {
    try { $VMS = Get-VM } catch {}
    
    $VMHost = $false
    $HasSnapshots = $false
    $SnapshotList = @()
    $enable = @()

    if ($VMS) {
        $VMHost = $true
        $Check = 0
        
        foreach ($VM in $VMS) {
            try {
                $Snapshot = Get-VMSnapshot -VMName $VM.Name
                if ($Snapshot) {
                    $SnapshotDetails = @{
                        Name = $VM.Name
                        Date = $Snapshot.CreationTime
                    }
                    $SnapshotList += $SnapshotDetails
                    $Check += 1
                }

                $IntegrationServices = (Get-VMIntegrationService -VMName $VM.Name | Select-Object -ExpandProperty Enabled) -notcontains $false
                $enable += $IntegrationServices
            }
            catch {}
        }

        $HasSnapshots = $Check -ge 1
        $enable = $enable -notcontains $false
    }

    $result = [PSCustomObject]@{
        "VM Host"              = $VMHost
        "Has Snapshots"        = $HasSnapshots
        "Snapshots"            = $SnapshotList
        "Integration Services" = $enable
    }

    return $result
}

function EsetAgent {
    try { $Status = (eshell get status).Replace("  ", "|").Replace("|", "") } catch { }
    if ($Status) {
        $a = [ordered]@{}
        foreach ($Line in $Status) {
            if ($Line -match ":") {
                $Line = $Line.Split(":").Trim()
                $a.Add($Line[0], $Line[1].Split(" ")[0])
            }
        }
        $a | ConvertTo-Json | ConvertFrom-Json
    }
}
