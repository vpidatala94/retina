#Requires -RunAsAdministrator

Function Assert-SoftwareInstalled
{
   [cmdletbinding(DefaultParameterSetName='Software')]

   Param
   (
      [Parameter(ParameterSetName='Service',Mandatory=$true)]
      [ValidateScript({-Not [String]::IsNullOrWhiteSpace($_)})]
      [String] $ServiceName,

      [Parameter(ParameterSetName='Service',Mandatory=$false)]
      [ValidateSet($null,'Running','Stopped')]
      [String] $ServiceState,

      [Parameter(ParameterSetName='Software',Mandatory=$true)]
      [ValidateScript({-Not [String]::IsNullOrWhiteSpace($_)})]
      [String] $SoftwareName,

      [Parameter(ParameterSetName='Software',Mandatory=$false)]
      [String] $SoftwareVersion,

      [Parameter(ParameterSetName='Service',Mandatory=$false)]
      [Parameter(ParameterSetName='Software',Mandatory=$false)]
      [Switch] $Silent
   )

   [String] $name = If($ServiceName) {"$($ServiceName)"}Else{"$($SoftwareName)"}

   If(-Not $Silent.IsPresent)
   {
       Write-Host -Object:"Checking if $($name) is installed ..."
   }

   [Boolean] $isInstalled = $false

   Try
   {
      If($SoftwareName)
      {
         $software = Get-WmiObject -Class:'Win32_Product' | Where-Object -Property:'Name' -like "*$($SoftwareName)*"

         If($software -And
            (-Not [String]::IsNullOrWhiteSpace($SoftwareVersion)))
         {
            $software = $software | Where-Object -Property:'Version' -like "*$($SoftwareVersion)*"
         }

         If($software)
         {
           $isInstalled = $true
         }
      }
      ElseIF($ServiceName)
      {
        [Object] $state = Get-Service -Name:"$($ServiceName)" -ErrorAction:'SilentlyContinue'
        If($state)
        {
           $isInstalled = $true

           If($ServiceState -And
              -Not ($state.Status -INE $ServiceState))
           {
              Write-Warning -Message:"`t$ServiceName is $$(state.Status)"
           }
        }
      }
   }
   Catch
   {

   }

   If(-Not $Silent.IsPresent)
   {
      If($isInstalled)
      {
         Write-Host -Object:"`t$($name) is installed"
      }
      Else
      {
         Write-Host -Object:"`t$($name) is not installed"
      }
   }

   Return $isInstalled
}

<#
 .Name
   Assert-TestSigningIsEnabled

 .Synopsis
   Internal cmdlet to check if testsigning is enabled in the boot loader.

 .Description
   Returns TRUE if test signing is enabled, otherwise FALSE.

 .Parameter Silent
   Optional switch used to suppress output messages

 .Example
   # Check if test signing is enabled
   Assert-TestSigningIsEnabled
#>
Function Assert-TestSigningIsEnabled
{
   Param
   (
      [Parameter(ParameterSetName='Default',Mandatory=$false)]
      [Switch] $Silent
   )

   [Boolean] $isEnabled = $false
   [String]  $state     = 'Disabled'

   Try
   {
      [Boolean] $current = $false

      If(-Not ($Silent.IsPresent))
      {
         Write-Host -Object:"`tAssert Test Signing is Enabled"
      }

      [Object[]] $entries = BCDEdit.exe /enum
      If($entries.Count -ILT 3)
      {
         Write-Error -Message:"$entries"

         Throw
      }

      ForEach($entry in $entries)
      {
         If($entry.StartsWith('identifier'))
         {
            If($entry -ILike '*{current}*')
            {
               $current = $true
            }
            Else
            {
               $current = $false
            }
         }
         Else
         {
            If($current)
            {
               If($entry -ILike '*testsigning*Yes*')
               {
                  $state = 'Enabled'

                  $isEnabled = $true

                  Break
               }
            }
         }
      }
   }
   Catch
   {
      $isEnabled = $false

      $state = 'Unknown'
   }

   If(-Not ($Silent.IsPresent))
   {
      Write-Host -Object:"`t`t$($state)"
   }

   Return $isEnabled
}

<#
 .Name
   Disable-TestSigning

 .Synopsis
   Internal cmdlet to turn off Test Signing in the Windows Boot Loader.

 .Description
   Returns TRUE if test signing is disabled, otherwise FALSE.
   If set, the setting does not take effect until a reboot

 .Parameter Reboot
   Optional parameter which will trigger a reboot if needed

 .Example
   # Disable test signing
   Disable-TestSigning
#>
Function Disable-TestSigning
{
   Param
   (
      [Parameter(ParameterSetName='Default',Mandatory=$false)]
      [Switch] $Reboot
   )

   [Boolean] $isSuccess = $true

   Try
   {
      [Boolean] $current = $false
      [Boolean] $found   = $false

      Write-Host -Object:"`tDisabling Test Signing"

      If(Assert-TestSigningIsEnabled -Silent)
      {
         Start-Process -FilePath:"$($env:WinDir)\System32\BCDEdit.exe" -ArgumentList @('/Set TestSigning Off') -PassThru | Wait-Process

         If(Assert-TestSigningIsEnabled -Silent)
         {
            Write-Error -Message:"`t`tFailed"

            Throw
         }

         $script:RequiresReboot = $true
      }

      Write-Host -Object:"`t`tDisabled"
   }
   Catch
   {
      $isSuccess = $false
   }

   If($Reboot.IsPresent -and
      $script:RequiresReboot)
   {
      Write-Host -Object:'Restarting'

      Start-Sleep -Seconds:5

      Restart-Computer
   }

   Return $isSuccess
}

<#
 .Name
   Enable-TestSigning

 .Synopsis
   Internal cmdlet to turn on Test Signing in the Windows Boot Loader.

 .Description
   Returns TRUE if test signing is enabled, otherwise FALSE.

 .Parameter Reboot
   Optional parameter which will trigger a reboot if needed

 .Example
   # Enable test signing
   Enable-TestSigning
#>
Function Enable-TestSigning
{
   Param
   (
      [Parameter(ParameterSetName='Default',Mandatory=$false)]
      [Switch] $Reboot
   )

   [Boolean] $isSuccess = $true

   Try
   {
      [Boolean] $current = $false
      [Boolean] $found   = $false

      Write-Host -Object:"`tEnabling Test Signing"

      If(-Not (Assert-TestSigningIsEnabled -Silent))
      {
         Start-Process -FilePath:"$($env:WinDir)\System32\BCDEdit.exe" -ArgumentList @('/Set TestSigning On') -PassThru | Wait-Process

         If(-Not (Assert-TestSigningIsEnabled -Silent))
         {
            Write-Error -Message:"`t`tFailed"

            Throw
         }

         $script:RequiresReboot = $true
      }

      Write-Host -Object:"`t`tEnabled"

   }
   Catch
   {
      $isSuccess = $false
   }

   If($Reboot.IsPresent -and
      $script:RequiresReboot)
   {
      Write-Host -Object:'Restarting'

      Start-Sleep -Seconds:5

      Restart-Computer
   }

   Return $isSuccess
}

#endregion PrivateFns

#region Public

<#
 .Name
   Assert-WindowsCiliumIsReady

 .Synopsis
   Check if Cilium for Windows is ready

 .Description
   Returns TRUE if Cilium for Windows is ready, otherwise FALSE.

 .Example
   # Check if Cilium for Windows is ready
   Assert-WindowsCiliumFunctions
#>
Function Assert-WindowsCiliumIsReady
{
    Write-Host -Object:'Validating Cilium for Windows is ready'

   [Boolean]  $isReady  = $true
   [String[]] $services = @(
                            'eBPFCore',
                            'NetEbpfExt',
                            'XDP'
                           )
   ForEach($service in $services)
   {
      If(-Not (Assert-SoftwareInstalled -ServiceName:"$($service)" -ServiceState:'Running'))
      {
         $isReady = $false

         Write-Warning -Message:"`t$($service) is not ready"
      }
   }

   Return $isReady
}

<#
 .Name
   Install-eBPF

 .Synopsis
   Installs extended Berkley Packet Filter for Windows.

 .Description
   Returns TRUE if extended Berkley Packet Filter for Windows is installed successfully, otherwise FALSE.
   Function requires that Test Signing is enabled.

 .Parameter LocalPath
   Local directory to the eBPF for Windows binaries.
   Default location is $env:LocalAppData\Temp

 .Example
   # Install eBPF for Windows
   Install-eBPF -LocalPath:"$env:TEMP"
#>
Function Install-eBPF
{
   [cmdletbinding(DefaultParameterSetName='Default')]

   Param
   (
      [Parameter(ParameterSetName='Default',Mandatory=$false)]
      [ValidateScript({Test-Path $_ -PathType:'Container'})]
      [String] $LocalPath = "$env:TEMP"
   )

   [Boolean] $isSuccess = $true

   Try
   {
      Write-Host 'Installing extended Berkley Packet Filter for Windows'
      If(-Not (Assert-TestSigningIsEnabled))
      {
         If(-Not (Enable-TestSigning -Reboot)) { Throw }
      }

      If(Assert-SoftwareInstalled -ServiceName:"eBPFCore")
      {
         Write-Host 'extended Berkley Packet Filter for Windows is already installed'
         return $isSuccess
      }

      Write-Host 'Installing extended Berkley Packet Filter for Windows'
      $ProgressPreference = 'SilentlyContinue'
      # Download eBPF-for-Windows.
      $packageEbpfUrl = "https://github.com/microsoft/ebpf-for-windows/releases/download/Release-v0.20.0/Build-x64-native-only.NativeOnlyRelease.zip"
      Invoke-WebRequest -Uri $packageEbpfUrl -OutFile "$LocalPath\\Build-x64-native-only-NativeOnlyRelease.zip"
      Expand-Archive -Path "$LocalPath\\Build-x64-native-only-NativeOnlyRelease.zip" -DestinationPath "$LocalPath\\Build-x64-native-only-NativeOnlyRelease\\msi" -Force
      Start-Process -FilePath:"$($env:WinDir)\System32\MSIExec.exe" -ArgumentList @("/i $($LocalPath)\ebpf-for-windows.msi", '/qn', "INSTALLFOLDER=`"$($env:ProgramFiles)\ebpf-for-windows`"", 'ADDLOCAL=eBPF_Runtime_Components') -PassThru | Wait-Process

      If(-Not (Assert-SoftwareInstalled -ServiceName:'eBPFCore' -Silent) -Or
         -Not (Assert-SoftwareInstalled -ServiceName:'NetEbpfExt' -Silent))
      {
         Write-Error -Message:"`teBPF service failed to install"

         Throw
      }

      $isSuccess = Assert-SoftwareInstalled -ServiceName:"eBPFCore"
   }
   Catch
   {
      $isSuccess = $false
      Write-Host "EBPF install failed : $_"
      Uninstall-eBPF
   }

   Return $isSuccess
}

<#
 .Name
   Install-XDP

 .Synopsis
   Installs the eXpress Data Path for Windows service.

 .Description
   Returns TRUE if the eXpress Data Path for Windows service is installed successfully, otherwise FALSE.

 .Parameter LocalPath
   Local directory to the eXpress Data Path for Windows service binaries.
   Default location is $env:LocalAppData\Temp

 .Example
   # Install the eXpress Data Path service
   Install-XDP -LocalPath:"$env:TEMP"
#>
Function Install-XDP
{
   [cmdletbinding(DefaultParameterSetName='Default')]

   Param
   (
      [Parameter(ParameterSetName='Default',Mandatory=$false)]
      [ValidateScript({Test-Path $_ -PathType:'Container'})]
      [String] $LocalPath = "$env:TEMP"
   )

   [Boolean] $isSuccess = $true

   Try
   {
      If(Assert-SoftwareInstalled -SoftwareName:'XDP for Windows' -Silent)
      {
         Write-Host 'XDP for Windows is already installed'
         return $isSuccess
      }

      # Download XDP-for-Windows.
      Write-Host 'Installing eXpress Data Path for Windows'
      $packageXdpUrl = "https://github.com/microsoft/xdp-for-windows/releases/download/v1.1.0%2Bbed474a/bin_Release_x64.zip"
      Invoke-WebRequest -Uri $packageXdpUrl -OutFile "$LocalPath\\bin_Release_x64.zip"
      Expand-Archive -Path "$LocalPath\\bin_Release_x64.zip" -DestinationPath "$LocalPath\\bin_Release_x64" -Force
      copy "$LocalPath\\bin_Release_x64\\amd64fre\\xdp.cer" $LocalPath
      copy "$LocalPath\\bin_Release_x64\\amd64fre\\xdpcfg.exe" $LocalPath
      CertUtil.exe -addstore Root "$LocalPath\xdp.cer"
      CertUtil.exe -addstore TrustedPublisher "$LocalPath\xdp.cer"
      Invoke-WebRequest -Uri "https://github.com/microsoft/xdp-for-windows/releases/download/v1.1.0%2Bbed474a/xdp-for-windows.1.1.0.msi" -OutFile "$LocalPath\xdp-for-windows.1.1.0.msi"
      Start-Process -FilePath:"$($env:WinDir)\System32\MSIExec.exe" -ArgumentList @("/i $LocalPath\xdp-for-windows.1.1.0.msi", '/qn') -PassThru | Wait-Process
      sc.exe query xdp
      reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\xdp\Parameters" /v XdpEbpfEnabled /d 1 /t REG_DWORD /f
      net.exe stop xdp
      net.exe start xdp
      Write-Output "XDP for Windows installed"
      Write-Host "Setting SDDL for XDP service"
      & "$LocalPath\xdpcfg.exe" SetDeviceSddl "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
      If(-Not (Assert-SoftwareInstalled -SoftwareName:'XDP for Windows' -Silent)) {
         Throw
      }
   }
   Catch
   {
      $isSuccess = $false
      Write-Host "XDP install failed : $_"
      Uninstall-XDP
   }

   Return $isSuccess
}

<#
 .Name
   Install-WindowsCilium

 .Description
   Returns TRUE if the Cilium for Windows installation is successfully, otherwise FALSE.
   Requires test signing to be enabled.  This is asserted up front and may trigger a restart.
   A restart will occur if the NoRestart switch is not specified.  Any caller needs to account for this.
#>
Function Install-WindowsCilium
{
   [cmdletbinding(DefaultParameterSetName='Default')]

   [Boolean] $isSuccess = $true

   Try
   {
      If(Assert-WindowsCiliumIsReady) {
          Write-Host 'Windows Cilium Installed already'
          return
      }

      Write-Host 'Installing Windows Cilium'

      If(-Not (Assert-TestSigningIsEnabled -Silent))
      {
         If(-Not (Enable-TestSigning -Reboot)) { Throw }
      }

      If(-Not (Install-eBPF)) {Throw}

      If(-Not (Install-XDP)) {Throw}

      # Create the probe ready file
      New-Item -Path "C:\install-ebpf-xdp-probe-ready" -ItemType File -Force

      Write-Host -Object:'Restarting'

      Start-Sleep -Seconds:5

      If(Assert-WindowsCiliumIsReady) {
         Throw "Cilium for Windows is not ready"
      }

      Restart-Computer
   }
   Catch
   {
      Write-Host "Exception: $_"
      $isSuccess = $false
   }

   Return $isSuccess
}

<#
 .Name
   Uninstall-eBPF

 .Synopsis
   Uninstalls the extended Berkley Packet Filter for Windows.

 .Description
   Returns TRUE if the extended Berkley Packet Filter for Windows is uninstalled successfully, otherwise FALSE.

 .Parameter LocalPath
   Local directory to the extended Berkley Packet Filter for Windows binaries.
   Default location is $env:LocalAppData\Temp

 .Example
   # Uninstall the extended Berkley Packet Filter for Windows
   Uninstall-eBPF -LocalPath:"$(env:LocalAppData)\Temp"
#>
Function Uninstall-eBPF
{
   [cmdletbinding(DefaultParameterSetName='Default')]

   Param
   (
      [Parameter(ParameterSetName='Default',Mandatory=$false)]
      [ValidateScript({Test-Path $_ -PathType:'Container'})]
      [String] $LocalPath = "$env:TEMP"
   )

   Write-Host 'Uninstalling the extended Berkley Packet Filter for Windows'

   [Boolean] $isSuccess = $true

   Try
   {
      [String[]] $services = @('eBPFCore',
                               'NetEbpfExt'
                              )

      ForEach($service in $services)
      {
         [Object] $state = Get-Service -Name:$($service) -ErrorAction:'SilentlyContinue'
         If($state)
         {
            For([Byte]$i = 0;
                $i -ILE 5;
                $i++)
            {
               If($state.Status -IEQ 'Stopped')
               {
                   Break
               }
               Else
               {
                  If($state.Status -IEQ 'Running')
                  {
                     Stop-Service -Name:"$($service)" -Force
                  }
                  ElseIf($state.Status -IEQ 'StopPending')
                  {
                     Start-Sleep -Seconds:5
                  }
                  Else
                  {
                     Write-Error -Message:"$($service) service is $($state.status)"

                     Throw
                  }
               }

               $state = Get-Service -Name:"$($service)"
            }
         }

         Start-Process -FilePath:"$($env:WinDir)\System32\MSIExec.exe" -ArgumentList @("/x $($LocalPath)\ebpf-for-windows.msi", '/qn') -PassThru | Wait-Process
      }

      If((Assert-SoftwareInstalled -ServiceName:'eBPFCore' -Silent) -or
         (Assert-SoftwareInstalled -ServiceName:'NetEbpfExt' -Silent) -or
         (Assert-SoftwareInstalled -SoftwareName:'eBPF for Windows' -Silent))
      {
         Write-Error -Message:"eBPF for Windows is still installed"

         Throw
      }
   }
   Catch
   {
      $isSuccess = $false
   }

   Return $isSuccess
}

<#
 .Name
   Uninstall-XDP

 .Synopsis
   Uninstalls the express Data Path for Windows service

 .Description
   Returns TRUE if the eXpress Data Path for Windows service is uninstalled successfully, otherwise FALSE.

 .Parameter LocalPath
   Local directory to the eXpress Data Path for Windows service binaries.
   Default location is $env:LocalAppData\Temp

 .Example
   # Uninstall the eXpress Data Path for Windows service
   Uninstall-XDP -LocalPath:"$($env:LocalAppData)\Temp"
#>
Function Uninstall-XDP
{
   [cmdletbinding(DefaultParameterSetName='Default')]

   Param
   (
      [Parameter(ParameterSetName='Default',Mandatory=$false)]
      [ValidateScript({Test-Path $_ -PathType:'Container'})]
      [String] $LocalPath = "$env:TEMP"
   )

   Write-Host 'Uninstalling eXpress Data Path for Windows'

   [Boolean] $isSuccess = $true

   Try
   {
      [Object] $state = Get-Service -Name:'XDP' -ErrorAction:'SilentlyContinue'
      If($state)
      {
         For([Byte]$i = 0;
             $i -ILE 5;
             $i++)
         {
            If($state.Status -IEQ 'Stopped')
            {
                Break
            }
            Else
            {
               If($state.Status -IEQ 'Running')
               {
                  Stop-Service -Name:'XDP' -Force
               }
               ElseIf($state.Status -IEQ 'StopPending')
               {
                  Start-Sleep -Seconds:5
               }
               Else
               {
                  Write-Error -Message:"XDP service is $($state.status)"

                  Throw
               }
            }

            $state = Get-Service -Name:'XDP'
         }

         $regValue = New-ItemProperty -Path:'HKLM:\SYSTEM\CurrentControlSet\Services\xdp\Parameters' -Name:'xdpEbpfEnabled' -PropertyType:'DWORD' -Value:0 -Force
         If($regValue.xdpEbpfEnabled -IEQ 0)
         {
            Start-Process -FilePath:"$($env:WinDir)\System32\MSIExec.exe" -ArgumentList @("/x $($LocalPath)\xdp-for-windows.1.1.0.msi", '/qn') -PassThru | Wait-Process
         }
      }

      If((Assert-SoftwareInstalled -ServiceName:'XDP' -Silent) -or
         (Assert-SoftwareInstalled -SoftwareName:'XDP for Windows' -Silent))
      {
         Write-Error -Message:"XDP for Windows is still installed"

         Throw
      }
   }
   Catch
   {
      $isSuccess = $false
   }

   Return $isSuccess
}

<#
 .Name
   Uninstall-WindowsCilium

 .Synopsis
   Uninstalls Cilium for Windows

 .Parameter LocalPath
   Local directory to the Cilium for Windows binaries.
   Default location is $env:LocalAppData\Temp

 .Parameter DisableTestSigning
   Optional switch used to disable test signing on the current Windows boot loader

 .Description
   Returns TRUE if Cilium for Windows is uninstalled successfully, otherwise FALSE.

 .Example
   # Uninstall Cilium for Windows
   Uninstall-WindowsCilium
#>
Function Uninstall-WindowsCilium
{
   [cmdletbinding(DefaultParameterSetName='Default')]

   Param
   (
      [Parameter(ParameterSetName='Default',Mandatory=$false)]
      [ValidateScript({Test-Path $_ -PathType:'Container'})]
      [String] $LocalPath = "$env:TEMP",

      [Parameter(ParameterSetName='Default',Mandatory=$false)]
      [Switch] $DisableTestSigning,

      [Parameter(ParameterSetName='Default',Mandatory=$false)]
      [Switch] $NoReboot
   )

   Write-Host 'Uninstalling Cilium for Windows'

   [Boolean] $isSuccess = $true

   Try
   {
      Uninstall-XDP -LocalPath:"$($LocalPath)"

      Uninstall-eBPF -LocalPath:"$($LocalPath)"

      If($DisableTestSigning.IsPresent)
      {
         Disable-TestSigning -Reboot:$(-Not ($NoReboot.IsPresent))
      }
   }
   Catch
   {
      $isSuccess = $false
   }

   Return $isSuccess
}


#Script Start
Install-WindowsCilium