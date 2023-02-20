function Get-HuntressInfo {
    <#
    .SYNOPSIS
        The function retrieves info about Huntress, that can then be used in troubleshooting Huntress. The function can also be used to install, uninstall and reinstall Huntress.
    .DESCRIPTION
        The function, when run without the install/uninstall/reinstall parameters, returns useful info about Huntress installed on a system, including running Services and Processes, as well as specific Huntress information stored in the Registry.
        It also returns info on the cert issuer returned by the huntress.io domain.
        The information retrieved by the function can then be used in troubleshooting Huntress not working as expected.
        Using the reinstall parameter can often resolve 'Huntress not working' issues. 
        When running with the 'InstallHuntress' parameter, the script also checks if the Huntress installer is being blocked from downloading.
        The script by default also checks for multiple running instances of the Huntress installer, a possible cause for Huntress not properly functioning on a system.
        The script also looks for an ARM processor (not compatible with Huntress), as well as checks for the presencs fo certain content filters that can block Huntress from functioning properly.
        Finally, the script checks if the Huntress portal is down. If it is, reinstalling won't work as expected. 
    .NOTES
        To run, simply paste the contents of this script into PowerShell, press 'Enter', and then run 'Get-HuntressInfo', followed by whatever parameters you'd like to use, if any.
        Note: The script can be run backstage from ConnectWise Control as well.
        Tip: Running the script with the '-Verbose' parameter will return detailed information about what the script is doing and testing for.
    .EXAMPLE
        Get-HuntressInfo -Verbose
        This will run the script with its default parameters. It will retrieve and display information about Huntress installed on the system.
        '-Verbose' will give you verbose information aobut the script as it runs.
    .EXAMPLE
        Get-HuntressInfo -InstallHuntress
        This will reinstall Huntress on top of whatever is already there, without uninstalling first. If needed (i.e. the Registry doesn't provide the necessary install parameters), the script will prompt you for the install parameters.
    .EXAMPLE
        Get-HuntressInfo -ReinstallHuntress
        This will uninstall Huntress and then reinstall it. When uninstalling, the script will attempt to use the Huntress uninstaller that comes with Huntress. If it's not present, it will attempt to manually uninstall the program.
        It will copy out information from specific registry keys before deleting them when uninstalling, so it can be used when re-installing and not have to prompt you fopr the info.
    #>
    [CmdletBinding()]
    param (
        [Switch]$InstallHuntress,
        
        [Switch]$UninstallHuntress,

        [Switch]$ReinstallHuntress,

        [Switch]$RestartServices,

        [Switch]$DefaultOverride,

        [Switch]$OpenHuntressLog
    )
    
    begin {}
    
    process {
        # $Color = $Host.PrivateData.WarningForegroundColor.ToString()
        # $Host.PrivateData.WarningForegroundColor = "Green"

        if ($OpenHuntressLog) {
            notepad.exe C:\Program Files\Huntress\HuntressAgent.log
            break
        }

        # Check for admin rights
        if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Warning "Script must be run as admin."
            $Answer = Read-Host "Relaunch shell as admin? (Y/N)"
            if ($Answer -eq 'Y') {
                Start-Process powershell.exe -Verb runas
                Stop-Process -Id $PID
            }
            else {
                Write-Host -ForegroundColor Green "Please launch an admin shell and try again.`nExiting script."
                Break
            }
        } # if not admin

        $HuntressPath = 'C:\Windows\LTSvc\Packages\Huntress\HuntressInstaller.exe'
        $UninstallPath = "C:\Program Files\Huntress\Uninstall.exe"
        function Get-RegInfo {
            [CmdletBinding()]
            param (
                # for when the Registry info is empty or incomplete
                [Switch]$PromptForParams,
                # outputs $Obj to the pipeline
                [Switch]$OutputObj  
            )
                
            begin {}

            process {
                $Script:RegInfo = Get-ItemProperty 'HKLM:\SOFTWARE\Huntress Labs\Huntress' -ErrorAction SilentlyContinue
                $Props = [Ordered]@{
                    'ACCT key' = $RegInfo.AccountKey
                    'ORG key'  = $RegInfo.OrganizationKey
                    'Tags'     = $RegInfo.Tags
                }
                Write-Debug "RegInfo Props gathered"
                $Obj = New-Object -TypeName psobject -Property $Props

                # format the install parameters pulled from the Registry (and make available script-wide)
                if ( ($RegInfo.AccountKey) -and ($RegInfo.OrganizationKey) -and ($RegInfo.Tags) ) {
                    $Script:ACTKey = $RegInfo.AccountKey
                    $Script:ORGKey = "`"$($RegInfo.OrganizationKey)`""
                    $Script:Site = "`"$($RegInfo.Tags)`""
                }
                
                if ($PromptForParams) {
                    if ( !(($RegInfo.AccountKey) -and ($RegInfo.OrganizationKey) -and ($RegInfo.Tags)) ) {
                        Write-Host -ForegroundColor Green "Failed to successfully pull the install parameters from the Registry. Please enter them manually:"
                        [String]$Script:ACTkey = (Read-Host "Enter our organizational Huntress account key")
                        [String]$ORGKey = (Read-Host "Enter the client name as it appears in Automate (without quotes)")
                        [String]$Site = (Read-Host "Enter the location name as it appears in Automate [for ex. Main] (without quotes)")
                        $Script:ORGKey = "`"$($ORGKey)`""
                        $Script:Site = "`"$($Site)`""
                    } # if !Keys
                } # if $PrompForParams

                if ($OutputObj) {
                    Write-Output $Obj
                }
            } # process
                
            end {}
        } # function Get-RegInfo

        function Uninstall {
            Write-Host -ForegroundColor Green "Uninstalling Huntress.."
            if (Test-Path $UninstallPath) {
                Start-Process -FilePath $($UninstallPath) -ArgumentList "/S"
                Write-Verbose "Waiting for the uninstall to complete"
                Start-Sleep -Seconds 20
            }
            else {
                Write-Verbose "Huntress uninstaller not found. Attempting manuall uninstall"
                Write-Verbose "Uninstalling HuntressAgent"
                try { Start-Process -FilePath "C:\Program Files\Huntress\HuntressAgent.exe" -ArgumentList "uninstall" } catch {}
                Write-Verbose "Uninstalling HuntressUpdater"
                try { Start-Process -FilePath "C:\Program Files\Huntress\HuntressUpdater.exe" -ArgumentList "uninstall" } catch {}
                Write-Verbose "Deleting the Huntress folder in Program Files"
                Remove-Item -Path "C:\Program Files\Huntress" -Recurse -Confirm:$false -ErrorAction SilentlyContinue
                Write-Verbose "Deleting Huntress Registry info"
                Remove-Item -Path "HKLM:\SOFTWARE\Huntress Labs" -Recurse -Confirm:$false -ErrorAction SilentlyContinue
            }
            Write-Host -ForegroundColor Green "Huntress uninstall complete.`n"
        } # function Uninstall

        function Install {
            if ( !(Test-Path $($HuntressPath)) -or ((Get-ChildItem $HuntressPath).CreationTime -lt (Get-Date).AddDays(-60)) ) {
                Write-Verbose "Huntress installer not present at 'C:\Windows\LTSvc\Packages\Huntress' or present but older than 60 days.`nDownloading the installer."
                (New-Object Net.WebClient).DownloadFile("https://huntress.io/download/$($ACTKey)", $env:temp + '/HuntressInstaller.exe')
                if ((Get-Content $env:temp\HuntressInstaller.exe) -match "WELCOME, PLEASE LOGIN") {
                    Write-Warning "The downloaded installer is corrupt and unreadable. Please double-check the organizational key you entered, and then re-run the script."
                    break
                }
                Write-Verbose "Download complete. Installer saved to $env:temp + '/HuntressInstaller.exe'."
                Write-Verbose "Attempting to pull install parameters from the Registry (from previous install if relevant)"
                Get-RegInfo -PromptForParams
                Write-Verbose "Running the installer"
                Start-Process -FilePath "$env:temp\HuntressInstaller.exe" -ArgumentList "/ACCT_KEY=$ACTKey /ORG_KEY=$ORGKey /TAGS=$Site"
            } # if !Test-Path
            else {
                Write-Verbose "Attempting to pull install parameters from the Registry (or from memory if the reinstall parameter was used)"
                # the following if statement is added for when the Reinstall parameter is used and reg info exists, 
                # so that the Install function doesn't re-run the Get-RegInfo function and overwrite the reg info already saved to memory from before the uninstall
                if (!( ($RegInfo.AccountKey) -and ($RegInfo.OrganizationKey) -and ($RegInfo.Tags) )) {
                    Get-RegInfo -PromptForParams
                }
                # the next if statement bypasses the 'Y/N' prompt if the Reinstall parameter was used
                if ($ReinstallHuntress) {
                    Write-Host -ForegroundColor Green "Installing Huntress. Please wait.."
                    Start-Process $($HuntressPath) -ArgumentList "/S /ACCT_KEY=$ACTKey /ORG_KEY=$ORGKey /TAGS=$Site"
                } # if $ReinstallHuntress
                else {
                    $Answer = Read-Host "Proceed with install? (Y/N)"
                    if ($Answer -eq 'N') {
                        Write-Host -ForegroundColor Green "Installation cancelled.`nExiting the script."
                        break
                    }
                    else {
                        Write-Host -ForegroundColor Green "Installing Huntress. Please wait.."
                        Start-Process $($HuntressPath) -ArgumentList "/S /ACCT_KEY=$ACTKey /ORG_KEY=$ORGKey /TAGS=$Site"
                    } # if $Answer -eq 'Y'
                } # if no $ReinstallHuntress
            } # else if Test-Path
            Write-Verbose "Waiting for the installation to complete"
            for ( $i = 0; $i -lt 5; $i++) {
                if (!(Get-Process HuntressInstaller -ErrorAction SilentlyContinue)) {
                    if ((Get-Service HuntressAgent -ErrorAction SilentlyContinue).status -ne 'Running') {
                        Start-Service HuntressAgent -ErrorAction SilentlyContinue
                        for ( $n = 0; $n -lt 3; $n++) {   
                            if ((Get-Service HuntressAgent -ErrorAction SilentlyContinue).status -ne 'Running') {
                                Write-Host -ForegroundColor Green "Waiting for services to start.."
                                Start-Sleep -Seconds 3
                            }
                            break
                        } # for $n
                    } # if HuntressAgent service -ne 'Running'
                    break
                } # if no HuntressInstaller process
                else {
                    Write-Host -ForegroundColor Green "Installation in progress.."
                    Start-Sleep -Seconds 3
                } # if HuntressInstaller process running
            } # for $i
            if ((Get-Service HuntressAgent -ErrorAction SilentlyContinue).Status -eq 'Running') {
                $Services = Get-Service Huntress* | Format-Table Name, DisplayName, Status, StartType
                $Processes = Get-Process Huntress* | Format-Table Name, Description, FileVersion, StartTime
                Write-Host -ForegroundColor Green "Installation Complete.`nProcesses:"
                $Processes
                Write-Host -ForegroundColor Green "Services:"
                $Services
                Write-Host -ForegroundColor Green "Registry info:"
                Get-RegInfo -OutputObj | Format-List
                Write-Host -ForegroundColor Green "Exiting Script."
                break
            } # if Get-Service HuntressAgent
            elseif ($($HuntressPath) -lt 50KB) {
                Write-Warning "Huntress did not install correctly.`nThe installer is present at $($HuntressPath), but is smaller in size than it should be.`nA DNS filter may be blocking the Huntress installer from downloading. To confirm, examine the contents of the installer in notepad, or simply visit 'huntress.io' in a browser."
            }
            else {
                Write-Warning "Installation failed for an unknown reason.`nPlease look into this and install manually."
            } # else HuntressAgent service NOT running
        } # function Install

        function Test-Filter {
            Write-Verbose "Testing for the presence of the Techloq, Gentech and Meshimer content filters"
            $RegFilter = (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName -like '*Techloq*' -or $_.DisplayName -like '*GenTech*' -or $_.DisplayName -like '*Meshimer*' }).displayname | Select-Object -Unique
            Write-Debug "RegFilter info gathered"
            switch -wildcard ($RegFilter) {
                '*Techloq*' { $Script:Filter = "Techloq"; $Script:FilterName = "Techloq" }
                '*Gentech*' { $Script:Filter = "Livigent"; $Script:FilterName = "Gentech" }
                '*Livigent*' { $Script:Filter = "Livigent"; $Script:FilterName = "Meshimer" } 
                # Default {}
            }
            <#
            # Get-ItemProperty hklm:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.publisher -like '*techloq*' -or $_.displayname -like '*techloq*' -or $_.pschildname -like '*techloq*' }
            # if (Get-Process WindowsFilterAgentWPFClient -ErrorAction SilentlyContinue | Where-Object { $_.Company -eq 'Techloq' }) { $Filter = "Techloq"; $FilterName = "Techloq" }
            if (Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object displayname -like *Techloq*) { $Script:Filter = "Techloq"; $Script:FilterName = "Techloq" }
            # try { if ( (Invoke-WebRequest -Uri "test.techloq.com" -UseBasicParsing -Verbose:$false).Content -match "Your filter is functioning properly.") { $Script:Filter = "Techloq"; $Script:FilterName = "Techloq" } } catch {}
            try { if ( (Invoke-WebRequest -Uri "filterstatus.com" -UseBasicParsing -Verbose:$false).Content -match "Your device is being filtered by GenTech!") { $Script:Filter = "Livigent"; $Script:FilterName = "Gentech" } } catch {}
            try { if ( ((Invoke-WebRequest -Uri "filterstatus.com" -UseBasicParsing -Verbose:$false).Content -notmatch "Your device is being filtered by GenTech!") -and ($AgentLog -match 'Livigent')) { $Script:Filter = "Livigent"; $Script:FilterName = "Meshimer" } } catch {}
            # try { if ( (Invoke-WebRequest -Uri "test.mehismer.com" -UseBasicParsing -Verbose:$false).Content -match "") { $Script:Filter = "Livigent"; $Script:FilterName = "Meshimer" } } catch {}
            # if (!(Test-Path "C:\ProgramData\LvgIC") -and ($AgentLog -match 'Livigent')) { $Script:Filter = "Livigent"; $Script:FilterName = "Meshimer" }
        #>
        } # function Test-Filter

        function Test-HuntressConnection {
            # test for unexpected huntress.io cert
            Write-Verbose "Testing connection to huntress.io for SSL interception using the TestHuntressConnection command-line tool"
            if (!(Test-Path "C:\Windows\Temp\TestHuntressConnection.exe")) {
                Write-Verbose "Tool not present at 'C:\Windows\Temp\TestHuntressConnection.exe'. Dowloading tool from our LTShare.."
                (New-Object Net.WebClient).DownloadFile("https://labtech.intellicomp.net/labtech/transfer/Tools/TestHuntressConnection.exe", "C:\Windows\Temp\TestHuntressConnection.exe")
                if (Test-Path "C:\Windows\Temp\TestHuntressConnection.exe") {
                    Write-Verbose "Download complete"
                }
                else {
                    Write-Verbose "Download not successful"
                }
            }
            $TestHuntressConnection = & "C:\Windows\Temp\TestHuntressConnection.exe"
            Write-Host -ForegroundColor Green "`nResults from the TestHuntressConnection command-line tool:"
            if (($TestHuntressConnection | Select-String "- Connection") -notlike "*Connection Successful*") {
                Write-Warning "Huntress Connection Test failed"
                $TestHuntressConnection | Where-Object { $_ -notmatch "Please see" -and $_ -notmatch "For help" }
            } # if $TestHuntressConnection not successful
            elseif ( ($TestHuntressConnection | Select-String "- Connection") -like "*Connection Successful*" ) {
                $TestHuntressConnection
            } # if $TestHuntressConnection successful
        }

        function Test-SSL {
            param (
                [ValidateScript({
                        if ($_ -match "^http[s]*:\/\/") {
                            $true
                        }
                        else {
                            Throw "The URL $_ was entered in an incorrect format. Please append 'https://' to the URL and try again."
                        }
                    })]
                [String]$url = "https://huntress.io/",

                [string]$Program = "Huntress",
                
                [Switch]$OutputObj
            )
            Write-Verbose "Testing the SSL cert returned by the huntress.io domain"
            # Allow connection to sites with an invalid certificate
            # [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            # Create the web request
            $req = [Net.HttpWebRequest]::Create($url)
            # Set the timeout to 5 seconds
            $timeoutMilliseconds = 5000
            $req.Timeout = $timeoutMilliseconds
            # Populate the $req.ServicePoint.Certificate property
            try { $req.GetResponse() | Out-Null } catch {}
            # Grab the cert issuer
            if ($req.ServicePoint.Certificate) {
                $Script:Issuer = (($req.ServicePoint.Certificate.Issuer.Split(',')) | Select-String "O=").ToString().Substring(3)   
            }
            Write-Debug "Huntress.io cert issuer info retrieved.`n$Issuer"
            if ($OutputObj) {
                $req.ServicePoint.Certificate
            }
            else {
                Write-Host -ForegroundColor Green "`nThe SSL cert returned by the $url domain:"
                Write-Host "Issuer: $Issuer"
                Write-Host "Complete issuer info: $($req.ServicePoint.Certificate.Issuer)"
                if ($Issuer -notlike "*DigiCert*") {
                    $Script:Status = 1
                }
            } # if !$OutputObj
        } # function Test-SSL

        if ($UninstallHuntress) {
            Uninstall
        } # if $UninstallHuntress

        if ($InstallHuntress) {
            Install
        } # if $InstallHuntress

        if ($ReinstallHuntress) {
            Get-RegInfo
            Uninstall
            Install
        } # if $ReinstallHuntress

        if ($RestartServices) {
            Write-Host -ForegroundColor Green "Restarting services"
            Get-Service Huntress* -ErrorAction SilentlyContinue | Restart-Service -PassThru
            break
        }

        # else {
        if ( (Get-Process HuntressInstaller -ErrorAction SilentlyContinue).Count -gt 1 ) {
            Write-Host -ForegroundColor Red "Multiple instances of the Huntress Installer were detected."
            $Answer = Read-Host "Stop the installers? (Y/N)"
            if ($Answer -eq 'Y') {
                Write-Verbose "`nStopping the installers.."                    
                Get-Process HuntressInstaller | Stop-Process -Force -Confirm:$false
                if (!(Get-Process HuntressInstaller)) {
                    Write-Host -ForegroundColor Green "`nAll instancess of the Huntress Installer have been stopped.`nPlease re-run the script, using the '-InstallHuntress' parameter."
                }
                else {
                    Write-Warning "The Huntress installers were not successfully stopped. Please look into this."
                }
            }
            elseif ($Answer -eq 'N') {
                Write-Host -ForegroundColor Green "The installers were NOT stopped."
            } # $Answer -eq 'N'
        } # if Count -gt 1

        Write-Verbose "Retrieving services, processes and Registry info"
        $Services = Get-Service Huntress* | Format-Table Name, DisplayName, Status, StartType -AutoSize
        $Processes = Get-Process Huntress* | Select-Object Name, Description, @{n = "AgentVersion"; e = { $_.FileVersion } }, StartTime | Format-Table -AutoSize
        Write-Host -ForegroundColor Green "Huntress Services:"
        $Services
        if (!(Get-Service Huntress*)) {
            Write-Host "No Huntress services detected.`n"
        }
        Write-Host -ForegroundColor Green "Huntress Processes:"
        $Processes
        if (!(Get-Process Huntress*)) {
            Write-Host "No Huntress processes running.`n"
        }
        Write-Host -ForegroundColor Green "Huntress info pulled from the Registry:"
        $RegInfo = Get-RegInfo -OutputObj
        if ( ($null -eq $RegInfo.AccountKey) -and ($null -eq $RegInfo.OrganizationKey) -and ($null -eq $RegInfo.Tags) ) {
            Write-Host "No Registry info found for Huntress.`n"
        }
        else {
            $RegInfo | Format-List
        }
        if ($($HuntressPath) -lt 50KB) {
            Write-Warning "`nThe installer is present at $($HuntressPath), but is smaller in size than it should be.`nA DNS filter may be blocking the Huntress installer from downloading. To confirm, examine the contents of the installer in notepad, or simply visit 'huntress.io' in a browser."
        }

        if (!$UninstallHuntress -and !$DefaultOverride) {
            # Checking the check.log file
            Write-Verbose "Checking the 'Check.log' file for errors"
            if (Test-Path 'C:\Program Files\Huntress\Check.log' -ErrorAction SilentlyContinue) {
                if ((Get-Content 'C:\Program Files\Huntress\Check.log' -ErrorAction SilentlyContinue) -notmatch "^[\d]+\.[\d]+\.[\d]+$") {
                    Write-Warning "The remote server returned an error.`n"
                    $CheckLog = Get-Content 'C:\Program Files\Huntress\Check.log'
                    Write-Host -ForegroundColor Green "Contents of the log file at 'C:\Program Files\Huntress\Check.log':"
                    $CheckLog
                    Write-Host ''
                } # if check.log errors
            } # if check.log file present
            else {
                Write-Host -ForegroundColor Cyan "The check.log file is not present on the machine."
            } # if check.log file not present
        
            # Testing for the Huntress portal being down
            Write-Verbose "Checking that the Huntress portal is up and that the machine can reach the Huntress update servers"
            try {
                $ProgressPreference = 'SilentlyContinue'
                $Var = Invoke-WebRequest -Uri 'update.huntress.io' -UseBasicParsing -Verbose:$False
                $ProgressPreference = 'Continue'
            }
            catch [System.Net.WebException] {
                Write-Warning "The Huntress site appears to be down. The machine will not be able to reach out for updates etc."
            }
            if ($Var.Content -notmatch "<title>Huntress Management Console</title>") {
                Write-Warning "The machine cannot successfully reach the Huntress update site."
            }

            # test for ARM processor
            Write-Verbose "Testing for ARM Processor"
            if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
                if ((Get-CimInstance Win32_Processor -Verbose:$false).Caption -like "*arm*") {
                    Write-Warning "ARM processor detected. Huntress is not compatible with this machine."
                    Write-Host "For more info: 'https://support.huntress.io/hc/en-us/articles/4410699983891-Supported-Operating-Systems-System-Requirements-Compatibility'`n"
                } 
            } # if Get-Command

            # test for free space
            Write-Verbose "Testing free space on C:"
            $Space = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceId='C:'" -Verbose:$false).FreeSpace
            if ($Space -lt 1GB) {
                Write-Host ""
                Write-Warning "<<< Free space on the C: drive is very low. >>>"
            }
            
            Test-HuntressConnection
            
            Test-SSL

            Test-Filter

            Write-Host ""
            $AgentLog = Get-Content 'C:\Program Files\Huntress\HuntressAgent.Log' -ErrorAction SilentlyContinue | Select-Object -Last 3
            Write-Debug "AgentLog cert test"
            if ( ($Status -eq 1) -and ($FilterName) ) {
                if ( ($AgentLog -match 'cert does not match pinned fingerprint') -and ($AgentLog -match $($Filter)) ) {
                    Write-Host -ForegroundColor Red "`n<<WARNING:>> The $($FilterName) content filter is installed on this machine.`nBased on the results from the TestHuntressConnection tool and the cert returned by huntress.io as well as the contents of the log file at 'C:\Program Files\Huntress\HuntressAgent.log', this machine is receiving an unexpected cert when verifying the huntress.io domain (i.e. a cert from $($Filter)). Please ask the user to have $($FilterName) create an SSL exception for the huntress.io domain in their filter settings."
                } # if $AgentLog -match cert errors
                elseif ( !(Test-Path -Path 'C:\Program Files\Huntress\HuntressAgent.Log') ) {
                    Write-Host -ForegroundColor Green "The $($FilterName) content filter is installed on this machine. The cert returned by huntress.io is from $Issuer. The HuntressAgent log file is NOT present."
                } # elseif filter present but no log file present
                else {
                    Write-Host -ForegroundColor Green "The $($FilterName) content filter is installed on this machine. The cert returned by huntress.io is from $Issuer. There are no current cert errors in the Huntress Agent Log file."
                } # else if filter present and Test-SSL returns warning but no cert errors
            } # if Test-SSL returns a warning and filter installed
            elseif ( ($Status -ne 1) -and ($FilterName) ) {
                if ($AgentLog -match 'cert does not match pinned fingerprint') {
                    Write-Host "The cert returned by Huntress.io is from Digicert but the log file still shows cert errors. The machine might therefore also not be in the Huntress portal."
                    $RS = Read-Host "Restart services? (Y/N)"
                    if ($RS -eq 'Y') {
                        restart services
                    } # if 'Y'
                    elseif ($RS -eq 'N') {
                        Write-Host "NOT restarting services.`Exiting script."
                        break
                    } # if 'N'
                } # if cert is from Digicert but log file still showing cert errors 
                else {
                    Write-Host -ForegroundColor Green "The $($FilterName) content filter is installed on this machine. The cert returned by huntress.io is from $Issuer. There are no current cert errors in the Huntress Agent Log file."
                } # if filter present but log file is fine
            } # if Test-SSL does NOT return a warning and filter installed
            
            # test for non-SSL related errors in the last 3 entries of the HuntressAgent log
            Write-Verbose "Testing for general errors at the end of the HuntressAgent log"
            $Log = Get-Content 'C:\Program Files\Huntress\HuntressAgent.Log' -ErrorAction SilentlyContinue -Last 3
            <#
            # https://support.huntress.io/hc/en-us/articles/4413150910867-Huntress-Agent-Error-Codes-HuntressAgent-log-
            switch -wildcard ($Log) {
                "bad status code: 400" { "Bad Status code: 400 -- There's an issue with the Account or Organization Key" }
                'level=error msg="(survey) post request - bad status code: 401' { $Err = 401; "Bad Status Code: 401 --Agent uninstalled from the portal (and uninstall task timed out-- ~30 days). Agent is orphaned. Uninstall and then reinstall." }
                "(monitored_registry_keys) get request - bad status code: 401" { "The registry key for AgentID has been modified.Search for the machine name in the portal and pull what the AgentID should be. Replace the incorrect value in the registry and it should start after restarting the HuntressAgent service." }
                "bad status code: 502" { "Bad Status Code: 502 Network Error -- The Host might not be connected to the Internet" }
                "bad status code: 413" { "Bad Status code: 413 -- Survey is too large, check for excessive number of scheduled tasks or contact support." }
            }
            #>

            foreach ($L in $Log) {
                if ($L -like '*x509: certificate signed by unknown authority*') {
                    Write-Warning "'Certificate signed by unknown authority' error."
                    $Answer = Read-Host "Restart services? (Y/N)"
                    if ($Answer -eq 'Y') {
                        Write-Host -ForegroundColor Green "Restarting services"
                        Get-Service HuntressAgent -ErrorAction SilentlyContinue | Stop-Service | Start-Service
                        Write-Host -ForegroundColor Green "Services restarted"
                        Write-Verbose "Checking updated log file"
                        $Log = Get-Content 'C:\Program Files\Huntress\HuntressAgent.Log' -ErrorAction SilentlyContinue -Last 3
                        foreach ($L in $Log) {
                            if ($L -like '*x509: certificate signed by unknown authority*') {
                                $IssueStillPresent = $True
                                Write-Warning "'Certificate signed by unknown authority' error still present. Restarting services did not resolve the issue. Please look into this manually."
                                break
                            } # if issue still present
                        } # foreach $L in $Log in updated log
                        if (!$IssueStillPresent) {
                            Write-Host -ForegroundColor Green "Issue is resolved"
                        }
                    } # if $Answer -eq 'Y'
                    elseif ($Answer -eq 'N') {
                        Write-Host -ForegroundColor Green "Not restarting services"
                        break
                    }
                } # if cert signed by unknown authority
            } # foreach $L in $Log in original log

            foreach ($L in $Log) {
                if ($L -like '*bad status code: 401*') {
                    $401 = $True
                    break
                }
                if ($401) {
                    Write-Warning "`n401 error."
                    $Ans = Read-Host "Reinstall Huntress? (Y/N)"
                    if ($Ans -eq 'Y') {
                        Get-RegInfo
                        Uninstall
                        Write-Host "`n"
                        Install
                    } # $Ans -eq 'Y'
                    elseif ($Ans -eq 'N') {
                        Write-Host "Not re-installing Huntress. Exiting."
                    } # $Ans -eq 'N'
                } # if $401
            } # foreach $L in $Log
        } # if !$UninstallHuntress
        # } # else if no parameters specified when running the script

        # $Host.PrivateData.WarningForegroundColor = "$Color"
    } # Process

    end {}
} # function