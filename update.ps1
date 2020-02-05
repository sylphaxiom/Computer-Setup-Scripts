## Log Location ##

$log = "C:\Windows\Logs\ScriptOut.log"

## Start Transcript for logging ##

$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -Path $log -Append

## Script Content ##

$title = "Check for Updates"
Install-PackageProvider -Name "NuGet" -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PSWindowsUpdate -Force -AllowClobber
$updates = Get-WindowsUpdate
if($updates.count -gt 0) {
	$updates
	$message = "Do you want to Install ALL the above updates?"
	$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Installs all updates."
	$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Skips this step and moves on to the rest of the script."
	$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
	$result = $Host.ui.PromptForChoice($title, $message, $options, 0)
	Switch ($result) {
		0 {
			Install-WindowsUpdate -AcceptAll -IgnoreReboot
			Write-Host "Rebooting Computer in 5 seconds."
			Remove-ItemProperty -Path 'HKLM:\Software\Micorsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultUserName' -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword' -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue
			Remove-Item -Path 'C:\Windows\System32\WindowsPowerShell\Scripts\join.ps1' -Force
			Remove-Item -Path 'C:\Windows\System32\WindowsPowerShell\Scripts\rename.ps1' -Force
			Remove-Item -Path $MyInvocation.MyCommand.Path -Force
			Start-Sleep -s 5
			Stop-Transcript
			Restart-Computer
		}
		1 {
			Write-Host "Updates, not installed. You may install updates later by going to Settings > Update & Security and clicking Check for Updates."
			Remove-ItemProperty -Path 'HKLM:\Software\Micorsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultUserName' -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword' -ErrorAction SilentlyContinue
			Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue
			Remove-Item -Path 'C:\Windows\System32\WindowsPowerShell\Scripts\join.ps1' -Force
			Remove-Item -Path 'C:\Windows\System32\WindowsPowerShell\Scripts\rename.ps1' -Force
			Remove-Item -Path $MyInvocation.MyCommand.Path -Force
			pause
			Stop-Transcript
		}
	}
} else {
	Write-Host "There are no updates available at this time."
	Remove-ItemProperty -Path 'HKLM:\Software\Micorsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultUserName' -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword' -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue
	Remove-Item -Path 'C:\Windows\System32\WindowsPowerShell\Scripts\join.ps1' -Force
	Remove-Item -Path 'C:\Windows\System32\WindowsPowerShell\Scripts\rename.ps1' -Force
	Remove-Item -Path $MyInvocation.MyCommand.Path -Force
	pause
	Stop-Transcript
}