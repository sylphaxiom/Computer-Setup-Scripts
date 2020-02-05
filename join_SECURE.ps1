## Log Location ##

$log = "C:\Windows\Logs\ScriptOut.log"

## Start Transcript for logging ##

$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -Path $log -Append

## Script Content ##

$secpasswd = ConvertTo-SecureString "<password>" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("<domain>\<username>", $secpasswd)
Add-Computer -DomainName "<domain>" -Credential $mycreds -Force
Write-Host "Computer added to Domain in lawrence.IN > Computers"

$title = "Check for Updates"
$message = "Do you want to Check for updates?"
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Checks for updates and prompts for installation."
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Skips this step and moves on to the rest of the script."
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$result = $Host.ui.PromptForChoice($title, $message, $options, 0)
Switch ($result) {
	0 {
		Write-Host "Getting ready to restart and run update script in 5 seconds..."
		#Set Registry key to run the next program
		Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'UpdateComputer' -Value 'C:\Windows\System32\WindowsPowershell\v1.0\Powershell.exe "C:\Windows\System32\WindowsPowerShell\Scripts\update.ps1"'
		Start-Sleep -s 5
		Stop-Transcript
		Restart-Computer
	}
	1 {
		Write-Host "Skipping Windows Update check and restarting in 5 seconds..."
		Remove-ItemProperty -Path 'HKLM:\Software\Micorsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultUserName' -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword' -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue
		Remove-Item -Path 'C:\Windows\System32\WindowsPowerShell\Scripts\update.ps1' -Force
		Remove-Item -Path 'C:\Windows\System32\WindowsPowerShell\Scripts\rename.ps1' -Force
		Remove-Item -Path $MyInvocation.MyCommand.Path -Force
		Start-Sleep -s 5
		Stop-Transcript
		Restart-Computer
	}
}