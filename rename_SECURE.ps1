## Log Location ##

$log = "C:\Windows\Logs\ScriptOut.log"

## Start Transcript for logging ##

$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -Path $log -Append

## Script Content ##

$title = "Re-name Computer"
$message = "Do you want to rename the computer?"
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Accepts user input to rename the computer based on user input."
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Skips this step and moves on to the rest of the script."
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$result = $Host.ui.PromptForChoice($title, $message, $options, 0)
$secpasswd = ConvertTo-SecureString "<password>" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("<domain>\<username>", $secpasswd)
$valid = $false
Switch ($result)
{
	0{
		$name = Read-Host -Prompt "Please Enter the ComputerName you want to use."
		while ($valid -eq $false) {
			# Validate Name
			if($name.Length -lt 63) {
				if($name -match "^[a-zA-Z0-9-]+$") {
					if($name -match "[a-zA-Z-]"){
						Rename-Computer -NewName $name -DomainCredential $mycreds -Force
						$valid = $true
						Write-Host "Computer has been renamed $name this action will take effect after the next re-start"
					}
					else {
						$name = Read-Host -Prompt "That name is invalid. Please make sure the new name does not consist only of numbers. Please try again"
						$valid = $false
					}
				}
				else{
					$name = Read-Host -Prompt "That name is invalid. Please make sure the new name contains only letters, numbers, or dashes. Please try again"
					$valid = $false
				}
			}
			else{
				$name = Read-Host -Prompt "That name is invalid. Please make sure the new name is less than 63 characters long. Please try again"
				$valid = $false
			}
		}
	}
	1{
		Write-Host "Skipping computer re-name"
	}
}

#Set Registry key to run the next program
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'JoinComputer' -Value 'C:\Windows\System32\WindowsPowershell\v1.0\Powershell.exe "C:\Windows\System32\WindowsPowerShell\Scripts\join.ps1"'
Write-Host "Computer Restarting in 5 seconds..."
Sleep -s 5
Stop-Transcript
Restart-Computer