
<#PSScriptInfo
.VERSION 1.0
.GUID 855eebd6-3ee1-4499-bea3-d859a39a157f
.AUTHOR Brian Sheaffer
.COMPANYNAME
.COPYRIGHT Copyright (c) 2021 by Brian Sheaffer, under the MIT license.
.TAGS
.LICENSEURI
.PROJECTURI
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
#>

<#
.SYNOPSIS
Toggles SMBv1 support based on the smDeployOrderClassifier WMI instance

.DESCRIPTION
Lots of text goes here to explain all the things.

.PARAMETER Name
Parameter Description

.EXAMPLE
smSMBv1.ps1

#>

[CmdLetBinding()]
Param (
    [ValidateSet('Enable', 'Disable', 'Test', 'Auto')]
    [string] $Mode = 'Test',
    [switch] $AllowReboot = $false
)

[string] $script:AppName = 'smSMBv1.ps1'
[string] $script:OSCaption = (Get-WmiObject Win32_OperatingSystem).Caption

<#
# New: Windows 10, Windows 8.1, Windows Server 2019, Windows Server 2016, and Windows 2012 R2
	Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
	Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol

# Old: Windows 8 and Windows Server 2012
	Disable: Set-SmbServerConfiguration -EnableSMB1Protocol $false
	Enable : Set-SmbServerConfiguration -EnableSMB1Protocol $true

# Oldest: Windows 7, Windows Server 2008 R2, Windows Vista, or Windows Server 2008
	Disable: Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
	Enable : Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 1 -Force
#>

[string] $script:OS = switch -regex ($script:OSCaption) {
    '(7|2008|vista)' { 'Oldest'; break }
    '(10|2019|2016|2012 R2)' { 'New'; break }
    '(8|2012)' { 'Old'; break }
    DEFAULT { "$_"; break }
}

function Get-Indent {
    param (
        [int] $Level,
        [string] $Char = '  '
    )
    ($Char * $Level)
}

function Write-Status {
    param (
        [Parameter(Position = 0)]
        [Alias('Text', 'Subject')]
        [string[]] $Message,
        [Parameter(Position = 1)]
        [string[]] $Type,
        [Parameter(Position = 2)]
        [int] $Level = 0,
        [Parameter(Position = 3)]
        [System.Management.Automation.ErrorRecord] $e,
        [int] $EventID = -1
    )
    [string] $LogType = 'Information'

    [System.ConsoleColor] $ColorInfo = [ConsoleColor]::White
    [System.ConsoleColor] $ColorGood = [ConsoleColor]::Green
    [System.ConsoleColor] $ColorError = [ConsoleColor]::Red
    [System.ConsoleColor] $ColorWarning = [ConsoleColor]::Yellow
    [System.ConsoleColor] $ColorDebug = [ConsoleColor]::Cyan

    [System.ConsoleColor] $FGColor = $ColorInfo
    [System.ConsoleColor] $DefaultBGColor = $Host.UI.RawUI.BackgroundColor
    [System.ConsoleColor] $BGColor = $DefaultBGColor

    [System.ConsoleColor] $ColorHighlight = [ConsoleColor]::DarkGray

    if ($BGColor -eq $ColorHighlight) {
        [System.ConsoleColor] $ColorHighlight = [ConsoleColor]::DarkMagenta
    }

    [string] $Space = Get-Indent -Level $Level

    if ($Message) {
        :parent foreach ($txt in $Message) {
            $BGColor = $DefaultBGColor
            [int] $index = [array]::indexof($Message, $txt)
            Switch -regex ($Type[$index]) {
                '^G' {
                    $FGColor = $ColorGood
                    $LogType = "Information"
                    break
                }
                '^E' {
                    $FGColor = $ColorError
                    $LogType = "Error"
                    break
                }
                '^W' {
                    $FGColor = $ColorWarning
                    $LogType = "Warning"
                    break
                }
                '^D' {
                    $FGColor = $ColorDebug
                    $LogType = "Information"
                    $EventLog = $false
                    break
                }
                '^S' {
                    break parent
                }
                DEFAULT {
                    $FGColor = $ColorInfo
                    $LogType = "Information"
                    break
                }
            }
            if ($index -ge 1) {
                $space = ' '
            }
            Write-Host $Space  -ForegroundColor $FGColor -BackgroundColor $BGColor -NoNewline
            if ($Type[$index] -match 'High$') { $BGColor = $ColorHighlight }
            Write-Host $txt -ForegroundColor $FGColor -BackgroundColor $BGColor -NoNewline
        }
        write-host ''
    }

    if ($e) {
        $Level += 1
        $space = Get-Indent -Level $Level

        [string[]] $wrapped = Set-WordWrap -Message $($e.InvocationInfo.PositionMessage -split "`n") -Level $Level
        $wrapped | ForEach-Object {
            if ($_ -notmatch '^\+ \~') {
                Write-Status -Message $_ -Type 'Warning' -Level $Level
            }
        }

        $wrapped = Set-WordWrap -Message $e.Exception.Message -Level $Level
        $wrapped | ForEach-Object {
            Write-Status -Message $_ -Type 'Error' -Level $Level
        }
    }
    if ($EventID -ge 0) {
        Write-brshEventLog -Type $LogType -Message $Message -e $e -ID $EventID
    }
}

<#
.SYNOPSIS
wraps a string or an array of strings at the console width without breaking within a word
.PARAMETER chunk
a string or an array of strings
.EXAMPLE
word-wrap -chunk $string
.EXAMPLE
$string | word-wrap
#>
function Set-WordWrap {
    [CmdletBinding()]
    Param(
        [string[]] $Message,
        [int] $Level = 0
    )

    BEGIN {
        [string] $Space = Get-Indent -Level $Level
        $Lines = @()
    }

    PROCESS {
        foreach ($line in $Message) {
            $words = ''
            $count = 0
            $line -split '\s+' | ForEach-Object {
                $count += $_.Length + 1
                if ($count -gt ($Host.UI.RawUI.WindowSize.Width - $Space.Length - 6)) {
                    $Lines += , $words.trim()
                    $words = ''
                    $count = $_.Length + 1
                }
                $words = "$words$_ "
            }
            $Lines += , $words.trim()
        }
        # $Lines
    }

    END {
        $Lines
    }
}

function Write-brshEventLog {
    <#
	.SYNOPSIS
	Basic 'Write to the EventLog' function

	.DESCRIPTION
	Everything needs to log something sometime, right? Well, that's what this is for.
	Basically, I extended the Write-Status function to _also_ write an event to the
	EventLog - just supply an EventID to Write-Status, and the message will both
	write to screen with color and indenting, and write to the EventLog ... with ...
	well ... line breaks.

	.PARAMETER Message
	The message - same as Write-Status takes

	.PARAMETER Source
	The "source" for the event - by default, the Module name

	.PARAMETER ID
	An ID number to differentiate various events

	.PARAMETER Type
	The type of event - Information, Warning, or Error

	.PARAMETER e
	An exception object - very simple to pass thru via $_ in a Try/Catch

	.EXAMPLE
	Write-brshEventLog -Message 'This is my entry on brontosauruses.' -EventID 10 -Type 'Information' -Source 'The SuperWhamoDyne App'
	#>
    [cmdletbinding()]
    param (
        [string[]] $Message = 'Default Message',
        [string] $Source = $script:AppName,
        [int] $ID = 9999,
        [ValidateSet('Information', 'Warning', 'Error')]
        [string] $Type = 'Information',
        [Parameter(Position = 3)]
        [System.Management.Automation.ErrorRecord] $e
    )

    $EventType = Switch ($Type) {
        'Error' { 'Error' }
        'Warning' { 'Warning' }
        Default { 'Information' }
    }

    if (New-brshEventLog -EventLog Application -AppName $Source) {
        try {
            [string] $Formatted = $Message -join "`r`n"
            if ($null -ne $e) {
                $Formatted += "`r`n`r`n$($e.InvocationInfo.PositionMessage -split "`n")"
                $Formatted += "`r`n`r`nError message was: $($e.Exception.Message)"

            }
            Write-EventLog -LogName "Application" -Source $Source -EventID $ID -EntryType $EventType -Message $Formatted -ErrorAction Stop
        } catch {
            Write-Status -Message 'Could not write to the EventLog - error writing event' -Type Error -Level 0 -e $_
            Write-Status -Message "Message was:", $Message -Type Warning, Info -Level 1
        }
    }
}

function New-brshEventLog {
    <#
	.SYNOPSIS
	Registers a new EventLog and source
	.DESCRIPTION
	All events need logs, and all logs need sources. This obfuscates the donut making.
	You must register a source with a log before you can write to that log.
	.PARAMETER AppName
	The name of the source (generally the app or script calling it)
	.PARAMETER EventLog
	The event log - 'Application', 'System', or one of your own choosing
	.EXAMPLE
	New-brshEventLog -AppName 'MyApp' -EventLog 'Application'
	#>
    [cmdletbinding()]
    param (
        [string] $AppName = '',
        [string] $EventLog = 'Application'

    )
    [bool] $Found = $false
    if ($AppName.Trim().Length -gt 0) {
        try {
            $Found = [System.Diagnostics.EventLog]::SourceExists($AppName)
        } catch {
            $Found = $false
        }
        if (-not $Found) {
            try {
                Write-Status "Registering new Source ($AppName) in EventLog ($EventLog)" -Level 0 -Type Info
                New-EventLog -LogName $EventLog -Source $AppName -ErrorAction Stop
                $True
            } catch [System.InvalidOperationException] {
                $True
            } catch {
                Write-Status -Message 'Could not write to the EventLog - error registering Log Source' -Type Error -Level 1 -e $_
                $False
            }
        } else {
            $true
        }
    } else {
        $False
    }
}

function Disable-smSMBv1 {
    Write-Status -Message 'Disabling SMBv1' -Type Info -Level 0
    if ($script:OS -eq 'Oldest') {
        Try {
            Write-Status -Message 'Updating Registry' -type Info -Level 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
            if ($AllowReboot) {
                Write-Status -Message 'AllowReboot is True - so rebooting' -Type Info -Level 500
                Restart-Computer -Force
            }
        } catch {
            Write-Status -Message "Failed to update registry to disable SMBv1! OS is '$script:OSCaption' ($OS)" -Type Error -e $_ -EventID 301 -Level 2
        }
    } else {
        try {
            Write-Status -Message 'Running Set-SmbServerConfiguration to false' -type Info -Level 1
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        } catch {
            Write-Status -Message "Failed to disable SMBv1 via Set-SmbServerConfiguration! OS is '$script:OSCaption' ($OS)" -Type Error -e $_ -EventID 302 -Level 2
        }
        if ($script:OS -eq 'New') {
            try {
                Write-Status -Message 'Running Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol' -Type Info -Level 1
                $a = Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart
                if (($a.RestartNeeded) -and ($AllowReboot)) {
                    Write-Status -Message 'AllowReboot is True - so rebooting' -Type Info -Level 500
                                       Restart-Computer -Force
                }
            } catch {
                Write-Status -Message "Failed to disable windows optional feature smb1protocol! OS is '$script:OSCaption' ($OS)" -Type Error -e $_ -EventID 303 -Level 2
            }
        }
    }
}

function Enable-smSMBv1 {
    Write-Status -Message 'Enabling SMBv1' -Type Info -Level 0
    if ($script:OS -eq 'Oldest') {
        try {
            Write-Status -Message 'Updating Registry' -type Info -Level 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 1 -Force
            if ($AllowReboot) {
                Write-Status -Message 'AllowReboot is True - so rebooting' -Type Info -Level 500
                Restart-Computer -Force
            }
        } catch {
            Write-Status -Message "Failed to update registry to enable SMBv1! OS is '$script:OSCaption' ($OS)" -Type Error -e $_ -EventID 201 -Level 2
        }
    } else {
        try {
            Write-Status -Message 'Running Set-SmbServerConfiguration to false' -Type Info -Level 1
            Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
        } catch {
            Write-Status -Message "Failed to enable SMBv1 via Set-SmbServerConfiguration! OS is '$script:OSCaption' ($OS)" -Type Error -e $_ -EventID 202 -Level 2
        }
        if ($script:OS -eq 'New') {
            try {
                Write-Status -Message 'Running Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol' -Type Info -Level 1
                $a = Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart
                if (($a.RestartNeeded) -and ($AllowReboot)) {
                    Write-Status -Message 'AllowReboot is True - so rebooting' -Type Info -Level 500
                    Restart-Computer -Force
                }
            } catch {
                Write-Status -Message "Failed to enable windows optional feature smb1protocol! OS is '$script:OSCaption' ($OS)" -Type Error -e $_ -EventID 203 -Level 2
            }
        }
    }
}

function Test-smSMBv1 {
    <#
	.SYNOPSIS
	Tests if SMBv1 is (and should be) enabled

	.DESCRIPTION
	A simple test of either registry (for older OS's like 2008 and Win7) or the Get-SMBServerConfiguration cmdlet.
	This is just to check if SMBv1 is and/or should be enabled. Useful in the other functions of this module to
	short-circuit actual work if it's not necessary.

	.EXAMPLE
	Test-smSMBv1
	#>
    param (
        [switch] $ReturnObject = $false
    )
    Write-Status 'Testing SMBv1 Status' -type Info -Level 0
    [string] $retval = ''
    [string] $IsEnabled = if ($script:OS -eq 'Oldest') {
        try {
            $retval = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -ErrorAction SilentlyContinue).SMB1
        } catch {
            Write-Status -Message "Failed to read registry to test SMBv1! OS is '$script:OSCaption' ($OS)" -Type Error -e $_ -EventID 101 -Level 2
            $retval = ''
        }
        if (($null -eq $retval) -or ($retval.Trim() -ne "0") -or ($retval.Trim() -eq '')) {
            Write-Status -Message "Registry value for SMBv1 is '$($retval.SMB1)'. OS is '$script:OSCaption' ($OS)" -Type Info -EventID 101 -Level 1
            $true.ToString()
        } else {
            $false.ToString()
        }
    } else {
        try {
            ((Get-SmbServerConfiguration).EnableSMB1Protocol).ToString()
        } catch {
            Write-Status -Message "Failed to test SMBv1 via Get-SmbServerConfiguration! OS is '$script:OSCaption' ($OS)" -Type Error -e $_ -EventID 102 -Level 2
        }
    }
    [string] $ShouldBe = try {
        (Get-WmiObject smDeployOrderClassifier).SMBv1Enable
    } catch {
        Write-Status -Message "Failed to read WMI instance for smDeployOrderClassifier! OS is '$script:OSCaption' ($OS)" -Type Error -e $_ -EventID 103 -Level 2
        $false.ToString()
    }
    [string] $OSFeature = 'n/a'
    if ($script:OS -ne 'Oldest') {
        $OSFeature = (Get-WindowsOptionalFeature -FeatureName smb1protocol -Online).State
        <#
        EnablePending
        Enabled
        DisablePending
        Disabled
        #>
    }
    if ($null -eq $ShouldBe) { $ShouldBe -eq $False.ToString() }
    $Outval = [pscustomobject] @{
        SMBv1ShouldBeEnabled = $ShouldBe
        SMBv1IsEnabled       = $IsEnabled
        OSFeature            = $OSFeature
    }
    Write-Status -Message "SMBv1ShouldBeEnabled = $($Outval.SMBv1ShouldBeEnabled);", "SMBv1IsEnabled = $($Outval.SMBv1IsEnabled);", "OSFeature = $($Outval.OSFeature)" -Type Info, Info, Info -Level 1 -EventID 100
    if ($ReturnObject) { $Outval }
}

function Set-Auto {
    $Status = Test-smSMBv1 -ReturnObject
    if ($Status.OSFeature -match 'Pending') {
        if ($AllowReboot) {
            Write-Status -Message 'Changes are pending - and AllowReboot is True... so rebooting' -Type Info -Level 501
            Restart-Computer -Force
        } else {
        Write-Status "Changes to the OS are pending ('$($Status.OSFeature)') - bypassing any further processing until a reboot" -Type Warning -Level 0 -EventID 9
    }
    } else {
        if ($Status.SMBv1ShouldBeEnabled -match 'True') {
            if ($Status.SMBv1IsEnabled -match 'True') {
                Write-Status 'SMBv1 should be and _is_ enabled. Nothing to do here' -Type Good -Level 0 -EventID 11
            } else {
                Write-Status 'SMBv1 should be but _is not_ enabled.' -Type Warning -Level 0 -EventID 10
                Enable-smSMBv1
            }
        } else {
            if ($Status.SMBv1IsEnabled -match 'True') {
                Write-Status 'SMBv1 should _not_ be but _is_ enabled.' -Type Warning -Level 0 -EventID 20
                Disable-smSMBv1
            } else {
                Write-Status 'SMBv1 should _not_ be and is not enabled. Nothing to do here' -Type Good -Level 0 -EventID 21
            }
        }
    }
}

Switch ($Mode.ToLower()) {
    'Auto' { Set-Auto; break }
    'Enable' { Enable-smSMBv1; break }
    'Disable' { Disable-smSMBv1; break }
    DEFAULT { Test-smSMBv1; break }
}

