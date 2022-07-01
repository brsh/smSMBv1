# smSMBv1.ps1 - Enable or Disable Server-Side SMBv1 Protocol

A script used to enable/disable (incl. install/uninstall if approps) the SMBv1 protocol
on Windows systems. 

Note: This only affects the _serving_ of SMBv1 - it does not affect a client being able
to _read_ (or _access_) SMBv1 resources.

This script is intended to be used with a specific WMI Class (which is not public, sorry).
However, it can be used "manually" via command line switches or modified to support a 
different WMI class.

Syntax
```
PS> .\smSMBv1.ps1 [[-Mode] <String>] [-AllowReboot ] 
```

-Mode:

| Value | Definition |
| ------ | ---------- |
| Enable | Enable/Install SMBv1 Server |
| Disable | Disable/Uninstall SMBv1 Server |
| Test | Test the state of SMBv1 Server |
| Auto | Process SMBv1 Server status as defined by `SMBv1Enable` WMI value |

-AllowReboot:

Enabling/disabling generally requires a reboot. This switch will reboot the server (if needed)

