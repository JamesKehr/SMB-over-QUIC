# Validate-SoQCertificate
Runs basic checks to on a certificate, or the LocalMachine\My store, to verify whether a certificate is SMB over QUIC compatible.

This script works PowerShell 5.1 or 7+. PowerShell 7 is the preferred method because .NET 7 has better certificate methods, which guarantees better accuracy.

```powershell
# download the script
iwr https://raw.githubusercontent.com/JamesKehr/Validate-SoQCertificate/main/Validate-SoQCertificate.ps1 -OutFile "$pwd\Validate-SoQCertificate.ps1"

### Standard output mode ###
# test all scripts in LocalMachine\My
.\Validate-SoQCertificate.ps1

# test a single certificate
.\Validate-SoQCertificate.ps1 -Thumbprint <thumbprint>


### Detailed output mode ###
# test all scripts in LocalMachine\My with detailed results
.\Validate-SoQCertificate.ps1 -Detailed

# test a single certificate with detailed results
.\Validate-SoQCertificate.ps1 -Thumbprint <thumbprint> -Detailed


### Troubleshooting ###
# run with verbose output, shows where certificates fail a test.
.\Validate-SoQCertificate.ps1 -Verbose

# debug level output
# WARNING: This can output a large amount of data to the console
if ($Host.Version.Major -ge 7) {
  .\Validate-SoQCertificate.ps1 -Verbose -Debug
} else {
  # -Debug doesn't work right in Windows PowerShell 5.1, so change the DebugPreference instead
  $currDP = $DebugPreference
  $DebugPreference = "Continue"
  
  .\Validate-SoQCertificate.ps1 -Verbose
  
  $DebugPreference = $currDP
}
  

# output verbose and debug logging, and results to a file on the desktop
.\Validate-SoQCertificate.ps1 -Verbose *> "$([Environment]::GetFolderPath("Desktop"))\soqCerts.txt"
```

## NOTE

This script is in beta and not fully validated. Results are currently not guaranteed to be accurate. Though they should be mostly accurate.
