# Validate-SoQCertificate
Runs basic checks to on a certificate, or the LocalMachine\My store, to verify whether a certificate is SMB over QUIC compatible.

This script uses PowerShell 5.1 or 7+.

```powershell
# download the script
iwr https://raw.githubusercontent.com/JamesKehr/Validate-SoQCertificate/main/Validate-SoQCertificate.ps1 -OutFile "$pwd\Validate-SoQCertificate.ps1"

# run the script
.\Validate-SoQCertificate.ps1


# run with verbose output, shows where certificates fail a test.
.\Validate-SoQCertificate.ps1 -Verbose

# output verbose results to a file on the desktop
.\Validate-SoQCertificate.ps1 -Verbose *> "$env:USERPROFILE\Desktop\soqCerts.txt"
```

## NOTE

This script is in beta and not fully validated. Results are currently not guaranteed to be accurate. Though they should be mostly accurate.
