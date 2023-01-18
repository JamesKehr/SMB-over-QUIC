# Validate-SoQCertificate
Runs basic checks to on a certificate, or the LocalMachine\My store, to verify whether a certificate is SMB over QUIC compatible.

```powershell
# download the script
iwr https://raw.githubusercontent.com/JamesKehr/Validate-SoQCertificate/main/Validate-SoQCertificate.ps1 -OutFile "$pwd\Validate-SoQCertificate.ps1"

# run the script
.\Validate-SoQCertificate.ps1


# run with verbose output, shows where certificates fail a test.
.\Validate-SoQCertificate.ps1 -Verbose
```
