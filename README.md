# Validate-SoQCertificate
Runs basic checks on a certificate, or the entire LocalMachine\My store, to verify whether a certificate is SMB over QUIC (TLS 1.3) compatible.

These scripts now require PowerShell 7.4+. PowerShell 7 is the preferred method because .NET 7 has better certificate support, which guarantees better accuracy. Legacy Windows PowerShell 5.1 will only work with the legacy validation cmdlet.

:warning: **Warning** :warning:

Some functionality will not work with the legacy script and Windows PowerShell 5.1; such as, ECDSA public key algorithm detection and Quiet mode. Please use PowerShell 7.4+ when executing these scripts.



## Legacy command options

```powershell
# download the script
iwr https://raw.githubusercontent.com/JamesKehr/Validate-SoQCertificate/main/Validate-SoQCertificate.ps1 -OutFile "$pwd\Validate-SoQCertificate.ps1"

### Standard output mode ###
# test all scripts in LocalMachine\My
.\Validate-SmbOverQuicCertificateLegacy.ps1

# test a single certificate
.\Validate-SmbOverQuicCertificateLegacy.ps1 -Thumbprint <thumbprint>


### Detailed output mode ###
# test all scripts in LocalMachine\My with detailed results
.\Validate-SmbOverQuicCertificateLegacy.ps1 -Detailed

# test a single certificate with detailed results
.\Validate-SmbOverQuicCertificateLegacy.ps1 -Thumbprint <thumbprint> -Detailed


### IgnoreOS ###
# test a certificate on a non-Azure Edition system for validation purposes
# with detailed output.
.\Validate-SmbOverQuicCertificateLegacy.ps1 -Thumbprint <thumbprint> -Detailed -IgnoreOS


### Quiet mode ###
# return a boolean ($true or $false)
# Requires:
#    - PowerShell 7
#    - Thumbprint
# Optional:
#    - IgnoreOS
# Ignores:
#    - Detailed
#    - PassThru
.\Validate-SmbOverQuicCertificateLegacy.ps1 -Thumbprint <thumbprint> -Quiet


### Passthru mode ###
# returns the [SoQCertValidation] object(s)
# Detailed is ignored.
$isCertSoQValid = .\Validate-SmbOverQuicCertificateLegacy.ps1 -Thumbprint <thumbprint> -Passthru

### Troubleshooting ###
# run with verbose output, shows where certificates fail a test.
.\Validate-SmbOverQuicCertificateLegacy.ps1 -Verbose

# debug level output
# WARNING: This can output a large amount of data to the console
if ($Host.Version.Major -ge 7) {
  .\Validate-SmbOverQuicCertificateLegacy.ps1 -Verbose -Debug
} else {
  # -Debug doesn't work right in Windows PowerShell 5.1, so change the DebugPreference instead
  $currDP = $DebugPreference
  $DebugPreference = "Continue"
  
  .\Validate-SmbOverQuicCertificateLegacy.ps1 -Verbose
  
  $DebugPreference = $currDP
}
  

# output verbose and debug logging, and results to a file on the desktop
.\Validate-SmbOverQuicCertificateLegacy.ps1 -Verbose *> "$([Environment]::GetFolderPath("Desktop"))\soqCerts.txt"
```

## NOTE

This script is in beta and not fully validated. Results are currently not guaranteed to be accurate. Though they should be accurate when using PowerShell 7.
