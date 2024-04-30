These scripts now require PowerShell 7.4+. PowerShell 7 is the preferred method because .NET 7 has better certificate support, which guarantees better accuracy. Legacy Windows PowerShell 5.1 will only work with the legacy validation cmdlet.

# Initialize-SmbOverQuicServer

Given a certificate, or the necessary details to create a self-signed certificate, this cmdlet will validate the certificate and then setup the SMB over QUIC server.

This script requires:

- PowerShell 7.4 or newer.
- Windows Server 2025 (currently in Insiders Preview)
- Windows Server 2022: Azure Edition (will not work with standard/on-premises Windows Server 2022 editions)
- A TLS 1.3 capable certificate:
   - See this aricle for requirements: https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic#deploy-smb-over-quic
   - The certificate must be installed in the Computer > Personal store (Cert:\LocalMachine\My)
   - Thumprint of a certificate in the correct certificate store.
   - Certificate object in the correct certificate store.
   - The script can generate a self-signed certificate for testing/private deployments.

## SYNTAX

### Thumbprint set

The certificate must be in the Computer > Personal store (Cert:\LocalMachine\My).

```powershell
.\Initialize-SmbOverQuicServer.ps1 -Thumbprint <String> [-LogPath <String>] [-Verbose]
```

### Certificate set

The certificate must be in the Computer > Personal store (Cert:\LocalMachine\My).

```powershell
.\Initialize-SmbOverQuicServer.ps1 -Certificate <X509Certificate2> [-LogPath <String>] [-Verbose]
```

### Self-signed certificate set

All parameters are required. The certificate will be installed to Computer > Personal (LocalMachine\My) with the public certificate installed to Computer > Trusted Root Certification Authorities (LocalMachine\Root)

```powershell
.\Initialize-SmbOverQuicServer.ps1 -SelfSignedCert -Subject <String> -FriendlyName <String> -DnsNames <String[]> [-LogPath <String>] [-Verbose]
```

## Parameters

### -Thumbprint

The certificate thumbprint to be used to setup the SMB over QUIC server. The certificate must be in LocalMachine\My (Comptuer > Personal).

```yaml
Type: System.String
Parameter Sets: Thumbprint
Aliases:
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Certificate

The certificate object to be used to setup the SMB over QUIC server. The certificate must be in LocalMachine\My (Comptuer > Personal).

```yaml
Type: System.Security.Cryptography.X509Certificates.X509Certificate2
Parameter Sets: Certificate
Aliases:
Required: True
Position: Named
Default value: None
Accept pipeline input: True
Accept wildcard characters: False
```


### -SelfSignedCert

Creates a TLS 1.3 capable certificate and uses it to setup the SMB over QUIC server. The certificate will be in LocalMachine\My (Comptuer > Personal).

```yaml
Type: Switch
Parameter Sets: Self-signed certificate
Aliases:
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```


### -Subject

The certificate subject. This is required by SMB over QUIC, though what is contained in the subject does not matter. It just needs something.

```yaml
Type: String
Parameter Sets: Self-signed certificate
Aliases:
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```


### -FriendlyName

The certificate friendly name. This is required by SMB over QUIC, though what is contained in the subject does not matter. It just needs something.

```yaml
Type: String
Parameter Sets: Self-signed certificate
Aliases:
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsNames

A list of all possible DNS names (short and FQDN) and IP address that can be used to connect to the SMB over QUIC server. This list is added to the Subject Alternative Names (SAN) of the certificate.

The client certificate check will fail if it tries to connect to a server using a name that is not in SAN/DnsNames list.

```yaml
Type: String[]
Parameter Sets: Self-signed certificate
Aliases:
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogPath

Writes verbose logging to files in the provided path. This can be used to audit changes and the script actions, and should be collected when submitting a GitHub issue for troubleshooting purposes.

```yaml
Type: String
Parameter Sets: Self-signed certificate
Aliases:
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Verbose

Writes verbose logging to the console.

```yaml
Type: Switch
Parameter Sets: Self-signed certificate
Aliases:
Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## Examples

```powershell
# Validate and setup the SMB over QUIC server using an existing certificate in Cert:\LocalMachine\My
$certPath = "Cert:\LocalMachine\My\a05e95dc05436de2ee9d9c6e6a433fafc80b696b"
$cert = Get-Item $certPath

$cert | .\Initialize-SmbOverQuicServer.ps1 

# Validate and setup the SMB over QUIC server using an existing certificate thumbprint in Cert:\LocalMachine\My
$tp = 'a05e95dc05436de2ee9d9c6e6a433fafc80b696b'
.\Initialize-SmbOverQuicServer.ps1 -Thumbprint $tp

# Create a self-signed certificate and use it to setup the SMB over QUIC server
.\Initialize-SmbOverQuicServer.ps1 -SelfSignedCert -Subject "SoQ Test" -FriendlyName "My SoQ Test Cert" -DnsNames "$env:computername","soq.contoso.com"
```

# Validate-SmbOverQuicCertificate

Runs basic checks against a certificate, or the entire LocalMachine\My store, to verify whether a certificate is SMB over QUIC (TLS 1.3) compatible.


```powershell
### Standard output mode ###
# test all scripts in LocalMachine\My
.\Validate-SmbOverQuicCertificate.ps1

# test a single certificate
.\Validate-SmbOverQuicCertificate.ps1 -Thumbprint <thumbprint>


### Detailed output mode ###
# test all scripts in LocalMachine\My with detailed results
.\Validate-SmbOverQuicCertificate.ps1 -Detailed

# test a single certificate with detailed results
.\Validate-SmbOverQuicCertificate.ps1 -Thumbprint <thumbprint> -Detailed


### IgnoreOS ###
# test a certificate on a versions of Windows that do not support SMB over QUIC server. This can be used for validation purposes.
# with detailed output.
.\Validate-SmbOverQuicCertificate.ps1 -Thumbprint <thumbprint> -Detailed -IgnoreOS


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
.\Validate-SmbOverQuicCertificate.ps1 -Thumbprint <thumbprint> -Quiet


### Passthru mode ###
# returns the [SoQCertValidation] object(s)
# Detailed is ignored.
$isCertSoQValid = .\Validate-SmbOverQuicCertificate.ps1 -Thumbprint <thumbprint> -Passthru

### Troubleshooting ###
# run with verbose output, shows where certificates fail a test.
.\Validate-SmbOverQuicCertificate.ps1 -Verbose

# log events to file
.\Validate-SmbOverQuicCertificate.ps1 -LogPath C:\temp
```


# Validate-SoQCertificate

:warning: **Warning** :warning:

This is the legacy script built for Windows Server 2022 and Windows PowerShell 5.1. There are bug in this script that are fixed in the new version.

Runs basic checks on a certificate, or the entire LocalMachine\My store, to verify whether a certificate is SMB over QUIC (TLS 1.3) compatible.

:warning: **Warning** :warning:

Some functionality will not work with the legacy script and Windows PowerShell 5.1; such as, ECDSA public key algorithm detection and Quiet mode. Please use PowerShell 7.4+ when executing these scripts.



## Legacy command options

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


### IgnoreOS ###
# test a certificate on a non-Azure Edition system for validation purposes
# with detailed output.
.\Validate-SoQCertificate.ps1 -Thumbprint <thumbprint> -Detailed -IgnoreOS


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
.\Validate-SoQCertificate.ps1 -Thumbprint <thumbprint> -Quiet


### Passthru mode ###
# returns the [SoQCertValidation] object(s)
# Detailed is ignored.
$isCertSoQValid = .\Validate-SoQCertificate.ps1 -Thumbprint <thumbprint> -Passthru

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

This script is in beta and not fully validated. Results are currently not guaranteed to be accurate. Though they should be accurate when using PowerShell 7.
