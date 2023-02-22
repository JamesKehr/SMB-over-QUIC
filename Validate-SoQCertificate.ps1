# validate SMB over QUIC certificate
#requires -RunAsAdministrator
#requires -Version 5.1

using namespace System.Collections
using namespace System.Collections.Generic

<#

https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic

Rquirements retrieved on 18 Jan 2023

DONE - Key usage                      : Digital Signature
DONE - Purpose                        : Server Authentication (EKU 1.3.6.1.5.5.7.3.1)
DONE - Subject Alternative Name (SAN) : (A DNS name entry for each fully qualified DNS name used to reach the SMB server)
DONE - Subject                        : (CN= anything, but must exist)
DONE - Private key included           : yes

DONE - Signature algorithm            : SHA256RSA (or greater)
DONE - Signature hash                 : SHA256 (or greater)
DONE - Public key algorithm           : ECDSA_P256 (or greater. Can also use RSA with at least 2048 length)


Adding as part of validation

DONE - Valid lifetime (not expired)  : (Current date after NotBefore and before NotAfter certificate dates)
DONE - Trusted certificate chain            : (Root and Intermediate CAs are trusted)

DONE - Check cipher suites to ensure that TLS 1.3 suites are enabled. TLS 1.3 states that you cannot use downlevel cipher suites, so disabling TLS 1.3 suites breaks SMB over QUIC and possibly KDC Proxy.
DONE - Validate that the OS is 2022 Azure Edition

DONE - Create a warning state for tests that fail due to technical reason. Started by creating the bones of the SoQState enum and the SoQResult class.

IgnoreOS switch to bypass the OS test, which will allow validation of a certifiate to work anywhere. Helpful when someone is testing for certs that will work on an Azure Edition VM.

Quiet - returns a $true or $false. This will require PowerShell 7!

#>


# no params for now. Validate against everything in the store.
#   - Add ComputerName to test a remote computer
#   - Add Thumbprint to test a specific cert
[CmdletBinding()]
param (
    # Specifies one computer to validate certificate. Default is the local computer. Currently unused.
    [Parameter()]
    [string]
    $ComputerName = '.',

    # The thumbprint of the certificate to test. The certificate must be in the LocalMachine\My store.
    [Parameter()]
    [string]
    $Thumbprint = $null,

    # Returns the full test results.
    [Parameter()]
    [switch]
    $Detailed,

    # Ignore OS test. This allows you to test
    [Parameter()]
    [switch]
    $IgnoreOS,

    # Returns a true or false for a single certificate. Requires PowerShell 7!
    [Parameter()]
    [switch]
    $Quiet,

    # Returns the SMB over QUIC certificate test object(s) to the console.
    [Parameter()]
    [switch]
    $PassThru
)

#### CLASSES ####
#region


<#

class SoQCert {
    [string]
    $

    [bool]
    $isValidtmp

    SoQCert(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        $this.        = $Certificate
        $this.IsValid = $this.Validate()
    }

    [bool]
    Validate()
    {
        [bool]$isValidtmp = $false

        if (  )
        {
            $isValidtmp = $true
        }
        else 
        {
            $this.FailureReason = ""
        }

        return $isValidtmp
    }

    [string]
    ToString()
    {
        return @"
        
"@
    }
}

#>

enum SoQState {
    Pass
    Fail
    Warning
}

class SoQResult {
    [SoQState]
    $IsValid

    [string]
    $FailureReason

    SoQResult() {
        $this.IsValid       = "Warning"
        $this.FailureReason = $null
    }

    SetValidity([SoQState]$Result) {
        $this.IsValid = $Result
    }

    SetFailureReason([string]$FailureReason) {
        $this.FailureReason = $FailureReason
    }

    AddToFailureReason([string]$FR) {
        $this.FailureReason += $FR
    }

    [string]
    ToString() {
        return @"
Valid: $($this.IsValid); FailureReason: $($this.FailureReason)
"@
    }
}


# Make sure this is a SMB over QUIC supported server OS.
class SoQSupportedOS {
    [SoQResult]
    $Result = [SoQResult]::new()

    SoQSupportedOS() {
        Write-Verbose "SoQSupportedOS - Begin"
        $this.Result.SetValidity( "Pass" )
        $this.ValidateServerOS()
        Write-Verbose "SoQSupportedOS - End"
    }

    ValidateServerOS() {
        Write-Verbose "SoQSupportedOS.ValidateServerOS - Begin"

        # get OS version
        $osVer = [System.Environment]::OSVersion | ForEach-Object { $_.Version }
        Write-Verbose "SoQSupportedOS.ValidateServerOS - osVer: $($osVer.ToString())"

        # use WMI to get OS details, since this is designed to run on Windows
        $wmiOS = Get-WmiObject Win32_OperatingSystem -Property Caption,ProductType
        $osName =  $wmiOS.Caption
        Write-Verbose "SoQSupportedOS.ValidateServerOS - Caption: $osName"

        # ProductType: 1 = workstation, 2 = DC, 3 = Server
        $osType = $wmiOS.ProductType
        Write-Verbose "SoQSupportedOS.ValidateServerOS - osType: $osType"

        $this.Result.SetFailureReason("")
        Write-Verbose "SoQSupportedOS.ValidateServerOS - Start - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)"

        # must be server or DC product type
        if ( $osType -ne 2 -and $osType -ne 3 ) {
            $this.Result.SetValidity( "Fail" )
            $this.Result.AddToFailureReason( "Not Windows Server." )
        }
        Write-Verbose "SoQSupportedOS.ValidateServerOS - ProductType - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)"

        # must be Server 2022 or higher
        if ($osVer.Major -lt 10 -and $osVer.Build -lt 20348) {
            $this.Result.SetValidity( "Fail" )
            $this.Result.AddToFailureReason( " Not Windows Server 2022 or greater." )
        } 
        Write-Verbose "SoQSupportedOS.ValidateServerOS - Version - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)"
        
        # the edition must be Azure Edition
        if ($osName -notmatch "Azure Edition") {
            $this.Result.SetValidity( "Fail" )
            $this.Result.AddToFailureReason( " Not Azure Edition." )
        }
        Write-Verbose "SoQSupportedOS.ValidateServerOS - Azure Edition - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)"

        # clear failure reason if IsValid passed
        if ( $this.Result.IsValid -eq "Pass" ) {
            $this.Result.SetFailureReason( "" )
        }
        Write-Verbose "SoQSupportedOS.ValidateServerOS - End - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)"
    }

    [string]
    ToString() {
        return @"
SupportedOS
   Valid       : $($this.Result.IsValid)
   $( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }
}

# tracks and stores certificate dates and whether the certificate date is out of bounds
class SoQCertExpired {
    [datetime]
    $NotBefore

    [datetime]
    $NotAfter

    [SoQResult]
    $Result = [SoQResult]::new()

    SoQCertExpired(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertExpired] - Start"
        $this.NotBefore      = $Certificate.NotBefore
        $this.NotAfter       = $Certificate.NotAfter
        Write-Debug "[SoQCertExpired] - Validate"
        $this.Result.SetValidity( $this.ValidateDate() )
        Write-Debug "[SoQCertExpired] - End"
    }

    [SoQState]
    ValidateDate()
    {
        Write-Debug "[SoQCertExpired].ValidateDate() - Start"
        [SoQState]$isValidtmp = "Fail"
        
        $date = Get-Date
        if ( $this.NotBefore -lt $date -and $this.NotAfter -gt $date )
        {
            Write-Debug "[SoQCertExpired].ValidateDate() - IsValid: True"
            $isValidtmp = "Pass"
        }
        else
        {
            Write-Debug "[SoQCertExpired].ValidateDate() - IsValid: False"
            $FR = "Certificate is expired. Expires: $($this.NotAfter.ToShortDateString()) $($this.NotAfter.ToShortTimeString()), Date: $($date.ToShortDateString()) $($date.ToShortTimeString())"
            $this.Result.SetFailureReason( $FR )
            Write-Debug "[SoQCertExpired].ValidateDate() - Failure Reason: $($this.Result.FailureReason)"
            Write-Debug "[SoQCertExpired].ValidateDate() - NotBefore: $($this.NotBefore.ToString()), NotAfter: $($this.NotAfter.ToString()), Test Date: $($date.ToString()) "
        }

        Write-Debug "[SoQCertExpired].ValidateDate() - End"
        return $isValidtmp
    }

    [string]
    ToString()
    {
        return @"
Valid Dates
   Not Before : $($this.NotBefore.ToShortDateString()) $($this.NotBefore.ToShortTimeString())
   Not After  : $($this.NotAfter.ToShortDateString()) $($this.NotAfter.ToShortTimeString())
   Valid      : $($this.Result.IsValid)
   $( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }
}


# tests whether the Server Authentication EKU is a cert purpose
class SoQCertPurpose {
    [string[]]
    $Purpose

    [SoQResult]
    $Result = [SoQResult]::new()

    SoQCertPurpose(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertPurpose] - Start"
        $this.Purpose = $Certificate.EnhancedKeyUsageList.FriendlyName
        Write-Debug "[SoQCertPurpose] - Validate"
        $this.Result.SetValidity( $this.ValidatePurpose() )
        Write-Debug "[SoQCertPurpose] - End"
    }

    [SoQState]
    ValidatePurpose()
    {
        Write-Debug "[SoQCertPurpose].ValidatePurpose() - Start"
        [SoQState]$isValidtmp = "Fail"

        if ( $this.Purpose -contains "Server Authentication")
        {
            Write-Debug "[SoQCertPurpose].ValidatePurpose() - IsValid: True"
            $isValidtmp = "Pass"
        }
        else 
        {
            Write-Debug "[SoQCertPurpose].ValidatePurpose() - IsValid: False"
            $this.Result.SetFailureReason( "Purpose does not contain Server Authentication. Purpose: $($this.Purpose -join ', ')" )
            Write-Debug "[SoQCertPurpose].ValidatePurpose() - Failure Reason: $($this.FailureReason)"
            Write-Debug "[SoQCertPurpose].ValidatePurpose() - Purpose: $($this.Purpose), Must contain: Server Authentication"
        }

        Write-Debug "[SoQCertPurpose].ValidatePurpose() - End"
        return $isValidtmp
    }

    [string]
    ToString()
    {
        return @"
Purpose
   Purpose : $($this.Purpose -join ', ')
   Valid   : $($this.Result.IsValid)
   $( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }
}


# Key Usage must contain Digital Signature
class SoQCertKeyUsage {
    [string]
    $KeyUsage

    [SoQResult]
    $Result = [SoQResult]::new()

    SoQCertKeyUsage(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertKeyUsage] - Start"
        $tmpKey = $Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Key Usage" }
        if ( $tmpKey )
        {
            $this.KeyUsage = $tmpKey.Format(1)
        }
        else 
        {
            Write-Debug "[SoQCertKeyUsage] - KeyUsage was not found."
            $this.KeyUsage = $null
        }
        
        Write-Debug "[SoQCertKeyUsage] - Validate"
        $this.Result.SetValidity( $this.ValidateKeyUsage() )
        Write-Debug "[SoQCertKeyUsage] - End"
    }

    [SoqState]
    ValidateKeyUsage()
    {
        Write-Debug "[SoQCertKeyUsage].ValidateKeyUsage() - Start"
        [SoqState]$isValidtmp = "Fail"

        if ( $this.KeyUsage -match "Digital Signature" )
        {
            Write-Debug "[SoQCertKeyUsage].ValidateKeyUsage() - IsValid: True"
            $isValidtmp = "Pass"
        }
        else 
        {
            Write-Debug "[SoQCertKeyUsage].ValidateKeyUsage() - IsValid: False"
            $this.Result.SetFailureReason( "Key Usage does not contain Digital Signature. ($($this.KeyUsage))" )
            Write-Debug "[SoQCertKeyUsage].ValidateKeyUsage() - Failure Reason: $($this.Result.FailureReason)"
            Write-Debug "[SoQCertKeyUsage].ValidateKeyUsage() - KeyUsage: $($this.KeyUsage), Requires: Digital Signature"
        }

        Write-Debug "[SoQCertKeyUsage].ValidateKeyUsage() - End"
        return $isValidtmp
    }

    [string]
    ToString()
    {
        return @"
Key Usage
   Key Usage : $($this.KeyUsage.TrimEnd("`n`r"))
   Valid     : $($this.Result.IsValid)
   $( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }
}

# Subject must contain something
class SoQCertSubject {
    [string]
    $Subject

    [SoQResult]
    $Result = [SoQResult]::new()

    # regex expressions for Subject
    [regex] hidden static 
    $rgxSubject = "CN=\w{1}"

    SoQCertSubject(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertSubject] - Start"
        $this.Subject = $Certificate.Subject
        Write-Debug "[SoQCertSubject] - Validate"
        $this.Result.SetValidity( $this.ValidateSubject() )
        Write-Debug "[SoQCertSubject] - End"
    }

    [SoQState]
    ValidateSubject()
    {
        Write-Debug "[SoQCertSubject].ValidateSubject() - Start"
        [SoQState]$isValidtmp = "Fail"

        if ( $this.Subject -match $this.rgxSubject )
        {
            Write-Debug "[SoQCertSubject].ValidateSubject() - IsValid: True"
            $isValidtmp = "Pass"
        }
        else 
        {
            Write-Debug "[SoQCertSubject].ValidateSubject() - IsValid: False"
            $this.Result.SetFailureReason( "Does not contain a Subject. ($($this.Subject))" )
            Write-Debug "[SoQCertSubject].ValidateSubject() - Failure Reason: $($this.Result.FailureReason)"
            Write-Debug "[SoQCertSubject].ValidateSubject() - Subject: $($this.Subject), Requires: CN=<some text>"
        }

        Write-Debug "[SoQCertSubject].ValidateSubject() - End"
        return $isValidtmp
    }

    [string]
    ToString()
    {
        return @"
Subject
   Subject : $($this.Subject)
   Valid   : $($this.Result.IsValid)
   $( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }
}

# There must be at least one Subject Alternative Name
class SoQCertSAN {
    [string[]]
    $SubjectAltName

    [SoQResult]
    $Result = [SoQResult]::new()

    SoQCertSAN(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertSAN] - Start"
        $this.SubjectAltName = $Certificate.DnsNameList.Unicode
        Write-Debug "[SoQCertSAN] - Validate"
        $this.Result.SetValidity( $this.ValidateSAN() )
        Write-Debug "[SoQCertSAN] - End"
    }

    [SoQState]
    ValidateSAN()
    {
        Write-Debug "[SoQCertSAN].ValidateSAN() - Start"
        [SoQState]$isValidtmp = "Fail"

        if ( ($this.SubjectAltName).Count -ge 1 )
        {
            Write-Debug "[SoQCertSAN].ValidateSAN() - IsValid: True"
            $isValidtmp = "Pass"
        }
        else 
        {
            Write-Debug "[SoQCertSAN].ValidateSAN() - IsValid: False"
            $this.Result.SetFailureReason( "No Subject Alternative Names. ($($this.SubjectAltName -join ', '))" )
            Write-Debug "[SoQCertSAN].ValidateSAN() - Failure Reason: $($this.Result.FailureReason)"
            Write-Debug "[SoQCertSAN].ValidateSAN() - SubjectAltName: $($this.SubjectAltName -join ', '); Count: $(($this.SubjectAltName).Count); Count >= 1."
        }

        Write-Debug "[SoQCertSAN].ValidateSAN() - End"
        return $isValidtmp
    }

    [string]
    ToString()
    {
        return @"
Subject Alternative Name (DNS)
   DNS List : $($this.SubjectAltName -join ', ')
   Valid    : $($this.Result.IsValid)
   $( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }
}

# The private key must be installed
class SoQCertPrivateKey {
    [SoQResult]
    $Result = [SoQResult]::new()

    SoQCertPrivateKey(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertPrivateKey] - Start"
        if ($Certificate.HasPrivateKey) {
            $this.Result.SetValidity( "Pass" )
            Write-Debug "[SoQCertPrivateKey] - IsValid: True"
        } else {
            Write-Debug "[SoQCertPrivateKey] - IsValid: False"
            $this.Result.SetFailureReason( "No Private Key." )
            Write-Debug "[SoQCertPrivateKey] - Failure Reason: $($this.Result.FailureReason)"
            Write-Debug "[SoQCertPrivateKey] - HasPrivateKey: False"
        }

        Write-Debug "[SoQCertPrivateKey] - End"
    }

    [string]
    ToString()
    {
        return @"
Private Key
   HasPrivateKey : $($this.Result.IsValid)
   $( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" }) 
"@
    }
}

# TLS 1.3 algorithms must be supported
class SoQCertSignatureAlgorithm {
    [string]
    $SignatureAlgorithm

    [SoQResult]
    $Result = [SoQResult]::new()

    SoQCertSignatureAlgorithm(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertSignatureAlgorithm] - Start"
        $this.SignatureAlgorithm = $Certificate.SignatureAlgorithm.FriendlyName
        Write-Debug "[SoQCertSignatureAlgorithm] - Validate"
        $this.Result.SetValidity( $this.ValidateSignatureAlgorithm() )
        Write-Debug "[SoQCertSignatureAlgorithm] - End"
    }

    [string[]]
    GetValidSigAlgo()
    {
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/a48b02b2-2a10-4eb0-bed4-1807a6d2f5ad
        # Retrieved 18 Jan 2023
        # array of supported signature hash algorithms
        return @("sha256ECDSA", "sha384ECDSA", "sha512ECDSA", "sha256RSA", "sha384RSA", "sha512RSA")
    }

    [SoQState]
    ValidateSignatureAlgorithm()
    {
        Write-Debug "[SoQCertSignatureAlgorithm].ValidateSignatureAlgorithm() - Start"
        [SoQState]$isValidtmp = "Fail"

        if ( $this.SignatureAlgorithm -in $this.GetValidSigAlgo() )
        {

            Write-Debug "[SoQCertSignatureAlgorithm].ValidateSignatureAlgorithm() - IsValid: True"
            $isValidtmp = "Pass"
        }
        else 
        {
            Write-Debug "[SoQCertSignatureAlgorithm].ValidateSignatureAlgorithm() - IsValid: False"
            $this.Result.SetFailureReason( "Uses a Signature Algorithm not known to work. ($($this.SignatureAlgorithm))" )
            Write-Debug "[SoQCertSignatureAlgorithm].ValidateSignatureAlgorithm() - Failure Reason: $($this.Result.FailureReason)"
            Write-Debug "[SoQCertSignatureAlgorithm].ValidateSignatureAlgorithm() - SignatureAlgorithm: $($this.SignatureAlgorithm), Valid Range: $($this.GetValidSigAlgo() -join ', ')"
        }

        Write-Debug "[SoQCertSignatureAlgorithm].ValidateSignatureAlgorithm() - End"
        return $isValidtmp
    }

    [string]
    ToString()
    {
        return @"
Signature Algorithm
   SignatureAlgorithm : $($this.SignatureAlgorithm)
   Valid              : $($this.Result.IsValid)
   $( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }
}

# Cannot use a weak signature hash
class SoQCertSignatureHash {
    [string]
    $SignatureHash

    [SoQResult]
    $Result = [SoQResult]::new()

    SoQCertSignatureHash(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertSignatureHash] - Start"
        $this.SignatureHash  = $this.GetHashString($Certificate)
        Write-Debug "[SoQCertSignatureHash] - Validate"
        $this.Result.SetValidity( $this.ValidateSigHash() )
        Write-Debug "[SoQCertSignatureHash] - End"
    }

    [string[]]
    GetValidHash()
    {
        return @("sha256", "sha384", "sha512")
    }

    [string]
    GetHashString([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate)
    {
        Write-Debug "[SoQCertSignatureHash].GetHashString() - Start"
        $strHash = ""

        [regex]$rgxHash = "(?<hash>md\d{1})|(?<hash>sha\d{1,3})"

        if ( $Certificate.SignatureAlgorithm.FriendlyName -match $rgxHash )
        {
            $strHash = $Matches.hash.ToString().ToLower()
            Write-Debug "[SoQCertSignatureHash].GetHashString() - Hash found. strHash: $strHash"
        } else {
            Write-Debug "[SoQCertSignatureHash].GetHashString() - Hash not found."
            $strHash = "Unknown"
        }

        Write-Debug "[SoQCertSignatureHash].GetHashString() - Start"
        return $strHash
    }

    [SoQState]
    ValidateSigHash()
    {
        Write-Debug "[SoQCertSignatureHash].ValidateSigHash() - Start"
        [SoQState]$isValidtmp = "Fail"

        if ( $this.SignatureHash -in $this.GetValidHash() )
        {
            Write-Debug "[SoQCertSignatureHash].ValidateSigHash() - IsValid: True"
            $isValidtmp = "Pass"
        }
        else 
        {
            Write-Debug "[SoQCertSignatureHash].ValidateSigHash() - IsValid: False"
            $this.Result.SetFailureReason( "Not a valid signature hash. ($($this.SignatureHash))" )
            Write-Debug "[SoQCertSignatureHash].ValidateSigHash() - Failure Reason: $($this.Result.FailureReason)"
            Write-Debug "[SoQCertSignatureHash].ValidateSigHash() - SignatureHash: $($this.SignatureHash), Valid Range: $($this.GetValidHash() -join ', ')"
        }

        Write-Debug "[SoQCertSignatureHash].ValidateSigHash() - End"
        return $isValidtmp
    }

    [string]
    ToString()
    {
        return @"
Signature Hash
   Hash  : $($this.SignatureHash)
   Valid : $($this.Result.IsValid)
   $( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }
}

# A strong key algorithm must be used
class SoQCertPublicKeyAlgorithm {
    [string]
    $PublicKeyAlgorithm

    [SoQResult]
    $Result = [SoQResult]::new()

    SoQCertPublicKeyAlgorithm(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertPublicKeyAlgorithm] - Start"
        $this.PublicKeyAlgorithm = $this.GetPKAString($Certificate)
        Write-Debug "[SoQCertPublicKeyAlgorithm] - Validate"
        $this.Result.SetValidity( $this.ValidatePKA() )
        Write-Debug "[SoQCertPublicKeyAlgorithm] - End"
    }

    [string]
    GetPKAString([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate)
    {
        Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - Start"
        [string]$pka = ""

        if ($script:psVerMaj -ge 7)
        {
            Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - pwsh7 - Using [System.Security.Cryptography.X509Certificates.PublicKey] methods."

            <#
            
                It is possible that the Signature Algorithm and the Public Key Algorithm are different methods.
                For example, the SA can be RSA and the PKA can be ECDSA.

                Sometimes the PubilcKey namespace doesn't show any details about the algorithm in the main properties
                and guessing based on the SA doesn't work, so you have to go through down the lists of methods
                until you find one that works.

                The order:

                ECDSA
                RSA
                DSA
                ECDiffieHellman
            
            #>

            # controls whether the PKA has been found
            $fndPKA = $false

            # trying ECDSA, which should be used most
            Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (7) Testing: ECDSA"
            $objPKA = $Certificate.PublicKey.GetECDsaPublicKey()

            if ( -NOT [string]::IsNullOrEmpty($objPKA.SignatureAlgorithm) ) {
                Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (7) Found ECDSA"
                $fndPKA = $true
                $pka = "$($objPKA.SignatureAlgorithm.ToUpper())_P$($objPKA.KeySize.ToString())"
            }

            if ( -NOT $fndPKA ) {
                Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (7) Testing: RSA"
                # try RSA
                $objPKA = $Certificate.PublicKey.GetRSAPublicKey()

                if (-NOT [string]::IsNullOrEmpty($objPKA.SignatureAlgorithm) ) {
                    $fndPKA = $true
                    $pka = "$($objPKA.SignatureAlgorithm.ToUpper())$($objPKA.KeySize.ToString())"
                }
            }


            if ( -NOT $fndPKA ) {
                Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (7) Testing: DSA"
                # try DSA
                $objPKA = $Certificate.PublicKey.GetDSAPublicKey()

                if (-NOT [string]::IsNullOrEmpty($objPKA.SignatureAlgorithm) ) {
                    Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (7) Found RSA"
                    $fndPKA = $true
                    $pka = "$($objPKA.SignatureAlgorithm.ToUpper())$($objPKA.KeySize.ToString())"
                }
            }


            if ( -NOT $fndPKA ) {
                Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (7) Testing: ECDH"
                # try ECDiffieHellman
                $objPKA = $Certificate.PublicKey.GetECDiffieHellmanPublicKey()

                if (-NOT [string]::IsNullOrEmpty($objPKA.SignatureAlgorithm) ) {
                    Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (7) Found ECDH"
                    $fndPKA = $true
                    $pka = "$($objPKA.SignatureAlgorithm.ToUpper())$($objPKA.KeySize.ToString())"
                }
            }

            if ( -NOT $fndPKA ) {
                Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (7) Could not detect the Public Key Algorithm."
                $pka = "Unknown"
            }
        }
        else {
            Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - PowerShell 5.1 - Trying to abstract the answer."
            
            # .NET 4.x can only detect RSA and DSA. ECDSA and ECDH do not work
            $provider = $Certificate.PublicKey.Oid.FriendlyName
            $size = $Certificate.PublicKey.Key.KeySize

            if ( $pka -eq "RSA" -or $pka -eq "DSA" ) {
                $pka = "$provider$size"
            } else {
                $pka = "Unknown"
                $this.Result.SetFailureReason( "Legacy Windows PowerShell 5.1 cannot decode ECDSA and ECDH public keys. Please try again with PowerShell 7." )
            }

            
        }

        Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - PKA: $pka"

        Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - End"
        return $pka
    }

    [string[]]
    GetValidPKA()
    {
        return @("ECDSA_P256", "ECDSA_P384", "ECDSA_P512", "RSA2048", "RSA4096")
    }

    [SoQState]
    ValidatePKA()
    {
        Write-Debug "[SoQCertPublicKeyAlgorithm].ValidatePKA() - Start"
        [SoQState]$isValidtmp = "Fail"

        if ( $this.Result.FailureReason ) {
            # Detection will fail when PowerShell 5.1 is used and the PKA is EC-based. 
            # Use that FailureReason and return $false
            Write-Debug "[SoQCertPublicKeyAlgorithm].ValidatePKA() - IsValid: Warning"
            $isValidtmp = "Warning"
            Write-Debug "[SoQCertPublicKeyAlgorithm].ValidatePKA() - Warning Reason: $($this.Result.FailureReason)"
        } elseif ( $this.PublicKeyAlgorithm -in $this.GetValidPKA() )
        {
            Write-Debug "[SoQCertPublicKeyAlgorithm].ValidatePKA() - IsValid: True"
            $isValidtmp = "Pass"
        }
        else 
        {
            Write-Debug "[SoQCertPublicKeyAlgorithm].ValidatePKA() - IsValid: False"
            $this.Result.SetFailureReason( "Not a known supported Public Key Algorithm. ($($this.PublicKeyAlgorithm))" )
            Write-Debug "[SoQCertPublicKeyAlgorithm].ValidatePKA() - Failure Reason: $($this.Result.FailureReason)"
            Write-Debug "[SoQCertPublicKeyAlgorithm].ValidatePKA() - PublicKeyAlgorithm: $($this.PublicKeyAlgorithm), Valid Range: $($this.GetValidPKA() -join ', ')"
        }

        Write-Debug "[SoQCertPublicKeyAlgorithm].ValidatePKA() - End"
        return $isValidtmp
    }

    [string]
    ToString()
    {
        return @"
Public Key Algorithm     
   PKA   : $($this.PublicKeyAlgorithm)
   Valid : $($this.Result.IsValid)
   $( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }
}

# The certificate chain must be trusted
class SoQCertCertChain {
    [SoQResult]
    $Result = [SoQResult]::new()

    SoQCertCertChain(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertCertChain] - Start"
        Write-Debug "[SoQCertCertChain] - Validate"
        $this.Result.SetValidity( $this.ValidateCertChain($Certificate) )
        Write-Debug "[SoQCertCertChain] - End"
    }

    [SoQState]
    ValidateCertChain([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate)
    {
        Write-Debug "[SoQCertCertChain].ValidateCertChain() - Start"
        [SoQState]$isValidtmp = "Fail"

        ## let certutil handle cert chain validation ##
        # export the cer file
        $fn = "cert_$(Get-Date -Format "ddMMyyyyHHmmssffff").cer"
        Write-Debug "[SoQCertCertChain].ValidateCertChain() - Create file: $pwd\$fn"
        $null = Export-Certificate -Cert $Certificate -FilePath "$pwd\$fn" -Force

        # verify the cert chain
        Write-Debug "[SoQCertCertChain].ValidateCertChain() - Execute: certutil -verify `"$pwd\$fn`""
        $results = certutil -verify "$pwd\$fn"
        Write-Debug "[SoQCertCertChain].ValidateCertChain() - Results:`n$results`n"


        # remove the cer file
        Write-Debug "[SoQCertCertChain].ValidateCertChain() - Remove File"
        $null = Remove-Item "$pwd\$fn" -Force

        # validation is true if CERT_E_UNTRUSTEDROOT is not in the output
        if ( -NOT ($results | Where-Object { $_ -match 'CERT_E_UNTRUSTEDROOT' }) ) {
            Write-Debug "[SoQCertCertChain].ValidateCertChain() - IsValid: Pass"
            $isValidtmp = "Pass"
        }
        else 
        {
            Write-Debug "[SoQCertCertChain].ValidateCertChain() - IsValid: Fail"
            $this.Result.SetFailureReason( "Certificate chain validation failed. 'certutil -verify' returned error CERT_E_UNTRUSTEDROOT." )
            Write-Debug "[SoQCertCertChain].ValidateCertChain() - Failure Reason: $($this.Result.FailureReason)"
            Write-Debug "[SoQCertCertChain].ValidateCertChain() - CERT_E_UNTRUSTEDROOT:`n$(($results | Where-Object { $_ -match 'CERT_E_UNTRUSTEDROOT' }) -join "`n")`n`n "
        }

        Write-Debug "[SoQCertCertChain].ValidateCertChain() - End"
        return $isValidtmp
    }

    [string]
    ToString()
    {
        return @"
Certificate Chain
   ValidCertChain : $($this.Result.IsValid)
   $( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }
}


class SoQCipherSuite {
    [string]
    $TlsString

    [bool]
    $StrongCrypto

    [bool]
    $isVerTls13

    SoQCipherSuite(){
        $this.TlsString    = $null
        $this.StrongCrypto = $false
        $this.isVerTls13   = $false
    }

    # used to create a class object from ConvertFrom-Json
    SoQCipherSuite([PSCustomObject]$obj){
        $this.TlsString    = $obj.TlsString
        $this.StrongCrypto = $obj.StrongCrypto
        $this.isVerTls13   = $obj.isVerTls13
    }

    SetTlsString([string]$TlsString) {
        Write-Debug "SoQCipherSuite. - Cipher string: $TlsString"
        $this.TlsString = $TlsString
    }

    SetStrongCrypto([string]$str) {
        if ($str -match 'Yes') {
            $this.StrongCrypto = $true
        } else {
            $this.StrongCrypto = $false
        }

        Write-Debug "SoQCipherSuite.SetStrongCrypto - Strong crypto: $($this.StrongCrypto)"
    }

    SetIsVerTls13([string]$str) {
        if ($str -match 'TLS 1.3') {
            Write-Debug "SoQCipherSuite.SetIsVerTls13 - Is TLS 1.3"
            $this.isVerTls13 = $true
        } else {
            $this.isVerTls13 = $false
            Write-Debug "SoQCipherSuite.SetIsVerTls13 - Is NOT TLS 1.3"
        }
        Write-Debug "SoQCipherSuite.SetIsVerTls13 - TLS 1.3: $($this.isVerTls13)"
    }

    [string]
    ToString() {
        return @"
TlsString: $($this.TlsString); STRONG_CRYPTO: $($this.StrongCrypto); TLS1.3Suite: $($this.isVerTls13)
"@
    }
}


class SoQTls13Support {
    [array]
    $Tls13CipherSuites

    [SoQResult]
    $Result = [SoQResult]::new()

    SoQTls13Support() {
        Write-Verbose "SoQTls13Support - Begin"
        # if there is an internet connection we get the list of supported TLS 1.3 cipher suites
        if ((Get-NetConnectionProfile).IPv4Connectivity -contains "Internet" -or (Get-NetConnectionProfile).IPv6Connectivity -contains "Internet") {
            Write-Verbose "SoQTls13Support - Trying to get the live TLS 1.3 list."
            $this.GetTls13CipherSuitesFromInternet()
        } else {
            Write-Verbose "SoQTls13Support - Using last known good TLS 1.3 list."
           $this.UseLastKnownGoodTls13CipherSuites()
        }

        # test whether there is at least one valid TLS 1.3 cipher suite enabled on the system
        Write-Verbose "SoQTls13Support - Validating TLS 1.3 support."
        $this.ValidateLocalCipherSuite()

        Write-Verbose "SoQTls13Support - Result:`n$($this.ToString())"
        Write-Verbose "SoQTls13Support - End"
    }

    # populates Tls13CipherSuites with a list of known supported TLS 1.3 ciphers in Windows
    # https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022
    # Retrieved: 15 Feb 2023
    UseLastKnownGoodTls13CipherSuites() {
        Write-Verbose "SoQTls13Support.UseLastKnownGoodTls13CipherSuites() - Begin"
        # use the last known good list of TLS 1.3 cipher suites
        $tmpList = @'
[
   {
       "TlsString": "TLS_AES_256_GCM_SHA384",
       "StrongCrypto": true,
       "isVerTls13": true
   },
   {
       "TlsString": "TLS_AES_128_GCM_SHA256",
       "StrongCrypto": true,
       "isVerTls13": true
   },
   {
       "TlsString": "TLS_CHACHA20_POLY1305_SHA256",
       "StrongCrypto": true,
       "isVerTls13": true
   }
]
'@ | ConvertFrom-Json
        
        # do this separately or things get mixed up
        [array]$tmpObj = $tmpList | ForEach-Object { [SoQCipherSuite]::new($_) }

        # add results to the class
        $this.Tls13CipherSuites = $tmpObj   
        
        Write-Verbose "SoQTls13Support.UseLastKnownGoodTls13CipherSuites() - End"
   }

   # Retrieves the current list of supported TLS 1.3 cipher suites.
   # https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022
    GetTls13CipherSuitesFromInternet() {
        Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - Begin"
        # The TLS 1.3 cipher suites must be enabled in Windows.
        # right now SoQ only supports Windows Server 2022 so keep this simple for now
        $url = 'https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022'

        # download the page
        Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - Set TLS for Invoke-WebRequest."
        [System.Net.ServicePointManager]::SecurityProtocol = "Tls12", "Tls13"

        $rawSite = $null
        try {
            Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - Downloading the cipher suite site."
            $rawSite = Invoke-WebRequest $url -UseBasicParsing -EA Stop
        }
        catch {
            Write-Verbose "Failed to download the current TLS 1.3 list: $_"
            $this.UseLastKnownGoodTls13CipherSuites()
        }
        
        if ($rawSite) {
            # PowerShell 7 has no native HTML parser, so do this old school.
            # Only interested in saving details about TLS 1.3 cipher strings
            # first, initialize a bunch of variables.
            $tls13CipherTable = @()
            $tableStarted = $false
            $rowStarted = $false
            $tdNum = 0
            $tmpRow = [SoQCipherSuite]::new()
            $rawSite.RawContent -split "`n" | Foreach-Object { 
                # look for the table start
                if ($_ -match "<table>") {
                    Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - Start table"
                    # controls whether to look for tr elements
                    $tableStarted = $true

                    # start table row
                    $rowStarted = $false

                    # How many td elements have been found. Each table element has three:
                    # 1 = Cipher suite string
                    # 2 = Allowed by SCH_USE_STRONG_CRYPTO
                    # 3 = TLS/SSL Protocol versions
                    $tdNum = 1

                } elseif ($_ -match '</table>') {
                    Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - End table"
                    $tableStarted = $false
                } elseif ( $tableStarted ) {
                    # look for a table header we want.
                    if ($_ -match '<tr>') {
                        Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - Start row"
                        $rowStarted = $true
                    } elseif ($_ -match '</tr>') {
                        Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - End row"
                        $rowStarted = $false

                        $tmpRow = [SoQCipherSuite]::new()
                    } elseif ($rowStarted) {
                        # parse the text between <td> and <br/></td> and add it to the class
                        if ($_ -match "<td>(?<str>\w{2}.*)<br/></td>") {
                            $text = $Matches.str
                            Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - Found match: $text"
                            
                            if ( -NOT [string]::IsNullOrEmpty($text) ) {
                                switch ($tdNum) {
                                    1 { 
                                        Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - Adding cipher string"
                                        $tmpRow.SetTlsString($text)
                                        $tdNum++
                                    }
                                    
                                    2 { 
                                        Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - Adding strong crypto"
                                        $tmpRow.SetStrongCrypto($text) 
                                        $tdNum++
                                    }

                                    3 { 
                                        Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - Testing if TLS 1.3."
                                        $tmpRow.SetIsVerTls13($text) 

                                        # add to the results only if it's a TLS 1.3 compatible suite
                                        if ($tmpRow.isVerTls13) {
                                            Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - Adding to list.`n`n$($tmpRow.ToString())`n`n"
                                            $tls13CipherTable += $tmpRow
                                        }

                                        $tdNum = 1
                                    }

                                    default { Write-Error "You shouldn't be here."}
                                }
                            }
                        }
                    }
                }
            }

            # set the suites if we got results
            if ($tls13CipherTable.Count -ge 1) {
                Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - Successfully got a working list."
                $this.Tls13CipherSuites = $tls13CipherTable
            # Otherwise, use the last known good set. Just in case something doesn't work.
            } else {
                Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - Something went wrong, falling back to Last Known Good list."
                $this.UseLastKnownGoodTls13CipherSuites()
            }
        }

        Write-Verbose "SoQTls13Support.GetTls13CipherSuitesFromInternet() - End"
    }

    # checks whether the local list of suites has a TLS 1.3 cipher.
    # if the default is used we assume there is a supported cipher, because Windows Server 2022 supports TLS 1.3 by default
    ValidateLocalCipherSuite() {
        Write-Verbose "SoQTls13Support.ValidateLocalCipherSuite() - Begin"
        # look for the registry value that controls cipher suites
        [array]$cipherPol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' | ForEach-Object { $_.Functions.Split(',') }

        Write-Verbose "SoQTls13Support.ValidateLocalCipherSuite() - Cipher suites: $($cipherPol -join ', ')"

        if ($cipherPol.Count -ge 1) {
            Write-Verbose "SoQTls13Support.ValidateLocalCipherSuite() - Starting validation."
            # test whether there is an approved TLS 1.3 cipher
            $fndValidTls13Suite = $false

            $this.Tls13CipherSuites | ForEach-Object { 
                if ($_.String -in $cipherPol) {
                    Write-Verbose "SoQTls13Support.ValidateLocalCipherSuite() - Found a match: $($_.String)"
                    $fndValidTls13Suite = $true
                }
            }

            if ($fndValidTls13Suite) {
                Write-Verbose "SoQTls13Support.ValidateLocalCipherSuite() - Validation passed."
                $this.Result.SetValidity( "Pass" )
            } else {
                Write-Verbose "SoQTls13Support.ValidateLocalCipherSuite() - Validation failed."
                $this.Result.SetValidity( "Fail" )
                $this.FailureReason = "The 'SSL Cipher Suite Order' policy has been modified and does not include a TLS 1.3 compatible cipher suite. See: https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022"
            }

        } else {
            Write-Verbose "SoQTls13Support.ValidateLocalCipherSuite() - Policy is default. Accepting this as a pass."
            # no special cipher policy is installed, the default will be compatible.
            $this.Result.SetValidity( "Pass" )
        }
        Write-Verbose "SoQTls13Support.ValidateLocalCipherSuite() - End"
    }

    [string]
    ToString() {
        return @"
SoQTls13Support
   Tls13CipherSuites : $($this.Tls13CipherSuites.TlsString -join ',') 
   Valid             : $($this.Result.IsValid)
   $( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }
}


# this class monitors the certs 
class SoQCertValidation {
    # the certificate object
    [System.Security.Cryptography.X509Certificates.X509Certificate]
    $Certificate

    [SoQState]
    $IsValid

    [string[]]
    $FailedTests

    [SoQSupportedOS]
    $SupportedOS

    [SoQCertExpired]
    $Expiration

    [SoQCertPurpose]
    $Purpose

    [SoQCertKeyUsage]
    $KeyUsage

    [SoQCertSubject]
    $Subject

    [SoQCertSAN]
    $SubjectAltName

    [SoQCertPrivateKey]
    $PrivateKey

    [SoQCertSignatureAlgorithm]
    $SignatureAlgorithm

    [SoQCertSignatureHash]
    $SignatureHash

    [SoQCertPublicKeyAlgorithm]
    $PublicKeyAlgorithm

    [SoQCertCertChain]
    $CertChain

    [SoQTls13Support]
    $Tls13Support

    [bool]
    hidden $IgnoreOS


    SoQCertValidation([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate, $IgnoreOS)
    {
        Write-Debug "[SoQCertValidation] - Start"
        $this.Certificate        = $Certificate
        Write-Debug "[SoQCertValidation] - Thumbprint: $($this.Certificate.Thumbprint), Subject: $($this.Certificate.Subject)"
        Write-Debug "[SoQSupportedOS] - SupportedOS"
        if ($IgnoreOS) {
            $this.IgnoreOS           = $true
            $this.SupportedOS        = $null
        } else {
            $this.IgnoreOS           = $false
            $this.SupportedOS        = [SoQSupportedOS]::new()
        }
        Write-Debug "[SoQCertValidation] - Expiration"
        $this.Expiration         = [SoQCertExpired]::new($Certificate)
        Write-Debug "[SoQCertValidation] - Purpose"
        $this.Purpose            = [SoQCertPurpose]::new($Certificate)
        Write-Debug "[SoQCertValidation] - KeyUsage"
        $this.KeyUsage           = [SoQCertKeyUsage]::new($Certificate)
        Write-Debug "[SoQCertValidation] - Subject"
        $this.Subject            = [SoQCertSubject]::new($Certificate)
        Write-Debug "[SoQCertValidation] - SubjectAltName"
        $this.SubjectAltName     = [SoQCertSAN]::new($Certificate)
        Write-Debug "[SoQCertValidation] - PrivateKey"
        $this.PrivateKey         = [SoQCertPrivateKey]::new($Certificate)
        Write-Debug "[SoQCertValidation] - SignatureAlgorithm"
        $this.SignatureAlgorithm = [SoQCertSignatureAlgorithm]::new($Certificate)
        Write-Debug "[SoQCertValidation] - SignatureHash"
        $this.SignatureHash      = [SoQCertSignatureHash]::new($Certificate)
        Write-Debug "[SoQCertValidation] - PublicKeyAlgorithm"
        $this.PublicKeyAlgorithm = [SoQCertPublicKeyAlgorithm]::new($Certificate)
        Write-Debug "[SoQCertValidation] - CertChain"
        $this.CertChain          = [SoQCertCertChain]::new($Certificate)
        Write-Debug "[SoQCertValidation] - Tls13Support"
        $this.Tls13Support       = [SoQTls13Support]::new()
        Write-Debug "[SoQCertValidation] - Validate"
        $this.IsValid            = $this.ValidateSoQCert()
        Write-Debug "[SoQCertValidation] - End"
    }


    [string[]]
    GetSubclassVariables()
    {
        if ($this.IgnoreOS) {
            return [string[]]("Expiration","Purpose","KeyUsage","Subject","SubjectAltName","PrivateKey","SignatureAlgorithm","SignatureHash","PublicKeyAlgorithm","CertChain","Tls13Support")
        } else {
            return [string[]]("SupportedOS","Expiration","Purpose","KeyUsage","Subject","SubjectAltName","PrivateKey","SignatureAlgorithm","SignatureHash","PublicKeyAlgorithm","CertChain","Tls13Support")
        }
    }

    [SoQState]
    ValidateSoQCert()
    {
        Write-Debug "[SoQCertValidation].ValidateSoQCert() - Start"
        [SoQState]$valid = "Pass"
        $tests = $this.GetSubclassVariables()

        $theLongestLen = 0
        $tests | ForEach-Object { if ( $_.Length -gt $theLongestLen ) { $theLongestLen = $_.Length } }

        foreach ( $test in $tests )
        {
            Write-Verbose "[SoQCertValidation].ValidateSoQCert() - Testing $($test.PadRight($theLongestLen, " ")) : $($this."$test".Result.IsValid)"
            if ($this."$test".Result.IsValid -eq "Fail") { 
                $valid = "Fail" 
                $this.FailedTests += $test
                Write-Verbose "[SoQCertValidation].ValidateSoQCert() - Failure reason: $($this."$test".Result.FailureReason)"
            } elseif ($this."$test".Result.IsValid -eq "Warning") { 
                # do not overwrite the Fail state
                if ($valid -ne "Fail") {
                    $valid = "Warning"
                }

                $this.FailedTests += $test
                Write-Verbose "[SoQCertValidation].ValidateSoQCert() - Warning reason: $($this."$test".Result.FailureReason)"
            }
        }

        Write-Debug "[SoQCertValidation].ValidateSoQCert() - End"
        return $valid
    }


    [string]
    ToString()
    {
        if ($this.IgnoreOS) {
            return @"
Thumbprint: $($this.Certificate.Thumbprint)
$($this.Expiration.ToString())
$($this.Purpose.ToString())
$($this.KeyUsage.ToString())
$($this.Subject.ToString())
$($this.SubjectAltName.ToString())
$($this.PrivateKey.ToString())
$($this.SignatureAlgorithm.ToString())
$($this.SignatureHash.ToString())
$($this.PublicKeyAlgorithm.ToString())
$($this.CertChain.ToString())
"@
        } else {
        return @"
Thumbprint: $($this.Certificate.Thumbprint)
$($this.SupportedOS.ToString())
$($this.Expiration.ToString())
$($this.Purpose.ToString())
$($this.KeyUsage.ToString())
$($this.Subject.ToString())
$($this.SubjectAltName.ToString())
$($this.PrivateKey.ToString())
$($this.SignatureAlgorithm.ToString())
$($this.SignatureHash.ToString())
$($this.PublicKeyAlgorithm.ToString())
$($this.CertChain.ToString())
"@
        }
    }
    
}

#endregion




#### MAIN ####

$script:psVerMaj = $Host.Version.Major
if ( $scipt:psVerMaj -eq 5 )
{
    Write-Warning "Please use PowerShell 7 for the best experience. The .NET certificate namespaces used by Windows PowerShell 5.1 cannot full parse certificate details. `n`nhttps://aka.ms/powershell"
}

<# 
Run in a special mode if -Quiet is set.

- Must be PowerShell 7.
- Must have a thumbprint. Only a single cert is supported.

#>
if ($Quiet.IsPresent) {
    if ($Host.Version.Major -lt 7) {
        return ( Write-Error "Quiet mode only works on PowerShell 7." -EA Stop )
    }

    if ( [string]::IsNullOrEmpty($Thumbprint) ) {
        return ( Write-Error "Quiet mode requires a Thumbprint be set." -EA Stop )
    }

    # perform work
    # grab the cert
    try {
        $cert = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -EA Stop
    } catch {
        return ( Write-Error "Failed to find a certificate in LocalMachine\My with the Thumbprint $Thumbprint." -EA Stop )
    }

    # run the tests
    $tmpCert = [SoQCertValidation]::new($cert, $IgnoreOS.IsPresent)

    if ($tmpCert.IsValid -eq "Pass") {
        return $true
    } else {
        return $false
    }

}

# stores the certificate(s) being tested
$certs = [List[SoQCertValidation]]::new()

if ( [string]::IsNullOrEmpty($Thumbprint) )
{
    # get all the certs in LocalMachine\My, where the SMB over QUIC certs live
    try {
        [array]$tmpCerts = Get-ChildItem Cert:\LocalMachine\My -EA Stop
    }
    catch {
        return ( Write-Error "Failed to retrieve certificates from LocalMachine\My (Local Computer > Personal > Certificates): $_" -EA Stop)
    }
} else {
    # get the cert object based on the Thumbprint
    [array]$tmpCerts = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -EA Stop
}

if ( $tmpCerts.Count -lt 1 ) {
    return ( Write-Error "No certificates were found in LocalMachine\My (Local Computer > Personal > Certificates)" -EA Stop)
}

# loop through all discovered certs
# the SoQCertValidation class, and its sublasses, automatically does all the validation work 
foreach ( $cert in $tmpCerts)
{
    try {
        Write-Verbose "Main - Testing $($cert.Thumbprint) ($(($cert.Subject)))"
        $tmpCert = [SoQCertValidation]::new($cert, $IgnoreOS.IsPresent)
        $certs += $tmpCert
        Remove-Variable tmpCert
    }
    catch {
        Write-Error "Failed to convert the certificate ($($cert.Thumbprint)) to a [SoQCertValidation] object: $_"
    }
}




# the only thing left to do is output the results
if ( $Detailed.IsPresent )
{
    foreach ($cert in $certs)
    {
        $tests = $cert.GetSubclassVariables()
        
        $table = @()

        foreach ( $test in $tests )
        {
            $obj = [PSCustomObject]@{
                Test          = $test
                Result        = $cert."$test".Result.IsValid
                FailureReason = $cert."$test".Result.FailureReason
            }

            $table += $obj

            Remove-Variable obj -EA SilentlyContinue
        }
        

        if ($cert.IsValid -eq "Pass") {
            Write-Host -ForegroundColor Green "`nThumbprint: $($cert.Certificate.Thumbprint), Subject: $($cert.Subject.Subject), Result: $($cert.IsValid)"   
        } elseif ($cert.IsValid -eq "Fail") {
            Write-Host -ForegroundColor Red "`nThumbprint: $($cert.Certificate.Thumbprint), Subject: $($cert.Subject.Subject), Result: $($cert.IsValid)"
        } else {
            Write-Host -ForegroundColor Yellow "`nThumbprint: $($cert.Certificate.Thumbprint), Subject: $($cert.Subject.Subject), Result: $($cert.IsValid)"
        }

        # https://ss64.com/nt/syntax-ansi.html
        $table | Format-Table -AutoSize -Property Test, @{Label="Result"; Expression={
            if ($_.Result -eq "Pass") {
                $color = '36'
            } elseif ($_.Result -eq "Fail") {
                $color = '31'
            } else {
                $color = '93'
            }
            $e = [char]27
           "$e[${color}m$($_.Result)${e}[0m"
        }}, @{Label="FailureReason"; Expression={
            if ($_.Result -eq "Fail") {
                $color = '31'
            } elseif ($_.Result -eq "Warning") {
                $color = '93'
            } else {
                $color = '36'
            }
            $e = [char]27
           "$e[${color}m$($_.FailureReason)${e}[0m"
        }}
        
    }
}
# the standard returns a table of thumbprint, subject, and IsValid
else 
{
    $certs | Format-Table -Property @{Name="Thumbprint"; Expression={($_.Certificate.Thumbprint)}}, `
                                    @{Name="Subject"; Expression={($_.Subject.Subject)}}, `
                                    @{Name="IsValid"; Expression={($_.IsValid)}}, `
                                    @{Name="FailedTests"; Expression={($_.FailedTests)}}
}


if ( $PassThru.IsPresent )
{
    return $certs
}

