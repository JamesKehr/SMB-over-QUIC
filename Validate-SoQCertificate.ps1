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
Trusted certificate chain            : (Root and Intermediate CAs are trusted)

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

    # Returns the results to the console.
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

# tracks and stores certificate dates and whether the certificate date is out of bounds
class SoQCertExpired {
    [datetime]
    $NotBefore

    [datetime]
    $NotAfter

    [bool]
    $IsValid

    [string]
    $FailureReason = $null

    SoQCertExpired(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertExpired] - Start"
        $this.NotBefore   = $Certificate.NotBefore
        $this.NotAfter    = $Certificate.NotAfter
        Write-Debug "[SoQCertExpired] - Validate"
        $this.IsValid     = $this.ValidateDate()
        Write-Debug "[SoQCertExpired] - End"
    }

    [bool]
    ValidateDate()
    {
        Write-Debug "[SoQCertExpired].ValidateDate() - Start"
        [bool]$isValidtmp = $false
        
        $date = Get-Date
        if ( $this.NotBefore -lt $date -and $this.NotAfter -gt $date )
        {
            Write-Debug "[SoQCertExpired].ValidateDate() - IsValid: True"
            $isValidtmp = $true
        }
        else
        {
            Write-Debug "[SoQCertExpired].ValidateDate() - IsValid: False"
            $this.FailureReason = "Certificate is expired. Expires: $($this.NotAfter.ToShortDateString()) $($this.NotAfter.ToShortTimeString()), Date: $($date.ToShortDateString()) $($date.ToShortTimeString())"
            Write-Debug "[SoQCertExpired].ValidateDate() - Failure Reason: $($this.FailureReason)"
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
   Valid      : $($this.IsValid)
"@
    }
}


# tests whether the Server Authentication EKU is a cert purpose
class SoQCertPurpose {
    [string[]]
    $Purpose

    [bool]
    $IsValid

    [string]
    $FailureReason = $null

    SoQCertPurpose(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertPurpose] - Start"
        $this.Purpose = $Certificate.EnhancedKeyUsageList.FriendlyName
        Write-Debug "[SoQCertPurpose] - Validate"
        $this.IsValid = $this.ValidatePurpose()
        Write-Debug "[SoQCertPurpose] - End"
    }

    [bool]
    ValidatePurpose()
    {
        Write-Debug "[SoQCertPurpose].ValidatePurpose() - Start"
        [bool]$isValidtmp = $false

        if ( $this.Purpose -contains "Server Authentication")
        {
            Write-Debug "[SoQCertPurpose].ValidatePurpose() - IsValid: True"
            $isValidtmp = $true
        }
        else 
        {
            Write-Debug "[SoQCertPurpose].ValidatePurpose() - IsValid: False"
            $this.FailureReason = "Purpose does not contain Server Authentication. Purpose: $($this.Purpose -join ', ')"
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
   Valid   : $($this.IsValid)
"@
    }
}


# Key Usage must contain Digital Signature
class SoQCertKeyUsage {
    [string]
    $KeyUsage

    [bool]
    $IsValid

    [string]
    $FailureReason = $null

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
        $this.IsValid  = $this.ValidateKeyUsage()
        Write-Debug "[SoQCertKeyUsage] - End"
    }

    [bool]
    ValidateKeyUsage()
    {
        Write-Debug "[SoQCertKeyUsage].ValidateKeyUsage() - Start"
        [bool]$isValidtmp = $false

        if ( $this.KeyUsage -match "Digital Signature" )
        {
            Write-Debug "[SoQCertKeyUsage].ValidateKeyUsage() - IsValid: True"
            $isValidtmp = $true
        }
        else 
        {
            Write-Debug "[SoQCertKeyUsage].ValidateKeyUsage() - IsValid: False"
            $this.FailureReason = "Key Usage does not contain Digital Signature. ($($this.KeyUsage))"
            Write-Debug "[SoQCertKeyUsage].ValidateKeyUsage() - Failure Reason: $($this.FailureReason)"
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
   Valid     : $($this.IsValid)
"@
    }
}


class SoQCertSubject {
    [string]
    $Subject

    [bool]
    $IsValid

    [string]
    $FailureReason = $null

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
        $this.IsValid = $this.ValidateSubject()
        Write-Debug "[SoQCertSubject] - End"
    }

    [bool]
    ValidateSubject()
    {
        Write-Debug "[SoQCertSubject].ValidateSubject() - Start"
        [bool]$isValidtmp = $false

        if ( $this.Subject -match $this.rgxSubject )
        {
            Write-Debug "[SoQCertSubject].ValidateSubject() - IsValid: True"
            $isValidtmp = $true
        }
        else 
        {
            Write-Debug "[SoQCertSubject].ValidateSubject() - IsValid: False"
            $this.FailureReason = "Does not contain a Subject. ($($this.Subject))"
            Write-Debug "[SoQCertSubject].ValidateSubject() - Failure Reason: $($this.FailureReason)"
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
   Valid   : $($this.IsValid)
"@
    }
}


class SoQCertSAN {
    [string[]]
    $SubjectAltName

    [bool]
    $IsValid

    [string]
    $FailureReason = $null

    SoQCertSAN(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertSAN] - Start"
        $this.SubjectAltName = $Certificate.DnsNameList.Unicode
        Write-Debug "[SoQCertSAN] - Validate"
        $this.IsValid        = $this.ValidateSAN()
        Write-Debug "[SoQCertSAN] - End"
    }

    [bool]
    ValidateSAN()
    {
        Write-Debug "[SoQCertSAN].ValidateSAN() - Start"
        [bool]$isValidtmp = $false

        if ( ($this.SubjectAltName).Count -ge 1 )
        {
            Write-Debug "[SoQCertSAN].ValidateSAN() - IsValid: True"
            $isValidtmp = $true
        }
        else 
        {
            Write-Debug "[SoQCertSAN].ValidateSAN() - IsValid: False"
            $this.FailureReason = "No Subject Alternative Names. ($($this.SubjectAltName -join ', '))"
            Write-Debug "[SoQCertSAN].ValidateSAN() - Failure Reason: $($this.FailureReason)"
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
   Valid    : $($this.IsValid)
"@
    }
}


class SoQCertPrivateKey {
    [bool]
    $IsValid

    [string]
    $FailureReason = $null

    SoQCertPrivateKey(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertPrivateKey] - Start"
        $this.IsValid = $Certificate.HasPrivateKey

        if ( $Certificate.HasPrivateKey -eq $false)
        {
            Write-Debug "[SoQCertPrivateKey] - IsValid: False"
            $this.FailureReason = "No Private Key."
            Write-Debug "[SoQCertPrivateKey] - Failure Reason: $($this.FailureReason)"
            Write-Debug "[SoQCertPrivateKey] - HasPrivateKey: False"
        }
        else 
        {
            Write-Debug "[SoQCertPrivateKey] - IsValid: True"
        }
        Write-Debug "[SoQCertPrivateKey] - End"
    }

    [string]
    ToString()
    {
        return @"
Private Key
   HasPrivateKey : $($this.IsValid)        
"@
    }
}


class SoQCertSignatureAlgorithm {
    [string]
    $SignatureAlgorithm

    [bool]
    $IsValid

    [string]
    $FailureReason = $null

    SoQCertSignatureAlgorithm(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertSignatureAlgorithm] - Start"
        $this.SignatureAlgorithm = $Certificate.SignatureAlgorithm.FriendlyName
        Write-Debug "[SoQCertSignatureAlgorithm] - Validate"
        $this.IsValid            = $this.ValidateSignatureAlgorithm()
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

    [bool]
    ValidateSignatureAlgorithm()
    {
        Write-Debug "[SoQCertSignatureAlgorithm].ValidateSignatureAlgorithm() - Start"
        [bool]$isValidtmp = $false

        if ( $this.SignatureAlgorithm -in $this.GetValidSigAlgo() )
        {

            Write-Debug "[SoQCertSignatureAlgorithm].ValidateSignatureAlgorithm() - IsValid: True"
            $isValidtmp = $true
        }
        else 
        {
            Write-Debug "[SoQCertSignatureAlgorithm].ValidateSignatureAlgorithm() - IsValid: False"
            $this.FailureReason = "Uses a Signature Algorithm not known to work. ($($this.SignatureAlgorithm))"
            Write-Debug "[SoQCertSignatureAlgorithm].ValidateSignatureAlgorithm() - Failure Reason: $($this.FailureReason)"
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
   Valid              : $($this.IsValid)
"@
    }
}

class SoQCertSignatureHash {
    [string]
    $SignatureHash

    [bool]
    $IsValid

    [string]
    $FailureReason = $null

    SoQCertSignatureHash(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertSignatureHash] - Start"
        $this.SignatureHash  = $this.GetHashString($Certificate)
        Write-Debug "[SoQCertSignatureHash] - Validate"
        $this.IsValid        = $this.ValidateSigHash()
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

    [bool]
    ValidateSigHash()
    {
        Write-Debug "[SoQCertSignatureHash].ValidateSigHash() - Start"
        [bool]$isValidtmp = $false

        if ( $this.SignatureHash -in $this.GetValidHash() )
        {
            Write-Debug "[SoQCertSignatureHash].ValidateSigHash() - IsValid: True"
            $isValidtmp = $true
        }
        else 
        {
            Write-Debug "[SoQCertSignatureHash].ValidateSigHash() - IsValid: False"
            $this.FailureReason = "Not a valid signature hash. ($($this.SignatureHash))"
            Write-Debug "[SoQCertSignatureHash].ValidateSigHash() - Failure Reason: $($this.FailureReason)"
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
   Valid : $($this.IsValid)
"@
    }
}

class SoQCertPublicKeyAlgorithm {
    [string]
    $PublicKeyAlgorithm

    [bool]
    $IsValid

    [string]
    $FailureReason = $null

    SoQCertPublicKeyAlgorithm(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertPublicKeyAlgorithm] - Start"
        $this.PublicKeyAlgorithm = $this.GetPKAString($Certificate)
        Write-Debug "[SoQCertPublicKeyAlgorithm] - Validate"
        $this.IsValid            = $this.ValidatePKA()
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
            switch -Regex ($Certificate.SignatureAlgorithm.FriendlyName)
            {
                "ECDSA" {
                    Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (7) Switch: ECDSA"
                    $objPKA = $Certificate.PublicKey.GetECDsaPublicKey()
                    $pka = "$($objPKA.SignatureAlgorithm.ToUpper())_P$($objPKA.KeySize.ToString())"
                    break
                }
    
                "RSA" {
                    Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (7) Switch: RSA"
                    $objPKA = $Certificate.PublicKey.GetRSAPublicKey()
                    $pka = "$($objPKA.SignatureAlgorithm.ToUpper())$($objPKA.KeySize.ToString())"
                    break
                }
    
                # untested... don't have a matching cert to test
                "DSA" {
                    Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (7) Switch: DSA"
                    $objPKA = $Certificate.PublicKey.GetDSAPublicKey()
                    $pka = "$($objPKA.SignatureAlgorithm.ToUpper())$($objPKA.KeySize.ToString())"
                    break
                }
    
                default {
                    Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - Switch: (7) default"
                    $pka = "Unknown"
                }
            }
        }
        else {
            Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - PowerShell 5.1 - Trying to abstract the answer."
            
            [regex]$rgxHash = "(?<hash>md\d{1})|(?<hash>sha\d{1,3})"
            [regex]$rgxBit = "(?<bit>\d{1,3})"

            $saName = $Certificate.SignatureAlgorithm.FriendlyName

            switch -Regex ($saName)
            {
                "ECDSA" {
                    Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (5) Switch: ECDSA"
                    if ( $saName -match $rgxHash)
                    {
                        $hash = $Matches.hash
                    }
                    else 
                    {
                        $hash = $null
                    }

                    if ( [string]::IsNullOrEmpty($hash) )
                    {
                        $pka = $null
                    }
                    else
                    {
                        [int]$bits = 1
                        if ($hash -match $rgxBit)
                        {
                            $bits = $Matches.bit
                        }
                        $pka = "ECDSA_P$bits"
                    }
                    break
                }

                "RSA" {
                    Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - (5) Switch: RSA"

                    # RSA public keys should have some legacy values that can be used
                    $provider = $Certificate.PublicKey.Oid.FriendlyName
                    $size = $Certificate.PublicKey.Key.KeySize

                    if ( -NOT [string]::IsNullOrEmpty($provider) -and -NOT [string]::IsNullOrEmpty($size) )
                    {
                        $pka = "$($provider.ToUpper())$size"
                    } elseif ( -NOT [string]::IsNullOrEmpty($size) )
                    {
                        $pka = "RSA$size"
                    }
                    else 
                    {
                        $pka = $null
                    }
                }

                default { 
                    Write-Debug "[SoQCertPublicKeyAlgorithm].GetPKAString() - Switch: (5) default"
                    $pka = "Unknown"
                }
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

    [bool]
    ValidatePKA()
    {
        Write-Debug "[SoQCertPublicKeyAlgorithm].ValidatePKA() - Start"
        [bool]$isValidtmp = $false

        if ( $this.PublicKeyAlgorithm -in $this.GetValidPKA() )
        {
            Write-Debug "[SoQCertPublicKeyAlgorithm].ValidatePKA() - IsValid: True"
            $isValidtmp = $true
        }
        else 
        {
            Write-Debug "[SoQCertPublicKeyAlgorithm].ValidatePKA() - IsValid: False"
            $this.FailureReason = "Not a known good Public Key Algorithm. ($($this.PublicKeyAlgorithm))"
            Write-Debug "[SoQCertPublicKeyAlgorithm].ValidatePKA() - Failure Reason: $($this.FailureReason)"
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
   Valid : $($this.IsValid)
"@
    }
}

class SoQCertCertChain {
    [bool]
    $IsValid

    [string]
    $FailureReason = $null

    SoQCertCertChain(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        Write-Debug "[SoQCertCertChain] - Start"
        Write-Debug "[SoQCertCertChain] - Validate"
        $this.IsValid = $this.ValidateCertChain($Certificate)
        Write-Debug "[SoQCertCertChain] - End"
    }

    [bool]
    ValidateCertChain([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate)
    {
        Write-Debug "[SoQCertCertChain].ValidateCertChain() - Start"
        [bool]$isValidtmp = $false

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
            Write-Debug "[SoQCertCertChain].ValidateCertChain() - IsValid: True"
            $isValidtmp = $true
        }
        else 
        {
            Write-Debug "[SoQCertCertChain].ValidateCertChain() - IsValid: False"
            $this.FailureReason = "Certificate chain validation failed. 'certutil -verify' returned error CERT_E_UNTRUSTEDROOT."
            Write-Debug "[SoQCertCertChain].ValidateCertChain() - Failure Reason: $($this.FailureReason)"
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
   ValidCertChain : $($this.IsValid)
"@
    }
}

# this class monitors the certs 
class SoQCertValidation
{
    # the certificate object
    [System.Security.Cryptography.X509Certificates.X509Certificate]
    $Certificate

    [bool]
    $IsValid

    [string[]]
    $FailedTests

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


    SoQCertValidation([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate)
    {
        Write-Debug "[SoQCertValidation] - Start"
        $this.Certificate        = $Certificate
        Write-Debug "[SoQCertValidation] - Thumbprint: $($this.Certificate.Thumbprint), Subject: $($this.Certificate.Subject)"
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
        Write-Debug "[SoQCertValidation] - Validate"
        $this.IsValid            = $this.ValidateSoQCert()
        Write-Debug "[SoQCertValidation] - End"
    }


    [string[]]
    GetSubclassVariables()
    {
        return [string[]]("Expiration","Purpose","KeyUsage","Subject","SubjectAltName","PrivateKey","SignatureAlgorithm","SignatureHash","PublicKeyAlgorithm","CertChain")
    }

    [bool]
    ValidateSoQCert()
    {
        Write-Debug "[SoQCertValidation].ValidateSoQCert() - Start"
        $valid = $true
        $tests = $this.GetSubclassVariables()

        $theLongestLen = 0
        $tests | ForEach-Object { if ( $_.Length -gt $theLongestLen ) { $theLongestLen = $_.Length } }

        foreach ( $test in $tests )
        {
            Write-Verbose "[SoQCertValidation].ValidateSoQCert() - Testing $($test.PadRight($theLongestLen, " ")) : $($this."$test".IsValid)"
            if ($this."$test".IsValid -eq $false) { 
                $valid = $false 
                $this.FailedTests += $test
                Write-Verbose "[SoQCertValidation].ValidateSoQCert() - Failure reason: $($this."$test".FailureReason)"
            }
        }

        Write-Debug "[SoQCertValidation].ValidateSoQCert() - End"
        return $valid
    }


    [string]
    ToString()
    {
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
    }
    
}

#endregion




#### MAIN ####

$script:psVerMaj = $Host.Version.Major
if ( $scipt:psVerMaj -eq 5 )
{
    Write-Host -ForegroundColor Yellow "Please use PowerShell 7 for the best experience. The .NET certificate namespaces used by Windows PowerShell 5.1 are not as robust as .NET 7. This requires some guess work when using PowerShell 5.1. `n`nhttps://aka.ms/powershell"
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
        $tmpCert = [SoQCertValidation]::new($cert)
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
                Pass          = $cert."$test".IsValid
                FailureReason = $cert."$test".FailureReason
            }

            $table += $obj

            Remove-Variable obj -EA SilentlyContinue
        }
        

        if ($cert.IsValid)
        {
            Write-Host -ForegroundColor Green "`nThumbprint: $($cert.Certificate.Thumbprint), Subject: $($cert.Subject.Subject), IsValid: $($cert.IsValid)"   
        }
        else 
        {
            Write-Host -ForegroundColor Red "`nThumbprint: $($cert.Certificate.Thumbprint), Subject: $($cert.Subject.Subject), IsValid: $($cert.IsValid)"
        }

        $table | Format-Table -AutoSize -Property Test, @{Label="Pass"; Expression={
            if ($_.Pass)
            {
                $color = '36'
            } else {
                $color = '31'
            }
            $e = [char]27
           "$e[${color}m$($_.Pass)${e}[0m"
        }}, @{Label="FailureReason"; Expression={
            $color = '31'
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
                                    @{Name="IsValid"; Expression={($_.IsValid)}}, @{Name="FailedTests"; Expression={($_.FailedTests)}}
}


if ( $PassThru.IsPresent )
{
    return $certs
}

