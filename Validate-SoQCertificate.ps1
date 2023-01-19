# validate SMB over QUIC certificate
#requires -RunAsAdministrator
#requires -Version 5.1
#requires -Modules @{ ModuleName="Pester"; ModuleVersion="5.3.0" }

<#

https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic

Rquirements retrieved on 18 Jan 2023

DONE - Key usage                      : Digital Signature
DONE - Purpose                        : Server Authentication (EKU 1.3.6.1.5.5.7.3.1)
DONE - Subject Alternative Name (SAN) : (A DNS name entry for each fully qualified DNS name used to reach the SMB server)
DONE - Subject                        : (CN= anything, but must exist)
DONE - Private key included           : yes

Signature algorithm            : SHA256RSA (or greater)
Signature hash                 : SHA256 (or greater)
Public key algorithm           : ECDSA_P256 (or greater. Can also use RSA with at least 2048 length)


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
    $ComputerName = '.'
)

BeforeAll {
    try {
        # get all the certs in LocalMachine\My, where the SMB over QUIC certs live
        [array]$script:LmMyCerts = Get-ChildItem Cert:\LocalMachine\My -EA Stop
    }
    catch {
        return ( Write-Error "Failed to retrieve certificates from LocalMachine\My (Local Computer > Personal > Certificates): $_" -EA Stop)
    }
    
    if ( $script:LmMyCerts.Count -le 0 ) {
        return ( Write-Error "No certificates were found in LocalMachine\My (Local Computer > Personal > Certificates)" -EA Stop)
    }

    if ($Verbose) {
        Write-Verbose "$($script:LmMyCerts.Count) certificates were discovered in LocalMachine\My:`n$($script:LmMyCerts | Format-Table -AutoSize | Out-String)"
    }

    # date and time to check expiration
    $script:date = Get-Date

    # regex expressions for Subject
    [regex]$script:rgxSubject = "CN=\w{1}"

    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/a48b02b2-2a10-4eb0-bed4-1807a6d2f5ad
    # Retrieved 18 Jan 2023
    # array of supported signature hash algorithms
    $script:ValidSigAlgorithms = "sha256ECDSA", "sha384ECDSA", "sha512ECDSA", "sha256RSA". "sha384RSA", "sha512RSA"

    # array of supported sig hashes
    $script:ValidSigHash = "sha256", "sha384", "sha512"



}

Describe 'Basic Requirements' {
    It 'The certificate is inside valid dates (not expired). ' {
        # the certificate cannot be outside the valid date range (between NotBefore and NotAfter dates)
        [array]$script:notExpired = $script:LmMyCerts | Where-Object { $_.NotBefore -lt $date -and $_.NotAfter -gt $date }
        $script:notExpired.Count | Should -BeGreaterOrEqual 1

        if ($Verbose) {
            $dq = $script:LmMyCerts | Where-Object { $_ -notin $script:notExpired }
            if ($dq.Count -ge 1) {
                Write-Verbose "$($script:notExpired.Count) certificate(s) were discovered within the valid certificate lifetime:`n$($script:notExpired | Format-Table -AutoSize | Out-String)"
                Write-Verbose "The following certificate(s) were disqualified on this step:`n$( $dq | Out-String )"

                Remove-Variable dq -EA SilentlyContinue
            } else {
                Write-Verbose "No change in certificate qualification detected (Expired)."
            }
        }
    }

    It 'The certificate must have the Server Authentication purpose (EKU 1.3.6.1.5.5.7.3.1). ' {     
        # filter certs by those with Server Authentication purpose
        [array]$script:WithP = $script:notExpired | Where-Object { $_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.1" }
        $script:WithP.Count | Should -BeGreaterOrEqual 1

        if ($Verbose) {
            $dq = $script:notExpired | Where-Object { $_ -notin $script:WithP }
            if ($dq.Count -ge 1) {
                Write-Verbose "$($script:WithP.Count) certificate(s) were discovered with the Server Authentication purpose:`n$($script:WithP | Format-Table -AutoSize | Out-String)"
                Write-Verbose "The following certificate(s) were disqualified on this step:`n$( $dq | Out-String )"

                Remove-Variable dq -EA SilentlyContinue
            } else {
                Write-Verbose "No change in certificate qualification detected (Server Authentication)."
            }
        }
    }

    It 'The key usage must be "Digital Signature". ' {
        # filter certs by those with Digital Signature in Key Usage
        [array]$script:WithPKu = $script:WithP | Where-Object { ($_.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Key Usage" }).Format(1) -match "Digital Signature" }
        $script:WithPKu.Count | Should -BeGreaterOrEqual 1

        if ($Verbose) {
            $dq = $script:WithP | Where-Object { $_ -notin $script:WithPKu }
            if ($dq.Count -ge 1) {
                Write-Verbose "$($script:WithPKu.Count) certificate(s) were discovered with the correct Key Usage:`n$($script:WithPKu | Format-Table -AutoSize | Out-String)"
                Write-Verbose "The following certificate(s) were disqualified on this step:`n$( $dq | Out-String )"
            } else {
                Write-Verbose "No change in certificate qualification detected (Key Usage)."
            }
        }
    }

    It 'There must be a Subject. ' {
        # make sure there's something in the Subject of the certificate.
        [array]$script:WithPKuS = $script:WithPKu | Where-Object { $_.Subject -match $rgxSubject }
        $script:WithPKuS.Count | Should -BeGreaterOrEqual 1

        if ($Verbose) {
            $dq = $script:WithPKu | Where-Object { $_ -notin $script:WithPKuS }
            if ($dq.Count -ge 1) {
                Write-Verbose "$($script:WithPKuS.Count) certificate(s) were discovered with a subject:`n$($script:WithPKuS | Format-Table -AutoSize | Out-String)"
                Write-Verbose "The following certificate(s) were disqualified on this step:`n$( $dq | Out-String )"
            } else {
                Write-Verbose "No change in certificate qualification detected (Subject)."
            }
        }
    }

    It 'There must at least one Subject Alternate Name. ' {
        # Subject Alternate Name must contain at least one DNS entry
        [array]$script:WithPKuSD = $script:WithPKuS | Where-Object { ($_.DnsNameList).Count -ge 1 }
        $script:WithPKuSD.Count | Should -BeGreaterOrEqual 1

        if ($Verbose) {
            $dq = $script:WithPKuS | Where-Object { $_ -notin $script:WithPKuSD }
            if ($dq.Count -ge 1) {
                Write-Verbose "$($script:WithPKuSD.Count) certificate(s) were discovered with at least one Subject Alternate Name (SAN):`n$($script:WithPKuSD | Format-Table -AutoSize | Out-String)"
                Write-Verbose "The following certificate(s) were disqualified on this step:`n$( $dq | Out-String)"
            } else {
                Write-Verbose "No change in certificate qualification detected (Subject Alternate Name)."
            }
        }
    }

    It 'The Private Key is included. ' {
        [array]$script:WithPKuSDK = $script:WithPKuSD | Where-Object HasPrivateKey
        $script:WithPKuSDK.Count | Should -BeGreaterOrEqual 1

        if ($Verbose) {
            $dq = $script:WithPKuSD | Where-Object { $_ -notin $script:WithPKuSDK }
            if ($dq.Count -ge 1) {
                Write-Verbose "$($script:WithPKuSDK.Count) certificate(s) were discovered with at least one Subject Alternate Name (SAN):`n$($script:WithPKuSDK | Format-Table -AutoSize | Out-String)"
                Write-Verbose "The following certificate(s) were disqualified on this step:`n$($dq | Out-String)"
            } else {
                Write-Verbose "No change in certificate qualification detected (Private Key)."
            }
        }
    }
}


Describe 'Cryptographic Requirements' {
    It 'The Signature Algorithm must be SHA256RSA or greater. ' {
        # array of the certificates that meet the sig requurement
        [array]$script:WithPKuSDKA = $script:WithPKuSDK | Where-Object {$_.SignatureAlgorithm.FriendlyName -in $script:ValidSigAlgorithms }
        $script:WithPKuSDKA.Count | Should -BeGreaterOrEqual 1

        if ($Verbose) {
            $dq = $script:WithPKuSDK | Where-Object { $_ -notin $script:WithPKuSDKA }
            if ($dq.Count -ge 1) {
                Write-Verbose "$($script:WithPKuSDKA.Count) certificate(s) were discovered with a valid Signature Algorithm:`n$($script:WithPKuSDKA | Format-Table -AutoSize | Out-String)"
                Write-Verbose "The following certificates were disqualified on this step:`n$($dq | Out-String)"
            } else {
                Write-Verbose "No change in certificate qualification detected (Signature Algorithm)."
            }
        }
    }

    <# All the supported algorithms use SH256+ so in theory if the algorithm passes so should the hash...?

    It 'The Signature Hash must be SHA256 or greater. ' {
        # array of the certificates that meet the sig requurement
        [array]$script:WithPKuSDKAH = $script:WithPKuSDKA | Where-Object {$_.SignatureAlgorithm.FriendlyName -in $script:ValidSigAlgorithms }
        $script:WithPKuSDKAH.Count | Should -BeGreaterOrEqual 1

        if ($Verbose) {
            $dq = $script:WithPKuSDKA | Where-Object { $_ -notin $script:WithPKuSDKAH }
            if ($dq.Count -ge 1) {
                Write-Verbose "$($script:WithPKuSDKAH.Count) certificate(s) were discovered with at least one Subject Alternate Name (SAN):`n$($script:WithPKuSDKAH | Format-Table -AutoSize | Out-String)"
                Write-Verbose "The following certificates were disqualified on this step:`n$($dq | Out-String)"
            } else {
                Write-Verbose "No change in certificate qualification detected (Private Key)."
            }
        }
    }

    #>

    # haven't figured this one out yet
    It 'The Public Key Algorithm must be ECDSA_P256 or greater, or RSA with a 2048-bit or greater length)' {
        $script:WithPKuSDKAPka = @()
        foreach ($cert in $script:WithPKuSDKA) {
            if ( $cert.SignatureAlgorithm.FriendlyName -match "ECDSA" ) {
                Write-Debug "Assuming $($cert.Subject | Where-Object { $_ -match "CN=" } | ForEach-Object { $_.Split('=')[1] }) is a valid public key algorithm since it uses ECDSA with SHA256+."
                $script:WithPKuSDKAPka += $cert
            } elseif ($cert.PublicKey) {
                if ($cert.PublicKey.Key.SignatureAlgorithm -eq "RSA" -and $cert.PublicKey.Key.KeySize -ge 2048) {
                    $script:WithPKuSDKAPka += $cert
                }
            } else {
                Write-Debug "Unable to determnine the Public Key Algorithm, so it is assumed invalid."
            }
        }

        if ($Verbose) {
            $dq = $script:WithPKuSDKA | Where-Object { $_ -notin $script:WithPKuSDKAPka }
            if ($dq.Count -ge 1) {
                Write-Verbose "$($script:WithPKuSDKAPka.Count) certificate(s) were discovered with a valid Public Key Algorithm:`n$($script:WithPKuSDKAPka | Format-Table -AutoSize | Out-String)"
                Write-Verbose "The following certificates were disqualified on this step:`n$($dq | Out-String)"
            } else {
                Write-Verbose "No change in certificate qualification detected (Public Key Algorithm)."
            }
        }
    }
}

Describe 'Certificate Trust Chain' {
    It 'The Root Certification Authority (CA) must be in LocalMachine\Root.' {
        $script:final = @()
        # use certutil to validate the chain
        foreach ($cert in $script:WithPKuSDKAPka) {
            # export the cer file
            $fn = "cert_$(Get-Date -Format "ddMMyyyyHHmmssffff").cer"
            $null = Export-Certificate -Cert $cert -FilePath "$pwd\$fn" -Force

            $results = certutil -verify "$pwd\$fn"

            $null = Remove-Item "$pwd\$fn" -Force

            if ( !($results | Where-Object { $_ -match 'CERT_E_UNTRUSTEDROOT' }) ) {
                $script:final += $cert
            }

            Remove-Variable fn, results -EA SilentlyContinue
        }

        if ($Verbose) {
            $dq = $script:WithPKuSDKAPka | Where-Object { $_ -notin $script:final }
            if ($dq.Count -ge 1) {
                Write-Verbose "$($script:final.Count) certificate(s) were discovered with valid CA trust path:`n$($script:final | Format-Table -AutoSize | Out-String)"
                Write-Verbose "The following certificates were disqualified on this step:`n$($dq | Out-String)"
            } else {
                Write-Verbose "No change in certificate qualification detected (Trusted CA)."
            }
        }
    }
}

AfterAll {
    Write-Host -ForegroundColor Green "`n`nThe following certificates should be valid for use with SMB over QUIC:`n$($script:final | Out-String)"
    Write-Host "`nAdd -Verbose to script execution to see details about why certificates were marked as invalid.`n`n"
}
