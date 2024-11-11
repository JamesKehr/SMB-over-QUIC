#requires -RunAsAdministrator
#requires -Version 7.4

#using module ".\class\libLogging.psm1"

<#
    Aids in setting up an SMB over QUIC server on Windows Server 2025 Preview.

    This script is built and tested using PowerShell 7.4.1. It's possible this will work with Windows PowerShell 5.1 
    by removing "#requires -Version 7.4" in line 2, but it is untested. the clean{} section must be moved/migrated to
    end{} if you attempt to run this in legacy Windows PowerShell.

    Windows Server 2025 has Windows Terminal and winget installed by default. PowerShell 7.4 is the current LTS version 
    of PowerShell. Windows PowerShell 5.1 has not seen significant updates in several years. It's time to move on...
    
    To install PowerShell on Windows Server 2025:

    - Open an elevated (Run as administrator) Terminal or Windows PowerShell console.
    - Run this command:

        winget install Microsoft.PowerShell

    -OR-

    ... download and install PowerShell from:

    https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.4

    - Open Terminal settings (Ctrl+,).
    - Change the default profile from Windows PowerShell to PowerShell.



    LEGAL STUFF

    This sample code is provided AS-IS with no warranties or guarantees. Use at your own risk. These scripts are not 
    Microsoft supported code or processes.

#>

<#

TLS 1.3 cipher suite (5/1/2024):
https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022

    TLS_AES_256_GCM_SHA384
    TLS_AES_128_GCM_SHA256
    AEAD-CHACHA20-POLY1305-SHA256

Certificate requirements:
https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic

    Signature algorithm: SHA256RSA (or greater)
    Signature hash: SHA256 (or greater)
    Public key algorithm: ECDSA_P256 (or greater. Can also use RSA with at least 2048 length)

This translates to:

https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
    Signature hash: SHA256, SHA384, SHA512

https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
https://learn.microsoft.com/en-us/windows/win32/seccrypto/hash-and-signature-algorithms
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/a48b02b2-2a10-4eb0-bed4-1807a6d2f5ad
    Signature algorithm: SHA256RSA, SHA382RSA, SHA512RSA, SHA256ECDSA, SHA384ECDSA, SHA512ECDSA

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/ff1a8675-0008-408c-ba5f-686a10389adc
    Public key algorithm (length): ECDSA_P256 (256), ECDSA_P384 (384), ECDSA_P521 (521), RSA (2048), RSA (4096)



TO-DO:
    - Allow custom self-signed certificate properties. See above for options.
    - Implement Initialize-SmbOverQuicClient



#>



[CmdletBinding()]
param (
    ## EXISTING CERT PARAMETERS ##

    # A valid certificate object. See https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic#deploy-smb-over-quic for certificate requirements.
    [Parameter(Mandatory=$true, ParameterSetName = 'CertObj', ValueFromPipeline=$true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]
    $Certificate,

    # The certificate thumbprint of a valid certificate. See https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic#deploy-smb-over-quic for certificate requirements.
    [Parameter(Mandatory, ParameterSetName = 'CertThumb')]
    [string]
    $Thumbprint,


    ## SELF-SIGNED CERT PARAMETERS ##

    # Generates a self-signed certificate. Please only use this option for testing.
    [Parameter(Mandatory, ParameterSetName = 'SSC')]
    [switch]
    $SelfSignedCert,

    # The subject name of the certificate. Can be any string following cert subject naming standards (alphanumerical characters only). Cannot be blank.
    [Parameter(Mandatory, ParameterSetName = 'SSC', Position = 0)]
    [string]
    $Subject,

    # A friendly name for the certificate.
    [Parameter(Mandatory=$false, ParameterSetName = 'SSC', Position = 1)]
    [string]
    $FriendlyName = "",
    
    <# The comma separated list of Subject Alternative Names (SAN) for the certificate. This should be a full list of names the SMB server will be accessed using. Including:
    
    - FQDN
    - Short name (NETBIOS)
    - Cluster name
    - All A and CNAME resource record names in DNS pointing to the server
    - IP address(es)
    #>
    [Parameter(Mandatory, ParameterSetName = 'SSC', Position = 2)]
    [Alias("SAN", "SubjectAlternateNames")]
    $DnsNames,

    # The certificate signature hash algorithm. Valid options are: SHA256, SHA384, SHA512
    [Parameter(Mandatory = $false, ParameterSetName = 'SSC', Position = 3)]
    [ValidateSet("SHA256", "SHA384", "SHA512")]
    $SignatureHash = "SHA256",

    # The certificate public key algorithm. Valid options are: ECDSA_P256 (256), ECDSA_P384 (384), ECDSA_P521 (521), RSA (2048), RSA (4096)
    [Parameter(Mandatory = $false, ParameterSetName = 'SSC', Position = 4)]
    [ValidateSet("ECDSA_P256", "ECDSA_P384", "ECDSA_P521", "RSA_2048", "RSA_4096")]
    $PublicKeyAlgorithm = "ECDSA_P256",

    # Certificate expiration date.
    [Parameter(Mandatory = $false, ParameterSetName = 'SSC', Position = 5)]
    [ValidateScript({$_ -gt ([DateTime]::Now)})]
    $NotAfter = ((Get-Date).AddMonths(12)),

    # The export the self-signed certificate CER file (X.509 certificate file). The filename is autogenerated as: <subject>_<timestamp>.cer
    [Parameter(Mandatory = $false, ParameterSetName = 'SSC', Position = 6)]
    $ExportPath = "$($PWD.Path)",


    ### ALL PARAMETER SETS ###

    # Enforces client access control when using SMB over QUIC.
    [Parameter(ParameterSetName = 'CertObj')]
    [Parameter(ParameterSetName = 'CertThumb')]
    [Parameter(ParameterSetName = 'SSC')]
    [switch]
    $RequireClientAuthentication,

    # Locaiton to write log files. Log files are not written without this explicit parameter.
    [Parameter(ParameterSetName = 'CertObj')]
    [Parameter(ParameterSetName = 'CertThumb')]
    [Parameter(ParameterSetName = 'SSC')]
    [string]
    $LogPath = $null
)

begin {

    # make sure there is no existing SMB cert mapping before we do any heavy lifting
    if ((Get-SmbServerCertificateMapping)) {
        return (Write-Error "An SMB server certificate mapping already exists." -EA Stop)
    }

    # import required classes
    try {
        . "$PSScriptRoot\class\libLogging.ps1"
        #Import-Module "$PSScriptRoot\class\libLogging.psm1"
    } catch {
        return ( Write-Error "Failed to import a required class library: $_" -EA Stop )
    }#>

    # the minimum key length supported by TLS 1.3 is 256-bits
    $MIN_KEY_LEN = 256

    # a list of TLS 1.3 PKAs that can be passed to new-selfsignedcertificate
    $VALID_PKA_NAMES = "ECDSA_P256", "ECDSA_P384", "ECDSA_P521", "RSA"

    <#
        Write-Log ""
        Write-LogError -Code "" -Text "" [-NonTerminating]
        Write-LogWarning -Code "" -Text ""
    #>
    # start logging
    $oldLogMod = Start-Logging -ModuleName ((Get-PSCallStack)[0].Command.Split('.')[0]) -LogPath $LogPath

    Write-Log "Enter begin"

    # for now, make sure we are in the script root path
    Push-Location "$PSScriptRoot"

    # certificate store path for SMB over QUIC certificates
    Write-Log "Get certificate store."
    #$certStorePath = "Cert:\LocalMachine\My"
    $certStorePath = "Microsoft.PowerShell.Security\Certificate::LocalMachine\My"
    $certStore = Get-Item $certStorePath

    $certStoreRootPath = "Cert:\LocalMachine\Root"

    Write-Log "Exit begin"
}

process {
    Write-Log "Enter process"

    <#
        Order of operation:
            - Self-signed
            - Certificate object
            - Thumbprint
    #>

    if ($SelfSignedCert.IsPresent) {
        Write-Log "Generating a self-signed certificate for the server."

        # RSA_<key length> needs to be converted down to something supported by the cmdlet
        $script:PublicKeyAlgo = ""
        
        # need to figure out the key length
        [int32]$KeyLength = -1
        switch -Regex ($PublicKeyAlgorithm) {
            "^ECDSA_P.*$" {
                $KeyLength = $PublicKeyAlgorithm | Select-String -Pattern "^ECDSA_P(?<len>\d{3})$" | ForEach-Object { $_.matches.Groups[1].Value }
                $script:PublicKeyAlgo = $PublicKeyAlgorithm
            }

            "^RSA.*$" {
                $KeyLength = $PublicKeyAlgorithm.split('_')[1]
                $script:PublicKeyAlgo = "RSA"
            }

            # just in case...
            default {
                Write-LogError -Code "INVALID_PKA" -Text "The Public Key Algorithm, $PublicKeyAlgorithm, is not supported."
            }
        }

        Write-Log "KeyLength: $KeyLength"
        Write-Log "PublicKeyAlgo: $script:PublicKeyAlgo"

        # do some checks
        if ($KeyLength -lt $MIN_KEY_LEN) {
            Write-LogError -Code "INVALID_KEY_LENGTH" -Text "The Key Length, $KeyLength, is not supported by TLS 1.3."
        }

        # the $script:PublicKeyAlgo variable must be valid
        if ($script:PublicKeyAlgo -notin $VALID_PKA_NAMES) {
            Write-LogError -Code "PKA_NOT_FOUND" -Text "The Public Key Algorithm, $script:PublicKeyAlgo, is not on the validation list."
        }

        # validate the export path
        if ( -NOT (Test-Path "$ExportPath" -IsValid -EA SilentlyContinue)) {
            Write-LogWarning -Code "INVALID_EXPORT_PATH" -Text "The export path () is invalid. Using PWD ($($PWD.Path))."
            $ExportPath = "$($PWD.Path)"
        }

        # the path is valid, create it if missing
        $epFnd = Get-Item "$ExportPath" -EA SilentlyContinue
        if (-NOT $epFnd) {
            try {
                $null = New-Item -Path "$ExportPath" -ItemType Directory -Force -EA Stop
                Write-Log "Export path created at: $ExportPath"
            } catch {
                # throw a warning and use PWD if creating the path failed.
                Write-LogWarning -Code "CREATE_EXPORT_PATH_FAILED" -Text "Failed to create the export path. Using PWD ($($PWD.Path)). Error: $_"
                $ExportPath = "$($PWD.Path)"
            }
        }

        Write-Log "Exporting the certificate to: $ExportPath"

        # Don't change anything below here...
        # create a hashtable of the cmdlet parameters
        $certSplat = @{
            Subject          = $Subject
            FriendlyName     = $FriendlyName
            KeyUsageProperty = "Sign"
            KeyUsage         = "DigitalSignature"
            CertStoreLocation = $certStore.PSPath
            HashAlgorithm     = $SignatureHash
            Provider          = "Microsoft Software Key Storage Provider"
            KeyAlgorithm      = $script:PublicKeyAlgo
            KeyLength         = $KeyLength
            NotAfter          = $NotAfter
            DnsName           = $DnsNames
        }

        Write-Log "Cert properties:`n$($certSplat | Format-List | Out-String)`n"

        # execute the command using splatting
        try {
            Write-Log "Creating the self signed certificate."
            $Certificate = New-SelfSignedCertificate @certSplat -EA Stop
            Write-Log "Creation successful."
        } catch {
            Write-LogError -Code "CERT_CREATION_ERROR" -Text "Failed to create the self-signed certificate: $_"
            #return ( Write-Error "Failed to create the self-signed certificate: $_" -EA Stop )
        }

        # export a CER file
        $selfSignFileName = "$Subject`_$(Get-Date -Format "yyyyMMddHHmmss")`.cer"
        # clean up any invalid path chars
        $selfSignFileName = $selfSignFileName -replace "[$([RegEx]::Escape([string][IO.Path]::GetInvalidFileNameChars()))]+","_"

        # generate the full path
        $selfSignFile = "$ExportPath\$selfSignFileName"

        # perform the ex
        try {
            $null = Export-Certificate -Cert $Certificate -Type CERT -FilePath "$selfSignFile" -EA Stop 
            Write-Log "Exported the self signed certificate to $selfSignFile"

            Write-Host -ForegroundColor Green "The SMB over QUIC server certificate has been exported to: $selfSignFile"

            # import the cert to the Root store
            $null = Import-Certificate -FilePath "$selfSignFile" -CertStoreLocation $certStoreRootPath -EA Stop
            Write-Log "Imported the self signed certificate to the Root store."
        } catch {
            Write-LogError -Code "SELF_CERT_IMPORT_FAILURE" -Text "Failed to import the self signed certificate to the Root store and create a trusted certificate chain: $_"
        }
        
    } elseif ( $null -ne $Certificate ) {
        <#
            Validation handles most of the checks.
            Certificate can only be a X509Certificate2 object so no need to validate this.
            Just need to make sure the certificate is in the right place in this block.
        #>
        # is the certificate in the proper store?
        Write-Log "Checking certificate path."
        if ($Certificate.PSParentPath -ne $certStorePath) {
            Write-LogError -Code "INVALID_CERT_STORE" -Text "The certificate is not in the correct store. Current store: $($Certificate.PSParentPath); Required store: $certStorePath"
        }
    } elseif ( -NOT [string]::IsNullOrEmpty($Thumbprint) ) {
        # Convert the thumbprint to a cert object
        try {  
           Write-Log "Searching for a certificate with thumbprint $Thumbprint."
           $Certificate = Get-ChildItem $certStorePath -EA Stop | Where-Object Thumbprint -eq $Thumbprint
           Write-Log "Certificate: $Certificate"
        } catch {
            Write-LogError -Code "CERT_STORE_FAILURE" -Text "Failed to open the certificate store: $_"
        }

        if ( -NOT $Certificate -or $Certificate.Thumbprint -ne $Thumbprint) {
            Write-LogError -Code "THUMB_NOT_FOUND" -Text "Failed to retrive a certficate with the thumbprint $Thumbprint in $certStorePath"
        }

    } else {
        Write-LogError -Code "INVALID_CERT" -Text "Invalid certificate : $_"
    }

    # Validate the certificate using Validate-SmbOverQuicCertificate.ps1
    # Do not ignore the OS since this is designed to run on a server capable of being an SMB over QUIC server
    # $validCert.IsCertValid stores the boolean result
    Write-Log "Validating the certificate."
    $validCert = . .\Validate-SmbOverQuicCertificate.ps1 -Thumbprint $Certificate.Thumbprint -PassThru # -IgnoreOS # comment IgnoreOS for production

    # bail if the certificate validation failed
    if ( -NOT $validCert.IsCertValid ) {
        $errTxt = "The certificate is not valid for SMB over QUIC: $($validCert.ToPassFailString())`n`nPlease run this command for more details: Validate-SmbOverQuicCertificate -Thumbprint $($Certificate.Thumbprint) -Detailed"
        Write-LogError -Code "CERT_VALIDATION_FAILURE" -Text $errTxt
    }

    Write-Log "Certificate validation successful."

    # create the SMB server certificate mapping(s)
    foreach ($name in $Certificate.DnsNameList.Unicode) {
        # skip if the name is not a valid DNS name...
        if ( ([System.Uri]::CheckHostName($name)) -ne "Unknown" ) {
            try {
                Write-Log "Creating mapping for $name with $($Certificate.Thumbprint)."
                New-SmbServerCertificateMapping -Name $name -Thumbprint $Certificate.Thumbprint -StoreName My -EA Stop
            } catch {
                Write-LogWarning -Code "CERT_MAP_ERROR" -Text "Failed to map the certificate ($($Certificate.Thumbprint)) to $name`: $_"
            }
        } else {
            Write-Log "Creating mapping for $name is an invalid DNS name."
        }
    }

    Write-Log "Exit process"
}

clean {
    Write-Log "Clean up, clean up, everybody do your part!"

    Close-Logging -ModuleName ((Get-PSCallStack)[0].Command.Split('.')[0]) -oldLogMod $oldLogMod
    
    ################################################
    ###                                          ###
    ###  NO LOGGING ALLOWED PAST CLOSE-LOGGING   ###
    ###                                          ###
    ################################################

    # Use Write-Verbose or Write-Debug if any back channel logging is needed, though it won't be in the log file

}

end {
    Write-Log "Enter end"
    Write-Log "Work Complete!"
    Write-Log "Exit end"
}