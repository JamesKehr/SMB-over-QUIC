#requires -RunAsAdministrator
#requires -Version 7.4

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

[CmdletBinding()]
param (
    ## EXISTING CERT PARAMETERS ##

    # A valid certificate object. See https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic#deploy-smb-over-quic for certificate requirements.
    [Parameter(Mandatory, ParameterSetName = 'CertObj', Position = 0)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]
    $Certificate,

    # The certificate thumbprint of a valid certificate. See https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic#deploy-smb-over-quic for certificate requirements.
    [Parameter(Mandatory, ParameterSetName = 'CertThumb', Position = 0)]
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
    [Parameter(Mandatory, ParameterSetName = 'SSC', Position = 1)]
    [string]
    $FriendlyName,
    
    <# The comma separated list of Subject Alternative Names (SAN) for the certificate. This should be a full list of names the SMB server will be accessed using. Including:
    
    - FQDN
    - Short name (NETBIOS)
    - Cluster name
    - All A and CNAME resource record names in DNS pointing to the server
    - IP address(es)
    #>
    [Parameter(Mandatory, ParameterSetName = 'SSC', Position = 2)]
    [string[]]
    [Alias("SAN", "SubjectAlternateNames")]
    $DnsNames
)


<#
    $script:log.NewLog("")
    $script:log.NewError("code", "msg", $true)
    $script:log.NewWarning("code", "msg")
#>

begin {

    # make sure there is no existing SMB cert mapping before we do any heavy lifting
    if ((Get-SmbServerCertificateMapping)) {
        return (Write-Error "An SMB server certificate mapping already exists." -EA Stop)
    }

    # import required classes
    try {
        . "$PSScriptRoot\class\libLogging.ps1"
    } catch {
        return ( Write-Error "Failed to import a required class library: $_" -EA Stop )
    }

    # start logging
    # do not write the log unless LogPath has a valid path
    $moduleName = "Initialize-SmbOverQuicServer"
    if ( [string]::IsNullOrEmpty($LogPath) ) {
        Write-Verbose "No log write mode."

        # change the module if the log var exists
        if ($script:log) {
            $oldLogMod = $script:log.Module
            Write-Verbose "oldLogMod: $oldLogMod"
            $script:log.Module = $moduleName
        # otherwise create a new log
        } else {
            Write-Verbose "New log file."
            $oldLogMod = $null
            # create new log with NoWrite set to $true
            $script:log = [Logging]::new($false, $moduleName)
        }
    } else {
        Write-Verbose "Write logs to path: $LogPath"
    
        # LogPath must be a directory
        $lpIsDir = Get-Item "$LogPath" -EA SilentlyContinue
        if ( $lpIsDir -and -NOT $lpIsDir.PSIsContainer ) { $LogPath = $PWD.Path }

        # create the dir if needed
        try {
            $null = New-Item "$LogPath" -ItemType Directory -Force -EA Stop
        } catch {
            # use PWD instead
            $LogPath = $PWD.Path
        }

        if ($logFnd) {
            $oldLogMod = $script:log.Module
            $script:log.Module = $moduleName
        # otherwise create a new log
        } else {
            $oldLogMod = ""
            # create new log with NoWrite set to $true
            $script:log = [Logging]::new($LogPath, $moduleName)
        } 
    }

    $script:log.NewLog("Enter begin")

    # for now, make sure we are in the script root path
    Push-Location "$PSScriptRoot"

    # certificate store path for SMB over QUIC certificates
    $script:log.NewLog("Get certificate store.")
    $certStorePath = "Cert:\LocalMachine\My"
    $certStore = Get-Item $certStorePath

    $certStoreRootPath = "Cert:\LocalMachine\Root"

    $script:log.NewLog("Exit begin")
}

process {
    $script:log.NewLog("Enter process")

    if ($SelfSignedCert.IsPresent) {
        $script:log.NewLog("Generating a self-signed certificate for the server.")

        # Don't change anything below here...
        # create a hashtable of the cmdlet parameters
        $certSplat = @{
            Subject          = $Subject
            FriendlyName     = $FriendlyName
            KeyUsageProperty = "Sign"
            KeyUsage         = "DigitalSignature"
            CertStoreLocation = $certStore.PSPath
            HashAlgorithm     = "SHA256"
            Provider          = "Microsoft Software Key Storage Provider"
            KeyAlgorithm      = "ECDSA_P256"
            KeyLength         = 256
            DnsName           = $DnsNames
        }

        $script:log.NewLog("Cert properties:`n$($certSplat | Format-List | Out-String)`n")

        # execute the command using splatting
        try {
            $script:log.NewLog("Creating the self signed certificate.")
            $Certificate = New-SelfSignedCertificate @certSplat -EA Stop
            $script:log.NewLog("Creation successful.")
        } catch {
            $script:log.NewError("CERT_CREATION_ERROR", "Failed to create the self-signed certificate: $_", $true)
            #return ( Write-Error "Failed to create the self-signed certificate: $_" -EA Stop )
        }

        # export a CER file
        $selfSignFile = "$env:temp\SoQTempCert.cer"
        try {
            $null = Export-Certificate -Cert $Certificate -Type CERT -FilePath "$selfSignFile" -EA Stop 
            $script:log.NewLog("Exported the self signed certificate to $selfSignFile")

            # import the cert to the Root store
            $null = Import-Certificate -FilePath "$selfSignFile" -CertStoreLocation $certStoreRootPath -EA Stop
            $script:log.NewLog("Imported the self signed certificate to the Root store.")
            
            # clean up after yourself
            $script:log.NewLog("Cleaning up the temp certificate file.")
            $null = Remove-Item "$selfSignFile" -Force
        } catch {
            $script:log.NewError("SELF_CERT_IMPORT_FAILURE", "Failed to import the self signed certificate to the Root store and create a trusted certificate chain: $_", $true)
        }
        
    } elseif ( $null -ne $Certificate ) {
        # make sure the certificate is in Cert:\LocalMachine\My

    } elseif ( -NOT [string]::IsNullOrEmpty($Thumbprint) ) {
        # Convert the thumbprint to a cert object
        try {
           $Certificate = Get-ChildItem $certStorePath -EA Stop | Where-Object Thumbprint -eq $Thumbprint
        } catch {
            $script:log.NewError("CERT_STORE_FAILURE", "Failed to open the certificate store: $_", $true)
        }

        if ( -NOT $Certificate -or $Certificate.Thumbprint -ne $Thumbprint) {
            $script:log.NewError("THUMB_NOT_FOUND", "Failed to retrive a certficate with the thumbprint: $Thumbprint", $true)
        }

    } else {
        $script:log.NewError("INVALID_CERT", "Invalid certificate : $_", $true)
    }

    # Validate the certificate using Validate-SmbOverQuicCertificate.ps1
    # Do not ignore the OS since this is designed to run on a server capable of being an SMB over QUIC server
    # $validCert.IsCertValid stores the boolean result
    $script:log.NewLog("Validating the certificate.")
    $validCert = . .\Validate-SmbOverQuicCertificate.ps1 -Thumbprint $Certificate.Thumbprint -PassThru -IgnoreOS # comment IgnoreOS for production

    # bail if the certificate validation failed
    if ( -NOT $validCert.IsCertValid ) {
        $errTxt = "The certificate is not valid for SMB over QUIC: $($validCert.ToPassFailString())`n`nPlease run this command for more details: Validate-SmbOverQuicCertificate -Thumbprint $($Certificate.Thumbprint) -Detailed"
        $script:log.NewError("CERT_VALIDATION_FAILURE", $errTxt, $true)
    }

    $script:log.NewLog("Certificate validation successful.")

    # create the SMB server certificate mapping(s)
    foreach ($name in $DnsNames) {
        try {
            $script:log.NewLog("Creating mapping for $name with $($Certificate.Thumbprint).")
            New-SmbServerCertificateMapping -Thumbprint $Certificate.Thumbprint -StoreName My -Name $name -EA Stop
        } catch {
            $script:log.NewWarning("CERT_MAP_ERROR", "Failed to map the certificate ($($Certificate.Thumbprint)) to $name`: $_")
        }
    }

    $script:log.NewLog("Exit process")
}

clean {
    $script:log.NewLog("Enter clean")

    # swap module name back when returning to a caller
    if ( -NOT [string]::IsNullOrEmpty($oldLogMod) ) {
        $script:log.NewLog("Change log module back to $oldLogMod")
        $script:log.Module = $oldLogMod
    # close log when this is the parent
    } else {
        $script:log.NewLog("Closing log.")
        $script:log.Close()
    }

    $script:log.NewLog("Exit clean")

}

end {
    $script:log.NewLog("Enter end")
    $script:log.NewLog("Work Complete!")
    $script:log.NewLog("Exit end")
}