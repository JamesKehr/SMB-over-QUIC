# validate SMB over QUIC certificate
#requires -RunAsAdministrator
#requires -Version 5.1

using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Collections.Concurrent

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

DONE - IgnoreOS switch to bypass the OS test, which will allow validation of a certifiate to work anywhere. Helpful when someone is testing for certs that will work on an Azure Edition VM.

DONE - Quiet - returns a $true or $false. This will require PowerShell 7!


Logging ...

    Currently enabled by default with file write. Should file write be enabled by default?

    Option 1:

        Enable file write by default and add a -NoLog switch. The NoLog switch would output to Verbose and Debug streams but not write to file.

    Option 2:

        Disable file write by default and only log when -LogPath is set. Logging would go to Verbose and Debug streams only.

    
    I prefer Option 2 at the moment.
#>


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

    # Path to save the log files. Default: present working directory.
    [Parameter()]
    [string]
    $LogPath = $null,

    # Returns the SMB over QUIC certificate test object(s) to the console.
    [Parameter()]
    [switch]
    $PassThru
)


begin {
    #### CLASSES ####

    # import required classes
    try {
        . "$PSScriptRoot\class\libLogging.ps1"
        . "$PSScriptRoot\class\libValCert.ps1"
    } catch {
        return ( Write-Error "Failed to import a required class library: $_" -EA Stop )
    }


    # start logging
    # do not write the log unless LogPath has a valid path
    $moduleName = "Validate-SmbOverQuicCertificate"
    if ( [string]::IsNullOrEmpty($LogPath) ) {
        Write-Verbose "No log write mode."

        # change the module if the log var exists
        if ($script:log) {
            $oldLogMod = $script:log.Module
            Write-Verbose "oldLogMod: $oldLogMod"
            $script:log.Module = $moduleName
        # otherwise create a new log
        } else {
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
    

    $script:log.NewLog("Begin")
    $script:log.NewLog("Current user: $env:UserName")


    $script:psVerMaj = $Host.Version.Major
    if ( $script:psVerMaj -eq 5 ) {
        #$script:log.NewWarning("Please use PowerShell 7 for the best experience. The .NET certificate namespaces used by Windows PowerShell 5.1 cannot full parse certificate details.`n`nhttps://aka.ms/powershell")
        Write-Warning "Please use PowerShell 7 for the best experience. The .NET certificate namespaces used by Windows PowerShell 5.1 cannot full parse certificate details.`n`nhttps://aka.ms/powershell"
    }

    $script:log.NewLog("PowerShell version: $($Host.Version)")
    $script:log.NewLog("OS version: $([System.Environment]::OSVersion.Version.ToString())")
}

process {
    #### MAIN ####

    <#
        $script:log.NewLog("")
        $script:log.NewError("code", "", $false)
        $script:log.NewWarning("code", "")
    #>

    $script:log.NewLog("Process")
    <# 
    Run in a special mode if -Quiet is set.

    - Must be PowerShell 7.
    - Must have a thumbprint. Only a single cert is supported.

    #>
    if ($Quiet.IsPresent) {
        $script:log.NewLog("Quiet mode.")
        if ($Host.Version.Major -lt 7) {
            $script:log.NewError("INVALID_PWSH_VERSION", "Quiet mode only works on PowerShell 7.", $true)
        }

        if ( [string]::IsNullOrEmpty($Thumbprint) ) {
            $script:log.NewError("MISSING_THUMBPRINT", "Quiet mode requires a Thumbprint.", $true)
        }

        # perform work
        # grab the cert
        try {
            $cert = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -EA Stop
        } catch {
            $script:log.NewError("CERT_NOT_FOUND", "Failed to find a certificate in LocalMachine\My with the Thumbprint $Thumbprint.", $true)
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
    $script:log.NewLog("Create [SoQCertValidation] object.")
    $certs = [List[SoQCertValidation]]::new()

    # get all the certs in LocalMachine\My, where the SMB over QUIC certs live
    $tmpCerts = @()
    try {
        $script:log.NewLog("Retrieving certificates.")
        if ( [string]::IsNullOrEmpty($Thumbprint) ) {
            $tmpCerts = Get-ChildItem Cert:\LocalMachine\My -EA Stop
            $script:log.NewLog("Discovered $() certificates.")
        } else {
            # get the cert object based on the Thumbprint
            $tmpCerts = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -EA Stop
            $script:log.NewLog("Found the certificate with thumbprint $Thumbprint.")
        }
    } catch {
        $script:log.NewError("CERT_FAILURE", "Failed to retrieve certificate(s) from LocalMachine\My (Local Computer > Personal > Certificates): $_", $true)
    }
    
    if ( $tmpCerts.Count -eq 0 ) {
        $script:log.NewLog("No certificates were found in LocalMachine\My (Local Computer > Personal > Certificates)")
        return #null
    }

    # loop through all discovered certs
    # the SoQCertValidation class, and its sublasses, automatically does all the validation work 
    foreach ( $cert in $tmpCerts)
    {
        $script:log.NewLog("IgnoreOS: $IgnoreOS")
        try {
            $script:log.NewLog("Processing: $($cert.Thumbprint) ($(($cert.Subject)))")
            $tmpCert = [SoQCertValidation]::new($cert, $IgnoreOS.IsPresent)
            $script:log.NewLog("Result: $($tmpCert.ToShortString())")
            $certs.Add($tmpCert)
            Remove-Variable tmpCert
        } catch {
            $script:log.NewWarning("PROCESS_CERT_FAILURE", "Failed to convert the certificate ($($cert.Thumbprint)) to a [SoQCertValidation] object: $_")
        }
    }


    # don't output if passthru is set or it messes with the object
    if ( $PassThru.IsPresent ) { return $certs }

    # the only thing left to do is output the results
    if ( $Detailed.IsPresent ) {
        $script:log.NewLog("Detailed output.")
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
            
            #Write-Host "$($table | fl * | Out-String)"

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
                if ($_.Result -eq "Pass") {
                    $color = '36'
                } elseif ($_.Result -eq "Fail") {
                    $color = '31'
                } else {
                    $color = '93'
                }
                $e = [char]27
                "$e[${color}m$($_.FailureReason -join ', ')${e}[0m"
            }}
            
        }
    # the standard returns a table of thumbprint, subject, and IsValid
    } else {
        $certs | Format-Table -Property @{Name="Thumbprint"; Expression={($_.Certificate.Thumbprint)}}, `
                                        @{Name="Subject"; Expression={($_.Subject.Subject)}}, `
                                        @{Name="IsValid"; Expression={($_.IsValid)}}, `
                                        @{Name="FailedTests"; Expression={($_.FailedTests)}}
    }
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
    $script:log.NewLog("End")

    # close logging - this should go in clean{} for PowerShell 7.3+ because it runs even when the script is terminated... but need that backward compat.
    $log.close()
}
