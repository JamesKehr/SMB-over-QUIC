# validate SMB over QUIC certificate
#requires -RunAsAdministrator
#requires -Version 5.1

using namespace System.Collections
using namespace System.Collections.Generic
using namespace System.Collections.Concurrent
#using module .\libLogging.psm1


<#
    Pass = the test was successful
    Fail = The test was not successful
    Warning = The test could not complete and pass/fail could not be determined
#>
enum SoQState {
    Pass
    Fail
    Warning
}

<#
    SMB over QUIC client access control requires client auth EKU certificates.
#>
enum SoQEKUType {
    Server
    Client
}

<#
    Used for EKU ID validation.
    Currently not required...
#
[hashtable]$EKUMap = @{
    Server = '1.3.6.1.5.5.7.3.1'
    Client = '1.3.6.1.5.5.7.3.2'
}#>


<#
    These are the validation classes.
#>

class SoQResult {
    [SoQState]
    $IsValid

    [List[string]]
    $FailureReason

    [bool]
    $Passed

    SoQResult() {
        $script:libLogging.NewLog($null, "SoQResult", "New SoQResult.")
        $this.IsValid       = "Warning"
        $this.FailureReason = [List[string]]::new()
        $this.Passed        = $false
        $script:libLogging.NewLog($null, "SoQResult", "Created SoQResult.")
    }

    SetValidity([SoQState]$Result) {
        $script:libLogging.NewLog("SoQResult", "SetValidity", "$Result")
        $this.IsValid = $Result
        $this.UpdatePassFail()
    }

    # set replaces any existing failure with whatever is passed in
    SetFailureReason([string]$FailureReason) {
        $this.ClearFailureReason()
        $this.AddToFailureReason($FailureReason)
        $this.UpdatePassFail()
    }

    AddToFailureReason([string]$FR) {
        $script:libLogging.NewLog("SoQResult", "AddToFailureReason", "$FR")
        $this.FailureReason.Add($FR)
        $this.UpdatePassFail()
    }

    ClearFailureReason() {
        $this.FailureReason.Clear()
        $this.UpdatePassFail()
    }

    UpdatePassFail() {
        switch ($this.IsValid) {
            "Pass"    { $this.Passed = $true  }
            "Fail"    { $this.Passed = $false }
            "Warning" { $this.Passed = $true  }
            default   { $this.Passed = $false }
        }
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

    [SoQEKUType]
    $RequiredEKU

    hidden
    [int]
    $MinOsVersion

    hidden
    [int]
    $OsBuild

    SoQSupportedOS() {
        $script:libLogging.NewLog($null, "SoQSupportedOS", "Begin [default]")

        # default to server authentication EKU
        $this.RequiredEKU = "Server"
        $script:libLogging.NewLog($null, "SoQSupportedOS", "EKU type: $($this.RequiredEKU) Authentication")

        $this.Result.SetValidity( "Pass" )
        $this.ValidateServerOS()
        $script:libLogging.NewLog($null, "SoQSupportedOS", "End [default]")
    }

    SoQSupportedOS([SoQEKUType]$eku) {
        $script:libLogging.NewLog($null, "SoQSupportedOS", "Begin [eku]")

        try {
            $this.RequiredEKU = $eku
            $script:libLogging.NewLog($null, "SoQSupportedOS", "EKU type: $($this.RequiredEKU) Authentication")
        } catch {
            $script:libLogging.NewError("SoQSupportedOS", "UNKNOWN_EKU_TYPE", "The EKU type, $eku, is unsupported. The supported types are: $([enum]::GetNames([SoQEKUType]) -join ', ')", $true)
        }
        

        $this.Result.SetValidity( "Pass" )
        $this.ValidateServerOS()
        $script:libLogging.NewLog($null, "SoQSupportedOS", "End [eku]")
    }

    ValidateServerOS() {
        $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "Begin")

        # get OS version
        $osVer = [System.Environment]::OSVersion | ForEach-Object { $_.Version }
        $this.OsBuild = $osVer.Build 
        $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "osVer: $($osVer.ToString())")

        # use WMI to get OS details, since this is designed to run on Windows
        $wmiOS = Get-WmiObject Win32_OperatingSystem -Property Caption,ProductType
        $osName =  $wmiOS.Caption

        switch ($this.RequiredEKU) {
            "Server" {
                $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "Supported SMB server detection.")
                if ($osName -match "Azure Edition") {
                    $this.MinOsVersion = 20348
                } else {
                    # RTM version of Windows Server 2025
                    $this.MinOsVersion = 26100
                }

                $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "Caption: $osName")

                # ProductType: 1 = workstation, 2 = DC, 3 = Server
                $osType = $wmiOS.ProductType
                $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "osType: $osType")

                $this.Result.ClearFailureReason()
                $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "Start - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)")

                # must be server or DC product type
                if ( $osType -ne 2 -and $osType -ne 3 ) {
                    $this.Result.SetValidity( "Fail" )
                    $this.Result.AddToFailureReason( "Not Windows Server." )
                }
                $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "ProductType - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)")

                # must be Server 2022 or higher
                if ($osVer.Major -lt 10 -or $osVer.Build -lt 20348) {
                    $this.Result.SetValidity( "Fail" )
                    $this.Result.AddToFailureReason( "Not Windows Server 2022 or greater." )
                } 
                $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "Version - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)")
                
                # the edition must be Azure Edition or above MinOsVersion (Windows Server 2025)
                if ($osName -notmatch "Azure Edition" -and $osVer.Build -lt $this.MinOsVersion) {
                    $this.Result.SetValidity( "Fail" )
                    $this.Result.AddToFailureReason( "Not Azure Edition and not Windows Server 2025 or newer." )
                }
                $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "Azure Edition - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)")
            }

            "Client" {
                $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "Supported SMB client detection.")
                # Set the min OS version to Windows Server 2022, the first OS version with SMB over QUIC client support.
                $this.MinOsVersion = 20348

                $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "Caption: $osName")

                # The only SoQ client check needed is version number.
                # the edition must be above MinOsVersion (Windows Server 2022)
                if ($osVer.Build -lt $this.MinOsVersion) {
                    $this.Result.SetValidity( "Fail" )
                    $this.Result.AddToFailureReason( "SMB over QUIC client is unsupported. Min. Build: $($this.MinOsVersion); Current Build: $($osVer.Build)" )
                }
                $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "OS version - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)")
            }
        }

        # clear failure reason if IsValid passed
        if ( $this.Result.IsValid -eq "Pass" ) {
            $this.Result.ClearFailureReason()
        }
        $script:libLogging.NewLog("SoQSupportedOS", "ValidateServerOS", "End - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)")
    }

    [string]
    ToLongString() {
        return @"
SupportedOS
Valid       : $($this.Result.IsValid)
$( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }

    [string]
    ToShortString() {
        return "SupportedOS        : $($this.Result.IsValid)"
    }

    [string]
    ToString() {
        return $($this.ToShortString())
    }

    hidden
    [string]
    ToResultString() {
        return "Build: $($this.OsBuild), MinBuild: $($this.MinOsVersion)"
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass ($($this.ToResultString()))"
        } else {
            return "Fail ($($this.ToResultString()))"
        }
    }
}

# tracks and stores certificate dates and whether the certificate date is out of bounds
class SoQCertExpired {
    [datetime]
    $NotBefore

    [datetime]
    $NotAfter

    [datetime]
    $TestDate

    [SoQResult]
    $Result = [SoQResult]::new()

    SoQCertExpired(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        $script:libLogging.NewLog($null, "SoQCertExpired", "Begin")
        $this.NotBefore      = $Certificate.NotBefore
        $this.NotAfter       = $Certificate.NotAfter
        $this.TestDate       = [DateTime]::Now
        $script:libLogging.NewLog($null, "SoQCertExpired", "Validate")
        $this.Result.SetValidity( $this.ValidateDate() )
        $script:libLogging.NewLog($null, "SoQCertExpired", "End")
    }

    [SoQState]
    ValidateDate() {
        $script:libLogging.NewLog("SoQCertExpired", "ValidateDate", "Start")
        [SoQState]$isValidtmp = "Fail"
        
        $date = $this.TestDate
        if ( $this.NotBefore -lt $date -and $this.NotAfter -gt $date )
        {
            $script:libLogging.NewLog("SoQCertExpired", "ValidateDate", "IsValid: True")
            $isValidtmp = "Pass"
        }
        else
        {
            $script:libLogging.NewLog("SoQCertExpired", "ValidateDate", "IsValid: False")
            $FR = "Certificate is expired. Expired: $($this.NotAfter.ToShortDateString()) $($this.NotAfter.ToShortTimeString()), Today's Date: $($this.TestDate.ToShortDateString()) $($this.TestDate.ToShortTimeString())"
            $this.Result.SetFailureReason( $FR )
            $script:libLogging.NewLog("SoQCertExpired", "ValidateDate", "Failure Reason: $($this.Result.FailureReason)")
            $script:libLogging.NewLog("SoQCertExpired", "ValidateDate", "NotBefore: $($this.NotBefore.ToString()), NotAfter: $($this.NotAfter.ToString()), Test Date: $($date.ToString())")
        }

        $script:libLogging.NewLog("SoQCertExpired", "ValidateDate", "End")
        return $isValidtmp
    }

    [string]
    ToLongString() {
        return @"
Valid Dates
Not Before : $($this.NotBefore.ToShortDateString()) $($this.NotBefore.ToShortTimeString())
Not After  : $($this.NotAfter.ToShortDateString()) $($this.NotAfter.ToShortTimeString())
Valid      : $($this.Result.IsValid)
$( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }

    [string]
    ToShortString() {
        return "Expiration         : $($this.Result.IsValid)"
    }

    [string]
    ToString() {
        return $($this.ToShortString())
    }

    hidden
    [string]
    ToResultString() {
        return "Valid Dates: $($this.NotBefore.ToShortDateString()) - $($this.NotAfter.ToShortDateString()); Current Date: $($this.TestDate.ToShortDateString())"
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass ($($this.ToResultString()))"
        } else {
            return "Fail ($($this.ToResultString()))"
        }
    }
}


# tests whether the Server Authentication EKU is a cert purpose
class SoQCertPurpose {
    [string[]]
    $Purpose

    [SoQEKUType]
    $RequiredEKU

    [SoQResult]
    $Result = [SoQResult]::new()

    SoQCertPurpose(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    ) {
        $script:libLogging.NewLog($null, "SoQCertPurpose", "Begin [default]")
        
        # default to server
        $this.RequiredEKU = "Server"
        $script:libLogging.NewLog($null, "SoQCertPurpose", "EKU type: $($this.RequiredEKU) Authentication")

        $this.Purpose = $Certificate.EnhancedKeyUsageList.FriendlyName
        $script:libLogging.NewLog($null, "SoQCertPurpose", "Validate")
        $this.Result.SetValidity( $this.ValidatePurpose() )
        $script:libLogging.NewLog($null, "SoQCertPurpose", "End [default]")
    }

    # add client support
    SoQCertPurpose(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate,
        [SoQEKUType]
        $eku
    ) {
        $script:libLogging.NewLog($null, "SoQCertPurpose", "Begin [eku]")

        # default to server
        $this.RequiredEKU = $eku
        $script:libLogging.NewLog($null, "SoQCertPurpose", "EKU type: $($this.RequiredEKU) Authentication")
        
        $this.Purpose = $Certificate.EnhancedKeyUsageList.FriendlyName
        $script:libLogging.NewLog($null, "SoQCertPurpose", "Validate")
        $this.Result.SetValidity( $this.ValidatePurpose() )
        $script:libLogging.NewLog($null, "SoQCertPurpose", "End [eku]")
    }

    [SoQState]
    ValidatePurpose()
    {
        $script:libLogging.NewLog("SoQCertPurpose", "ValidatePurpose", "Start")
        [SoQState]$isValidtmp = "Fail"

        # supports Server or Client Authentication
        $script:libLogging.NewLog("SoQCertPurpose", "ValidatePurpose", "Required purpose: $($this.RequiredEKU) Authentication")
        if ( $this.Purpose -contains "$($this.RequiredEKU) Authentication")
        {
            $script:libLogging.NewLog("SoQCertPurpose", "ValidatePurpose", "IsValid: True")
            $isValidtmp = "Pass"
        }
        else 
        {
            $script:libLogging.NewLog("SoQCertPurpose", "ValidatePurpose", "IsValid: False")
            $this.Result.SetFailureReason( "Purpose does not contain Server Authentication. $( if ($this.Purpose.Count -gt 0) {"Purpose: $($this.Purpose -join ', ')"})" )
            $script:libLogging.NewLog("SoQCertPurpose", "ValidatePurpose", "Failure Reason: $($this.Result.FailureReason)")
            $script:libLogging.NewLog("SoQCertPurpose", "ValidatePurpose", "Purpose: $($this.Purpose), Must contain: Server Authentication")
        }

        $script:libLogging.NewLog("SoQCertPurpose", "ValidatePurpose", "End")
        return $isValidtmp
    }

    [string]
    ToLongString()
    {
        return @"
Purpose
Purpose : $($this.Purpose -join ', ')
Valid   : $($this.Result.IsValid)
$( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }

    [string]
    ToShortString() {
        return "Purpose            : $($this.Purpose -join ', ') ($($this.Result.IsValid))"
    }

    [string]
    ToString() {
        return $($this.ToShortString())
    }

    hidden
    [string]
    ToResultString() {
        return "Mandatory Purpose: Server Authentication; Cert Purposes: $($this.Purpose -join ', ')"
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass ($($this.ToResultString()))"
        } else {
            return "Fail ($($this.ToResultString()))"
        }
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
        $script:libLogging.NewLog($null, "SoQCertKeyUsage","Start")
        $tmpKey = $Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Key Usage" }
        if ( $tmpKey )
        {
            $this.KeyUsage = $tmpKey.Format(1)
        }
        else 
        {
            $script:libLogging.NewLog($null, "SoQCertKeyUsage","KeyUsage was not found.")
            $this.KeyUsage = $null
        }
        
        $script:libLogging.NewLog($null, "SoQCertKeyUsage","Validate")
        $this.Result.SetValidity( $this.ValidateKeyUsage() )
        $script:libLogging.NewLog($null, "SoQCertKeyUsage","End")
    }

    [SoqState]
    ValidateKeyUsage() {
        $script:libLogging.NewLog("SoQCertKeyUsage", "ValidateKeyUsage", "Start")
        [SoqState]$isValidtmp = "Fail"

        if ( $this.KeyUsage -match "Digital Signature" )
        {
            $script:libLogging.NewLog("SoQCertKeyUsage", "ValidateKeyUsage", "IsValid: True")
            $isValidtmp = "Pass"
        }
        else 
        {
            $script:libLogging.NewLog("SoQCertKeyUsage", "ValidateKeyUsage", "IsValid: False")
            $this.Result.SetFailureReason( "Key Usage does not match 'Digital Signature'. $(if (-NOT [string]::IsNullOrEmpty($this.KeyUsage)) {"($($this.KeyUsage))"})" )
            $script:libLogging.NewLog("SoQCertKeyUsage", "ValidateKeyUsage", "Failure Reason: $($this.Result.FailureReason)")
            $script:libLogging.NewLog("SoQCertKeyUsage", "ValidateKeyUsage", "KeyUsage: $($this.KeyUsage), Requires: Digital Signature")
        }

        $script:libLogging.NewLog("SoQCertKeyUsage", "ValidateKeyUsage", "End")
        return $isValidtmp
    }

    [string]
    ToLongString() {
        return @"
Key Usage
Key Usage : $($this.KeyUsage.TrimEnd("`n`r"))
Valid     : $($this.Result.IsValid)
$( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }

    [string]
    ToShortString() {
        return "KeyUsage           : $($this.KeyUsage.TrimEnd("`n`r")) ($($this.Result.IsValid))"
    }

    [string]
    ToString() {
        return $($this.ToShortString())
    }

    hidden
    [string]
    ToResultString() {
        return "Mandatory Key Usage: Digital Signature; Cert Purposes: $($this.KeyUsage.TrimEnd("`n`r"))"
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass ($($this.ToResultString()))"
        } else {
            return "Fail ($($this.ToResultString()))"
        }
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
        $script:libLogging.NewLog($null, "SoQCertSubject","Start")
        $this.Subject = $Certificate.Subject
        $script:libLogging.NewLog($null, "SoQCertSubject","Validate")
        $this.Result.SetValidity( $this.ValidateSubject() )
        $script:libLogging.NewLog($null, "SoQCertSubject","End")
    }

    [SoQState]
    ValidateSubject()
    {
        $script:libLogging.NewLog("SoQCertSubject", "ValidateSubject", "Start")
        [SoQState]$isValidtmp = "Fail"

        if ( $this.Subject -match $this.rgxSubject )
        {
            $script:libLogging.NewLog("SoQCertSubject", "ValidateSubject", "IsValid: True")
            $isValidtmp = "Pass"
        }
        else 
        {
            $script:libLogging.NewLog("SoQCertSubject", "ValidateSubject", "IsValid: False")
            $this.Result.SetFailureReason( "Does not contain a Subject. ($($this.Subject))" )
            $script:libLogging.NewLog("SoQCertSubject", "ValidateSubject", "Failure Reason: $($this.Result.FailureReason)")
            $script:libLogging.NewLog("SoQCertSubject", "ValidateSubject", "Subject: $($this.Subject), Requires: CN=<some text>")
        }

        $script:libLogging.NewLog("SoQCertSubject", "ValidateSubject", "End")
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

    [string]
    ToShortString()
    {
        return "Subject            : $($this.Subject) ($($this.Result.IsValid))"
    }

    [string]
    ToShorterString()
    {
        return "Subject : $($this.Subject) ($($this.Result.IsValid))"
    }

    hidden
    [string]
    ToResultString() {
        return "Subject: $($this.Subject)"
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass ($($this.ToResultString()))"
        } else {
            return "Fail ($($this.ToResultString()))"
        }
    }
}

# There must be at least one Subject Alternative Name
class SoQCertSAN {
    [string[]]
    $SubjectAltName

    [SoQResult]
    $Result = [SoQResult]::new()

    [bool]
    $ValidSANFnd

    SoQCertSAN(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        $script:libLogging.NewLog($null, "SoQCertSAN","Start")
        $this.ValidSANFnd    = $false
        $this.SubjectAltName = $Certificate.DnsNameList.Unicode
        $script:libLogging.NewLog($null, "SoQCertSAN","Validate")
        $this.Result.SetValidity( $this.ValidateSAN() )
        $script:libLogging.NewLog($null, "SoQCertSAN","End")
    }

    [SoQState]
    ValidateSAN() {
        $script:libLogging.NewLog("SoQCertSAN","ValidateSAN", "Start")
        [SoQState]$isValidtmp = "Fail"

        # there must be a SAN
        if ( ($this.SubjectAltName).Count -ge 1 ) {
            $script:libLogging.NewLog("SoQCertSAN","ValidateSAN", "IsValidNum: True")
            $isValidtmp = "Pass"

            # SAN's must be valid DNS names
            foreach ($e in $this.SubjectAltName) {
                $isDNS = [System.Uri]::CheckHostName($e)
                if ( $isDNS -eq "Unknown" ) {
                    $script:libLogging.NewLog("SoQCertSAN","ValidateSAN", "IsValid: False")
                    $script:libLogging.NewLog("SoQCertSAN","ValidateSAN", "dnsName: $e; isDNS: $isDNS")
                    $this.Result.AddToFailureReason("Invalid Subject Alternative Name: $e" )
                    $isValidtmp = "Warning"
                } elseif ( $isDNS -eq "DNS" ) {
                    $script:libLogging.NewLog("SoQCertSAN","ValidateSAN", "Found a valid DNS name in SAN: $e")
                    $this.ValidSANFnd = $true
                }
            }
        } else {
            $script:libLogging.NewLog("SoQCertSAN","ValidateSAN", "IsValid: False")
            $this.Result.SetFailureReason( "No Subject Alternative Names. $(if ($this.SubjectAltName -gt 0) {"($($this.SubjectAltName -join ', '))"})" )
            $script:libLogging.NewLog("SoQCertSAN","ValidateSAN", "Failure Reason: $($this.Result.FailureReason)")
            $script:libLogging.NewLog("SoQCertSAN","ValidateSAN", "SubjectAltName: $($this.SubjectAltName -join ', '); Count: $(($this.SubjectAltName).Count); Count >= 1.")
        }

        # decide whether to fail or warn
        # with a warning and no valid SAN we switch to fail
        if ( $isValidtmp -eq [SoQState]"Warning" -and $this.ValidSANFnd -eq $false ) {
            $this.Result.ClearFailureReason()
            $isValidtmp = "Fail"
            $this.Result.AddToFailureReason("No valid Subject Alternative Names found.")
        # with a warning and a valid SAN we switch to pass but keep the warning in failure reason
        } elseif ( $isValidtmp -eq [SoQState]"Warning" -and $this.ValidSANFnd ) {
            $isValidtmp = "Pass"
            $this.Result.AddToFailureReason("but test passed due to a valid Subject Alternative Name found.")
        }

        $script:libLogging.NewLog("SoQCertSAN","ValidateSAN", "End")
        return $isValidtmp
    }

    [string]
    ToLongString() {
        return @"
Subject Alternative Name (DNS)
DNS List : $($this.SubjectAltName -join ', ')
Valid    : $($this.Result.IsValid)
$( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }

    [string]
    ToShortString() {
        return "SubjectAltName     : $($this.SubjectAltName -join ', ') ($($this.Result.IsValid))"
    }

    [string]
    ToString() {
        return $($this.ToShortString())
    }

    hidden
    [string]
    ToResultString() {
        return "SubjectAltName: $($this.SubjectAltName -join ', ')"
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass ($($this.ToResultString()))"
        } else {
            return "Fail ($($this.ToResultString()))"
        }
    }
}

# The private key must be installed
class SoQCertPrivateKey {
    [SoQResult]
    $Result = [SoQResult]::new()

    hidden
    [bool]
    $HasPrivateKey

    SoQCertPrivateKey(
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $Certificate
    )
    {
        $script:libLogging.NewLog($null, "SoQCertPrivateKey","Start")
        $this.HasPrivateKey = $Certificate.HasPrivateKey
        if ($Certificate.HasPrivateKey) {
            $this.Result.SetValidity( "Pass" )
            $script:libLogging.NewLog($null, "SoQCertPrivateKey","IsValid: True")
        } else {
            $script:libLogging.NewLog($null, "SoQCertPrivateKey","IsValid: False")
            $this.Result.SetFailureReason( "No Private Key." )
            $script:libLogging.NewLog($null, "SoQCertPrivateKey","Failure Reason: $($this.Result.FailureReason)")
            $script:libLogging.NewLog($null, "SoQCertPrivateKey","HasPrivateKey: False")
        }

        $script:libLogging.NewLog($null, "SoQCertPrivateKey","End")
    }

    [string]
    ToLongString() {
        return @"
Private Key
HasPrivateKey : $($this.Result.IsValid)
$( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" }) 
"@
    }

    [string]
    ToShortString() {
        return "HasPrivateKey      : $($this.Result.IsValid)"
    }

    [string]
    ToString() {
        return $($this.ToShortString())
    }

    hidden
    [string]
    ToResultString() {
        return "Private Key: $($this.HasPrivateKey)"
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass ($($this.ToResultString()))"
        } else {
            return "Fail ($($this.ToResultString()))"
        }
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
        $script:libLogging.NewLog($null, "SoQCertSignatureAlgorithm","Start")
        $this.SignatureAlgorithm = $Certificate.SignatureAlgorithm.FriendlyName
        $script:libLogging.NewLog($null, "SoQCertSignatureAlgorithm","Validate")
        $this.Result.SetValidity( $this.ValidateSignatureAlgorithm() )
        $script:libLogging.NewLog($null, "SoQCertSignatureAlgorithm","End")
    }

    [string[]]
    GetValidSigAlgo() {
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpnap/a48b02b2-2a10-4eb0-bed4-1807a6d2f5ad
        # Retrieved 18 Jan 2023
        # array of supported signature hash algorithms
        return @("sha256ECDSA", "sha384ECDSA", "sha512ECDSA", "sha256RSA", "sha384RSA", "sha512RSA")
    }

    [SoQState]
    ValidateSignatureAlgorithm() {
        $script:libLogging.NewLog("SoQCertSignatureAlgorithm","ValidateSignatureAlgorithm", "Start")
        [SoQState]$isValidtmp = "Fail"

        if ( $this.SignatureAlgorithm -in $this.GetValidSigAlgo() ) {

            $script:libLogging.NewLog("SoQCertSignatureAlgorithm","ValidateSignatureAlgorithm", "IsValid: True")
            $isValidtmp = "Pass"
        }
        else 
        {
            $script:libLogging.NewLog("SoQCertSignatureAlgorithm","ValidateSignatureAlgorithm", "IsValid: False")
            $this.Result.SetFailureReason( "Uses a Signature Algorithm not known to work. ($($this.SignatureAlgorithm))" )
            $script:libLogging.NewLog("SoQCertSignatureAlgorithm","ValidateSignatureAlgorithm", "Failure Reason: $($this.Result.FailureReason)")
            $script:libLogging.NewLog("SoQCertSignatureAlgorithm","ValidateSignatureAlgorithm", "SignatureAlgorithm: $($this.SignatureAlgorithm), Valid Range: $($this.GetValidSigAlgo() -join ', ')")
        }

        $script:libLogging.NewLog("SoQCertSignatureAlgorithm","ValidateSignatureAlgorithm", "End")
        return $isValidtmp
    }

    [string]
    ToLongString() {
        return @"
Signature Algorithm
SignatureAlgorithm : $($this.SignatureAlgorithm)
Valid              : $($this.Result.IsValid)
$( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }

    [string]
    ToShortString() {
        return "SignatureAlgorithm : $($this.SignatureAlgorithm) ($($this.Result.IsValid))"
    }

    [string]
    ToString() {
        return $($this.ToShortString())
    }

    hidden
    [string]
    ToResultString() {
        return "SignatureAlgorithm: $($this.SignatureAlgorithm); Valid Algorithms: $($this.GetValidSigAlgo() -join ', ')"
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass ($($this.ToResultString()))"
        } else {
            return "Fail ($($this.ToResultString()))"
        }
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
        $script:libLogging.NewLog($null, "SoQCertSignatureHash","Start")
        $this.SignatureHash  = $this.GetHashString($Certificate)
        $script:libLogging.NewLog($null, "SoQCertSignatureHash","Validate")
        $this.Result.SetValidity( $this.ValidateSigHash() )
        $script:libLogging.NewLog($null, "SoQCertSignatureHash","End")
    }

    [string[]]
    GetValidHash() {
        return @("sha256", "sha384", "sha512")
    }

    [string]
    GetHashString([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate) {
        $script:libLogging.NewLog("SoQCertSignatureHash","GetHashString", "Start")
        $strHash = ""

        [regex]$rgxHash = "(?<hash>md\d{1})|(?<hash>sha\d{1,3})"

        if ( $Certificate.SignatureAlgorithm.FriendlyName -match $rgxHash )
        {
            $strHash = $Matches.hash.ToString().ToLower()
            $script:libLogging.NewLog("SoQCertSignatureHash","GetHashString", "Hash found. strHash: $strHash")
        } else {
            $script:libLogging.NewLog("SoQCertSignatureHash","GetHashString", "Hash not found.")
            $strHash = "Unknown"
        }

        $script:libLogging.NewLog("SoQCertSignatureHash","GetHashString", "End")
        return $strHash
    }

    [SoQState]
    ValidateSigHash() {
        $script:libLogging.NewLog("SoQCertSignatureHash","ValidateSigHash", "Start")
        [SoQState]$isValidtmp = "Fail"

        if ( $this.SignatureHash -in $this.GetValidHash() )
        {
            $script:libLogging.NewLog("SoQCertSignatureHash","ValidateSigHash", "IsValid: True")
            $isValidtmp = "Pass"
        }
        else 
        {
            $script:libLogging.NewLog("SoQCertSignatureHash","ValidateSigHash", "IsValid: False")
            $this.Result.SetFailureReason( "Not a valid signature hash. ($($this.SignatureHash))" )
            $script:libLogging.NewLog("SoQCertSignatureHash","ValidateSigHash", "Failure Reason: $($this.Result.FailureReason)")
            $script:libLogging.NewLog("SoQCertSignatureHash","ValidateSigHash", "SignatureHash: $($this.SignatureHash), Valid Range: $($this.GetValidHash() -join ', ')")
        }

        $script:libLogging.NewLog("SoQCertSignatureHash","ValidateSigHash", "End")
        return $isValidtmp
    }

    [string]
    ToLongString() {
        return @"
Signature Hash
Hash  : $($this.SignatureHash)
Valid : $($this.Result.IsValid)
$( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }

    [string]
    ToShortString() {
        return "SignatureHash      : $($this.SignatureHash) ($($this.Result.IsValid))"
    }

    [string]
    ToString() {
        return $($this.ToShortString())
    }

    hidden
    [string]
    ToResultString() {
        return "SignatureHash: $($this.SignatureHash); Valid Hash Algorithms: $($this.GetValidHash() -join ', ')"
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass ($($this.ToResultString()))"
        } else {
            return "Fail ($($this.ToResultString()))"
        }
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
        $script:libLogging.NewLog($null, "SoQCertPublicKeyAlgorithm","Start")
        $this.PublicKeyAlgorithm = $this.GetPKAString($Certificate)
        $script:libLogging.NewLog($null, "SoQCertPublicKeyAlgorithm","Validate")
        $this.Result.SetValidity( $this.ValidatePKA() )
        $script:libLogging.NewLog($null, "SoQCertPublicKeyAlgorithm","End")
    }

    [string]
    GetPKAString([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate) {
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
    GetValidPKA() {
        return @("ECDSA_P256", "ECDSA_P384", "ECDSA_P521", "RSA2048", "RSA4096")
    }

    [SoQState]
    ValidatePKA() {
        $script:libLogging.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "Start")
        
        [SoQState]$isValidtmp = "Fail"

        if ( $this.Result.FailureReason ) {
            # Detection will fail when PowerShell 5.1 is used and the PKA is EC-based. 
            # Use that FailureReason and return $false
            $script:libLogging.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "IsValid: Warning")
            $isValidtmp = "Warning"
            $script:libLogging.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "Warning Reason: $($this.Result.FailureReason)")
        } elseif ( $this.PublicKeyAlgorithm -in $this.GetValidPKA() )
        {
            $script:libLogging.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "IsValid: True")
            $isValidtmp = "Pass"
        }
        else 
        {
            $script:libLogging.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "IsValid: False")
            $this.Result.SetFailureReason( "Not a known supported Public Key Algorithm. ($($this.PublicKeyAlgorithm))" )
            $script:libLogging.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "Failure Reason: $($this.Result.FailureReason)")
            $script:libLogging.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "PublicKeyAlgorithm: $($this.PublicKeyAlgorithm), Valid Range: $($this.GetValidPKA() -join ', ')")
        }

        $script:libLogging.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "End")
        return $isValidtmp
    }

    [string]
    ToLongString() {
        return @"
Public Key Algorithm     
PKA   : $($this.PublicKeyAlgorithm)
Valid : $($this.Result.IsValid)
$( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }

    [string]
    ToShortString() {
        return "PublicKeyAlgorithm : $($this.PublicKeyAlgorithm) ($($this.Result.IsValid))"
    }

    [string]
    ToString() {
        return $($this.ToShortString())
    }

    hidden
    [string]
    ToResultString() {
        return "PublicKeyAlgorithm: $($this.PublicKeyAlgorithm); Valid Public Key Algorithms: $(($this.GetValidPKA()) -join ', ')"
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass ($($this.ToResultString()))"
        } else {
            return "Fail ($($this.ToResultString()))"
        }
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
        $script:libLogging.NewLog($null, "SoQCertCertChain", "Start")
        $script:libLogging.NewLog($null, "SoQCertCertChain", "Validate")
        $this.Result.SetValidity( $this.ValidateCertChain($Certificate) )
        $script:libLogging.NewLog($null, "SoQCertCertChain", "End")
    }

    [SoQState]
    ValidateCertChain([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate) {
        $script:libLogging.NewLog("SoQCertCertChain", "ValidateCertChain", "Start")
        [SoQState]$isValidtmp = "Fail"

        ## let certutil handle cert chain validation ##
        # export the cer file
        $fn = "cert_$(Get-Date -Format "ddMMyyyyHHmmssffff").cer"
        $script:libLogging.NewLog("SoQCertCertChain", "ValidateCertChain", "Create file: $pwd\$fn")
        $null = Export-Certificate -Cert $Certificate -FilePath "$pwd\$fn" -Force

        # verify the cert chain
        $script:libLogging.NewLog("SoQCertCertChain", "ValidateCertChain", "Execute: certutil -verify `"$pwd\$fn`"")
        $results = certutil -verify "$pwd\$fn"
        $script:libLogging.NewLog("SoQCertCertChain", "ValidateCertChain", "Results:`n$results`n")


        # remove the cer file
        $script:libLogging.NewLog("SoQCertCertChain", "ValidateCertChain", "Remove File")
        $null = Remove-Item "$pwd\$fn" -Force

        # validation is true if CERT_E_UNTRUSTEDROOT is not in the output
        if ( -NOT ($results | Where-Object { $_ -match 'CERT_E_UNTRUSTEDROOT' }) ) {
            $script:libLogging.NewLog("SoQCertCertChain", "ValidateCertChain", "IsValid: Pass")
            $isValidtmp = "Pass"
        }
        else 
        {
            $script:libLogging.NewLog("SoQCertCertChain", "ValidateCertChain", "IsValid: Fail")
            $this.Result.SetFailureReason( "Certificate chain validation failed. 'certutil -verify' returned error CERT_E_UNTRUSTEDROOT." )
            $script:libLogging.NewLog("SoQCertCertChain", "ValidateCertChain", "Failure Reason: $($this.Result.FailureReason)")
            $script:libLogging.NewLog("SoQCertCertChain", "ValidateCertChain", "CERT_E_UNTRUSTEDROOT:`n$(($results | Where-Object { $_ -match 'CERT_E_UNTRUSTEDROOT' }) -join "`n")`n`n ")
        }

        $script:libLogging.NewLog("SoQCertCertChain", "ValidateCertChain", "End")
        return $isValidtmp
    }

    [string]
    ToLongString() {
        return @"
Certificate Chain
ValidCertChain : $($this.Result.IsValid)
$( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }

    [string]
    ToShortString() {
        return "ValidCertChain     : $($this.Result.IsValid)"
    }

    [string]
    ToString() {
        return $($this.ToShortString())
    }

    hidden
    [string]
    ToResultString() {
        return ""
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass"
        } else {
            return "Fail"
        }
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
        $script:libLogging.NewLog("SoQCipherSuite", "SetTlsString", "Cipher string: $TlsString")
        $this.TlsString = $TlsString
    }

    SetStrongCrypto([string]$str) {
        if ($str -match 'Yes') {
            $this.StrongCrypto = $true
        } else {
            $this.StrongCrypto = $false
        }

        $script:libLogging.NewLog("SoQCipherSuite", "SetStrongCrypto", "Strong crypto: $($this.StrongCrypto)")
    }

    SetIsVerTls13([string]$str) {
        if ($str -match 'TLS 1.3') {
            $script:libLogging.NewLog("SoQCipherSuite", "SetIsVerTls13", "Is TLS 1.3")
            $this.isVerTls13 = $true
        } else {
            $this.isVerTls13 = $false
            $script:libLogging.NewLog("SoQCipherSuite", "SetIsVerTls13", "Is NOT TLS 1.3")
        }
        $script:libLogging.NewLog("SoQCipherSuite", "SetIsVerTls13", "TLS 1.3: $($this.isVerTls13)")
    }

    [string]
    ToString() {
        return @"
TlsString: $($this.TlsString); STRONG_CRYPTO: $($this.StrongCrypto); TLS1.3Suite: $($this.isVerTls13)
"@
    }

    hidden
    [string]
    ToResultString() {
        return "$($this.ToString())"
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass ($($this.ToResultString()))"
        } else {
            return "Fail ($($this.ToResultString()))"
        }
    }
}


class SoQTls13Support {
    # list of the locally supported/enabled TLS 1.3 cipher suites.
    [array]
    $LocalCipherSuites

    # the known or discovered TLS 1.3 cipher suites.
    [array]
    $Tls13CipherSuites

    [SoQResult]
    $Result = [SoQResult]::new()

    SoQTls13Support() {
        $script:libLogging.NewLog($null, "SoQTls13Support", "Begin")
        # if there is an internet connection we get the list of supported TLS 1.3 cipher suites
        if ((Get-NetConnectionProfile).IPv4Connectivity -contains "Internet" -or (Get-NetConnectionProfile).IPv6Connectivity -contains "Internet") {
            $script:libLogging.NewLog($null, "SoQTls13Support", "Trying to get the live TLS 1.3 list.")
            $this.GetTls13CipherSuitesFromInternet()
        } else {
            $script:libLogging.NewLog($null, "SoQTls13Support", "Using last known good TLS 1.3 list.")
            $this.UseLastKnownGoodTls13CipherSuites()
        }

        # initiate LocalCipherSuites as an empty array
        $this.LocalCipherSuites = @()

        # test whether there is at least one valid TLS 1.3 cipher suite enabled on the system
        $script:libLogging.NewLog($null, "SoQTls13Support", "Validating TLS 1.3 support.")
        $this.ValidateLocalCipherSuite()

        $script:libLogging.NewLog($null, "SoQTls13Support", "Result:`n$($this.ToString())")
        $script:libLogging.NewLog($null, "SoQTls13Support", "End")
    }

    # populates Tls13CipherSuites with a list of known supported TLS 1.3 ciphers in Windows
    # https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022
    # Retrieved: 15 Feb 2023
    UseLastKnownGoodTls13CipherSuites() {
        $script:libLogging.NewLog("SoQTls13Support", "UseLastKnownGoodTls13CipherSuites", "Begin")
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
        
        $script:libLogging.NewLog("SoQTls13Support", "UseLastKnownGoodTls13CipherSuites", "End")
    }

    # Retrieves the current list of supported TLS 1.3 cipher suites.
    # https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022
    GetTls13CipherSuitesFromInternet() {
        $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Start")
        # The TLS 1.3 cipher suites must be enabled in Windows.
        # right now SoQ only supports Windows Server 2022 so keep this simple for now
        $url = 'https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022'

        # download the page
        $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Set TLS for Invoke-WebRequest.")
        [System.Net.ServicePointManager]::SecurityProtocol = "Tls12", "Tls13"

        $rawSite = $null
        try {
            $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Downloading the cipher suite site.")
            $rawSite = Invoke-WebRequest $url -UseBasicParsing -EA Stop
        }
        catch {
            $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Failed to download the current TLS 1.3 list: $_")
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
                    $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Start table")
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
                    $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "End table")
                    $tableStarted = $false
                } elseif ( $tableStarted ) {
                    # look for a table header we want.
                    if ($_ -match '<tr>') {
                        $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Start row")
                        $rowStarted = $true
                    } elseif ($_ -match '</tr>') {
                        $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "End row")
                        $rowStarted = $false

                        $tmpRow = [SoQCipherSuite]::new()
                    } elseif ($rowStarted) {
                        # parse the text between <td> and <br/></td> and add it to the class
                        if ($_ -match "<td>(?<str>\w{2}.*)<br/></td>") {
                            $text = $Matches.str
                            $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Found match: $text")
                            
                            if ( -NOT [string]::IsNullOrEmpty($text) ) {
                                switch ($tdNum) {
                                    1 { 
                                        $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Adding cipher string")
                                        $tmpRow.SetTlsString($text)
                                        $tdNum++
                                    }
                                    
                                    2 { 
                                        $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Adding strong crypto")
                                        $tmpRow.SetStrongCrypto($text) 
                                        $tdNum++
                                    }

                                    3 { 
                                        $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Testing if TLS 1.3.")
                                        $tmpRow.SetIsVerTls13($text) 

                                        # add to the results only if it's a TLS 1.3 compatible suite
                                        if ($tmpRow.isVerTls13) {
                                            $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Adding to list.`n`n$($tmpRow.ToString())`n`n")
                                            $tls13CipherTable += $tmpRow
                                        }

                                        $tdNum = 1
                                    }

                                    default { $script:libLogging.NewError("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "UNSUPPORTED_SWITCH_OPTION", "You shouldn't be here.", $true)}
                                }
                            }
                        }
                    }
                }
            }

            # set the suites if we got results
            if ($tls13CipherTable.Count -ge 1) {
                $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Successfully got a working list.")
                $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "tls13CipherTable: $($tls13CipherTable.TlsString -join ', ')")
                $this.Tls13CipherSuites = $tls13CipherTable
            # Otherwise, use the last known good set. Just in case something doesn't work.
            } else {
                $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Something went wrong, falling back to Last Known Good list.")
                $this.UseLastKnownGoodTls13CipherSuites()
            }
        }

        $script:libLogging.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "End")
    }

    # checks whether the local list of suites has a TLS 1.3 cipher.
    # if the default is used we assume there is a supported cipher, because Windows Server 2022 supports TLS 1.3 by default
    ValidateLocalCipherSuite() {
        $script:libLogging.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Begin")
        # look for the registry value that controls cipher suites
        [array]$cipherPol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' | ForEach-Object { $_.Functions.Split(',') }

        $script:libLogging.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Cipher suites: $($cipherPol -join ', ')")
        $script:libLogging.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "TLS 1.3 suites: $($this.Tls13CipherSuites | Format-List | Out-String)")

        if ($cipherPol.Count -ge 1) {
            $script:libLogging.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Starting validation.")
            # test whether there is an approved TLS 1.3 cipher
            $fndValidTls13Suite = $false

            foreach ($c in $this.Tls13CipherSuites) { 
                $script:libLogging.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Looking for $($c.TlsString) in local cipher suites.")
                if ($c.TlsString -in $cipherPol) {
                    $script:libLogging.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Found in local cipher suites. Marking test passed.")
                    $this.LocalCipherSuites += $c.TlsString
                    $fndValidTls13Suite = $true
                } else {
                    $script:libLogging.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "No match found in local cipher suite.")
                }
            }

            if ($fndValidTls13Suite) {
                $script:libLogging.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Validation passed.")
                $this.Result.SetValidity( "Pass" )
            } else {
                $script:libLogging.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Validation failed.")
                $this.Result.SetValidity( "Fail" )
                $this.Result.FailureReason = "The 'SSL Cipher Suite Order' policy has been modified and does not include a TLS 1.3 compatible cipher suite. See: https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022"
            }

        } else {
            $script:libLogging.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Policy is default. Accepting this as a pass.")
            # use last known good as a filler
            $this.LocalCipherSuites = $this.Tls13CipherSuites.TlsString
            # no special cipher policy is installed, the default will be compatible.
            $this.Result.SetValidity( "Pass" )
        }
        $script:libLogging.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "End")
    }

    [string]
    ToString() {
        return @"
SoQTls13Support
LocalCipherSuites : $($this.LocalCipherSuites -join ', ') 
Tls13CipherSuites : $($this.Tls13CipherSuites.TlsString -join ', ') 
Valid             : $($this.Result.IsValid)
$( if ( $this.Result.IsValid -eq "Fail") { "FailureReason : $($this.Result.FailureReason)" } elseif ($this.Result.IsValid -eq "Warning") { "WarningReason : $($this.Result.FailureReason)" })
"@
    }

    [string]
    ToShortString() {
        return "LocalCipherSuites  : $($this.LocalCipherSuites -join ', ') ($($this.Result.IsValid))"
    }

    hidden
    [string]
    ToResultString() {
        return "LocalCipherSuites  : $($this.LocalCipherSuites -join ', '); Tls13CipherSuites: $($this.Tls13CipherSuites.TlsString -join ',') "
    }

    [string]
    ToPassFailString() {
        if ($this.Result.Passed) {
            return "Pass ($($this.ToResultString()))"
        } else {
            return "Fail ($($this.ToResultString()))"
        }
    }
}


# this class monitors the certs 
class SoQCertValidation {
    ### PROPERTIES ###
    #region
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
    #endregion

    # defaults to Server SKU tests
    SoQCertValidation([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate, [bool]$IgnoreOS)
    {
        $script:libLogging.NewLog($null, "SoQCertValidation", "Start [default]")
        $this.Certificate        = $Certificate
        $script:libLogging.NewLog($null, "SoQCertValidation", "Thumbprint: $($this.Certificate.Thumbprint), Subject: $($this.Certificate.Subject)")
        if ($IgnoreOS) {
            $script:libLogging.NewLog($null, "SoQCertValidation", "SupportedOS: Ignored")
            $this.IgnoreOS           = $true
            $this.SupportedOS        = $null
        } else {
            $script:libLogging.NewLog($null, "SoQCertValidation", "SupportedOS")
            $this.IgnoreOS           = $false
            $this.SupportedOS        = [SoQSupportedOS]::new()
        }
        $script:libLogging.NewLog($null, "SoQCertValidation", "Expiration")
        $this.Expiration         = [SoQCertExpired]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "Purpose")
        $this.Purpose            = [SoQCertPurpose]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "KeyUsage")
        $this.KeyUsage           = [SoQCertKeyUsage]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "Subject")
        $this.Subject            = [SoQCertSubject]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "SubjectAltName")
        $this.SubjectAltName     = [SoQCertSAN]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "PrivateKey")
        $this.PrivateKey         = [SoQCertPrivateKey]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "SignatureAlgorithm")
        $this.SignatureAlgorithm = [SoQCertSignatureAlgorithm]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "SignatureHash")
        $this.SignatureHash      = [SoQCertSignatureHash]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "PublicKeyAlgorithm")
        $this.PublicKeyAlgorithm = [SoQCertPublicKeyAlgorithm]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "CertChain")
        $this.CertChain          = [SoQCertCertChain]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "Tls13Support")
        $this.Tls13Support       = [SoQTls13Support]::new()
        $script:libLogging.NewLog($null, "SoQCertValidation", "Validate")
        $this.IsValid            = $this.ValidateSoQCert()
        $script:libLogging.NewLog($null, "SoQCertValidation", "End [default]")
    } 

    # allows client SKU specific testing
    SoQCertValidation([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate, [bool]$IgnoreOS, [string]$strEKU)
    {
        $script:libLogging.NewLog($null, "SoQCertValidation", "Start [eku]")

        # convert the string EKU into a SoQEKUType
        try {
            [SoQEKUType]$eku = $strEKU
            $script:libLogging.NewLog($null, "SoQCertValidation", "EKU: $strEKU")
        } catch {
            $script:libLogging.NewError("SoQCertValidation", "INVALID_EKU_TYPE", "The EKU type, $strEKU, is unsupported. The supported types are: $([enum]::GetNames([SoQEKUType]) -join ', ')", $true)
        }

        $this.Certificate        = $Certificate
        $script:libLogging.NewLog($null, "SoQCertValidation", "Thumbprint: $($this.Certificate.Thumbprint), Subject: $($this.Certificate.Subject)")
        if ($IgnoreOS) {
            $script:libLogging.NewLog($null, "SoQCertValidation", "SupportedOS: Ignored")
            $this.IgnoreOS           = $true
            $this.SupportedOS        = $null
        } else {
            $script:libLogging.NewLog($null, "SoQCertValidation", "SupportedOS")
            $this.IgnoreOS           = $false
            $this.SupportedOS        = [SoQSupportedOS]::new($eku)
        }
        $script:libLogging.NewLog($null, "SoQCertValidation", "Expiration")
        $this.Expiration         = [SoQCertExpired]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "Purpose")
        $this.Purpose            = [SoQCertPurpose]::new($Certificate, $eku)
        $script:libLogging.NewLog($null, "SoQCertValidation", "KeyUsage")
        $this.KeyUsage           = [SoQCertKeyUsage]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "Subject")
        $this.Subject            = [SoQCertSubject]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "SubjectAltName")
        $this.SubjectAltName     = [SoQCertSAN]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "PrivateKey")
        $this.PrivateKey         = [SoQCertPrivateKey]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "SignatureAlgorithm")
        $this.SignatureAlgorithm = [SoQCertSignatureAlgorithm]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "SignatureHash")
        $this.SignatureHash      = [SoQCertSignatureHash]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "PublicKeyAlgorithm")
        $this.PublicKeyAlgorithm = [SoQCertPublicKeyAlgorithm]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "CertChain")
        $this.CertChain          = [SoQCertCertChain]::new($Certificate)
        $script:libLogging.NewLog($null, "SoQCertValidation", "Tls13Support")
        $this.Tls13Support       = [SoQTls13Support]::new()
        $script:libLogging.NewLog($null, "SoQCertValidation", "Validate")
        $this.IsValid            = $this.ValidateSoQCert()
        $script:libLogging.NewLog($null, "SoQCertValidation", "End [eku]")
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
        $script:libLogging.NewLog("SoQCertValidation", "ValidateSoQCert", "Start")
        [SoQState]$valid = "Pass"
        $tests = $this.GetSubclassVariables()

        $theLongestLen = 0
        $tests | ForEach-Object { if ( $_.Length -gt $theLongestLen ) { $theLongestLen = $_.Length } }

        foreach ( $test in $tests )
        {
            $script:libLogging.NewLog("SoQCertValidation", "ValidateSoQCert", "Testing $($test.PadRight($theLongestLen, " ")) : $($this."$test".Result.IsValid)")
            if ($this."$test".Result.IsValid -eq "Fail") { 
                $valid = "Fail" 
                $this.FailedTests += $test
                $script:libLogging.NewLog("SoQCertValidation", "ValidateSoQCert", "Failure reason: $($this."$test".Result.FailureReason)")
            } elseif ($this."$test".Result.IsValid -eq "Warning") { 
                # do not overwrite the Fail state
                if ($valid -ne "Fail") {
                    $valid = "Warning"
                }

                $this.FailedTests += $test
                $script:libLogging.NewLog("SoQCertValidation", "ValidateSoQCert", "Warning reason: $($this."$test".Result.FailureReason)")
            }
        }

        $script:libLogging.NewLog("SoQCertValidation", "ValidateSoQCert", "End")
        return $valid
    }

    # this method does not generate logs
    [bool]
    IsValidBool() {
        switch ($this.IsValid) {
            "Pass"    { return $true  }
            "Fail"    { return $false }
            "Warning" { return $true  }
            default   { return $false }
        }

        # return false if we somehow get here.
        return $false
    }

    [string]
    ToString()
    {
        $text = "Thumbprint         : $($this.Certificate.Thumbprint)"
        $this.GetSubclassVariables() | ForEach-Object { $text = [string]::Concat($text, "`n$($this."$_".ToShortString())") }

        return $text

        <#
        if ($this.IgnoreOS) {
            return @"
Thumbprint         : $($this.Certificate.Thumbprint)
$($this.Subject.ToShortString())
$($this.SubjectAltName.ToShortString())
$($this.Expiration.ToShortString())
$($this.Purpose.ToShortString())
$($this.KeyUsage.ToShortString())
$($this.PrivateKey.ToShortString())
$($this.SignatureAlgorithm.ToShortString())
$($this.SignatureHash.ToShortString())
$($this.PublicKeyAlgorithm.ToShortString())
$($this.CertChain.ToShortString())
"@
        } else {
        return @"
Thumbprint         : $($this.Certificate.Thumbprint)
$($this.Subject.ToShortString())
$($this.SupportedOS.ToShortString())
$($this.SubjectAltName.ToShortString())
$($this.Expiration.ToShortString())
$($this.Purpose.ToShortString())
$($this.KeyUsage.ToShortString())
$($this.PrivateKey.ToShortString())
$($this.SignatureAlgorithm.ToShortString())
$($this.SignatureHash.ToShortString())
$($this.PublicKeyAlgorithm.ToShortString())
$($this.CertChain.ToShortString())
"@
        }
        #>
    }

    [string]
    ToShortString()
    {
        $txt = "Certificate: $($this.Subject.Subject) ($($this.Certificate.Thumbprint)); Validation: $($this.IsValid)"

        if ($this.IsValid -ne "Pass" ) {
            $txt += "; FailedTests: $($this.FailedTests -join ', ')"
        }

        return $txt
    }

    [string]
    ToPassFailString() {
        return ($this.GetSubclassVariables() | ForEach-Object { [string]::Concat($text, "`n$($_.PadRight(19, " ")): $($this."$_".ToPassFailString())") })
    }
    
}


$TypeData = @{
    TypeName   = 'SoQCertValidation'
    MemberType = 'ScriptProperty'
    MemberName = 'CertThumbprint'
    Value      = {$this.Certificate.Thumbprint}
}
Update-TypeData @TypeData -EA SilentlyContinue

$TypeData = @{
    TypeName   = 'SoQCertValidation'
    MemberType = 'ScriptProperty'
    MemberName = 'CertSubject'
    Value      = {$this.Subject.Subject}
}
Update-TypeData @TypeData -EA SilentlyContinue

$TypeData = @{
    TypeName   = 'SoQCertValidation'
    MemberType = 'ScriptProperty'
    MemberName = 'IsCertValid'
    Value      = {$this.IsValidBool()}
}
Update-TypeData @TypeData -EA SilentlyContinue

$TypeData = @{
    TypeName   = 'SoQCertValidation'
    MemberType = 'ScriptProperty'
    MemberName = 'FailedCertTests'
    Value      = {$this.FailedTests}
}
Update-TypeData @TypeData -EA SilentlyContinue

$TypeData = @{
    TypeName   = 'SoQCertValidation'
    DefaultDisplayPropertySet = 'CertThumbprint', 'CertSubject', 'IsCertValid', 'FailedCertTests'
}
Update-TypeData @TypeData -EA SilentlyContinue

#endregion

#### CLASS TYPE ACCELERATOR ####
#region

<# Define the types to export with type accelerators.
$ExportableTypes = @(
    [SoQState]
    [SoQEKUType]
    [SoQResult]
    [SoQSupportedOS]
    [SoQCertExpired]
    [SoQCertPurpose]
    [SoQCertKeyUsage]
    [SoQCertSubject]
    [SoQCertSAN]
    [SoQCertPrivateKey]
    [SoQCertSignatureAlgorithm]
    [SoQCertSignatureHash]
    [SoQCertPublicKeyAlgorithm]
    [SoQCertCertChain]
    [SoQCipherSuite]
    [SoQTls13Support]
    [SoQCertValidation]
)
Write-Debug "ExportableTypes: $($ExportableTypes.FullName -join ', ')"

# Get the internal TypeAccelerators class to use its static methods.
$TypeAcceleratorsClass = [psobject].Assembly.GetType(
    'System.Management.Automation.TypeAccelerators'
)

# Ensure none of the types would clobber an existing type accelerator.
# If a type accelerator with the same name exists, throw an exception.
$ExistingTypeAccelerators = $TypeAcceleratorsClass::Get
foreach ($Type in $ExportableTypes) {
    if ($Type.FullName -in $ExistingTypeAccelerators.Keys) {
        $Message = @(
            "Unable to register type accelerator '$($Type.FullName)'"
            'Accelerator already exists.'
        ) -join ' - '

throw [System.Management.Automation.ErrorRecord]::new(
            [System.InvalidOperationException]::new($Message),
            'TypeAcceleratorAlreadyExists',
            [System.Management.Automation.ErrorCategory]::InvalidOperation,
            $Type.FullName
        )
    }
}
# Add type accelerators for every exportable type.
foreach ($Type in $ExportableTypes) {
    Write-Debug "Adding type: $($Type.FullName)"
    $TypeAcceleratorsClass::Add($Type.FullName, $Type)
}

Write-Debug "Accelerators:`n$($TypeAcceleratorsClass | Format-List | Out-String)"


# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    foreach($Type in $ExportableTypes) {
        Write-Debug "Removing type: $($Type.FullName)"
        $TypeAcceleratorsClass::Remove($Type.FullName)
    }
}.GetNewClosure()
#>

#### END ACCELERATOR
#endregion

