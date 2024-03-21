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

    # Path to save the log files. Default: present working directory.
    [Parameter()]
    [string]
    $LogPath,

    # Returns the SMB over QUIC certificate test object(s) to the console.
    [Parameter()]
    [switch]
    $PassThru
)


begin {
    #### CLASSES ####
    #region

    #region LOGGING
    enum LogType {
        main
        warning
        error
    }

    class Logging {
        ### PROPERTIES/CONSTRUCTOR ###
        #region

        # All logged text goes into the main stream
        [ConcurrentQueue[string]]
        $MainStream

        # Warning text also goes into the warning stream
        [ConcurrentQueue[string]]
        $WarningStream

        # Error text also goes into the error stream
        [ConcurrentQueue[string]]
        $ErrorStream

        # Where do the logs get written to?
        # Provide the path where the three log files will be written to
        [string]
        $LogPath

        # Name of the module. 
        hidden
        [string]
        $Module

        # Name of the MainStream file
        hidden
        [string]
        $MainFile

        # Name of the WarningStream file
        hidden
        [string]
        $WarningFile

        # Name of the MainStream file
        hidden
        [string]
        $ErrorFile

        # since the MainStream does some async writing the number of events in MainStream does not accurately reflect 
        # the total number of events added to MainStream
        # this variable tracks the total number of events
        hidden
        [uint64]
        $MainStreamTotal

        # prevents multiple writers from executing
        hidden
        [bool]
        $Writing

        # blocks adding new entries to logs once Close() has been called
        hidden
        [bool]
        $Closing

        #endregion


        ## CONSTRUCTOR ##
        #region

        Logging() {
            $this.MainStream    = [ConcurrentQueue[string]]::new()
            $this.WarningStream = [ConcurrentQueue[string]]::new()
            $this.ErrorStream   = [ConcurrentQueue[string]]::new()

            $this.MainStreamTotal = 0

            # setup logging files
            # use PWD for the LogPath
            $this.LogPath = $PWD.Path

            # stream log file names
            $stamp = $this.Filestamp()
            $this.MainFile    = "MainStream_$stamp`.log"
            $this.WarningFile = "WarningStream_$stamp`.log"
            $this.ErrorFile   = "ErrorStream_$stamp`.log"
            $this.Module      = "Validate-SoQCertificate"
            $this.Closing     = $false
            $this.Writing     = $false

            # create the files
            try {
                # the PWD should exist...
                $null = New-Item "$($this.LogPath)\$($this.MainFile)" -ItemType File -EA Stop
                $null = New-Item "$($this.LogPath)\$($this.WarningFile)" -ItemType File -EA Stop
                $null = New-Item "$($this.LogPath)\$($this.ErrorFile)" -ItemType File -EA Stop
            } catch {
                Write-Error "Failed to create a logging file: $_" -EA Stop
            }
        }

        Logging([string]$loggingPath) {
            $this.MainStream    = [ConcurrentQueue[string]]::new()
            $this.WarningStream = [ConcurrentQueue[string]]::new()
            $this.ErrorStream   = [ConcurrentQueue[string]]::new()
            
            $this.MainStreamTotal = 0

            # setup logging files
            # test logpath
            if ( (Test-Path "$loggingPath" -IsValid) ) {
                $this.LogPath = $loggingPath
            } else {
                $this.LogPath = $PWD.Path
            }
            

            # stream log file names
            $stamp = $this.Filestamp()
            $this.MainFile    = "MainStream_$stamp`.log"
            $this.WarningFile = "WarningStream_$stamp`.log"
            $this.ErrorFile   = "ErrorStream_$stamp`.log"
            $this.Closing     = $false
            $this.Writing     = $false
            $this.Module      = "Validate-SoQCertificate"

            # create the files
            try {
                # make sure the LogPath is there
                $null = mkdir "$($this.LogPath)" -Force -EA Stop

                $null = New-Item "$($this.LogPath)\$($this.MainFile)" -ItemType File -Force -EA Stop
                $null = New-Item "$($this.LogPath)\$($this.WarningFile)" -ItemType File -Force -EA Stop
                $null = New-Item "$($this.LogPath)\$($this.ErrorFile)" -ItemType File -Force -EA Stop
            } catch {
                Write-Error "Failed to create a logging file: $_" -EA Stop
            }
        }

        #endregion


        ### METHOD ###
        #region

        ## NEW ##
        #region

        # this version always terminates
        NewError(
            [string]$module, 
            [string]$function, 
            [string]$code, 
            [string]$message
        ) {
            if ( -NOT $this.Closing) {
                # get the formatted entry
                $txt = $this.FormatEntry($module, $function, $code, $message, "error")

                # add to the log
                $this.AddError($txt)

                # create a formatted entry without ERROR: at the beginning, because Write-Error adds that
                #$txt2 = $this.FormatEntry($module, $function, $code, $message, "main")

                $this.Close()
                #Write-Error -Message $txt -ErrorAction Stop
                throw $txt
            }
        }

        # this version optionally terminates
        NewError(
            [string]$module, 
            [string]$function, 
            [string]$code, 
            [string]$message,
            [bool]$terminate
        ) {
            if ( -NOT $this.Closing) {
                # get the formatted entry
                $txt = $this.FormatEntry($module, $function, $code, $message, "error")

                # add to the log
                $this.AddError($txt)

                # create a formatted entry without ERROR: at the beginning, because Write-Error adds that
                #$txt2 = $this.FormatEntry($module, $function, $code, $message, "main")

                if ($terminate) {
                    $this.Close()
                    #Write-Error -Message $txt -ErrorAction Stop
                    throw $txt
                } else {
                    Write-Error -Message $txt
                }
            }
        }

        # this version optionally terminates, uses the default module, and does not need a function
        NewError(
            [string]$code, 
            [string]$message,
            [bool]$terminate
        ) {
            if ( -NOT $this.Closing) {
                # get the formatted entry
                $txt = $this.FormatEntry($this.Module, $null, $code, $message, "error")

                # add to the log
                $this.AddError($txt)

                # create a formatted entry without ERROR: at the beginning, because Write-Error adds that
                #$txt2 = $this.FormatEntry($module, $function, $code, $message, "main")

                if ($terminate) {
                    $this.Close()
                    #Write-Error -Message $txt -ErrorAction Stop
                    throw $txt
                } else {
                    Write-Error -Message $txt
                }
            }
        }

        # warnings never terminate
        NewWarning(
            [string]$module, 
            [string]$function, 
            [string]$code, 
            [string]$message
        ) {
            if ( -NOT $this.Closing) {
                # get the formatted entry
                $txt = $this.FormatEntry($module, $function, $code, $message, "warning")

                # add to the log
                $this.AddWarning($txt)

                # create a formatted entry without WARNING: at the beginning, because Write-Warning adds that
                $txt2 = $this.FormatEntry($module, $function, $code, $message, "main")

                Write-Warning $txt2
            }
        }

        # warnings never terminate, use default module, no function
        NewWarning(
            [string]$code, 
            [string]$message
        ) {
            if ( -NOT $this.Closing) {
                # get the formatted entry
                $txt = $this.FormatEntry($this.Module, $null, $code, $message, "warning")

                # add to the log
                $this.AddWarning($txt)

                # create a formatted entry without WARNING: at the beginning, because Write-Warning adds that
                $txt2 = $this.FormatEntry($this.Module, $null, $code, $message, "main")

                Write-Warning $txt2
            }
        }

        # logging never terminates
        NewLog(
            [string]$module, 
            [string]$function, 
            [string]$message
        ) {
            if ( -NOT $this.Closing) {
                # get the formatted entry
                $txt = $this.FormatEntry($module, $function, "", $message, "main")
                
                # add to the log
                $this.AddLog($txt)

                # dump events to disk if there are more than 10000 lines in MainStream
                if ( $this.MainStream.Count -ge 10 ) {
                    $this.UpdateLogFile()
                }
            }
        }

        NewLog(
            [string]$function, 
            [string]$message
        ) {
            if ( -NOT $this.Closing) {
                # get the formatted entry
                $txt = $this.FormatEntry($this.Module, $function, "", $message, "main")
                
                # add to the log
                $this.AddLog($txt)

                # dump events to disk if there are more than 10000 lines in MainStream
                if ( $this.MainStream.Count -ge 10 ) {
                    $this.UpdateLogFile()
                }
            }
        }

        NewLog(
            [string]$message
        ) {
            if ( -NOT $this.Closing) {
                # get the formatted entry
                $txt = $this.FormatEntry($this.Module, $null, "", $message, "main")
                
                # add to the log
                $this.AddLog($txt)

                # dump events to disk if there are more than 10000 lines in MainStream
                if ( $this.MainStream.Count -ge 10 ) {
                    $this.UpdateLogFile()
                }
            }
        }

        #endregion NEW

        ## ADD ##
        #region
        
        # adds an event to a logging stream
        # no terminating errors come from here
        # don't use AddLog inside of AddLog
        AddLog([string]$txt) {
            if ( -NOT [string]::IsNullOrEmpty($txt) ) { 
                Write-Verbose "$txt"
                $txt = "$($this.Timestamp())`: $txt"
                $this.IncrementMainStream()
                $this.MainStream.Enqueue($txt)
            }
        }

        # non-terminating
        hidden
        AddWarning([string]$txt) {
            if ( -NOT [string]::IsNullOrEmpty($txt) ) { 
                $txt = "$($this.Timestamp())`: $txt" 
                #$this.MainStream.Enqueue($txt)
                #$this.IncrementMainStream()
                $this.AddLog($txt)

                $this.WarningStream.Enqueue($txt)
            }
        }

        # always terminates when calling this method
        hidden
        AddError([string]$txt) {
            if ( -NOT [string]::IsNullOrEmpty($txt) ) { 
                $txt = "$($this.Timestamp())`: $txt" 
                #$this.MainStream.Enqueue($txt)
                #$this.IncrementMainStream()
                $this.AddLog($txt)
                
                $this.ErrorStream.Enqueue($txt)
            }
        }

        #endregion

        ## WRITE ##
        #region

        # !!! DO NOT call NewError, NewWarning, or NewLog in these methods !!!
        # Use Write-Verbose cmdlets if troubleshooting logging is needed.

        # dumps events from the mainstream to file for up to ~250ms or no more entries
        hidden
        UpdateLogFile() {
            if ( $this.Writing -eq $false -and $this.MainStream.Count -gt 0 ) {
                # prevent overlapping writes by setting Writing to true - simple "lock" mechanism
                $this.Writing = $true

                # create the parsed file and stream writer
                $stream = [System.IO.StreamWriter]::new("$($this.LogPath)\$($this.MainFile)", $true)

                # dequeues an object to write it to file
                # only spend ~250ms writing, max, to prevent noticeable hangs
                $sw = [System.Diagnostics.Stopwatch]::new()
                $sw.Start()
                while ( $this.MainStream.Count -gt 0 -and $sw.ElapsedMilliseconds -lt 275 ) {
                    $line = ""
                    
                    # TryDequeue returns $true when the first element in the ConcurrentQueue was successfully dequeued to $line
                    if ( $this.MainStream.TryDequeue([ref]$line) ) {
                        # write the line to file
                        $stream.WriteLine( $line )
                    }
                }

                # stop the stopwatch
                $sw.Stop()

                # close the StreamWriter
                $stream.Close()

                # allow writing
                $this.Writing = $false
            }
        }

        # writes all MainStream events to file - used by Close()
        hidden
        WriteLog2File() {
            $logFile = "$($this.LogPath)\$($this.MainFile)"

            if ($this.MainStream.Count -gt 0) {
                # instance is closing so lock all other writing while the MainStream is written to file
                $this.Writing = $true
                $stream = [System.IO.StreamWriter]::new($logFile, $true)

                while ( $this.MainStream.Count -gt 0 ) {
                    $line = ""
                    
                    # TryDequeue returns $true when the first element in the ConcurrentQueue was successfully dequeued to $line
                    if ( $this.MainStream.TryDequeue([ref]$line) ) {
                        # write the line to file
                        $stream.WriteLine( $line )
                    }
                }

                # close the StreamWriter
                $stream.Close()
            }
        }

        # writes all WarningStream events to file - used by Close()
        hidden
        WriteWarningLog2File() {
            $warnFile = "$($this.LogPath)\$($this.WarningFile)"

            if ($this.WarningStream.Count -gt 0) {
                $stream = [System.IO.StreamWriter]::new("$warnFile")

                while ( $this.WarningStream.Count -gt 0 ) {
                    $line = ""
                    
                    # TryDequeue returns $true when the first element in the ConcurrentQueue was successfully dequeued to $line
                    if ( $this.WarningStream.TryDequeue([ref]$line) ) {
                        # write the line to file
                        $stream.WriteLine( $line )
                    }
                }

                # close the StreamWriter
                $stream.Close()
            }
        }

        # writes all ErrorStream events to file - used by Close()
        hidden
        WriteErrorLog2File() {
            $errFile = "$($this.LogPath)\$($this.ErrorFile)"

            if ($this.ErrorStream.Count -gt 0) {
                $stream = [System.IO.StreamWriter]::new("$errFile")

                while ( $this.ErrorStream.Count -gt 0 ) {
                    $line = ""
                    
                    # TryDequeue returns $true when the first element in the ConcurrentQueue was successfully dequeued to $line
                    if ( $this.ErrorStream.TryDequeue([ref]$line) ) {
                        # write the line to file
                        $stream.WriteLine( $line )
                    }
                }

                # close the StreamWriter
                $stream.Close()
            }
        }

        #endregion WRITE

        ## UTILITY ##
        #region

        # get a timestamp
        [string]
        hidden
        Timestamp() {
            return (Get-Date -Format "yyyyMMdd-HH:mm:ss.ffffff")
        }

        # get a timestamp for a file name
        [string]
        hidden
        Filestamp() {
            return (Get-Date -Format "yyyyMMdd_HHmmss")
        }

        IncrementMainStream() {
            $this.MainStreamTotal = $this.MainStreamTotal + 1
        }

        [string]
        hidden
        FormatEntry(
            [string]$module, 
            [string]$function, 
            [string]$code, 
            [string]$message,
            [LogType]$logType
        ) {
            $str = ""
            if ($module -match '-') {
                $modIsFunc = $true
            } else {
                $modIsFunc = $false
            }
            #Write-Host "1 - mod: $module, func: $function, code: $code, mess: $message, type: $logtype, str: $str"

            # there must always be a module
            switch ($logType) {
                "error"   { 
                    # do not wrap in [] if the module name contains a dash (-)... assume this is a function
                    if ($modIsFunc) {
                        $str = "ERROR: $module" 
                    } else {
                        $str = "ERROR: [$module]" 
                    }
                }
                
                "warning" { 
                    if ($modIsFunc) {
                        $str = "WARNING: $module" 
                    } else {
                        $str = "WARNING: [$module]" 
                    }
                }

                default   { 
                    if ($modIsFunc) {
                        $str = "$module"
                    } else {
                        $str = "[$module]"
                    }
                    
                }
            }
            #Write-Host "2 - mod: $module, func: $function, code: $code, mess: $message, type: $logtype, str: $str"
            
            # function is options
            if ( -NOT [string]::IsNullOrEmpty($function) -and -NOT $modIsFunc) {
                $str = [string]::Concat($str, ".$function - ")
            } elseif ( -NOT [string]::IsNullOrEmpty($function) -and $modIsFunc ) {
                $str = [string]::Concat($str, " - [$function] - ")
            } else {
                $str = [string]::Concat($str, " - ")
            }
            #Write-Host "3 - mod: $module, func: $function, code: $code, mess: $message, type: $logtype, str: $str"

            # add the message (not optional)
            $str = [string]::Concat($str, $message)
            #Write-Host "4 -mod: $module, func: $function, code: $code, mess: $message, type: $logtype, str: $str"

            # code is optional
            if ( -NOT [string]::IsNullOrEmpty($code) ) {
                $str = [string]::Concat($str, " code: $code")
            }

            #Write-Host "5 - mod: $module, func: $function, code: $code, mess: $message, type: $logtype, str: $str"

            return $str
        }

        Close() {
            # set Closing to $true
            $this.Closing = $true

            # wait for 100ms to make sure any outstanding work is completed
            Start-Sleep -Milliseconds 100

            # are there outstanding writes?
            if ( $this.Writing ) {
                $sw = [System.Diagnostics.Stopwatch]::new()
                $sw.Start()

                do {
                    Start-Sleep -Milliseconds 50
                } until ($this.Writing -eq $false -or $sw.ElapsedMilliseconds -gt 500)

                # if still Writing then the StreamWriter may have experiences a failure
                # rename the MainFile and continue writing the events to the alternate file
                if ( $this.Writing ) { 
                    $this.MainFile = "$($this.MainFile.Split('.')[0])_StreamFailure.log" 
                    $null = New-Item "$($this.LogPath)\$($this.MainFile)" -ItemType File -Force
                }
            }

            # Write all the logs to file
            # now handled by the Clear() method
            
            # clear the log data
            $this.Clear()

            # clean up 0B files
            $logFileobj = Get-Item "$($this.LogPath)\$($this.MainFile)" -EA SilentlyContinue
            $errFileObj = Get-Item "$($this.LogPath)\$($this.ErrorFile)" -EA SilentlyContinue
            $warnFileObj = Get-Item "$($this.LogPath)\$($this.WarningFile)" -EA SilentlyContinue

            if ( $logFileobj.Length -eq 0 ) { Remove-Item $logFileobj -Force -EA SilentlyContinue }
            if ( $errFileObj.Length -eq 0 ) { Remove-Item $errFileObj -Force -EA SilentlyContinue }
            if ( $warnFileObj.Length -eq 0 ) { Remove-Item $warnFileObj -Force -EA SilentlyContinue }

            # set all variables to $null
            $this.MainFile = $null
            $this.MainStream = $null

            $this.WarningFile = $null
            $this.WarningStream = $null

            $this.ErrorFile = $null
            $this.ErrorStream = $null

            $this.Closing = $null
            $this.Writing = $null

            $this.LogPath = $null
        }

        Clear() {
            # clear all the streams by dequeing everything with the write log methods
            # the Clear() method for ConcurrentQueue does not work on PowerShell 5.1/.NET 4.8.1, so this acts as a workaround and a way to prevent log loss rolled into one
            $this.WriteErrorLog2File()
            $this.WriteWarningLog2File()
            $this.WriteLog2File()

            $this.MainStreamTotal = 0
        }
        #endregion UTILITY

        #endregion METHODS
    }


    $TypeData = @{
        TypeName   = 'Logging'
        MemberType = 'ScriptProperty'
        MemberName = 'MainCount'
        Value      = {$this.MainStreamTotal}
    }

    Update-TypeData @TypeData -EA SilentlyContinue

    $TypeData = @{
        TypeName   = 'Logging'
        MemberType = 'ScriptProperty'
        MemberName = 'WarningCount'
        Value      = {$this.WarningStream.Count}
    }

    Update-TypeData @TypeData -EA SilentlyContinue

    $TypeData = @{
        TypeName   = 'Logging'
        MemberType = 'ScriptProperty'
        MemberName = 'ErrorCount'
        Value      = {$this.ErrorStream.Count}
    }

    Update-TypeData @TypeData -EA SilentlyContinue


    $TypeData = @{
        TypeName   = 'Logging'
        DefaultDisplayPropertySet = 'MainCount', 'WarningCount', 'ErrorCount', 'LogPath'
    }

    Update-TypeData @TypeData -EA SilentlyContinue

    #endregion LOGGING

    <#
        $script:log.NewLog("")
        $script:log.NewLog("module", function", "message")
        $script:log.NewLog("function", "message")
        $script:log.NewError("code", "", $false)
        $script:log.NewWarning("code", "")
    #>

    enum SoQState {
        Pass
        Fail
        Warning
    }

    class SoQResult {
        [SoQState]
        $IsValid

        [List[string]]
        $FailureReason

        SoQResult() {
            $script:log.NewLog("SoQResult", "New SoQResult.")
            $this.IsValid       = "Warning"
            $this.FailureReason = [List[string]]::new()
            $script:log.NewLog("SoQResult", "Created SoQResult.")
        }

        SetValidity([SoQState]$Result) {
            $script:log.NewLog("SoQResult", "SetValidity", "$Result")
            $this.IsValid = $Result
        }

        SetFailureReason([string]$FailureReason) {
            $this.AddToFailureReason($FailureReason)
        }

        AddToFailureReason([string]$FR) {
            $script:log.NewLog("SoQResult", "AddToFailureReason", "$FR")
            $this.FailureReason.Add($FR)
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

        hidden
        static
        [int]
        $MinOsVersion = 26080

        SoQSupportedOS() {
            $script:log.NewLog("SoQSupportedOS", "Begin")

            $this.Result.SetValidity( "Pass" )
            $this.ValidateServerOS()
            $script:log.NewLog("SoQSupportedOS", "End")
        }

        ValidateServerOS() {
            $script:log.NewLog("SoQSupportedOS", "ValidateServerOS", "Begin")

            # get OS version
            $osVer = [System.Environment]::OSVersion | ForEach-Object { $_.Version }
            $script:log.NewLog("SoQSupportedOS", "ValidateServerOS", "osVer: $($osVer.ToString())")

            # use WMI to get OS details, since this is designed to run on Windows
            $wmiOS = Get-WmiObject Win32_OperatingSystem -Property Caption,ProductType
            $osName =  $wmiOS.Caption
            $script:log.NewLog("SoQSupportedOS", "ValidateServerOS", "Caption: $osName")

            # ProductType: 1 = workstation, 2 = DC, 3 = Server
            $osType = $wmiOS.ProductType
            $script:log.NewLog("SoQSupportedOS", "ValidateServerOS", "osType: $osType")

            $this.Result.SetFailureReason("")
            $script:log.NewLog("SoQSupportedOS", "ValidateServerOS", "Start - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)")

            # must be server or DC product type
            if ( $osType -ne 2 -and $osType -ne 3 ) {
                $this.Result.SetValidity( "Fail" )
                $this.Result.AddToFailureReason( "Not Windows Server." )
            }
            $script:log.NewLog("SoQSupportedOS", "ValidateServerOS", "ProductType - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)")

            # must be Server 2022 or higher
            if ($osVer.Major -lt 10 -and $osVer.Build -lt 20348) {
                $this.Result.SetValidity( "Fail" )
                $this.Result.AddToFailureReason( " Not Windows Server 2022 or greater." )
            } 
            $script:log.NewLog("SoQSupportedOS", "ValidateServerOS", "Version - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)")
            
            # the edition must be Azure Edition or above MinOsVersion (Windows Server 2025)
            if ($osName -notmatch "Azure Edition" -and $osVer.Build -lt $this.MinOsVersion) {
                $this.Result.SetValidity( "Fail" )
                $this.Result.AddToFailureReason( " Not Azure Edition and not Windows Server 2025 or newer." )
            }
            $script:log.NewLog("SoQSupportedOS", "ValidateServerOS", "Azure Edition - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)")

            # clear failure reason if IsValid passed
            if ( $this.Result.IsValid -eq "Pass" ) {
                $this.Result.SetFailureReason( "" )
            }
            $script:log.NewLog("SoQSupportedOS", "ValidateServerOS", "End - IsValid: $($this.Result.IsValid); FailureReason: $($this.Result.FailureReason)")
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
            $script:log.NewLog("SoQCertExpired", "Begin")
            $this.NotBefore      = $Certificate.NotBefore
            $this.NotAfter       = $Certificate.NotAfter
            $script:log.NewLog("SoQCertExpired", "Validate")
            $this.Result.SetValidity( $this.ValidateDate() )
            $script:log.NewLog("SoQCertExpired", "End")
        }

        [SoQState]
        ValidateDate() {
            $script:log.NewLog("SoQCertExpired", "ValidateDate", "Start")
            [SoQState]$isValidtmp = "Fail"
            
            $date = Get-Date
            if ( $this.NotBefore -lt $date -and $this.NotAfter -gt $date )
            {
                $script:log.NewLog("SoQCertExpired", "ValidateDate", "IsValid: True")
                $isValidtmp = "Pass"
            }
            else
            {
                $script:log.NewLog("SoQCertExpired", "ValidateDate", "IsValid: False")
                $FR = "Certificate is expired. Expires: $($this.NotAfter.ToShortDateString()) $($this.NotAfter.ToShortTimeString()), Date: $($date.ToShortDateString()) $($date.ToShortTimeString())"
                $this.Result.SetFailureReason( $FR )
                $script:log.NewLog("SoQCertExpired", "ValidateDate", "Failure Reason: $($this.Result.FailureReason)")
                $script:log.NewLog("SoQCertExpired", "ValidateDate", "NotBefore: $($this.NotBefore.ToString()), NotAfter: $($this.NotAfter.ToString()), Test Date: $($date.ToString())")
            }

            $script:log.NewLog("SoQCertExpired", "ValidateDate", "End")
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
            $script:log.NewLog("SoQCertPurpose", "Begin")
            $this.Purpose = $Certificate.EnhancedKeyUsageList.FriendlyName
            $script:log.NewLog("SoQCertPurpose", "Validate")
            $this.Result.SetValidity( $this.ValidatePurpose() )
            $script:log.NewLog("SoQCertPurpose", "End")
        }

        [SoQState]
        ValidatePurpose()
        {
            $script:log.NewLog("SoQCertPurpose", "ValidatePurpose", "Start")
            [SoQState]$isValidtmp = "Fail"

            if ( $this.Purpose -contains "Server Authentication")
            {
                $script:log.NewLog("SoQCertPurpose", "ValidatePurpose", "IsValid: True")
                $isValidtmp = "Pass"
            }
            else 
            {
                $script:log.NewLog("SoQCertPurpose", "ValidatePurpose", "IsValid: False")
                $this.Result.SetFailureReason( "Purpose does not contain Server Authentication. Purpose: $($this.Purpose -join ', ')" )
                $script:log.NewLog("SoQCertPurpose", "ValidatePurpose", "Failure Reason: $($this.FailureReason)")
                $script:log.NewLog("SoQCertPurpose", "ValidatePurpose", "Purpose: $($this.Purpose), Must contain: Server Authentication")
            }

            $script:log.NewLog("SoQCertPurpose", "ValidatePurpose", "End")
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
            $script:log.NewLog("SoQCertKeyUsage","Start")
            $tmpKey = $Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Key Usage" }
            if ( $tmpKey )
            {
                $this.KeyUsage = $tmpKey.Format(1)
            }
            else 
            {
                $script:log.NewLog("SoQCertKeyUsage","KeyUsage was not found.")
                $this.KeyUsage = $null
            }
            
            $script:log.NewLog("SoQCertKeyUsage","Validate")
            $this.Result.SetValidity( $this.ValidateKeyUsage() )
            $script:log.NewLog("SoQCertKeyUsage","End")
        }

        [SoqState]
        ValidateKeyUsage() {
            $script:log.NewLog("SoQCertKeyUsage", "ValidateKeyUsage", "Start")
            [SoqState]$isValidtmp = "Fail"

            if ( $this.KeyUsage -match "Digital Signature" )
            {
                $script:log.NewLog("SoQCertKeyUsage", "ValidateKeyUsage", "IsValid: True")
                $isValidtmp = "Pass"
            }
            else 
            {
                $script:log.NewLog("SoQCertKeyUsage", "ValidateKeyUsage", "IsValid: False")
                $this.Result.SetFailureReason( "Key Usage does not contain Digital Signature. ($($this.KeyUsage))" )
                $script:log.NewLog("SoQCertKeyUsage", "ValidateKeyUsage", "Failure Reason: $($this.Result.FailureReason)")
                $script:log.NewLog("SoQCertKeyUsage", "ValidateKeyUsage", "KeyUsage: $($this.KeyUsage), Requires: Digital Signature")
            }

            $script:log.NewLog("SoQCertKeyUsage", "ValidateKeyUsage", "End")
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
            $script:log.NewLog("SoQCertSubject","Start")
            $this.Subject = $Certificate.Subject
            $script:log.NewLog("SoQCertSubject","Validate")
            $this.Result.SetValidity( $this.ValidateSubject() )
            $script:log.NewLog("SoQCertSubject","End")
        }

        [SoQState]
        ValidateSubject()
        {
            $script:log.NewLog("SoQCertSubject", "ValidateSubject", "Start")
            [SoQState]$isValidtmp = "Fail"

            if ( $this.Subject -match $this.rgxSubject )
            {
                $script:log.NewLog("SoQCertSubject", "ValidateSubject", "IsValid: True")
                $isValidtmp = "Pass"
            }
            else 
            {
                $script:log.NewLog("SoQCertSubject", "ValidateSubject", "IsValid: False")
                $this.Result.SetFailureReason( "Does not contain a Subject. ($($this.Subject))" )
                $script:log.NewLog("SoQCertSubject", "ValidateSubject", "Failure Reason: $($this.Result.FailureReason)")
                $script:log.NewLog("SoQCertSubject", "ValidateSubject", "Subject: $($this.Subject), Requires: CN=<some text>")
            }

            $script:log.NewLog("SoQCertSubject", "ValidateSubject", "End")
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
            $script:log.NewLog("SoQCertSAN","Start")
            $this.SubjectAltName = $Certificate.DnsNameList.Unicode
            $script:log.NewLog("SoQCertSAN","Validate")
            $this.Result.SetValidity( $this.ValidateSAN() )
            $script:log.NewLog("SoQCertSAN","End")
        }

        [SoQState]
        ValidateSAN() {
            $script:log.NewLog("SoQCertSAN","ValidateSAN", "Start")
            [SoQState]$isValidtmp = "Fail"

            # there must be a SAN
            if ( ($this.SubjectAltName).Count -ge 1 ) {
                $script:log.NewLog("SoQCertSAN","ValidateSAN", "IsValidNum: True")
                $isValidtmp = "Pass"

                # SAN's must be valid DNS names
                foreach ($e in $this.SubjectAltName) {
                    $isDNS = [System.Uri]::CheckHostName($e)
                    if ( $isDNS -eq "Unknown" ) {
                        $script:log.NewLog("SoQCertSAN","ValidateSAN", "IsValid: False")
                        $script:log.NewLog("SoQCertSAN","ValidateSAN", "dnsName: $e; isDNS: $isDNS")
                        $this.Result.AddToFailureReason("Invalid Subject Alternative Name: $e" )
                        [SoQState]$isValidtmp = "Fail"
                    }
                }
            } else {
                $script:log.NewLog("SoQCertSAN","ValidateSAN", "IsValid: False")
                $this.Result.SetFailureReason( "No Subject Alternative Names. ($($this.SubjectAltName -join ', '))" )
                $script:log.NewLog("SoQCertSAN","ValidateSAN", "Failure Reason: $($this.Result.FailureReason)")
                $script:log.NewLog("SoQCertSAN","ValidateSAN", "SubjectAltName: $($this.SubjectAltName -join ', '); Count: $(($this.SubjectAltName).Count); Count >= 1.")
            }

            $script:log.NewLog("SoQCertSAN","ValidateSAN", "End")
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
            $script:log.NewLog("SoQCertPrivateKey","Start")
            if ($Certificate.HasPrivateKey) {
                $this.Result.SetValidity( "Pass" )
                $script:log.NewLog("SoQCertPrivateKey","IsValid: True")
            } else {
                $script:log.NewLog("SoQCertPrivateKey","IsValid: False")
                $this.Result.SetFailureReason( "No Private Key." )
                $script:log.NewLog("SoQCertPrivateKey","Failure Reason: $($this.Result.FailureReason)")
                $script:log.NewLog("SoQCertPrivateKey","HasPrivateKey: False")
            }

            $script:log.NewLog("SoQCertPrivateKey","End")
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
            $script:log.NewLog("SoQCertSignatureAlgorithm","Start")
            $this.SignatureAlgorithm = $Certificate.SignatureAlgorithm.FriendlyName
            $script:log.NewLog("SoQCertSignatureAlgorithm","Validate")
            $this.Result.SetValidity( $this.ValidateSignatureAlgorithm() )
            $script:log.NewLog("SoQCertSignatureAlgorithm","End")
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
            $script:log.NewLog("SoQCertSignatureAlgorithm","ValidateSignatureAlgorithm", "Start")
            [SoQState]$isValidtmp = "Fail"

            if ( $this.SignatureAlgorithm -in $this.GetValidSigAlgo() ) {

                $script:log.NewLog("SoQCertSignatureAlgorithm","ValidateSignatureAlgorithm", "IsValid: True")
                $isValidtmp = "Pass"
            }
            else 
            {
                $script:log.NewLog("SoQCertSignatureAlgorithm","ValidateSignatureAlgorithm", "IsValid: False")
                $this.Result.SetFailureReason( "Uses a Signature Algorithm not known to work. ($($this.SignatureAlgorithm))" )
                $script:log.NewLog("SoQCertSignatureAlgorithm","ValidateSignatureAlgorithm", "Failure Reason: $($this.Result.FailureReason)")
                $script:log.NewLog("SoQCertSignatureAlgorithm","ValidateSignatureAlgorithm", "SignatureAlgorithm: $($this.SignatureAlgorithm), Valid Range: $($this.GetValidSigAlgo() -join ', ')")
            }

            $script:log.NewLog("SoQCertSignatureAlgorithm","ValidateSignatureAlgorithm", "End")
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
            $script:log.NewLog("SoQCertSignatureHash","Start")
            $this.SignatureHash  = $this.GetHashString($Certificate)
            $script:log.NewLog("SoQCertSignatureHash","Validate")
            $this.Result.SetValidity( $this.ValidateSigHash() )
            $script:log.NewLog("SoQCertSignatureHash","End")
        }

        [string[]]
        GetValidHash() {
            return @("sha256", "sha384", "sha512")
        }

        [string]
        GetHashString([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate) {
            $script:log.NewLog("SoQCertSignatureHash","GetHashString", "Start")
            $strHash = ""

            [regex]$rgxHash = "(?<hash>md\d{1})|(?<hash>sha\d{1,3})"

            if ( $Certificate.SignatureAlgorithm.FriendlyName -match $rgxHash )
            {
                $strHash = $Matches.hash.ToString().ToLower()
                $script:log.NewLog("SoQCertSignatureHash","GetHashString", "Hash found. strHash: $strHash")
            } else {
                $script:log.NewLog("SoQCertSignatureHash","GetHashString", "Hash not found.")
                $strHash = "Unknown"
            }

            $script:log.NewLog("SoQCertSignatureHash","GetHashString", "End")
            return $strHash
        }

        [SoQState]
        ValidateSigHash() {
            $script:log.NewLog("SoQCertSignatureHash","ValidateSigHash", "Start")
            [SoQState]$isValidtmp = "Fail"

            if ( $this.SignatureHash -in $this.GetValidHash() )
            {
                $script:log.NewLog("SoQCertSignatureHash","ValidateSigHash", "IsValid: True")
                $isValidtmp = "Pass"
            }
            else 
            {
                $script:log.NewLog("SoQCertSignatureHash","ValidateSigHash", "IsValid: False")
                $this.Result.SetFailureReason( "Not a valid signature hash. ($($this.SignatureHash))" )
                $script:log.NewLog("SoQCertSignatureHash","ValidateSigHash", "Failure Reason: $($this.Result.FailureReason)")
                $script:log.NewLog("SoQCertSignatureHash","ValidateSigHash", "SignatureHash: $($this.SignatureHash), Valid Range: $($this.GetValidHash() -join ', ')")
            }

            $script:log.NewLog("SoQCertSignatureHash","ValidateSigHash", "End")
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
            $script:log.NewLog("SoQCertPublicKeyAlgorithm","Start")
            $this.PublicKeyAlgorithm = $this.GetPKAString($Certificate)
            $script:log.NewLog("SoQCertPublicKeyAlgorithm","Validate")
            $this.Result.SetValidity( $this.ValidatePKA() )
            $script:log.NewLog("SoQCertPublicKeyAlgorithm","End")
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
            return @("ECDSA_P256", "ECDSA_P384", "ECDSA_P512", "RSA2048", "RSA4096")
        }

        [SoQState]
        ValidatePKA() {
            $script:log.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "Start")
            
            [SoQState]$isValidtmp = "Fail"

            if ( $this.Result.FailureReason ) {
                # Detection will fail when PowerShell 5.1 is used and the PKA is EC-based. 
                # Use that FailureReason and return $false
                $script:log.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "IsValid: Warning")
                $isValidtmp = "Warning"
                $script:log.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "Warning Reason: $($this.Result.FailureReason)")
            } elseif ( $this.PublicKeyAlgorithm -in $this.GetValidPKA() )
            {
                $script:log.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "IsValid: True")
                $isValidtmp = "Pass"
            }
            else 
            {
                $script:log.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "IsValid: False")
                $this.Result.SetFailureReason( "Not a known supported Public Key Algorithm. ($($this.PublicKeyAlgorithm))" )
                $script:log.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "Failure Reason: $($this.Result.FailureReason)")
                $script:log.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "PublicKeyAlgorithm: $($this.PublicKeyAlgorithm), Valid Range: $($this.GetValidPKA() -join ', ')")
            }

            $script:log.NewLog("SoQCertPublicKeyAlgorithm", "ValidatePKA", "End")
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
            $script:log.NewLog("SoQCertCertChain", "Start")
            $script:log.NewLog("SoQCertCertChain", "Validate")
            $this.Result.SetValidity( $this.ValidateCertChain($Certificate) )
            $script:log.NewLog("SoQCertCertChain", "End")
        }

        [SoQState]
        ValidateCertChain([System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate) {
            $script:log.NewLog("SoQCertCertChain", "ValidateCertChain", "Start")
            [SoQState]$isValidtmp = "Fail"

            ## let certutil handle cert chain validation ##
            # export the cer file
            $fn = "cert_$(Get-Date -Format "ddMMyyyyHHmmssffff").cer"
            $script:log.NewLog("SoQCertCertChain", "ValidateCertChain", "Create file: $pwd\$fn")
            $null = Export-Certificate -Cert $Certificate -FilePath "$pwd\$fn" -Force

            # verify the cert chain
            $script:log.NewLog("SoQCertCertChain", "ValidateCertChain", "Execute: certutil -verify `"$pwd\$fn`"")
            $results = certutil -verify "$pwd\$fn"
            $script:log.NewLog("SoQCertCertChain", "ValidateCertChain", "Results:`n$results`n")


            # remove the cer file
            $script:log.NewLog("SoQCertCertChain", "ValidateCertChain", "Remove File")
            $null = Remove-Item "$pwd\$fn" -Force

            # validation is true if CERT_E_UNTRUSTEDROOT is not in the output
            if ( -NOT ($results | Where-Object { $_ -match 'CERT_E_UNTRUSTEDROOT' }) ) {
                $script:log.NewLog("SoQCertCertChain", "ValidateCertChain", "IsValid: Pass")
                $isValidtmp = "Pass"
            }
            else 
            {
                $script:log.NewLog("SoQCertCertChain", "ValidateCertChain", "IsValid: Fail")
                $this.Result.SetFailureReason( "Certificate chain validation failed. 'certutil -verify' returned error CERT_E_UNTRUSTEDROOT." )
                $script:log.NewLog("SoQCertCertChain", "ValidateCertChain", "Failure Reason: $($this.Result.FailureReason)")
                $script:log.NewLog("SoQCertCertChain", "ValidateCertChain", "CERT_E_UNTRUSTEDROOT:`n$(($results | Where-Object { $_ -match 'CERT_E_UNTRUSTEDROOT' }) -join "`n")`n`n ")
            }

            $script:log.NewLog("SoQCertCertChain", "ValidateCertChain", "End")
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
            $script:log.NewLog("SoQCipherSuite", "SetTlsString", "Cipher string: $TlsString")
            $this.TlsString = $TlsString
        }

        SetStrongCrypto([string]$str) {
            if ($str -match 'Yes') {
                $this.StrongCrypto = $true
            } else {
                $this.StrongCrypto = $false
            }

            $script:log.NewLog("SoQCipherSuite", "SetStrongCrypto", "Strong crypto: $($this.StrongCrypto)")
        }

        SetIsVerTls13([string]$str) {
            if ($str -match 'TLS 1.3') {
                $script:log.NewLog("SoQCipherSuite", "SetIsVerTls13", "Is TLS 1.3")
                $this.isVerTls13 = $true
            } else {
                $this.isVerTls13 = $false
                $script:log.NewLog("SoQCipherSuite", "SetIsVerTls13", "Is NOT TLS 1.3")
            }
            $script:log.NewLog("SoQCipherSuite", "SetIsVerTls13", "TLS 1.3: $($this.isVerTls13)")
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
            $script:log.NewLog("SoQTls13Support", "Begin")
            # if there is an internet connection we get the list of supported TLS 1.3 cipher suites
            if ((Get-NetConnectionProfile).IPv4Connectivity -contains "Internet" -or (Get-NetConnectionProfile).IPv6Connectivity -contains "Internet") {
                $script:log.NewLog("SoQTls13Support", "Trying to get the live TLS 1.3 list.")
                $this.GetTls13CipherSuitesFromInternet()
            } else {
                $script:log.NewLog("SoQTls13Support", "Using last known good TLS 1.3 list.")
                $this.UseLastKnownGoodTls13CipherSuites()
            }

            # test whether there is at least one valid TLS 1.3 cipher suite enabled on the system
            $script:log.NewLog("SoQTls13Support", "Validating TLS 1.3 support.")
            $this.ValidateLocalCipherSuite()

            $script:log.NewLog("SoQTls13Support", "Result:`n$($this.ToString())")
            $script:log.NewLog("SoQTls13Support", "End")
        }

        # populates Tls13CipherSuites with a list of known supported TLS 1.3 ciphers in Windows
        # https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022
        # Retrieved: 15 Feb 2023
        UseLastKnownGoodTls13CipherSuites() {
            $script:log.NewLog("SoQTls13Support", "UseLastKnownGoodTls13CipherSuites", "Begin")
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
            
            $script:log.NewLog("SoQTls13Support", "UseLastKnownGoodTls13CipherSuites", "End")
        }

        # Retrieves the current list of supported TLS 1.3 cipher suites.
        # https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022
        GetTls13CipherSuitesFromInternet() {
            $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Start")
            # The TLS 1.3 cipher suites must be enabled in Windows.
            # right now SoQ only supports Windows Server 2022 so keep this simple for now
            $url = 'https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022'

            # download the page
            $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Set TLS for Invoke-WebRequest.")
            [System.Net.ServicePointManager]::SecurityProtocol = "Tls12", "Tls13"

            $rawSite = $null
            try {
                $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Downloading the cipher suite site.")
                $rawSite = Invoke-WebRequest $url -UseBasicParsing -EA Stop
            }
            catch {
                $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Failed to download the current TLS 1.3 list: $_")
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
                        $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Start table")
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
                        $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "End table")
                        $tableStarted = $false
                    } elseif ( $tableStarted ) {
                        # look for a table header we want.
                        if ($_ -match '<tr>') {
                            $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Start row")
                            $rowStarted = $true
                        } elseif ($_ -match '</tr>') {
                            $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "End row")
                            $rowStarted = $false

                            $tmpRow = [SoQCipherSuite]::new()
                        } elseif ($rowStarted) {
                            # parse the text between <td> and <br/></td> and add it to the class
                            if ($_ -match "<td>(?<str>\w{2}.*)<br/></td>") {
                                $text = $Matches.str
                                $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Found match: $text")
                                
                                if ( -NOT [string]::IsNullOrEmpty($text) ) {
                                    switch ($tdNum) {
                                        1 { 
                                            $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Adding cipher string")
                                            $tmpRow.SetTlsString($text)
                                            $tdNum++
                                        }
                                        
                                        2 { 
                                            $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Adding strong crypto")
                                            $tmpRow.SetStrongCrypto($text) 
                                            $tdNum++
                                        }

                                        3 { 
                                            $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Testing if TLS 1.3.")
                                            $tmpRow.SetIsVerTls13($text) 

                                            # add to the results only if it's a TLS 1.3 compatible suite
                                            if ($tmpRow.isVerTls13) {
                                                $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Adding to list.`n`n$($tmpRow.ToString())`n`n")
                                                $tls13CipherTable += $tmpRow
                                            }

                                            $tdNum = 1
                                        }

                                        default { $script:log.NewError("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "UNSUPPORTED_SWITCH_OPTION", "You shouldn't be here.", $true)}
                                    }
                                }
                            }
                        }
                    }
                }

                # set the suites if we got results
                if ($tls13CipherTable.Count -ge 1) {
                    $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Successfully got a working list.")
                    $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "tls13CipherTable: $($tls13CipherTable.TlsString -join ', ')")
                    $this.Tls13CipherSuites = $tls13CipherTable
                # Otherwise, use the last known good set. Just in case something doesn't work.
                } else {
                    $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "Something went wrong, falling back to Last Known Good list.")
                    $this.UseLastKnownGoodTls13CipherSuites()
                }
            }

            $script:log.NewLog("SoQTls13Support", "GetTls13CipherSuitesFromInternet", "End")
        }

        # checks whether the local list of suites has a TLS 1.3 cipher.
        # if the default is used we assume there is a supported cipher, because Windows Server 2022 supports TLS 1.3 by default
        ValidateLocalCipherSuite() {
            $script:log.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Begin")
            # look for the registry value that controls cipher suites
            [array]$cipherPol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' | ForEach-Object { $_.Functions.Split(',') }

            $script:log.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Cipher suites: $($cipherPol -join ', ')")

            if ($cipherPol.Count -ge 1) {
                $script:log.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Starting validation.")
                # test whether there is an approved TLS 1.3 cipher
                $fndValidTls13Suite = $false

                foreach ($c in $this.Tls13CipherSuites) { 
                    if ($c.String -in $cipherPol) {
                        $script:log.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Found a match: $($_.String)")
                        $fndValidTls13Suite = $true
                    }
                }

                if ($fndValidTls13Suite) {
                    $script:log.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Validation passed.")
                    $this.Result.SetValidity( "Pass" )
                } else {
                    $script:log.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Validation failed.")
                    $this.Result.SetValidity( "Fail" )
                    $this.FailureReason = "The 'SSL Cipher Suite Order' policy has been modified and does not include a TLS 1.3 compatible cipher suite. See: https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-server-2022"
                }

            } else {
                $script:log.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "Policy is default. Accepting this as a pass.")
                # no special cipher policy is installed, the default will be compatible.
                $this.Result.SetValidity( "Pass" )
            }
            $script:log.NewLog("SoQTls13Support", "ValidateLocalCipherSuite", "End")
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

        [string]
        ToShortString()
        {
            return "Tls13CipherSuites: $($this.Tls13CipherSuites.TlsString -join ',') ($($this.Result.IsValid))"
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
            $script:log.NewLog("SoQCertValidation", "Start")
            $this.Certificate        = $Certificate
            $script:log.NewLog("SoQCertValidation", "Thumbprint: $($this.Certificate.Thumbprint), Subject: $($this.Certificate.Subject)")
            if ($IgnoreOS) {
                $script:log.NewLog("SoQCertValidation", "SupportedOS: Ignored")
                $this.IgnoreOS           = $true
                $this.SupportedOS        = $null
            } else {
                $script:log.NewLog("SoQCertValidation", "SupportedOS")
                $this.IgnoreOS           = $false
                $this.SupportedOS        = [SoQSupportedOS]::new()
            }
            $script:log.NewLog("SoQCertValidation", "Expiration")
            $this.Expiration         = [SoQCertExpired]::new($Certificate)
            $script:log.NewLog("SoQCertValidation", "Purpose")
            $this.Purpose            = [SoQCertPurpose]::new($Certificate)
            $script:log.NewLog("SoQCertValidation", "KeyUsage")
            $this.KeyUsage           = [SoQCertKeyUsage]::new($Certificate)
            $script:log.NewLog("SoQCertValidation", "Subject")
            $this.Subject            = [SoQCertSubject]::new($Certificate)
            $script:log.NewLog("SoQCertValidation", "SubjectAltName")
            $this.SubjectAltName     = [SoQCertSAN]::new($Certificate)
            $script:log.NewLog("SoQCertValidation", "PrivateKey")
            $this.PrivateKey         = [SoQCertPrivateKey]::new($Certificate)
            $script:log.NewLog("SoQCertValidation", "SignatureAlgorithm")
            $this.SignatureAlgorithm = [SoQCertSignatureAlgorithm]::new($Certificate)
            $script:log.NewLog("SoQCertValidation", "SignatureHash")
            $this.SignatureHash      = [SoQCertSignatureHash]::new($Certificate)
            $script:log.NewLog("SoQCertValidation", "PublicKeyAlgorithm")
            $this.PublicKeyAlgorithm = [SoQCertPublicKeyAlgorithm]::new($Certificate)
            $script:log.NewLog("SoQCertValidation", "CertChain")
            $this.CertChain          = [SoQCertCertChain]::new($Certificate)
            $script:log.NewLog("SoQCertValidation", "Tls13Support")
            $this.Tls13Support       = [SoQTls13Support]::new()
            $script:log.NewLog("SoQCertValidation", "Validate")
            $this.IsValid            = $this.ValidateSoQCert()
            $script:log.NewLog("SoQCertValidation", "End")
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
            $script:log.NewLog("SoQCertValidation", "ValidateSoQCert", "Start")
            [SoQState]$valid = "Pass"
            $tests = $this.GetSubclassVariables()

            $theLongestLen = 0
            $tests | ForEach-Object { if ( $_.Length -gt $theLongestLen ) { $theLongestLen = $_.Length } }

            foreach ( $test in $tests )
            {
                $script:log.NewLog("SoQCertValidation", "ValidateSoQCert", "Testing $($test.PadRight($theLongestLen, " ")) : $($this."$test".Result.IsValid)")
                if ($this."$test".Result.IsValid -eq "Fail") { 
                    $valid = "Fail" 
                    $this.FailedTests += $test
                    $script:log.NewLog("SoQCertValidation", "ValidateSoQCert", "Failure reason: $($this."$test".Result.FailureReason)")
                } elseif ($this."$test".Result.IsValid -eq "Warning") { 
                    # do not overwrite the Fail state
                    if ($valid -ne "Fail") {
                        $valid = "Warning"
                    }

                    $this.FailedTests += $test
                    $script:log.NewLog("SoQCertValidation", "ValidateSoQCert", "Warning reason: $($this."$test".Result.FailureReason)")
                }
            }

            $script:log.NewLog("SoQCertValidation", "ValidateSoQCert", "End")
            return $valid
        }


        [string]
        ToString()
        {
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
        }

        [string]
        ToShortString()
        {
            $txt = "$($this.Subject.ToString()) ($($this.Certificate.Thumbprint)); Validation: $($this.IsValid)"

            if ($this.IsValid -ne "Pass" ) {
                $txt += "; FailedTests: $($this.FailedTests -join ', ')"
            }

            return $txt
        }
        
    }


    $TypeData = @{
        TypeName   = 'SoQCertValidation'
        MemberType = 'ScriptProperty'
        MemberName = 'Thumbprint'
        Value      = {$this.Certificate.Thumbprint}
    }

    $TypeData = @{
        TypeName   = 'SoQCertValidation'
        MemberType = 'ScriptProperty'
        MemberName = 'Subject'
        Value      = {$this.Subject.Subject}
    }

    $TypeData = @{
        TypeName   = 'SoQCertValidation'
        MemberType = 'ScriptProperty'
        MemberName = 'IsValid'
        Value      = {$this.IsValid}
    }

    $TypeData = @{
        TypeName   = 'SoQCertValidation'
        MemberType = 'ScriptProperty'
        MemberName = 'FailedTests'
        Value      = {$this.FailedTests}
    }

    $TypeData = @{
        TypeName   = 'Logging'
        DefaultDisplayPropertySet = 'Thumbprint', 'Subject', 'IsValid', 'FailedTests'
    }

    #endregion

    # Validate LogPath - Failures cause $PWD to be used.
    # make sure the log path is a valid path
    if ( -NOT (Test-Path "$LogPath" -IsValid)) { $LogPath = $PWD.Path }

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

    # start logging
    $script:log = [Logging]::new($LogPath)

    $script:log.NewLog("Begin")


    $script:psVerMaj = $Host.Version.Major
    if ( $script:psVerMaj -eq 5 ) {
        $script:log.NewWarning("Please use PowerShell 7 for the best experience. The .NET certificate namespaces used by Windows PowerShell 5.1 cannot full parse certificate details.`n`nhttps://aka.ms/powershell")
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
        $script:log.NewError("NO_CERTS_FOUND", "No certificates were found in LocalMachine\My (Local Computer > Personal > Certificates)", $true)
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
            }}, @{Label="FailureReason"; Expression={s
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
    # the standard returns a table of thumbprint, subject, and IsValid
    } else {
        $certs | Format-Table -Property @{Name="Thumbprint"; Expression={($_.Certificate.Thumbprint)}}, `
                                        @{Name="Subject"; Expression={($_.Subject.Subject)}}, `
                                        @{Name="IsValid"; Expression={($_.IsValid)}}, `
                                        @{Name="FailedTests"; Expression={($_.FailedTests)}}
    }
}

end {
    $script:log.NewLog("End")

    # close logging - this should go in clean{} for PowerShell 7.3+ because it runs even when the script is terminated... but need that backward compat.
    $log.close()
}