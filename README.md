These scripts now require PowerShell 7.4+. PowerShell 7 is the preferred method because .NET 7 has better certificate support, which guarantees better accuracy. Legacy Windows PowerShell 5.1 will only work with the legacy validation cmdlet.

# Wiki

[Initialize-SmbOverQuicServer](https://github.com/JamesKehr/SMB-over-QUIC/wiki/Initialize%E2%80%90SmbOverQuicServer)

Given a certificate, or the necessary details to create a self-signed certificate, this cmdlet will validate the certificate and then setup the SMB over QUIC server.

[Validate-SmbOverQuicCertificate](https://github.com/JamesKehr/SMB-over-QUIC/wiki/Validate%E2%80%90SmbOverQuicCertificate)

Runs basic checks against a certificate, or the entire LocalMachine\My store, to verify whether a certificate is SMB over QUIC (TLS 1.3) compatible.

[Validate-SoQCertificate](https://github.com/JamesKehr/SMB-over-QUIC/wiki/Validate%E2%80%90SoQCertificate)

This is the legacy script built for Windows Server 2022 and Windows PowerShell 5.1. There are bug in this script that are fixed in the new version.

Runs basic checks on a certificate, or the entire LocalMachine\My store, to verify whether a certificate is SMB over QUIC (TLS 1.3) compatible.

## NOTE

This script is in beta and not fully validated. Results are currently not guaranteed to be accurate. Though they should be accurate when using PowerShell 7.
