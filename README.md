# Get-CertificateInfo
Remotely check the status of SSL certificates, and prepare a summary of risks and fualts - such as near to expire
run the get-CertificateInfo.ps1 script (or save this as a Module *.psm1), then run the function get-CertificateInfo

use  Import-CSVFromWHM to parse the CSV that cPanel Accounts list export creates - so that the output can be used by the Get-Certitificate script
Import-CSVFromWHM -inputFile .\kisshost.csv |Get-CertificateInfo -DontCreateExport