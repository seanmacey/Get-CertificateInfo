<#
.SYNOPSIS
Gets infromation about one or more websites SSL certificates

.DESCRIPTION
Gets infromation about one or more websites SSL certificates
can take an object array as input (with parameters url and port )

.PARAMETER url
is the url of the site to check (does NOT require https:// at the start)

.PARAMETER port
[Optional]
defaults to 443

.PARAMETER WarnDaysLeft
default value is 90 days
any difference between now and the cert ecxpiry that is less than this will generate an error

.EXAMPLE
Get-CertificateInfo -url tank.imatec.co.nz -port 443

#import a CSV file, scan it and push the results to a new CSV file
$si = import-csv .\sitestocheck.csv   #CSV file with 1st row header:  url,port
$si |Get-CertificateInfo|Export-Csv -NoTypeInformation siteschecked.csv -Force 


.NOTES
General notes
#>
function Get-CertificateInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("Domain")]
        [string]$Url,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Port = 443,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$Comment = "",
        [Parameter(Mandatory = $false)]
        [int]$WarnDaysLeft = 90,
        [Parameter(Mandatory = $false)]
        [int]$WarnAutoRenew = 29,
        [Alias("Is Suspended")]
        [string]$IsSuspended
                 
    )
    
    begin {
        $today = (get-date).DateTime
      #  $delim = @('/', ' ')
    }
    
    process {

        # if ($IsSuspended) {
        #     write-host "Found $Url" -ForegroundColor Red
        #     #return
        # }
        # return
        $port = $port.trim(" ")
        $url = $url.Trim()
        #$url = $url.TrimStart("https:")#.trim("http:////")

        if (!$port) { $port = 443 }

        $res = [PSCustomObject]@{
     
            name           = "$($url):$port"
            site           = $url
            port           = $port
            foundAt        = "Unknown"
            IP             = ""
            #CipherStrength  = ""
            #HashAlgorithm   = ""
            SslProtocol    = ""
            ExpirationDate = "Unknown"
            Subject        = "Unknown"
            issuer         = ""
            Connected      = ""
            Error          = ""
            # Warnings       = ""
            DaysToExpire   = ""
            Comment        = $Comment
        }

        $IP = Resolve-DnsName -name $url -ErrorAction SilentlyContinue
        if ($IP) {
            $res.IP = $IP.IPAddress
        }

        try {
            $Req = [System.Net.Sockets.TcpClient]::new($url, $port)
            $res.Connected = $Req.Client.Connected    
        }
        catch {
            <#Do this if a terminating exception happens#>
            # the website was not reachable
            $res.Error = $Error[0].exception.innerexception.message
            Write-Host "$($url):$port $($res.Error)" -ForegroundColor Yellow
            # $res.Error = $error[0].Exception.Message
            return $res
        }


        #$Req.Client |Select-Object -Property * |FL
        if ($Req) {
            $Stream = [System.Net.Security.SslStream]::new($Req.GetStream())
            try {
                $Stream.AuthenticateAsClient($url)
            }
            catch [System.Security.Authentication.AuthenticationException] {
                #AuthenticationException
                $res.Error = $Error[0].exception.innerexception.message
                Write-Host "$($url):$port $($res.Error)" -ForegroundColor Yellow
                $res
                return
            }
            catch {
                $res.Error = $Error[0].exception
                Write-Host "$($url):$port $($res.Error)" -ForegroundColor Yellow
                $res
                return 
            }

            $IP = Resolve-DnsName -name $url -ErrorAction SilentlyContinue
            if ($stream) {
                #  $res.name = "$($url):$port"
                #$res.CipherAlgorithm = $stream.CipherAlgorithm
                $res.foundAt = $Req.Client.RemoteEndPoint

                #$res.CipherStrength = $stream.CipherStrength
                #$res.HashAlgorithm = $stream.HashAlgorithm
                $res.SslProtocol = $Stream.SslProtocol
                try {
                    $res.Expirationdate = $Stream.RemoteCertificate.GetExpirationDateString() 
                }
                catch {}
                $res.Subject = $Stream.RemoteCertificate.Subject
                $res.issuer = $Stream.RemoteCertificate.Issuer
            }
        }



        if ( $res.ExpirationDate) {
            $warnabout = $WarnDaysLeft
            $_renewString = ""
            if ($res.issuer -like "*O=Let's Encrypt*") {
                $_renewString = "(Auto-Renews) "
                $warnabout = $WarnAutoRenew
                $res.comment = "$_renewString $Comment" 
            }            

            $dateparts = ($res.ExpirationDate -split (" "))[0]
            $dateparts2 = $dateparts.split("/")
                
            # $ssldate = [Datetime]::parse($d,'dd/MM/yyyy',$null)
            $ssldate = get-date -Day $dateparts2[0] -Month $dateparts2[1] -Year $dateparts2[2] 
            $T = New-TimeSpan -Start  $today -End $ssldate

            $res.DaysToExpire = $T.Days
            if ($T.Days -le 0) {
                $res.Error = "Expired Certificate"
                write-host "$($res.name) Expired Certificate" -ForegroundColor Yellow
            }

            elseif ($T.Days -le $warnabout) {
                $res.Error = "Only $($T.Days) days left before Certificate expires"
                write-host "$($_renewString)$($res.name) has only $($T.Days) days left before Certificate expires" -ForegroundColor Yellow
            } 
    }
    $res  
}
    
end {
        
}
}


