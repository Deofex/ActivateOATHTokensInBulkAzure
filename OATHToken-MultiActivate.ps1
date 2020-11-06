<#
    .SYNOPSIS
        Active OATH tokens in batches

    .DESCRIPTION
        This script active OATH tokens in batches

    .INPUTS
        None.

    .OUTPUTS
        None.

    .EXAMPLE
        PS C:\> C:\OATHToken-MultiActivate.ps1 -tenantid 'aaa5b397-b4e6-4442-bce9-2663490e8114' -csv 'C:\tokens.csv'
        Activate unactivated OATH tokens in tenant aaa5b397-b4e6-4442-bce9-2663490e8114 where the private OATH information are available in the CSV file

    .NOTES
        Author : Roy Pahlplatz
        License : MIT License

    .LINK
        https://github.com/Deofex/ActivateOATHTokensInBulkAzure
#>
param
(
    # The tenant ID of the tenant which contains the OATH tokens
    [Parameter(Mandatory = $true)]
    [System.String]
    $tenantid,

    # The location of the CSV file which contains the private information of the OATH tokens (the same file as imported in Azure)
    [Parameter(Mandatory = $true)]
    [System.String]
    $csvfile
)


#Support function for the OTP Get-TimeBasedOneTimePassword function, created by Claudio Spizzi
function Convert-Base32ToByte {
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Base32
    )

    # RFC 4648 Base32 alphabet
    $rfc4648 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

    $bits = ''

    # Convert each Base32 character to the binary value between starting at
    # 00000 for A and ending with 11111 for 7.
    foreach ($char in $Base32.ToUpper().ToCharArray()) {
        $bits += [Convert]::ToString($rfc4648.IndexOf($char), 2).PadLeft(5, '0')
    }

    # Convert 8 bit chunks to bytes, ignore the last bits.
    for ($i = 0; $i -le ($bits.Length - 8); $i += 8) {
        [Byte] [Convert]::ToInt32($bits.Substring($i, 8), 2)
    }
}

<#
    .SYNOPSIS
        Generate a Time-Base One-Time Password based on RFC 6238.

    .DESCRIPTION
        This command uses the reference implementation of RFC 6238 to calculate
        a Time-Base One-Time Password. It bases on the HMAC SHA-1 hash function
        to generate a shot living One-Time Password.

    .INPUTS
        None.

    .OUTPUTS
        System.String. The one time password.

    .EXAMPLE
        PS C:\> Get-TimeBasedOneTimePassword -SharedSecret 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        Get the Time-Based One-Time Password at the moment.

    .NOTES
        Author : Claudio Spizzi
        License : MIT License

    .LINK
        https://github.com/claudiospizzi/SecurityFever
        https://tools.ietf.org/html/rfc6238
#>
function Get-TimeBasedOneTimePassword {
    [CmdletBinding()]
    [Alias('Get-TOTP')]
    param
    (
        # Base 32 formatted shared secret (RFC 4648).
        [Parameter(Mandatory = $true)]
        [System.String]
        $SharedSecret,

        # The date and time for the target calculation, default is now (UTC).
        [Parameter(Mandatory = $false)]
        [System.DateTime]
        $Timestamp = (Get-Date).ToUniversalTime(),

        # Token length of the one-time password, default is 6 characters.
        [Parameter(Mandatory = $false)]
        [System.Int32]
        $Length = 6,

        # The hash method to calculate the TOTP, default is HMAC SHA-1.
        [Parameter(Mandatory = $false)]
        [System.Security.Cryptography.KeyedHashAlgorithm]
        $KeyedHashAlgorithm = (New-Object -TypeName 'System.Security.Cryptography.HMACSHA1'),

        # Baseline time to start counting the steps (T0), default is Unix epoch.
        [Parameter(Mandatory = $false)]
        [System.DateTime]
        $Baseline = '1970-01-01 00:00:00',

        # Interval for the steps in seconds (TI), default is 30 seconds.
        [Parameter(Mandatory = $false)]
        [System.Int32]
        $Interval = 30
    )

    # Generate the number of intervals between T0 and the timestamp (now) and
    # convert it to a byte array with the help of Int64 and the bit converter.
    $numberOfSeconds = ($Timestamp - $Baseline).TotalSeconds
    $numberOfIntervals = [Convert]::ToInt64([Math]::Floor($numberOfSeconds / $Interval))
    $byteArrayInterval = [System.BitConverter]::GetBytes($numberOfIntervals)
    [Array]::Reverse($byteArrayInterval)

    # Use the shared secret as a key to convert the number of intervals to a
    # hash value.
    $KeyedHashAlgorithm.Key = Convert-Base32ToByte -Base32 $SharedSecret
    $hash = $KeyedHashAlgorithm.ComputeHash($byteArrayInterval)

    # Calculate offset, binary and otp according to RFC 6238 page 13.
    $offset = $hash[($hash.Length - 1)] -band 0xf
    $binary = (($hash[$offset + 0] -band '0x7f') -shl 24) -bor
    (($hash[$offset + 1] -band '0xff') -shl 16) -bor
    (($hash[$offset + 2] -band '0xff') -shl 8) -bor
    (($hash[$offset + 3] -band '0xff'))
    $otpInt = $binary % ([Math]::Pow(10, $Length))
    $otpStr = $otpInt.ToString().PadLeft($Length, '0')

    return $otpStr
}


<#
    .SYNOPSIS
        Collects an OAuth access and refresh key from MicrosoftOnline

    .DESCRIPTION
        This command retrieve an OAuth token from Microsoft for the resource of the given
        resourceID.

    .PARAMETER tenantid
        The tenant ID of the tenant to collect the OAUTH token from

    .PARAMETER resourceid
        The resource ID of resource you want an OAUTH token for

    .INPUTS
        None.

    .OUTPUTS
        System.Management.Automation.PSobject which includes an access_token, refresh_token, and expires_on System.String

    .EXAMPLE
        PS C:\> get-oauthtokens -tenantid 'aaa5b397-b4e6-4442-bce9-2663490e8114' -resourceid '74658136-14ec-4630-ad9b-26e160ff0fc6'
        Get an OAuth tokenfor the resource OATH tokens in the tenant 'aaa5b397-b4e6-4442-bce9-2663490e8114'

#>
function get-oauthtokens {
    [CmdletBinding()]
    param
    (
        # The tenant ID of the tenant to collect the OAUTH token from
        [Parameter(Mandatory = $true)]
        [System.String]
        $tenantid,

        # The resource ID of resource you want an OAUTH token for
        [Parameter(Mandatory = $true)]
        [System.String]
        $resourceid
    )
    # Known Client ID for PowerShell
    $clientid = '1950a258-227b-4e31-a9cf-717495945fc2'

    # Request device login @ Microsoft
    $DeviceCodeRequestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/$TenantID/oauth2/devicecode"
        Body   = @{
            client_id = $ClientId
            resource  = $ResourceID
        }
    }
    $DeviceCodeRequest = Invoke-RestMethod @DeviceCodeRequestParams

    # Show the user a message where he/she should login
    Write-Host $DeviceCodeRequest.message -ForegroundColor Yellow

    # Poll the token site to see or the user succesfully autorized
    do {
        try {
            $TokenRequestParams = @{
                Method = 'POST'
                Uri    = "https://login.microsoftonline.com/$TenantId/oauth2/token"
                Body   = @{
                    grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                    code       = $DeviceCodeRequest.device_code
                    client_id  = $ClientId
                }
            }
            $TokenRequest = Invoke-RestMethod @TokenRequestParams
            # Add a new line to the ouput, so it lookks better
            write-host ""
            # Return the token information
            return $TokenRequest
        }
        catch {
            if ((convertfrom-json $_.ErrorDetails.Message).error -eq "authorization_pending") {
                write-host "." -NoNewline
                Start-Sleep -Seconds 10
            }
            else {
                throw "Unkown error while requesting token"
            }
        }
    } while ($true)

}


<#
    .SYNOPSIS
        Refresh an OAuth access at MicrosoftOnline

    .DESCRIPTION
        This command resfresh an OAuth token at Microsoft

    .PARAMETER refreshtoken
        A string which contains the refresh token of an OAUTH token

    .INPUTS
        None.

    .OUTPUTS
        System.Management.Automation.PSobject which includes an access_token, refresh_token, and expires_on System.String

    .EXAMPLE
        PS C:\> get-oauthtokensviarefreshtoken -refreshtoken '123etc'}
        Get a new OAUTH access token
#>
function get-oauthtokensviarefreshtoken {
    [CmdletBinding()]
    param
    (
        # The OAUTH refresh token
        [Parameter(Mandatory = $true)]
        [System.string]
        $refreshtoken
    )
    # Known Client ID for PowerShell
    $clientid = '1950a258-227b-4e31-a9cf-717495945fc2'
    $TokenRequestParams = @{
        Method = 'POST'
        Uri    = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        Body   = @{
            grant_type    = "refresh_token"
            refresh_token = $refreshtoken
            client_id     = $ClientId
        }
    }
    $TokenRequest = Invoke-RestMethod @TokenRequestParams
    return $TokenRequest
}


<#
    .SYNOPSIS
        Tests or an OAUTH access tolen is still valid

    .DESCRIPTION
        This function tests or the OAUTH token is expired.

    .PARAMETER expiredate
        A string with the EPOCH expire date of an OAUth token

    .INPUTS
        None.

    .OUTPUTS
        System.Boolean - The function returns True if the OAUTH token is still valid and False if it isn't valid

    .EXAMPLE
        PS C:\> test-validityaccesstoken -expiredate '1604648756'
        Returns false because the provided token is expired

#>
function test-validityaccesstoken {
    [CmdletBinding()]
    param
    (
        # The expire date in EPOCH format
        [Parameter(Mandatory = $true)]
        [System.String]
        $expiredate
    )
    # Current time
    $ValidTime = (New-Object System.DateTime (1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)).AddSeconds($expiredate)
    # Current Time(-5 minuten to avoid timing issues)
    $CurrentTime = (get-date).ToUniversalTime().AddMinutes(-5)
    if ($CurrentTime -lt $ValidTime) {
        return $true
    }
    else {
        return $false
    }
}


<#
    .SYNOPSIS
        Get a list with all OATH tokens in Azure

    .DESCRIPTION
        This function collects a list with OATH tokens available in the Azure tenant where the given OAUTH token is available

    .PARAMETER accesstoken
        A string which contains the access token of tenant from where to collect the OATH tokens

    .INPUTS
        None.

    .OUTPUTS
        System.Management.Automation.PSobject - which includes OATH token information

    .EXAMPLE
        PS C:\> get-oathtokens -accesstoken '12312fsdfada......'
        Returns a list with OATH tokens and information

#>
function get-oathtokens {
    [CmdletBinding()]
    param
    (
        # The OATH access token
        [Parameter(Mandatory = $true)]
        [System.String]
        $accesstoken
    )
    $apiUrl = 'https://main.iam.ad.ext.azure.com/api/MultifactorAuthentication/HardwareToken/users?skipToken=&upn=&enabledFilter='

    $header = @{
        'Authorization'          = "Bearer $accesstoken"
        'Content-Type'           = 'application/json'
        'X-Requested-With'       = 'XMLHttpRequest'
        'x-ms-client-request-id' = [guid]::NewGuid()
        'x-ms-correlation-id'    = [guid]::NewGuid()
    }

    $Data = (Invoke-RestMethod -Headers $header -Uri $apiUrl -Method Get).items


    write-verbose "Er zijn $($data.count) OATH tokens gevonden, hiervan zijn er $(($data | where-object {$_.enabled -eq $false}).count) niet enabled"
    return $data
}

<#
    .SYNOPSIS
        Activate OATH tokens in Azure

    .DESCRIPTION
        This function activate OATH tokens in Azure via an unsupported API Azure provides. The function
        calculates the OTP token to activate the tokens from the secret key provided in the input.

    .PARAMETER accesstoken
        A string which contains the access token of tenant from where to collect the OATH tokens

    .PARAMETER oathId
        A string which contains the ID of the OATH token

    .PARAMETER objectID
        A string which contains the object ID of the OATH token

    .PARAMETER secretkey
        A string which contains the secret key of the OATH token. This parameter is used to
        calculate the OTP token

    .PARAMETER interval
        An interger which contains the refresh rate of the OTP token

    .INPUTS
        None.

    .OUTPUTS
        $true if the token is succesfully activated

    .EXAMPLE
        PS C:\> new-oathtokenactivation -accesstoken '12312fsdfada......' -oathid 'd4992e60-4509-4384-8a19-aea0c2c54439' -objectid '932d36ca-52de-400f-9a79-ee07e775db92' -secretkey '334567ABCDEF234567ABCDEF' -interval 30
        Returns a list with OATH tokens and information

#>
function new-oathtokenactivation {
    [CmdletBinding()]
    param
    (
        # The OAuth access token
        [Parameter(Mandatory = $true)]
        [System.String]
        $accesstoken,
        # The OathID
        [Parameter(Mandatory = $true)]
        [System.String]
        $oathId,
        # The ObjectID
        [Parameter(Mandatory = $true)]
        [System.String]
        $objectId,
        # The secretkey of the OATH token
        [Parameter(Mandatory = $true)]
        [System.String]
        $secretkey,
        # The interval of the OATH token
        [Parameter(Mandatory = $true)]
        [System.Int32]
        $Interval
    )
    $apiUrl = 'https://main.iam.ad.ext.azure.com/api/MultifactorAuthentication/HardwareToken/enable'
    $verificationCode = Get-TimeBasedOneTimePassword -SharedSecret $secretkey -Interval $Interval

    $JSON = @"
{"@enableAction":"Activate",
    "oathId":"$oathId",
    "objectId":"$objectId",
    "verificationCode":"$verificationCode"
}
"@

    $header = @{
        'Authorization'          = "Bearer $accesstoken"
        'Content-Type'           = 'application/json'
        'X-Requested-With'       = 'XMLHttpRequest'
        'x-ms-client-request-id' = [guid]::NewGuid()
        'x-ms-correlation-id'    = [guid]::NewGuid()
    }

    try {
        Invoke-RestMethod -Headers $header -Body $JSON -Uri $apiUrl -Method Post
    }
    catch {
        throw (convertfrom-json $_.ErrorDetails.Message).message
    }
    return $succes
}

# Import the CSV file, stop the script if this fails
try {
    $oathcsv = import-csv $csvfile -ErrorAction Stop
}
catch {
    write-host "CSV kan niet geimporteerd worden. Stop script."
    exit
}

# Retrieve the OAUTH token for the OATH tokens resource in the given tenant (user will be asked to authorize this request via a browser)
$resourceid = "74658136-14ec-4630-ad9b-26e160ff0fc6"
$oauthtokens = get-oauthtokens -tenantId $tenantId -resourceid $resourceid

# Retrieve the OATH tokens in Azure and filter only the not-activated tokens
$unactivatedoathtokens = get-oathtokens -accesstoken $oauthtokens.access_token | where-object { $_.enabled -eq $false }

# Foreach unactivated OATH token, go into a loop
foreach ($oathtoken in $unactivatedoathtokens) {
    # Renew the OAuth token when it's expired
    if (test-validityaccesstoken -expiredate $oauthtokens.expires_on) {
        Write-Verbose "Access token is valid."
    }
    else {
        Write-Verbose "Access token is expired or will soon expire, get a new token with the refresh token"
        $oauthtokens = get-oauthtokensviarefreshtoken -refreshtoken $oauthtokens.refresh_token
    }

    if (@($oathcsv | Where-Object { $_."serial number" -eq $oathtoken.serialNumber }).count -eq 1) {
        write-verbose "Private OATH info found in the CSV for user $($oathtoken.displayname), proceeding with activation for this token"
        $oathsecretinfo = $oathcsv | Where-Object { $_."serial number" -eq $oathtoken.serialNumber }
        # Activate the OATH token
        try {
            new-oathtokenactivation -accesstoken $oauthtokens.access_token -oathId $oathtoken.oathId -objectid $oathtoken.objectId -secretkey $oathsecretinfo.'secret key' -Interval $oathsecretinfo.'time interval' | Out-Null
            write-host "Token is succesfully acgtivated for $($oathtoken.displayname)" -ForegroundColor Green
        }
        catch {
            write-host "Token can't be activated for $($oathtoken.displayname). Error $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        write-host "No secret OATH information found for $($oathtoken.displayname). This info is not in the CSV or the CSV lacks the correct headers. Activation will not proceed for this user"
    }
}

