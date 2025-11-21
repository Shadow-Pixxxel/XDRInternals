function Get-XdrEndpointCustomDataCollectionRules {
    <#
    .SYNOPSIS
        Retrieves XdrEndpointCustomDataCollection rules from XDR.

    .DESCRIPTION
        Retrieves XdrEndpointCustomDataCollection rules from XDR.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointCustomDataCollectionRules
        Retrieves XdrEndpointCustomDataCollection rules from XDR.

    .EXAMPLE
        Get-XdrEndpointCustomDataCollectionRules -Force
        Forces a fresh retrieval, bypassing the cache.

    .OUTPUTS
        Object
        Returns the API response.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        $currentCacheValue = Get-XdrCache -CacheKey "GetXdrEndpointCustomDataCollectionRules" -ErrorAction SilentlyContinue
        if (-not $Force -and $currentCacheValue.NotValidAfter -gt (Get-Date)) {
            Write-Verbose "Using cached GetXdrEndpointCustomDataCollectionRules data"
            return $currentCacheValue.Value
        }
        elseif ($Force) {
            Write-Verbose "Force parameter specified, bypassing cache"
            Clear-XdrCache -CacheKey "GetXdrEndpointCustomDataCollectionRules"
        }
        else {
            Write-Verbose "GetXdrEndpointCustomDataCollectionRules cache is missing or expired"
        }

        $Uri = "https://security.microsoft.com/apiproxy/mtp/mdeCustomCollection/rules"
        Write-Verbose "Retrieving GetXdrEndpointCustomDataCollectionRules data"
        $result = Invoke-RestMethod -Uri $Uri -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers

        Set-XdrCache -CacheKey "GetXdrEndpointCustomDataCollectionRules" -Value $result -TTLMinutes 30
        return $result
    }

    end {
    }
}