function Get-XdrEndpointConfigurationAuthenticatedTelemetry {
    <#
    .SYNOPSIS
        Retrieves the Authenticated Telemetry status for Microsoft Defender for Endpoint.

    .DESCRIPTION
        Gets the Authenticated Telemetry status for Microsoft Defender for Endpoint.
        This function includes caching support with a 30-minute TTL to reduce API calls.

    .PARAMETER Force
        Bypasses the cache and forces a fresh retrieval from the API.

    .EXAMPLE
        Get-XdrEndpointConfigurationAuthenticatedTelemetry
        Retrieves the Authenticated Telemetry status for Microsoft Defender for Endpoint.

    .EXAMPLE
        Get-XdrEndpointConfigurationAuthenticatedTelemetry -Force
        Forces a fresh retrieval, bypassing the cache.
    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Update-XdrConnectionSettings
    }

    process {
        Write-Verbose "Retrieving Defender for Endpoint Authenticated Telemetry configuration"
        Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/senseauth/allownonauthsense" -Method Get -ContentType "application/json" -WebSession $script:session -Headers $script:headers
    }

    end {

    }
}