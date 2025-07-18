<#
.SYNOPSIS
    Updates existing IIS SSL bindings to the latest valid certificates
    in the LocalMachine\MY store, primarily matching host headers to certificate Common Names (CNs).

.DESCRIPTION
    This script iterates through all IIS websites and their existing HTTPS bindings.
    For each binding, it attempts to find the latest valid certificate in the 'LocalMachine\MY' store
    whose Subject Common Name (CN) or Subject Alternative Name (SAN) matches the binding's host header.
    If a newer or more appropriate certificate is found, the existing binding is updated.
    This version explicitly avoids adding new bindings if no HTTPS binding is found.
    It also handles bindings with empty host headers (IP-based SSL).

.NOTES
    - This script assumes a convention where IIS website host headers closely match the
      Common Name (CN) or Subject Alternative Name (SAN) of your SSL certificates.
    - For bindings with no host header (IP-based SSL), it will attempt to find a certificate
      where its CN matches the website's name, or a general purpose certificate.
    - It prefers SNI (Server Name Indication) bindings (SslFlags = 0).
    - Requires the WebAdministration PowerShell module (IIS Management Tools installed).
#>

# Function to log messages with timestamp
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO" # INFO, WARN, ERROR
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] [$Level] $Message"
}

Write-Log "Starting IIS SSL Binding Update Script (Existing Bindings Only)..."

#region Module Check
# Import WebAdministration module if not already loaded
if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
    Write-Log "WebAdministration module not found. Attempting to install if possible." "WARN"
}
try {
    Import-Module WebAdministration -ErrorAction Stop
    Write-Log "WebAdministration module imported successfully."
} catch {
    Write-Log "Failed to import WebAdministration module. Please ensure IIS Management Tools are installed on this VM." "ERROR"
    exit 1
}
#endregion

#region Certificate Store Path
$certStorePath = "Cert:\LocalMachine\My" # Default store where Key Vault extension places certs
#endregion

#region Get All Websites
$iisWebsites = Get-Website
if ($iisWebsites.Count -eq 0) {
    Write-Log "No IIS websites found on this server. Exiting." "INFO"
    exit 0
}
#endregion

#region Main Binding Logic
foreach ($site in $iisWebsites) {
    Write-Log "Processing website: $($site.Name)"

    $hostHeadersProcessed = @{} # Track host headers to avoid duplicate processing for a site

    # --- UPDATED DEBUGGING BLOCK WITH DIRECT ATTRIBUTE ACCESS ---
    Write-Log "  Dumping all raw bindings found for site '$($site.Name)':"
    $allSiteBindings = $site.Bindings
    if ($allSiteBindings.Count -eq 0) {
        Write-Log "    No bindings found for this site at all (raw collection empty)."
    } else {
        foreach ($b in $allSiteBindings) {
            # Safely get property values using Attributes collection
            # If the attribute exists, get its Value, otherwise default to empty string
            $protocol = ($b.Attributes["protocol"] | Select-Object -ExpandProperty Value) -as [string] | Where-Object { $_ -ne $null } | ForEach-Object { $_.Trim() }
            $bindingInformation = ($b.Attributes["bindingInformation"] | Select-Object -ExpandProperty Value) -as [string] | Where-Object { $_ -ne $null } | ForEach-Object { $_.Trim() }
            $hostHeaderRaw = ($b.Attributes["hostHeader"] | Select-Object -ExpandProperty Value) -as [string] | Where-Object { $_ -ne $null } | ForEach-Object { $_.Trim() }
            $portRaw = ($b.Attributes["port"] | Select-Object -ExpandProperty Value) -as [string] | Where-Object { $_ -ne $null } | ForEach-Object { $_.Trim() }
            $sslFlagsRaw = ($b.Attributes["sslFlags"] | Select-Object -ExpandProperty Value) -as [string] | Where-Object { $_ -ne $null } | ForEach-Object { $_.Trim() }

            # If properties are still null after trying to expand Value (for strange object types), default to empty string
            $protocol = if ($protocol) { $protocol } else { "" }
            $bindingInformation = if ($bindingInformation) { $bindingInformation } else { "" }
            $hostHeaderRaw = if ($hostHeaderRaw) { $hostHeaderRaw } else { "" }
            $portRaw = if ($portRaw) { $portRaw } else { "" }
            $sslFlagsRaw = if ($sslFlagsRaw) { $sslFlagsRaw } else { "" }


            Write-Log "    Raw Binding - Protocol: '$protocol', Info: '$bindingInformation', Host: '$hostHeaderRaw', Port: '$portRaw', SslFlags: '$sslFlagsRaw'"
        }
    }
    # --- END UPDATED DEBUGGING BLOCK ---


    # Iterate existing HTTPS bindings to check for updates
    # Safely get Protocol property using Attributes collection and compare
    $httpsBindingsFound = $site.Bindings | Where-Object { 
        $protocolValue = ($_.Attributes["protocol"] | Select-Object -ExpandProperty Value) -as [string]
        # Check if $protocolValue is not null and equals "https" after trimming
        # ADDED VERY SPECIFIC DEBUG HERE
        Write-Log "    DEBUG: Evaluating binding protocol. Raw value: '$($protocolValue)', Trimmed value: '$($protocolValue.Trim())'" -Level "INFO"
        ($protocolValue -ne $null -and $protocolValue.Trim() -eq "https")
    }

    # --- NEW DEBUGGING AFTER FILTERING ---
    if ($httpsBindingsFound.Count -gt 0) {
        Write-Log "  After filtering, found $($httpsBindingsFound.Count) HTTPS binding(s) for site '$($site.Name)'."
    }
    # --- END NEW DEBUGGING AFTER FILTERING ---

    if ($httpsBindingsFound.Count -eq 0) {
        Write-Log "  Website '$($site.Name)' has no existing HTTPS bindings to update. Skipping." "INFO"
        continue # Move to the next website
    }

    foreach ($binding in $httpsBindingsFound) {
        # Safely get properties using Attributes collection
        $hostHeader = ($binding.Attributes["hostHeader"] | Select-Object -ExpandProperty Value) -as [string]
        $hostHeader = if ($hostHeader -ne $null) { $hostHeader.ToLowerInvariant().Trim() } else { "" } # Normalize host header

        $bindingInformation = ($binding.Attributes["bindingInformation"] | Select-Object -ExpandProperty Value) -as [string]
        $bindingInformation = if ($bindingInformation -ne $null) { $bindingInformation.Trim() } else { "" }

        $port = ($binding.Attributes["port"] | Select-Object -ExpandProperty Value) -as [string]
        $port = if ($port -ne $null) { $port.Trim() } else { "" }

        $sslFlags = ($binding.Attributes["sslFlags"] | Select-Object -ExpandProperty Value) -as [string]
        $sslFlags = if ($sslFlags -ne $null) { $sslFlags.Trim() } else { "0" } # Default to 0 if null

        $certificateHash = ($binding.Attributes["certificateHash"] | Select-Object -ExpandProperty Value) -as [string]
        $certificateHash = if ($certificateHash -ne $null) { $certificateHash.Trim() } else { "" }


        # Log the binding information for debugging
        Write-Log "  Found existing HTTPS binding. BindingInformation: '$bindingInformation', HostHeader: '$hostHeader', Port: '$port', SSLFlags: '$sslFlags', CertificateHash: '$certificateHash'"

        if ($hostHeadersProcessed.ContainsKey($hostHeader)) {
            Write-Log "  Skipping already processed host header: $hostHeader for site '$($site.Name)'" "INFO"
            continue
        }
        $hostHeadersProcessed[$hostHeader] = $true # Mark as processed

        Write-Log "  Checking binding for host: '$hostHeader' (empty means IP-based) on port: $port"

        # Find the latest valid certificate for this binding.
        $latestCert = $null
        try {
            $certsInStore = Get-ChildItem -Path $certStorePath | Where-Object { $_.NotAfter -gt (Get-Date) } | Sort-Object -Property NotAfter -Descending

            if ([string]::IsNullOrEmpty($hostHeader)) {
                # For IP-based bindings (no host header), prioritize by FriendlyName which often comes from Key Vault secret name
                Write-Log "    Binding has no host header (IP-based). Attempting to find certificate by FriendlyName or common patterns." "INFO"
                
                # First, try to find a cert whose FriendlyName matches "IIS-Key-Vault" or similar pattern
                # IMPORTANT: Replace "IIS-Key-Vault" below with the actual FriendlyName of your certificate if it's different.
                # You can find this in certlm.msc on the VM in the Personal -> Certificates store.
                $latestCert = $certsInStore | Where-Object { 
                    ($_.FriendlyName -like "*IIS-Key-Vault*") -or # Matches if FriendlyName contains "IIS-Key-Vault"
                    ($_.Subject -like "*CN=$($site.Name)*") -or # Matches CN of cert to site name
                    ($_.DnsNames -contains $site.Name) # Matches SAN of cert to site name
                } | Select-Object -First 1

                if ($null -eq $latestCert) {
                    Write-Log "    Specific certificate for IP-based binding for site '$($site.Name)' not found by friendly name or CN/SAN. Trying to find a general latest valid cert in the store." "WARN"
                    # Fallback: if no specific match, just pick the overall newest valid certificate.
                    # This fallback is less precise but might work if only one relevant cert is present.
                    $latestCert = $certsInStore | Select-Object -First 1
                }
                
            } else {
                # For bindings with a host header, use existing logic
                $latestCert = $certsInStore |
                    Where-Object {
                        ($_.Subject -like "*CN=$hostHeader*") -or # Match CN directly
                        ($_.DnsNames -contains $hostHeader) -or # Match SANs
                        ($_.DnsNames -contains "*.$hostHeader" -and $hostHeader -notlike "www.*") -or # Match wildcard SAN for subdomain
                        ("www.$hostHeader" -in $_.DnsNames) # Handle www. conversion for SANs
                    } | Select-Object -First 1
            }
        } catch {
            Write-Log "  Error searching for certificate for host '$hostHeader': $($_.Exception.Message)" "ERROR"
            continue
        }

        if ($null -eq $latestCert) {
            Write-Log "  No suitable valid certificate found in '$certStorePath' for host header '$hostHeader'. Current binding will be kept as is." "WARN"
            continue
        }

        Write-Log "  Found target certificate: Subject = '$($latestCert.Subject)', FriendlyName = '$($latestCert.FriendlyName)', Thumbprint = '$($latestCert.Thumbprint)', NotAfter = '$($latestCert.NotAfter)'"

        # Check if the current binding uses the latest cert
        if ($certificateHash -ne $latestCert.Thumbprint) { # Use the safely retrieved $certificateHash
            Write-Log "  Binding for host '$hostHeader' on port '$port' is using an old certificate. Updating to new thumbprint: $($latestCert.Thumbprint)" "WARN"
            try {
                # Attempt to remove the old binding (important for clean update)
                Remove-WebBinding -Name $site.Name -Protocol "https" -BindingInformation "$bindingInformation" -ErrorAction SilentlyContinue | Out-Null
                Write-Log "    Old binding removed for '$hostHeader' (if it existed)."

                # Get the actual numeric SSLFlags
                $numericSslFlags = [int]$sslFlags 

                # Re-add binding with updated cert. Need to use original object's IPAddress and Port
                # It seems some properties are direct, others are attributes. This is confusing.
                # Let's try to get IPAddress and Port from the 'Attributes' as well, for consistency
                $ipAddressForBinding = ($binding.Attributes["ipAddress"] | Select-Object -ExpandProperty Value) -as [string]
                $portForBinding = ($binding.Attributes["port"] | Select-Object -ExpandProperty Value) -as [int] # Cast to int for port

                New-WebBinding -Name $site.Name -Protocol "https" -IPAddress $ipAddressForBinding -Port $portForBinding -HostHeader $finalHostHeader -SslFlags $numericSslFlags -ErrorAction Stop
                Set-WebBinding -Name $site.Name -Protocol "https" -HostHeader $finalHostHeader -IPAddress $ipAddressForBinding -Port $portForBinding -SslFlags $numericSslFlags -CertificateThumbprint $latestCert.Thumbprint -CertificateStoreName $certStorePath.Split('\')[-1] -ErrorAction Stop

                Write-Log "    Successfully updated binding for '$hostHeader' to certificate $($latestCert.Thumbprint)."
            } catch {
                Write-Log "    Failed to update binding for host '$hostHeader' on website '$($site.Name)': $($_.Exception.Message)" "ERROR"
            }
        } else {
            Write-Log "  Binding for host '$hostHeader' on port '$port' is already using the correct certificate. No update needed." "INFO"
        }
    }
}
#endregion

Write-Log "IIS SSL Binding Auto-Update Script finished."
exit 0
