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

    # --- UPDATED DEBUGGING BLOCK ---
    Write-Log "  Dumping all raw bindings found for site '$($site.Name)':"
    $allSiteBindings = $site.Bindings
    if ($allSiteBindings.Count -eq 0) {
        Write-Log "    No bindings found for this site at all (raw collection empty)."
    } else {
        foreach ($b in $allSiteBindings) {
            # Explicitly cast Protocol to string and trim any whitespace
            Write-Log "    Raw Binding - Protocol: '$([string]$b.Protocol.Trim())', Info: '$([string]$b.BindingInformation.Trim())', Host: '$([string]$b.HostHeader.Trim())', Port: '$([string]$b.Port.ToString().Trim())'"
        }
    }
    # --- END UPDATED DEBUGGING BLOCK ---


    # Iterate existing HTTPS bindings to check for updates
    # Explicitly cast $_.Protocol to string and trim to avoid any type/whitespace issues
    $httpsBindingsFound = $site.Bindings | Where-Object { ([string]$_.Protocol.Trim()) -eq "https" }

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
        $hostHeader = $binding.HostHeader.ToLowerInvariant() # Normalize host header
        
        # Log the raw binding information for debugging
        Write-Log "  Found existing HTTPS binding. BindingInformation: '$($binding.BindingInformation)', HostHeader: '$hostHeader', Port: '$($binding.Port)', SSLFlags: '$($binding.SslFlags)'"

        if ($hostHeadersProcessed.ContainsKey($hostHeader)) {
            Write-Log "  Skipping already processed host header: $hostHeader for site '$($site.Name)'" "INFO"
            continue
        }
        $hostHeadersProcessed[$hostHeader] = $true # Mark as processed

        Write-Log "  Checking binding for host: '$hostHeader' (empty means IP-based) on port: $($binding.Port)"

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
        if ($binding.CertificateHash -ne $latestCert.Thumbprint) {
            Write-Log "  Binding for host '$hostHeader' on port '$($binding.Port)' is using an old certificate. Updating to new thumbprint: $($latestCert.Thumbprint)" "WARN"
            try {
                # Attempt to remove the old binding (important for clean update)
                Remove-WebBinding -Name $site.Name -Protocol "https" -BindingInformation "$($binding.BindingInformation)" -ErrorAction SilentlyContinue | Out-Null
                Write-Log "    Old binding removed for '$hostHeader' (if it existed)."

                # Add the new binding with the updated certificate
                # For IP-based, Set-WebBinding might need the HostHeader parameter as ""
                $finalHostHeader = if ([string]::IsNullOrEmpty($hostHeader)) { "" } else { $hostHeader }

                # Use New-WebBinding with -Force to ensure it's added, then Set-WebBinding for cert.
                # Sometimes a direct Set-WebBinding on an existing binding works, but recreating is safer if issues persist.
                New-WebBinding -Name $site.Name -Protocol "https" -IPAddress $binding.IPAddress -Port $binding.Port -HostHeader $finalHostHeader -SslFlags $binding.SslFlags -ErrorAction Stop
                Set-WebBinding -Name $site.Name -Protocol "https" -HostHeader $finalHostHeader -IPAddress $binding.IPAddress -Port $binding.Port -SslFlags $binding.SslFlags -CertificateThumbprint $latestCert.Thumbprint -CertificateStoreName $certStorePath.Split('\')[-1] -ErrorAction Stop

                Write-Log "    Successfully updated binding for '$hostHeader' to certificate $($latestCert.Thumbprint)."
            } catch {
                Write-Log "    Failed to update binding for host '$hostHeader' on website '$($site.Name)': $($_.Exception.Message)" "ERROR"
            }
        } else {
            Write-Log "  Binding for host '$hostHeader' on port '$($binding.Port)' is already using the correct certificate. No update needed." "INFO"
        }
    }
}
#endregion

Write-Log "IIS SSL Binding Auto-Update Script finished."
exit 0
