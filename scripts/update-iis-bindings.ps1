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
    - This version uses appcmd.exe for more robust binding detection and update due to
      observed inconsistencies with WebAdministration module property access.
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

#region Module Check (Still useful for Set-WebBinding cmdlets if needed later)
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

#region AppCmd Path
$appCmdPath = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
if (-not (Test-Path $appCmdPath)) {
    Write-Log "appcmd.exe not found at '$appCmdPath'. Cannot proceed with binding updates." "ERROR"
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

    Write-Log "  Using appcmd.exe to dump all raw bindings for site '$($site.Name)':"
    # Get all bindings for the site using appcmd.exe with /text:bindings
    # Output format is now comma-separated: protocol/bindingInfo,protocol/bindingInfo
    $rawAppCmdBindingsText = (&$appCmdPath list site "$($site.Name)" /text:bindings)

    Write-Log "    Raw appcmd.exe output for bindings: `n$rawAppCmdBindingsText" # For debugging

    # Split the comma-separated bindings and then parse each individual binding string
    $appCmdBindingsRaw = $rawAppCmdBindingsText -split ',' | Where-Object { $_ -match '^(.+?)/(.+)$' }

    if ($appCmdBindingsRaw.Count -eq 0) {
        Write-Log "    No bindings found for this site at all via appcmd.exe. (After parsing)"
    } else {
        foreach ($bindingString in $appCmdBindingsRaw) {
            # Extract protocol and bindingInformation part
            if ($bindingString -match '^(.+?)/(.+)$') {
                $protocol = $Matches[1]
                $bindingInfoAndHost = $Matches[2]

                # Extract bindingInformation, hostHeader and potential sslFlags from bindingInfoAndHost
                # Example: *:443:host.com or *:443: or *:443: sslFlags=0
                # When using /text:bindings, the output doesn't explicitly include sslFlags or hostHeader
                # So, we'll try to get them from the Get-WebBinding object for existing HTTPS bindings.

                $bindingInformation = ($bindingInfoAndHost -split ':') | Select-Object -First 2 | Join-String -Separator ':' # e.g., *:443
                $hostHeader = ""
                $sslFlags = "0" # Default, assume SNI unless found otherwise

                # When using /text:bindings, hostHeader might not be explicitly present, or it's part of bindingInfoAndHost.
                # Let's try to extract hostHeader if it exists in bindingInfoAndHost string like *:443:host.com
                if ($bindingInfoAndHost -match '^(.+?:.+?:)(.+)$') { # Matches *:443:host.com or similar
                    $hostHeader = $Matches[2].Trim()
                }

                # We log the raw appcmd derived values for debugging
                Write-Log "    Parsed appcmd Binding - Protocol: '$protocol', Info: '$bindingInformation', Host: '$hostHeader', Assumed SslFlags: '$sslFlags'"

                # Now process HTTPS bindings
                if ($protocol.ToLowerInvariant() -eq "https") {
                    Write-Log "  Found existing HTTPS binding for host: '$hostHeader' on port: '$bindingInformation' via appcmd."

                    if ($hostHeadersProcessed.ContainsKey($hostHeader)) {
                        Write-Log "  Skipping already processed host header: $hostHeader for site '$($site.Name)'" "INFO"
                        continue
                    }
                    $hostHeadersProcessed[$hostHeader] = $true # Mark as processed

                    # Use Get-WebBinding to get the full binding object to determine current certificate, IP, Port, and actual SslFlags
                    $currentWebBinding = Get-WebBinding -Name $site.Name -Protocol "https" -BindingInformation "$bindingInformation" -ErrorAction SilentlyContinue

                    if ($null -eq $currentWebBinding) {
                        Write-Log "    Could not find matching WebAdministration binding object for HTTPS binding: $bindingInformation (Host: $hostHeader). Skipping." "WARN"
                        continue
                    }

                    # Extract actual values from the WebAdministration object as it's more reliable for these details
                    $ipAddress = $currentWebBinding.ipAddress
                    $port = $currentWebBinding.port
                    $hostHeaderFromWebBinding = $currentWebBinding.Host # Use this as it's definitive
                    $numericSslFlags = [int]$currentWebBinding.SslFlags # Use actual SslFlags from the object

                    # Re-evaluate hostHeader based on the WebAdministration object, which is more reliable
                    # For `appcmd set site`, an empty host header is just "", not a space
                    if ([string]::IsNullOrEmpty($hostHeaderFromWebBinding)) { $hostHeaderFromWebBinding = "" }


                    Write-Log "    Retrieved WebBinding details - IP: '$ipAddress', Port: '$port', Host: '$hostHeaderFromWebBinding', SslFlags: '$numericSslFlags'"


                    # Find the latest valid certificate for this binding.
                    $latestCert = $null
                    try {
                        $certsInStore = Get-ChildItem -Path $certStorePath | Where-Object { $_.NotAfter -gt (Get-Date) } | Sort-Object -Property NotAfter -Descending

                        if ([string]::IsNullOrEmpty($hostHeaderFromWebBinding)) {
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
                                    ($_.Subject -like "*CN=$hostHeaderFromWebBinding*") -or # Match CN directly
                                    ($_.DnsNames -contains $hostHeaderFromWebBinding) -or # Match SANs
                                    ($_.DnsNames -contains "*.$hostHeaderFromWebBinding" -and $hostHeaderFromWebBinding -notlike "www.*") -or # Match wildcard SAN for subdomain
                                    ("www.$hostHeaderFromWebBinding" -in $_.DnsNames) # Handle www. conversion for SANs
                                } | Select-Object -First 1
                        }
                    } catch {
                        Write-Log "  Error searching for certificate for host '$hostHeaderFromWebBinding': $($_.Exception.Message)" "ERROR"
                        continue
                    }

                    if ($null -eq $latestCert) {
                        Write-Log "  No suitable valid certificate found in '$certStorePath' for host header '$hostHeaderFromWebBinding'. Current binding will be kept as is." "WARN"
                        continue
                    }

                    Write-Log "  Found target certificate: Subject = '$($latestCert.Subject)', FriendlyName = '$($latestCert.FriendlyName)', Thumbprint = '$($latestCert.Thumbprint)', NotAfter = '$($latestCert.NotAfter)'"

                    # Get current binding's certificate hash using Get-WebBinding directly
                    $currentCertHash = ""
                    if ($currentWebBinding -and ($currentWebBinding.CertificateHash | Select-Object -ExpandProperty Value)) {
                         $currentCertHash = ($currentWebBinding.CertificateHash | Select-Object -ExpandProperty Value) -as [string] | ForEach-Object { $_.Trim() }
                    }

                    # Check if the current binding uses the latest cert
                    if ($currentCertHash -ne $latestCert.Thumbprint) { 
                        Write-Log "  Binding for host '$hostHeaderFromWebBinding' on port '$port' is using an old certificate. Updating to new thumbprint: $($latestCert.Thumbprint)" "WARN"
                        try {
                            # Construct the bindingInformation string for appcmd.exe, including the host header if present
                            $appcmdBindingInformation = "$ipAddress`:$port"
                            if (-not [string]::IsNullOrEmpty($hostHeaderFromWebBinding)) {
                                $appcmdBindingInformation += ":$hostHeaderFromWebBinding"
                            }
                            
                            # Construct the appcmd command using triple quotes for easier embedding of required double quotes for appcmd.
                            # Example appcmd format: appcmd set site "MySite" /bindings.[protocol='https',bindingInformation='*:443:example.com'].sslFlags:0 /bindings.[protocol='https',bindingInformation='*:443:example.com'].certificateStoreName:My /bindings.[protocol='https',bindingInformation='*:443:example.com'].certificateHash:THUMBPRINT
                            
                            $appcmdCommand = "$appCmdPath set site ""$($site.Name)"" /bindings.[protocol='https',bindingInformation='$appcmdBindingInformation'].sslFlags:$numericSslFlags /bindings.[protocol='https',bindingInformation='$appcmdBindingInformation'].certificateStoreName:$($certStorePath.Split('\')[-1]) /bindings.[protocol='https',bindingInformation='$appcmdBindingInformation'].certificateHash:$($latestCert.Thumbprint)"
                            
                            Write-Log "    Executing appcmd: $appcmdCommand"
                            $appcmdResult = Invoke-Expression $appcmdCommand -ErrorAction Stop

                            Write-Log "    appcmd.exe update result: $($appcmdResult | Out-String)"
                            Write-Log "    Successfully updated binding for '$hostHeaderFromWebBinding' to certificate $($latestCert.Thumbprint) using appcmd.exe."
                        } catch {
                            Write-Log "    Failed to update binding for host '$hostHeaderFromWebBinding' on website '$($site.Name)' using appcmd.exe: $($_.Exception.Message)" "ERROR"
                        }
                    } else {
                        Write-Log "  Binding for host '$hostHeaderFromWebBinding' on port '$port' is already using the correct certificate. No update needed." "INFO"
                    }
                }
            }
        }
    }
}
#endregion

Write-Log "IIS SSL Binding Auto-Update Script finished."
exit 0
