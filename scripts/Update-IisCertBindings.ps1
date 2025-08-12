Write-Host "Starting IIS Certificate Binding Update script using Microsoft.Web.Administration..."

try {
    Add-Type -Path "C:\Windows\System32\inetsrv\Microsoft.Web.Administration.dll" -ErrorAction Stop
    Write-Host "Microsoft.Web.Administration assembly loaded successfully."

    # Create a ServerManager object to interact with IIS configuration
    $iisManager = New-Object Microsoft.Web.Administration.ServerManager
    Write-Host "ServerManager object created."

    # Iterate through all websites in IIS
    foreach ($site in $iisManager.Sites) {
        Write-Host "`n--- Processing Website: $($site.Name) ---"

        # Flag to track if any binding was updated for the current site, to control app pool recycling
        $bindingUpdatedForSite = $false 

        # Get all HTTPS bindings for the current website
        $httpsBindings = $site.Bindings | Where-Object { $_.Protocol -eq "https" }

        if (-not $httpsBindings) {
            Write-Host "  No HTTPS bindings found for site '$($site.Name)'. Skipping."
            continue # Move to the next site if no HTTPS bindings are found
        }

        foreach ($binding in $httpsBindings) {
            # --- Extract Host Header, IP, and Port from BindingInformation ---
            $bindingInfo = $binding.BindingInformation
            $hostHeader = ""
            $currentIpAddress = "*" # Default IP, will be parsed if present
            $currentPort = 443    # Default Port, will be parsed if present

            # Regex to parse binding information (e.g., "192.168.1.1:443:www.example.com" or "*:443:hostname")
            # This robustly extracts IP, Port, and HostHeader
            if ($bindingInfo -match '^(?<ip>.+?):(?<port>\d+)(?::(?<host>.*))?$') {
                $currentIpAddress = $Matches.ip
                $currentPort = $Matches.port
                $hostHeader = $Matches.host # This will be an empty string if no host header (IP-based binding)
            } else {
                Write-Warning "  Could not parse binding information '$bindingInfo' for site '$($site.Name)'. Skipping this binding."
                continue
            }

            Write-Host "  DEBUG: Processing binding info: '$bindingInfo' (IP: '$currentIpAddress', Port: '$currentPort', Host: '$hostHeader')"

            # For certificates typically from Key Vault (issued for hostnames), we focus on SNI bindings.
            # Bindings without a host header are non-SNI/IP-based default SSL sites, which might have different update logic.
            if ([string]::IsNullOrEmpty($hostHeader) -or [string]::IsNullOrWhiteSpace($hostHeader)) {
                Write-Host "  Skipping HTTPS binding '$bindingInfo' on site '$($site.Name)' because it lacks a host header (non-SNI). This script primarily targets host-header bindings."
                continue
            }

            Write-Host "  Processing HTTPS binding for Host: $hostHeader (Site: $($site.Name))"

            # Find the newest valid certificate in the LocalMachine\My store that matches the host header (via SAN or CN)
            $certs = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
                $isValidDate = ($_.NotAfter -gt (Get-Date) -and $_.NotBefore -le (Get-Date))
                $sanMatches = $false
                $cnMatches = $false

                # Check Subject Alternative Names (SAN)
                $sanExtension = $_.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
                if ($sanExtension) {
                    # Escape hostHeader for regex safety, and ensure it's a full match for an entry in SAN list
                    # SAN entries are often like "DNS Name=example.com, DNS Name=www.example.com"
                    $sanMatches = ($sanExtension.Format(0) -match "DNS Name=$([regex]::Escape($hostHeader))")
                }
                
                # Check Common Name (CN) as a fallback
                if ($_.Subject -match "CN=([^\,]+)" -and $Matches[1] -eq $hostHeader) {
                    $cnMatches = $true
                }

                # A certificate is a match if it's valid and its SAN or CN matches the host header
                $isValidDate -and ($sanMatches -or $cnMatches)
            } | Sort-Object NotAfter -Descending

            if ($certs.Count -eq 0) {
                Write-Host "    No valid certificate found in LocalMachine\My store for host '$hostHeader'. Current binding will not be updated."
                continue # Move to the next binding
            }

            $newCert = $certs[0] # Get the newest, valid certificate (due to Sort-Object NotAfter -Descending)
            Write-Host "    Found newest valid certificate for '$hostHeader':"
            Write-Host "      Subject: $($newCert.Subject)"
            Write-Host "      Thumbprint: $($newCert.Thumbprint)"
            Write-Host "      NotAfter: $($newCert.NotAfter)"

            # Get the current binding's certificate hash as a string for comparison
            $currentBindingHash = ""
            if ($binding.CertificateHash) {
                $currentBindingHash = [System.BitConverter]::ToString($binding.CertificateHash).Replace("-", "").ToUpper()
            }

            if ($currentBindingHash -eq $newCert.Thumbprint.ToUpper()) {
                Write-Host "    Binding for '$hostHeader' already uses the newest certificate. No update needed."
            } else {
                Write-Host "    Outdated certificate found for '$hostHeader'. Updating binding..."

                try {
                    # Convert the new certificate's thumbprint (hex string) to a byte array
                    $bytes = [System.Collections.Generic.List[byte]]::new()
                    for ($i = 0; $i -lt $newCert.Thumbprint.Length; $i += 2) {
                        $bytes.Add([byte]::Parse($newCert.Thumbprint.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber))
                    }
                    $binding.CertificateHash = $bytes.ToArray()
                    $binding.CertificateStoreName = "MY"
                    
                    # Ensure SslFlags is set correctly for SNI (1 for SNI). For host-header bindings, it should always be SNI.
                    $binding.SslFlags = 1 

                    $iisManager.CommitChanges() # This commits changes to applicationHost.config and http.sys
                    Write-Host "    Successfully updated binding for '$hostHeader' on site '$($site.Name)'."
                    $bindingUpdatedForSite = $true # Mark that an update occurred for this site
                } catch {
                    Write-Error "    Error updating binding for '$hostHeader' on site '$($site.Name)': $($_.Exception.Message)"
                    if ($_.Exception.InnerException) {
                        Write-Error "    Inner Exception: $($_.Exception.InnerException.Message)"
                    }
                }
            }
        } # End foreach $binding

        # This block runs only if at least one binding in the current site was updated.
        if ($bindingUpdatedForSite) {
            Write-Host "  Attempting to recycle application pool for site '$($site.Name)'..."
            
            # Try to load WebAdministration module if not already loaded
            if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
                try {
                    Import-Module WebAdministration -ErrorAction SilentlyContinue
                    Write-Host "  WebAdministration module loaded successfully (for app pool management)."
                } catch {
                    Write-Warning "  Could not load WebAdministration module for app pool management. Application pool recycling might fail for site '$($site.Name)'."
                }
            }

            # Check if Get-WebAppPool cmdlet is available after module import attempts
            if (Get-Command -Name Get-WebAppPool -ErrorAction SilentlyContinue) {
                $appPool = $site.Applications["/"].ApplicationPool
                if ($appPool) {
                    Write-Host "  Recycling application pool '$($appPool.Name)'..."
                    try {
                        Restart-WebAppPool -Name $appPool.Name -ErrorAction Stop
                        Write-Host "  Application pool '$($appPool.Name)' recycled successfully for site '$($site.Name)'."
                    } catch {
                        Write-Warning "  Failed to recycle application pool '$($appPool.Name)'. Error: $($_.Exception.Message). Manual recycling might be needed for site '$($site.Name)'."
                    }
                } else {
                    Write-Warning "  Could not find application pool for site '$($site.Name)'. Manual recycling might be needed."
                }
            } else {
                Write-Warning "  Get-WebAppPool cmdlet is not available. Manual application pool recycling will be needed for site '$($site.Name)' if bindings were updated."
            }
        } else {
            Write-Host "  No bindings updated for site '$($site.Name)'. Application pool recycling skipped."
        }

    } # End foreach $site

} # End outer try block
catch {
    Write-Error "An unhandled error occurred during IIS binding update process: $($_.Exception.Message)"
    if ($_.Exception.InnerException) {
        Write-Error "Inner Exception: $($_.Exception.InnerException.Message)"
    }
    exit 1
}

Write-Host "`nIIS Certificate Binding Update script finished for all processed sites."
