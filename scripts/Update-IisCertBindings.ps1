# scripts/Update-IisCertBindings.ps1

# This script updates IIS HTTPS bindings to use the newest valid certificates
# found in the LocalMachine\My certificate store.
# All informational messages are written to StandardError,
# and the final output (summary of site updates) is written to StandardOutput as JSON.

# Requires the Microsoft.Web.Administration assembly (usually available on systems with IIS)

# Write initial message to StandardError (for logging, not for JSON output)
Write-Host "Starting IIS Certificate Binding Update script using Microsoft.Web.Administration..." -Stream StandardError

# Array to hold structured results for each site processed
$siteResults = @()

try {
    # Load the Microsoft.Web.Administration assembly
    # Using explicit path for robustness. If this path differs on your VMs, adjust it.
    Add-Type -Path "C:\Windows\System32\inetsrv\Microsoft.Web.Administration.dll" -ErrorAction Stop
    Write-Host "Microsoft.Web.Administration assembly loaded successfully." -Stream StandardError

    # Create a ServerManager object to interact with IIS configuration
    $iisManager = New-Object Microsoft.Web.Administration.ServerManager
    Write-Host "ServerManager object created." -Stream StandardError

    # Iterate through all websites in IIS
    foreach ($site in $iisManager.Sites) {
        Write-Host "`n--- Processing Website: $($site.Name) ---" -Stream StandardError

        # Variables to track status for the current site for the JSON output
        $currentSiteStatus = "No HTTPS bindings found or processed" # Default
        $currentSiteDetails = "No HTTPS bindings were found or processed for this site."
        $bindingUpdatedForSite = $false # Flag to track if any binding was updated for the current site

        # Get all HTTPS bindings for the current website
        $httpsBindings = $site.Bindings | Where-Object { $_.Protocol -eq "https" }

        if (-not $httpsBindings) {
            Write-Host "  No HTTPS bindings found for site '$($site.Name)'. Skipping." -Stream StandardError
            # Add to results even if no HTTPS bindings, to be explicit in report
            $siteResults += [PSCustomObject]@{
                SiteName = $site.Name
                Status   = $currentSiteStatus
                Details  = $currentSiteDetails
            }
            continue # Move to the next site if no HTTPS bindings are found
        }
        
        # If HTTPS bindings are found, set initial status and details assuming no update yet
        $currentSiteStatus = "No Changes Needed"
        $currentSiteDetails = "All applicable HTTPS bindings for this site were already up-to-date."


        foreach ($binding in $httpsBindings) {
            # --- Extract Host Header, IP, and Port from BindingInformation ---
            $bindingInfo = $binding.BindingInformation
            $hostHeader = ""
            $currentIpAddress = "*" # Default IP, will be parsed if present
            $currentPort = 443      # Default Port, will be parsed if present

            # Regex to parse binding information (e.g., "192.168.1.1:443:www.example.com" or "*:443:hostname")
            if ($bindingInfo -match '^(?<ip>.+?):(?<port>\d+)(?::(?<host>.*))?$') {
                $currentIpAddress = $Matches.ip
                $currentPort = $Matches.port
                $hostHeader = $Matches.host # This will be an empty string if no host header (IP-based binding)
            } else {
                Write-Warning "  Could not parse binding information '$bindingInfo' for site '$($site.Name)'. Skipping this binding." -Stream StandardError
                # If a parsing error occurs for a binding, update overall site details
                $currentSiteDetails = "Binding parsing error for '$bindingInfo': $($_.Exception.Message)"
                continue
            }

            Write-Host "  DEBUG: Processing binding info: '$bindingInfo' (IP: '$currentIpAddress', Port: '$currentPort', Host: '$hostHeader')" -Stream StandardError

            # For certificates typically from Key Vault (issued for hostnames), we focus on SNI bindings.
            # Bindings without a host header are non-SNI/IP-based default SSL sites, which might have different update logic.
            if ([string]::IsNullOrEmpty($hostHeader) -or [string]::IsNullOrWhiteSpace($hostHeader)) {
                Write-Host "  Skipping HTTPS binding '$bindingInfo' on site '$($site.Name)' because it lacks a host header (non-SNI). This script primarily targets host-header bindings." -Stream StandardError
                continue
            }

            Write-Host "  Processing HTTPS binding for Host: $hostHeader (Site: $($site.Name))" -Stream StandardError

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
                Write-Host "    No valid certificate found in LocalMachine\My store for host '$hostHeader'. Current binding will not be updated." -Stream StandardError
                # Update site details if no cert is found for a relevant binding
                $currentSiteDetails = "No valid certificate found for '$hostHeader'. Binding skipped."
                continue # Move to the next binding
            }

            $newCert = $certs[0] # Get the newest, valid certificate (due to Sort-Object NotAfter -Descending)
            Write-Host "    Found newest valid certificate for '$hostHeader':" -Stream StandardError
            Write-Host "      Subject: $($newCert.Subject)" -Stream StandardError
            Write-Host "      Thumbprint: $($newCert.Thumbprint)" -Stream StandardError
            Write-Host "      NotAfter: $($newCert.NotAfter)" -Stream StandardError

            # Get the current binding's certificate hash as a string for comparison
            $currentBindingHash = ""
            if ($binding.CertificateHash) {
                $currentBindingHash = [System.BitConverter]::ToString($binding.CertificateHash).Replace("-", "").ToUpper()
            }

            if ($currentBindingHash -eq $newCert.Thumbprint.ToUpper()) {
                Write-Host "    Binding for '$hostHeader' already uses the newest certificate. No update needed." -Stream StandardError
            } else {
                Write-Host "    Outdated certificate found for '$hostHeader'. Updating binding..." -Stream StandardError

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
                    Write-Host "    Successfully updated binding for '$hostHeader' on site '$($site.Name)'." -Stream StandardError
                    $bindingUpdatedForSite = $true # Mark that an update occurred for this site
                    
                    # If any binding on the site is updated, the site's overall status should reflect this.
                    $currentSiteStatus = "Changes Applied Successfully"
                    $currentSiteDetails = "Certificate binding updated for host '$hostHeader'. New thumbprint: $($newCert.Thumbprint)."

                } catch {
                    Write-Error "    Error updating binding for '$hostHeader' on site '$($site.Name)': $($_.Exception.Message)" -Stream StandardError
                    if ($_.Exception.InnerException) {
                        Write-Error "    Inner Exception: $($_.Exception.InnerException.Message)" -Stream StandardError
                    }
                    # If an error occurs during update, set status to reflect that for the site.
                    $currentSiteStatus = "Error During Update"
                    $currentSiteDetails = "Failed to update binding for '$hostHeader'. Error: $($_.Exception.Message)"
                }
            }
        } # End foreach $binding

        # Application Pool Recycling Logic for the current site
        # This block runs only if at least one binding in the current site was updated.
        if ($bindingUpdatedForSite) {
            Write-Host "  Attempting to recycle application pool for site '$($site.Name)'..." -Stream StandardError
            
            # Try to load WebAdministration module if not already loaded
            if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
                try {
                    Import-Module WebAdministration -ErrorAction SilentlyContinue
                    Write-Host "  WebAdministration module loaded successfully (for app pool management)." -Stream StandardError
                } catch {
                    Write-Warning "  Could not load WebAdministration module for app pool management. Application pool recycling might fail for site '$($site.Name)'." -Stream StandardError
                    # If app pool module can't load, add to site details/status
                    if ($currentSiteStatus -ne "Error During Update") { # Don't overwrite a more critical error
                        $currentSiteDetails += " Note: Could not load WebAdministration module for app pool recycling."
                    }
                }
            }

            # Check if Get-WebAppPool cmdlet is available after module import attempts
            if (Get-Command -Name Get-WebAppPool -ErrorAction SilentlyContinue) {
                $appPool = $site.Applications["/"].ApplicationPool
                if ($appPool) {
                    Write-Host "  Recycling application pool '$($appPool.Name)'..." -Stream StandardError
                    try {
                        Restart-WebAppPool -Name $appPool.Name -ErrorAction Stop
                        Write-Host "  Application pool '$($appPool.Name)' recycled successfully for site '$($site.Name)'." -Stream StandardError
                        if ($currentSiteStatus -eq "Changes Applied Successfully") {
                            $currentSiteDetails += " Application pool successfully recycled."
                        }
                    } catch {
                        Write-Warning "  Failed to recycle application pool '$($appPool.Name)'. Error: $($_.Exception.Message). Manual recycling might be needed for site '$($site.Name)'." -Stream StandardError
                        # If app pool recycling fails after an update, set an appropriate status
                        if ($currentSiteStatus -ne "Error During Update") {
                            $currentSiteStatus = "Changes Applied, AppPool Issue" # New status for this specific case
                        }
                        $currentSiteDetails += " App pool recycling failed: $($_.Exception.Message)."
                    }
                } else {
                    Write-Warning "  Could not find application pool for site '$($site.Name)'. Manual recycling might be needed." -Stream StandardError
                    if ($currentSiteStatus -ne "Error During Update") {
                        $currentSiteStatus = "Changes Applied, AppPool Issue"
                    }
                    $currentSiteDetails += " No application pool found for recycling."
                }
            } else {
                Write-Warning "  Get-WebAppPool cmdlet is not available. Manual application pool recycling will be needed for site '$($site.Name)' if bindings were updated." -Stream StandardError
                if ($currentSiteStatus -ne "Error During Update") {
                    $currentSiteStatus = "Changes Applied, AppPool Issue"
                }
                $currentSiteDetails += " Get-WebAppPool cmdlet not available for app pool recycling."
            }
        } else {
            Write-Host "  No bindings updated for site '$($site.Name)'. Application pool recycling skipped." -Stream StandardError
        }
        
        # Add the final result for this site to the array
        # This ensures every site processed (or skipped due to no HTTPS bindings) is in the report
        $siteResults += [PSCustomObject]@{
            SiteName = $site.Name
            Status   = $currentSiteStatus
            Details  = $currentSiteDetails
        }

    } # End foreach $site

} # End outer try block
catch {
    Write-Error "An unhandled error occurred during IIS binding update process: $($_.Exception.Message)" -Stream StandardError
    if ($_.Exception.InnerException) {
        Write-Error "Inner Exception: $($_.Exception.InnerException.Message)" -Stream StandardError
    }
    
    # In case of a critical unhandled error, ensure something is output to stdout,
    # even if it's an error object, so the GitHub Actions YAML doesn't fail on empty stdout.
    # It's better to provide an empty JSON array or an error object as JSON.
    # For now, we will just let the script exit with an error code, and the YAML will catch stderr.
    $siteResults += [PSCustomObject]@{
        SiteName = "Overall Script Error"
        Status   = "Critical Failure"
        Details  = "An unhandled error occurred: $($_.Exception.Message). Check stderr for more details."
    }
    
    # Output any collected results before exiting on critical error
    $siteResults | ConvertTo-Json -Depth 5 -Compress
    exit 1 # Exit with a non-zero code to indicate overall script failure
}

Write-Host "`nIIS Certificate Binding Update script finished for all processed sites." -Stream StandardError

# Output the structured data as JSON to stdout
# This is the ONLY thing that should go to stdout for GitHub Actions to parse as JSON
$siteResults | ConvertTo-Json -Depth 5 -Compress # -Compress removes whitespace for smaller output
