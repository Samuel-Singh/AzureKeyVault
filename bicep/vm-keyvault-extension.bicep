// Define parameters for your deployment
param vmName string        // The name of your existing VM
param location string      // The location of your existing VM
param resourceGroupName string // The resource group where your VM exists

// This is the core parameter that will hold your list of certificates for the KV extension
param observedCertificates array = [] 

// PARAMETER for Custom Script Extension
param iisScriptFileUri string // URI to the PowerShell script (e.g., raw GitHub URL or Blob Storage SAS URL)

// --- Existing VM Resource Reference ---
resource vm 'Microsoft.Compute/virtualMachines@2024-11-01' existing = {
  name: vmName
}

// --- Key Vault VM Extension Resource Definition ---
resource keyVaultExtension 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = {
  name: 'KeyVaultForWindows'
  parent: vm
  location: location

  properties: {
    publisher: 'Microsoft.Azure.KeyVault'
    type: 'KeyVaultForWindows'
    typeHandlerVersion: '3.0'
    autoUpgradeMinorVersion: true

    settings: {
      secretsManagementSettings: {
        pollingIntervalInS: '300'
        observedCertificates: [for cert in observedCertificates: {
          url: cert.url
          certificateStoreName: cert.certificateStoreName
          certificateStoreLocation: cert.certificateStoreLocation
        }]
        linkOnRenewal: true
      }
    }
  }
}

// --- Custom Script Extension for IIS Binding ---
resource iisBindingScriptExtension 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = {
  // Use a GUID based on VM name and script URI for uniqueness and re-deployment if script changes
  name: 'iisBindingScript-${guid(vmName, iisScriptFileUri)}' 
  parent: vm
  location: location
  
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'CustomScriptExtension'
    typeHandlerVersion: '1.9' // For Windows VMs, typically 1.9 or later
    autoUpgradeMinorVersion: true
    
    // Ensure this runs AFTER the Key Vault extension has been configured.
    // The KV extension downloads certificates asynchronously, so the PS script should be robust.
    dependsOn: [
      keyVaultExtension
    ]

    settings: {
      fileUris: [
        iisScriptFileUri
      ]
      // No parameters are passed to the PowerShell script now, as it's self-sufficient
      commandToExecute: 'powershell.exe -ExecutionPolicy Unrestricted -File ${last(split(iisScriptFileUri, '/'))}'
    }
  }
}
