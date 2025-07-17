// Define parameters for your deployment
param vmName string        // The name of your existing VM
param location string      // The location of your existing VM
param resourceGroupName string // The resource group where your VM exists

// This is the core parameter that will hold your list of certificates for the KV extension
param observedCertificates array = [] 

// PARAMETER for Custom Script Extension
param iisScriptFileUri string // URI to the PowerShell script (e.g., raw GitHub URL or Blob Storage SAS URL)

// NEW PARAMETER: To force Custom Script Extension re-execution
param forceIisScriptUpdateTag string = newGuid() // Use newGuid() as a default value here

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
  
  // CORRECT PLACEMENT for dependsOn: Direct under the resource, not inside 'properties'
  dependsOn: [
    keyVaultExtension
  ]

  properties: {
    publisher: 'Microsoft.Compute'
    type: 'CustomScriptExtension'
    typeHandlerVersion: '1.9' // For Windows VMs, typically 1.9 or later
    autoUpgradeMinorVersion: true
    
    // Use the new parameter here
    forceUpdateTag: forceIisScriptUpdateTag // Now references the parameter

    settings: {
      fileUris: [
        iisScriptFileUri
      ]
      commandToExecute: 'powershell.exe -ExecutionPolicy Unrestricted -File ${last(split(iisScriptFileUri, '/'))}'
    }
  }
}
