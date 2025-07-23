// Define parameters for your deployment
param vmName string     // The name of your existing VM
param location string   // The location of your existing VM
// param resourceGroupName string // The resource group where your VM exists -- REMOVE THIS LINE

// This is the core parameter that will hold your list of certificates for the KV extension
param observedCertificates array = []

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
