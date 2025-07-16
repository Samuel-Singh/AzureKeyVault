// Define parameters for your deployment
param resourceGroupName string // The resource group where your VM exists
param vmName string         // The name of your existing VM
param location string = resourceGroup(resourceGroupName).location // Use the RG's location by default

// This is the core parameter that will hold your list of certificates
// Each item in the array should match the structure of an observed certificate
param observedCertificates array = []

// --- Existing VM Resource Reference ---
resource vm 'Microsoft.Compute/virtualMachines@2024-11-01' existing = {
  name: vmName
  scope: resourceGroup(resourceGroupName)
}

// --- Key Vault VM Extension Resource Definition ---
resource keyVaultExtension 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = {
  name: 'KeyVaultForWindows' // <--- Static value for the Key Vault extension
  parent: vm
  location: location

  properties: {
    publisher: 'Microsoft.Azure.KeyVault' // <--- Static value for the Key Vault extension publisher
    type: 'KeyVaultForWindows'             // <--- Static value for the Key Vault extension type
    typeHandlerVersion: '3.0'              // <--- Needs to be verified/updated
    autoUpgradeMinorVersion: true

    settings: {
      secretsManagementSettings: {
        pollingIntervalInS: '1800' // <--- Configurable value (30 minutes in this case)
        observedCertificates: [for cert in observedCertificates: {
          url: cert.url                           // <--- From your parameter file
          certificateStoreName: cert.certificateStoreName // <--- From your parameter file
          certificateStoreLocation: cert.certificateStoreLocation // <--- From your parameter file
        }]
      }
    }
  }
}
