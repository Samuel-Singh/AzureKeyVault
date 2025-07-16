// Define parameters for your deployment
param resourceGroupName string // The resource group where your VM exists
param vmName string            // The name of your existing VM
// We need the location of the VM to deploy the extension
// We can either pass it as a parameter, or get it from the 'vm' resource later.
// Let's pass it as a parameter to ensure it's explicitly available.
param location string

// This is the core parameter that will hold your list of certificates
// Each item in the array should match the structure of an observed certificate
param observedCertificates array = []

// --- Existing VM Resource Reference ---
// Remove the 'scope' property as the deployment itself targets the resource group,
// and this 'existing' resource is implicitly within that scope.
resource vm 'Microsoft.Compute/virtualMachines@2024-11-01' existing = {
  name: vmName
}

// --- Key Vault VM Extension Resource Definition ---
resource keyVaultExtension 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = {
  name: 'KeyVaultForWindows'
  parent: vm
  location: location // Use the location passed in or directly from vm.location if not a param

  properties: {
    publisher: 'Microsoft.Azure.KeyVault'
    type: 'KeyVaultForWindows'
    typeHandlerVersion: '3.0'
    autoUpgradeMinorVersion: true

    settings: {
      secretsManagementSettings: {
        pollingIntervalInS: '1800'
        observedCertificates: [for cert in observedCertificates: {
          url: cert.url
          certificateStoreName: cert.certificateStoreName
          certificateStoreLocation: cert.url
        }]
      }
    }
  }
}
