resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'insecurestorage'
  location: 'eastus'
  properties: {
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: false
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
}

resource ownerAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid('owner')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '8e3af657-a8ff-443c-a75c-2fe8c4bcb635')
    principalId: principalId
  }
}

resource contribAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid('contrib')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
    principalId: principalId
  }
}
