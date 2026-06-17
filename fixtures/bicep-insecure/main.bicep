// Deliberately-insecure Bicep fixture for cloud-controls tests.
resource sa 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: 'fixturesa'
  location: 'eastus'
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: false
    minimumTlsVersion: 'TLS1_0'
  }
}

resource sql 'Microsoft.Sql/servers@2022-05-01-preview' = {
  name: 'fixture-sql'
  location: 'eastus'
  properties: {
    administratorLogin: 'sqladmin'
    publicNetworkAccess: 'Enabled'
  }
}
