resource "azurerm_storage_account" "sa" {
  name                      = "fixturesa"
  resource_group_name       = "fixture-rg"
  location                  = "eastus"
  enable_https_traffic_only = false
}

resource "azurerm_key_vault" "kv" {
  name                = "fixture-kv"
  resource_group_name = "fixture-rg"
  location            = "eastus"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
}
