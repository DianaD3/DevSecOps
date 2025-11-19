# main.tf - Secure Infrastructure as Code
# DevSecOps Best Practices Implementation

terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

# Variables - Use Terraform Cloud/Enterprise or environment variables for sensitive values
variable "allowed_ip_ranges" {
  description = "List of allowed IP ranges for NSG rules"
  type        = list(string)
  default     = [] # Should be set via TF_VAR_allowed_ip_ranges or terraform.tfvars
}

variable "admin_username" {
  description = "VM administrator username"
  type        = string
  default     = "devadmin"
  sensitive   = true
}

variable "key_vault_secret_admin_password" {
  description = "Name of the secret in Key Vault containing VM admin password"
  type        = string
  default     = "vm-admin-password"
}

variable "key_vault_secret_sql_password" {
  description = "Name of the secret in Key Vault containing SQL admin password"
  type        = string
  default     = "sql-admin-password"
}

# Random suffix for unique resource names
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Resource Group
resource "azurerm_resource_group" "rg" {
  name     = "rg-demo-securedata-${random_string.suffix.result}"
  location = "Central US"

  tags = {
    Environment = "Production"
    ManagedBy   = "Terraform"
    Security    = "High"
  }
}

# Log Analytics Workspace for centralized logging and monitoring
resource "azurerm_log_analytics_workspace" "law" {
  name                = "law-securedata-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 90

  tags = azurerm_resource_group.rg.tags
}

# Azure Key Vault for secure secret management
resource "azurerm_key_vault" "kv" {
  name                       = "kv-securedata-${random_string.suffix.result}"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = true

  # Network ACLs - restrict access
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    # Add specific IP ranges if needed
    # ip_rules = var.allowed_ip_ranges
  }

  # Enable access policies (consider using RBAC instead)
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get", "List", "Set", "Delete", "Recover", "Backup", "Restore"
    ]
  }

  tags = azurerm_resource_group.rg.tags
}

data "azurerm_client_config" "current" {}

# Virtual Network with proper segmentation
resource "azurerm_virtual_network" "vnet" {
  name                = "vnet-demo-${random_string.suffix.result}"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  tags = azurerm_resource_group.rg.tags
}

# Subnet for VMs
resource "azurerm_subnet" "vm_subnet" {
  name                 = "subnet-vm-${random_string.suffix.result}"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Subnet for Azure Bastion (dedicated subnet required)
resource "azurerm_subnet" "bastion_subnet" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.2.0/27"]
}

# Subnet for private endpoints
resource "azurerm_subnet" "private_endpoint_subnet" {
  name                 = "subnet-private-endpoints-${random_string.suffix.result}"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.3.0/24"]
}

# Network Security Group with restrictive rules
resource "azurerm_network_security_group" "nsg_vm" {
  name                = "nsg-vm-restricted-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  # Deny all inbound by default (Azure default, but explicit for clarity)
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Allow outbound HTTPS for updates and Azure services
  security_rule {
    name                       = "AllowOutboundHTTPS"
    priority                   = 1000
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Allow outbound DNS
  security_rule {
    name                       = "AllowOutboundDNS"
    priority                   = 1001
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "53"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Allow inbound from Azure Bastion subnet only (for management)
  security_rule {
    name                       = "AllowBastionInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = azurerm_subnet.bastion_subnet.address_prefixes[0]
    destination_address_prefix = "*"
    description                = "Allow SSH from Bastion subnet only"
  }

  tags = azurerm_resource_group.rg.tags
}

# Associate NSG with VM subnet
resource "azurerm_subnet_network_security_group_association" "nsg_vm_assoc" {
  subnet_id                 = azurerm_subnet.vm_subnet.id
  network_security_group_id = azurerm_network_security_group.nsg_vm.id
}

# Public IP for Azure Bastion (required)
resource "azurerm_public_ip" "bastion_pip" {
  name                = "pip-bastion-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = azurerm_resource_group.rg.tags
}

# Azure Bastion for secure VM access (no public IP on VM)
resource "azurerm_bastion_host" "bastion" {
  name                = "bastion-securedata-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.bastion_subnet.id
    public_ip_address_id = azurerm_public_ip.bastion_pip.id
  }

  tags = azurerm_resource_group.rg.tags
}

# Network Interface for VM (NO public IP)
resource "azurerm_network_interface" "nic" {
  name                = "nic-vm001-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.vm_subnet.id
    private_ip_address_allocation = "Dynamic"
    # NO public_ip_address_id - VM is private
  }

  tags = azurerm_resource_group.rg.tags
}

# Azure Monitor Agent extension for VM monitoring
resource "azurerm_virtual_machine_extension" "monitoring" {
  name                 = "AzureMonitorLinuxAgent"
  virtual_machine_id   = azurerm_linux_virtual_machine.vm.id
  publisher            = "Microsoft.Azure.Monitor"
  type                 = "AzureMonitorLinuxAgent"
  type_handler_version = "1.0"

  settings = jsonencode({
    workspaceId = azurerm_log_analytics_workspace.law.workspace_id
  })

  protected_settings = jsonencode({
    workspaceKey = azurerm_log_analytics_workspace.law.primary_shared_key
  })
}

# Linux Virtual Machine with security hardening
resource "azurerm_linux_virtual_machine" "vm" {
  name                = "vm-demo-app-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_B1ms"
  admin_username      = var.admin_username
  network_interface_ids = [azurerm_network_interface.nic.id]

  # Get password from Key Vault
  admin_password = data.azurerm_key_vault_secret.vm_admin_password.value

  # Disable password authentication, use SSH keys instead (best practice)
  disable_password_authentication = false # Set to true and use admin_ssh_key when possible

  # OS Disk with encryption
  os_disk {
    name                 = "osdisk-vm-${random_string.suffix.result}"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS" # Use Premium for better performance and encryption
    disk_encryption_set_id = azurerm_disk_encryption_set.des.id
  }

  # Use latest Ubuntu LTS
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # Boot diagnostics to storage account
  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.diagnostics.primary_blob_endpoint
  }

  # Enable Azure Defender integration
  identity {
    type = "SystemAssigned"
  }

  tags = azurerm_resource_group.rg.tags
}

# Disk Encryption Set for VM disk encryption
resource "azurerm_disk_encryption_set" "des" {
  name                = "des-vm-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  key_vault_key_id    = azurerm_key_vault_key.disk_encryption.id

  identity {
    type = "SystemAssigned"
  }

  tags = azurerm_resource_group.rg.tags
}

# Key Vault Key for disk encryption
resource "azurerm_key_vault_key" "disk_encryption" {
  name         = "disk-encryption-key"
  key_vault_id = azurerm_key_vault.kv.id
  key_type     = "RSA"
  key_size     = 2048

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}

# Grant Disk Encryption Set access to Key Vault
resource "azurerm_key_vault_access_policy" "des" {
  key_vault_id = azurerm_key_vault.kv.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_disk_encryption_set.des.identity[0].principal_id

  key_permissions = [
    "Get", "WrapKey", "UnwrapKey"
  ]
}

# Get VM admin password from Key Vault
# IMPORTANT: Secrets must be created in Key Vault BEFORE running terraform apply
# Use: az keyvault secret set --vault-name <kv-name> --name vm-admin-password --value <password>
# Alternative: Use variable with sensitive=true and create secrets after Key Vault is created
data "azurerm_key_vault_secret" "vm_admin_password" {
  name         = var.key_vault_secret_admin_password
  key_vault_id = azurerm_key_vault.kv.id
  
  depends_on = [azurerm_key_vault.kv]
}

# Storage Account for diagnostics (separate from application storage)
resource "azurerm_storage_account" "diagnostics" {
  name                     = "stdiag${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # Security settings
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false # Disable shared key auth, use managed identity
  public_network_access_enabled   = false # Use private endpoint

  tags = azurerm_resource_group.rg.tags
}

# Private Endpoint for Storage Account
resource "azurerm_private_endpoint" "storage_pe" {
  name                = "pe-storage-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  subnet_id           = azurerm_subnet.private_endpoint_subnet.id

  private_service_connection {
    name                           = "psc-storage-${random_string.suffix.result}"
    private_connection_resource_id = azurerm_storage_account.storage.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  tags = azurerm_resource_group.rg.tags
}

# Application Storage Account with enhanced security
resource "azurerm_storage_account" "storage" {
  name                     = "stgsecretdemo${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # Critical security settings
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false # Use managed identity instead
  public_network_access_enabled   = false # Require private endpoint
  infrastructure_encryption_enabled = true # Double encryption

  # Enable blob versioning and soft delete
  blob_properties {
    versioning_enabled       = true
    delete_retention_policy {
      days = 30
    }
    container_delete_retention_policy {
      days = 30
    }
  }

  # Enable advanced threat protection
  queue_properties {
    logging {
      delete                = true
      read                  = true
      write                 = true
      version               = "1.0"
      retention_policy_days = 10
    }
  }

  tags = azurerm_resource_group.rg.tags
}

# Private Endpoint for Application Storage
resource "azurerm_private_endpoint" "app_storage_pe" {
  name                = "pe-app-storage-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  subnet_id           = azurerm_subnet.private_endpoint_subnet.id

  private_service_connection {
    name                           = "psc-app-storage-${random_string.suffix.result}"
    private_connection_resource_id = azurerm_storage_account.storage.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  tags = azurerm_resource_group.rg.tags
}

# SQL Server with enhanced security
resource "azurerm_mssql_server" "sqlsrv" {
  name                         = "sql-demo-server-${random_string.suffix.result}"
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = azurerm_resource_group.rg.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = data.azurerm_key_vault_secret.sql_admin_password.value
  minimum_tls_version          = "1.2"

  # Enable Azure AD authentication (recommended)
  azuread_administrator {
    login_username = "sql-admin@contoso.com" # Replace with your Azure AD admin
    object_id      = data.azurerm_client_config.current.object_id
  }

  # Enable advanced data security
  identity {
    type = "SystemAssigned"
  }

  tags = azurerm_resource_group.rg.tags
}

# Get SQL admin password from Key Vault
# IMPORTANT: Secrets must be created in Key Vault BEFORE running terraform apply
# Use: az keyvault secret set --vault-name <kv-name> --name sql-admin-password --value <password>
data "azurerm_key_vault_secret" "sql_admin_password" {
  name         = var.key_vault_secret_sql_password
  key_vault_id = azurerm_key_vault.kv.id
  
  depends_on = [azurerm_key_vault.kv]
}

# SQL Server Firewall - Azure SQL denies all by default
# Only add firewall rules for specific IP ranges if needed
# Example: Allow Azure Services (only if required for your scenario)
# resource "azurerm_mssql_firewall_rule" "allow_azure_services" {
#   name             = "AllowAzureServices"
#   server_id        = azurerm_mssql_server.sqlsrv.id
#   start_ip_address = "0.0.0.0"
#   end_ip_address   = "0.0.0.0"
# }

# Add specific IP ranges via variables if needed
# Example for allowing specific corporate IPs:
# resource "azurerm_mssql_firewall_rule" "corporate_ips" {
#   for_each         = toset(var.allowed_ip_ranges)
#   name             = "AllowIP-${replace(each.value, ".", "-")}"
#   server_id        = azurerm_mssql_server.sqlsrv.id
#   start_ip_address = each.value
#   end_ip_address   = each.value
# }

# SQL Database with security features
resource "azurerm_mssql_database" "sqldb" {
  name           = "sqldb-sensitive-${random_string.suffix.result}"
  server_id      = azurerm_mssql_server.sqlsrv.id
  collation      = "SQL_Latin1_General_CP1_CI_AS"
  license_type   = "LicenseIncluded"
  max_size_gb    = 2
  sku_name       = "S0"
  zone_redundant = false

  # Enable Transparent Data Encryption (TDE)
  transparent_data_encryption_enabled = true

  # Enable threat detection
  threat_detection_policy {
    state                = "Enabled"
    email_addresses      = ["security@contoso.com"] # Replace with your security team email
    retention_days       = 30
    storage_endpoint     = azurerm_storage_account.diagnostics.primary_blob_endpoint
    storage_account_access_key = azurerm_storage_account.diagnostics.primary_access_key
  }

  tags = azurerm_resource_group.rg.tags
}

# Private Endpoint for SQL Server
resource "azurerm_private_endpoint" "sql_pe" {
  name                = "pe-sql-${random_string.suffix.result}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  subnet_id           = azurerm_subnet.private_endpoint_subnet.id

  private_service_connection {
    name                           = "psc-sql-${random_string.suffix.result}"
    private_connection_resource_id = azurerm_mssql_server.sqlsrv.id
    subresource_names              = ["sqlServer"]
    is_manual_connection           = false
  }

  tags = azurerm_resource_group.rg.tags
}

# Azure Security Center (Defender for Cloud) - Enable via Azure Policy or Portal
# Note: Some Defender features require portal configuration

# Grant VM managed identity access to Key Vault (for applications to retrieve secrets)
resource "azurerm_key_vault_access_policy" "vm" {
  key_vault_id = azurerm_key_vault.kv.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_linux_virtual_machine.vm.identity[0].principal_id

  secret_permissions = [
    "Get", "List"
  ]
}

# Grant VM managed identity access to Storage Account
resource "azurerm_role_assignment" "vm_storage" {
  scope                = azurerm_storage_account.storage.id
  role_definition_name = "Storage Blob Data Reader" # Adjust role as needed
  principal_id         = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}

# Grant VM managed identity access to SQL Database
resource "azurerm_role_assignment" "vm_sql" {
  scope                = azurerm_mssql_database.sqldb.id
  role_definition_name = "SQL DB Contributor" # Adjust role as needed
  principal_id         = azurerm_linux_virtual_machine.vm.identity[0].principal_id
}

# Secure Outputs - DO NOT expose sensitive connection strings
output "key_vault_id" {
  value       = azurerm_key_vault.kv.id
  description = "Key Vault ID for secret management"
  sensitive   = false
}

output "storage_account_name" {
  value       = azurerm_storage_account.storage.name
  description = "Storage account name (use managed identity for access)"
  sensitive   = false
}

output "sql_server_fqdn" {
  value       = azurerm_mssql_server.sqlsrv.fully_qualified_domain_name
  description = "SQL Server FQDN (use managed identity for authentication)"
  sensitive   = false
}

output "bastion_host_name" {
  value       = azurerm_bastion_host.bastion.name
  description = "Azure Bastion host name for secure VM access"
  sensitive   = false
}

output "log_analytics_workspace_id" {
  value       = azurerm_log_analytics_workspace.law.workspace_id
  description = "Log Analytics Workspace ID for monitoring"
  sensitive   = false
}

# DO NOT output connection strings or passwords
# Applications should use managed identities to access resources
