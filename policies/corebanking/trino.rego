package policies.corebanking.trino

default allow = false

# Metadata
table := "corebanking_vault_core_posting_summary__daily"
schema := "corebanking"
catalog := "gold"

# Allow roles (users from team)
allowed_users := { "@ikigaidigital/core-banking-bc", "kamil@ikigaidigital.io" }

# Allow SELECT queries for allowed users
allow {
  input.action.operation == "SelectFromColumns"
  input.action.resource.table.catalogName == catalog
  input.action.resource.table.schemaName == schema
  input.action.resource.table.tableName == table
  input.context.identity.user == allowed_users[_]
}
