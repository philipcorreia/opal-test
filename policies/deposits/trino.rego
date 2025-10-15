package policies.corebanking.trino

default allow = false

# Metadata
table := "deposits_vault_core_posting_summary__daily"
schema := "deposits"
catalog := "gold"

# Allow roles (users from team)
allowed_users := { "@ikigaidigital/deposits-bc", "michael@ikigaidigital.io" }

# Allow SELECT queries for allowed users
allow if {
  input.action.operation == "SelectFromColumns"
  input.action.resource.table.catalogName == catalog
  input.action.resource.table.schemaName == schema
  input.action.resource.table.tableName == table
  input.context.identity.user == allowed_users[_]
}
