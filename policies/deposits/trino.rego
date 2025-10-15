package policies.deposits.trino

default allow = false
default deny_reason = ""

# Metadata
table := "corebanking_vault_core_posting_summary__daily"
schema := "gold"
catalog := "datamesh"
domain := "deposits"

# Allow roles (users from team)
allowed_users := { "@ikigaidigital/deposits-bc", "kamil@ikigaidigital.io" }

# Allow SELECT queries for allowed users
allow {
  input.operation == "SELECT"
  input.catalog == catalog
  input.schema == schema
  input.table == table
  input.identity.user == allowed_users[_]
}
