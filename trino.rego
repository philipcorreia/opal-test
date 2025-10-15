package trino

bc := lower(input.action.resource.table.schemaName)

# existence check for a matching policy package
selected := data.policies[bc]["trino"] { data.policies[bc]["trino"] }

default allow = false

# Allow if the selected package exposes allow == true
allow {
  selected.allow
}

# Bubble up child denies (if the child exports deny as a set/array of messages)
deny[msg] {
  selected.deny[msg]
}

# Sensible fallbacks when no policy package exists
deny[msg] {
  not data.policies[bc]
  msg := sprintf("no policy packages for bc=%q", [bc])
}
deny[msg] {
  data.policies[bc]
  not data.policies[bc]["trino"]
  msg := sprintf("no policy package at policies.%s.%s", [bc, svc])
}

result := {
  "bc":      bc,
  "service": svc,
  "allow":   allow,
  "deny":    [m | m := deny[_]],
}
