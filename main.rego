package main

import rego.v1

applicable_policy := {
    "vm": "compute",
    "lambda": "compute",
    "container": "compute",
    "ip": "network",
    "securitygroup": "network",
    "waf": "network",
    "ssd": "storage",
    "volume": "storage"
}

name := applicable_policy[input.resource]

router[policy] := data.policies[name][policy].deny

deny contains msg if {
    not name
    msg := sprintf("no applicable policy found for input.resource %v", [input.resource])
}

deny contains msg if {
    some policy in router
    some msg in policy
}

decision["allow"] := count(deny) == 0
decision["reason"] :=  concat(" | ", deny)
decision["explain"] := router if {
    input.explain == true
}


