package main

import data.label_validation

module_address[i] = address {
    changeset := input.resource_changes[i]
    address := changeset.address
}

labels_contain_minimum_set[i] = resources {
    changeset := input.resource_changes[i]
    labels := changeset.change.after.labels
    resources := [resource | resource := module_address[i]; not label_validation.labels_contain_proper_keys(changeset.change.after.labels)]
}

deny[msg] {
    resources := labels_contain_minimum_set[_]
    resources != []
    msg := sprintf("Missing required labels for the following resources: %v", [resources])
}
