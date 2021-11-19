package main

deny[msg] {
	changeset := input.resource_changes[_]
    is_create_or_update(changeset.change.actions)
    
    confidential_resources := [resource_to_check | changeset.change.after.labels.dataclassification == "confidential"; resource_to_check := changeset]
    kms_enabled_resources := [output | confidential_resources[_].change.after.kms_key_name; output := confidential_resources[_]]
    outputs := [output | kms_enabled_resources[_].change.after.kms_key_name == null; output := kms_enabled_resources[_].address]
    outputs != []
    
    banned := concat(", ", outputs)
	msg := sprintf("Data marked as confidential must be protected with CMEK: %v", [banned])
}

is_create_or_update(actions) {
	actions[_] == "create"
}

is_create_or_update(actions) {
	actions[_] == "update"
}
