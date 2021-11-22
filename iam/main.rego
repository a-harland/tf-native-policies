package main

monitored_resource = [
    "google_project_iam_binding",
    "google_project_iam_member"
]

allow_list = [
  "roles/storage.objectViewer",
  "roles/viewer",
  "roles/bigquery.dataViewer",
]

deny[msg] {
	changeset := input.resource_changes[_]
    is_create_or_update(changeset.change.actions)
    
    confidential_resources := [resource_to_check | is_project_iam_type(changeset.type) ; resource_to_check := changeset]
    kms_enabled_resources := [output | not contains(confidential_resources[i].change.after.role, allow_list[i]); output := confidential_resources[i].address]
    kms_enabled_resources != []
    
    banned := concat(", ", kms_enabled_resources)
    msg := sprintf("Only approved IAM permissions are permitted. The following resources use unapproved IAM permissions %v. Only the following roles are allowed %v", [banned, allow_list])
}

is_project_iam_type(resource) {
    monitored_resource[_] == resource
}

is_create_or_update(actions) {
	actions[_] == "create"
}

is_create_or_update(actions) {
	actions[_] == "update"
}

