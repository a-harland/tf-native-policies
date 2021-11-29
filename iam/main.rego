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
    allowed_values := concat(", ", allow_list)
    
    iam_resources := [resource_to_check | is_project_iam_type(changeset.type) ; resource_to_check := changeset]
    iam_failures := [output | not contains(allowed_values, iam_resources[i].change.after.role); output := iam_resources[i].address]
    iam_failures != []
    
    failures := concat(", ", iam_failures)
	msg := sprintf("Only approved IAM permissions are permitted. The following resources use unapproved IAM permissions. Only the following roles are allowed %v", [allow_list])
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
