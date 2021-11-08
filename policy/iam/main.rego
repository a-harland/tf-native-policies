package main

block_list = [
  "google_project_iam_policy",
  "google_project_iam_binding",
  "google_project_iam_member",
  "google_project_iam_audit_config"
]

deny[msg] {
  check_resources(input.resource_changes, block_list)
  banned := concat(", ", block_list)
  msg = sprintf("The following IAM changes require approval from the IAM team: %v", [banned])
}

check_resources(resources, disallowed_prefixes) {
  startswith(resources[_].type, disallowed_prefixes[_])
}
