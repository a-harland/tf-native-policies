package label_validation

minimum_labels = {"dataclassification"}

labels_contain_proper_keys(labels) {
    keys := {key | labels[key]}
    leftover := minimum_labels - keys
    leftover == set()
}
