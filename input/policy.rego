package cicd.image

default allow := false

deny[msg] {
  endswith(input.image, ":latest")
  msg := "Blocked: image tag ':latest' is not allowed. Pin a version like python:3.11-slim."
}

deny[msg] {
  not startswith(input.image, "python:")
  msg := "Blocked: only python base images are allowed in this demo."
}

approved_images := {"python:3.11-slim"}

allow {
  count(deny) == 0
  input.image in approved_images
}

deny[msg] {
  count(deny) == 0
  not input.image in approved_images
  msg := sprintf("Blocked: '%s' is not in the approved allowlist: %v", [input.image, approved_images])
}
