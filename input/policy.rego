package cicd.image

default allow := false

# 1) Block :latest
deny[msg] {
  endswith(input.image, ":latest")
  msg := "Blocked: image tag ':latest' is not allowed. Pin a version like python:3.11-slim."
}

# 2) Only allow python images (keeps it consistent with your demo)
deny[msg] {
  not startswith(input.image, "python:")
  msg := "Blocked: only python base images are allowed in this demo."
}

# 3) Allowlist (your current rule, but made explicit and reusable)
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
