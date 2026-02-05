package cicd.image

default allow := false

approved_images := {"python:3.11-slim"}

# Collect violations
violations[msg] {
  endswith(input.image, ":latest")
  msg := "Blocked: image tag ':latest' is not allowed."
}

violations[msg] {
  not startswith(input.image, "python:")
  msg := "Blocked: only python images are allowed."
}

violations[msg] {
  startswith(input.image, "python:")
  not input.image in approved_images
  msg := sprintf("Blocked: '%s' is not in the approved allowlist.", [input.image])
}

# Deny = all violations
deny[msg] {
  msg := violations[_]
}

# Allow ONLY when there are no violations
allow {
  count(violations) == 0
}
