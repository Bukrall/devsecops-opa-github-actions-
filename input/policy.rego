package cicd.image

default allow = false

approved_images = {"python:3.11-slim"}

deny[msg] {
  endswith(input.image, ":latest")
  msg := "Blocked: image tag ':latest' is not allowed."
}

deny[msg] {
  not startswith(input.image, "python:")
  msg := "Blocked: only python images are allowed."
}

deny[msg] {
  startswith(input.image, "python:")
  not approved_images[input.image]
  msg := sprintf("Blocked: '%s' is not in the approved allowlist.", [input.image])
}

allow {
  count(deny) == 0
}
