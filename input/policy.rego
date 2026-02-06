package cicd.image

default allow = false

approved_images = {
  "dev":  {"python:3.11-slim", "python:3.11-alpine"},
  "prod": {"python:3.11-slim"},
}

env = e {
  e := input.env
} else = "dev"

deny[msg] {
  endswith(input.image, ":latest")
  msg := "Blocked: image tag ':latest' is not allowed."
}

deny[msg] {
  not startswith(input.image, "python:")
  msg := "Blocked: only python images are allowed."
}

deny[msg] {
  not approved_images[env][input.image]
  msg := sprintf("Blocked: '%s' is not approved for env '%s'.", [input.image, env])
}

allow {
  count(deny) == 0
}
