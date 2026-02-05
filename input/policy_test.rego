package cicd.image

test_allow_approved {
  allow with input as {"image": "python:3.11-slim"}
}

test_deny_latest {
  deny[_] with input as {"image": "python:latest"}
}

test_deny_non_python {
  deny[_] with input as {"image": "node:20"}
}

test_deny_unapproved_python_tag {
  deny[_] with input as {"image": "python:3.10-slim"}
}
