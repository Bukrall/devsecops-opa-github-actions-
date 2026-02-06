package cicd.image

test_dev_allows_slim {
  allow with input as {"env": "dev", "image": "python:3.11-slim"}
}

test_dev_allows_alpine {
  allow with input as {"env": "dev", "image": "python:3.11-alpine"}
}

test_prod_allows_slim {
  allow with input as {"env": "prod", "image": "python:3.11-slim"}
}

test_prod_denies_alpine {
  deny[_] with input as {"env": "prod", "image": "python:3.11-alpine"}
}

test_denies_latest {
  deny[_] with input as {"env": "prod", "image": "python:latest"}
}

test_denies_non_python {
  deny[_] with input as {"env": "dev", "image": "node:20"}
}
