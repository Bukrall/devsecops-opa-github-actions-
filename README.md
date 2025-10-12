# DevSecOps OPA GitHub Actions Demo

This project demonstrates **policy-based security integration** in a CI/CD pipeline using **Open Policy Agent (OPA)** and **GitHub Actions**.

## 🚀 Overview
The workflow enforces a security rule that checks the Docker image used in the pipeline:
- ✅ Approved: `python:3.11-slim`
- ❌ Blocked: any other image (e.g. `python:latest`)

If the image violates the policy, the build fails automatically — ensuring compliance from the start of the CI/CD process.

## 🧩 Technologies Used
- **GitHub Actions** – Continuous Integration/Delivery  
- **Open Policy**
