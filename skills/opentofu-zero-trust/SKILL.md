---
name: opentofu-zero-trust
description: OpenTofu & policy-hub Rego constraints for Cloudflare Zero Trust, mTLS, R2 object lock, and least-privilege bindings.
---

# OpenTofu Zero-Trust Workflow

- **Zero Secrets in HCL/State Prompts**: Never hardcode tokens, keys, or account secrets; never inspect `.terraform/` provider caches or `.env*`.
- **Policy-Hub Rego Gate**: Validate plans locally against `policy-hub` Rego policies; never run `tofu apply` autonomously (confused-deputy boundary).
- **Network & Storage Ceilings**: Require mTLS + short-lived OAuth 2.1/DPoP on Zero Trust endpoints and indefinite R2 object locks on audit buckets.
