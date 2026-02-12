
---

---

# 🔐 docs/SECRETS.md

```markdown
# Secrets Management

Secrets MUST NOT be committed.

## Required Secrets

- DATABASE_URL
- JWT_SECRET_KEY
- STRIPE_SECRET_KEY
- REDIS_URL

## Production

Use:

- AWS Secrets Manager
- GCP Secret Manager
- Doppler
- Vault

Rotate keys quarterly.
