# Production Launch Checklist

## Security
- [ ] JWT secret rotated
- [ ] PAYSTACK_SECRET stored in env vars
- [ ] HTTPS enforced
- [ ] CORS locked down

## Payments
- [ ] Webhooks verified & idempotent
- [ ] Subscription plans enforced
- [ ] Manual reconciliation job ready

## Data Safety
- [ ] Tenant isolation verified
- [ ] RBAC enforced on all routes

## Abuse Protection
- [ ] Rate limiting enabled
- [ ] Automation quotas enforced
- [ ] Worker caps configured

## Ops
- [ ] Logs centralized
- [ ] Error tracking live
- [ ] Backups scheduled
