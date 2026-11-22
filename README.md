# WedPlan Backend

Express + MongoDB + Stripe backend for the WedPlan wedding marketplace.

## Getting started

```bash
npm install
cp .env.example .env   # then fill in real values
npm run dev            # start in watch mode
npm run start          # start in production mode
npm run seed           # seed sample marketplace data
npm run seed:admin     # seed the admin user from ADMIN_SEED_EMAIL
```

## Environment variables

| Variable          | Description                                        | Default |
| ----------------- | -------------------------------------------------- | ------- |
| `PORT`            | Server port                                        | `5000`  |
| `MONGODB_USER`    | MongoDB user for the Atlas cluster               | —       |
| `MONGODB_PASS`    | MongoDB password for the Atlas cluster          | —       |
| `STRIPE_SECRET_KEY` | Stripe secret key used for subscriptions     | —       |
| `JWKS_URL`        | Auth server JWKS endpoint used to verify JWTs    | `http://localhost:3000/api/auth/jwks` |
| `ADMIN_SEED_EMAIL` | Email used by `npm run seed:admin`              | —       |
| `CORS_ORIGIN`     | Comma-separated list of allowed CORS origins     | `*`     |

## API overview

- `GET /api/health` – service health check
- `GET /api/services` – public marketplace service listing (search, filter, sort, paginate)
- `GET /api/services/:id` – public service details
- `GET /api/services/meta` – service categories metadata
- `GET /api/services/mine` – vendor's own services (JWT required, vendor role)
- `POST /api/services` – vendor submits a service for admin review
- `PATCH /api/services/:id` – vendor updates their own service (admin can moderate)
- `DELETE /api/services/:id` – vendor deletes their own service
- `POST /api/bookings` – customer submits a booking request
- `GET /api/bookings/mine` – customer booking history
- `GET /api/bookings/vendor` – vendor booking requests inbox
- `PATCH /api/bookings/:id/cancel` – customer cancels a pending booking
- `PATCH /api/bookings/:id/respond` – vendor accepts/rejects a booking
- `GET /api/vendor/stats` – vendor dashboard statistics
- `GET /api/customer/stats` – customer booking statistics
- `GET /api/admin/stats` – platform-wide admin statistics
- `GET /api/admin/users` – admin user listing / moderation
- `GET /api/admin/services` – admin service moderation listing
- `PATCH /api/admin/services/:id/status` – admin approve/reject a service
- `GET /api/admin/transactions` – admin transaction history
- `GET /api/subscriptions/plans` – subscription plan catalog
- `GET /api/subscriptions/status` – vendor subscription status
- `POST /api/subscriptions/checkout` – create Stripe checkout session
- `POST /api/subscriptions/checkout-verify` – verify completed Stripe payment
- `POST /api/subscriptions/webhook` – Stripe webhook receiver

All API responses use the shape `{ success, data?, message?, meta? }`.
Routes under `/api` that are not matched return a JSON 404.
