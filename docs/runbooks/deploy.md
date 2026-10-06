# Deploying the control plane

Status on 2026-10-06: **nothing is deployed anywhere.** Every hosted path has been tested against
a fake GitHub only. This runbook is the shortest route from the repository to a running
instance, and says who does each step.

## What runs

| Part | Image | Needs |
| --- | --- | --- |
| web (FastAPI, uvicorn) | Dockerfile target `web` | Postgres, Redis, the GitHub App's secrets |
| worker (ARQ: webhooks, hosted scans, TLS probes) | Dockerfile target `worker` | the same variables as web |
| Postgres 16 | host plugin | durable storage, EU region |
| Redis | host plugin | the job queue; losing it loses queued jobs only |

Migrations run from the web image before each web deploy (`railway.toml`, `preDeployCommand`).
Hosted scanning covers public repositories only (D1), so the missing network isolation on a
PaaS (`docs/hosted-scanning.md`) is accepted. The scanner itself runs in customers' CI, so load
on this service is small: CBOM uploads are kilobytes of JSON.

## Which host

Plans and prices below were checked on 2026-10-06 from public summaries, not from the vendors'
pricing pages (the cloud sandbox cannot reach them). Confirm before you pay.

| Host | Free tier | Fits this app? | Notes |
| --- | --- | --- | --- |
| **Railway** | 30-day trial with a small credit and no card; then Hobby from $5 a month, billed by usage, and Pro at $20 per seat | Yes: web, worker, Postgres and Redis in one project; `railway.toml` already exists | The recommended start. It cannot choose a Dockerfile target, so the worker uses the `ROLE` variable (below). Usage-based, so set a spending limit |
| **Render** | Free web service that sleeps after inactivity; free Postgres that expires after 30 days; free Key Value of 25 MB without persistence | Only as a throwaway demo: the worker is paid (about $7 a month), and the free database disappears | Frankfurt region. Plans changed on 1 Aug 2026 (included bandwidth cut) |
| **Google Cloud** | Always Free covers Cloud Run for the web service within a monthly quota (2 million requests, 180,000 vCPU-seconds, 360,000 GiB-seconds). There is no free Postgres or Redis, and the free VM exists only in three US regions. New accounts get a trial credit | Only with credits. The smallest Cloud SQL PostgreSQL instance is about $8 a month and Memorystore Redis about $36 a month for 1 GB (US prices; check the EU region). An always-on worker uses about 2.6 million vCPU-seconds a month, against 180,000 free | EU regions exist. More setup than Railway: IAM, a VPC connection for Redis, Artifact Registry, a deploy workflow. Startup credits are below |
| **Hetzner Cloud VPS** | None | Yes: one 2 vCPU, 4 GB server (about 5.5 euro a month) runs all four parts under Docker Compose | German and Finnish regions, the strongest EU story. You run backups, updates and TLS. It also allows a no-network scan sandbox, which hosted scanning of private repos would need later (D1) |

### Google Cloud and startup credits

The free tier alone does not cover this app, because Postgres, Redis and an always-on worker have
no free quota. Credits can: Google for Startups Cloud Program (cloud.google.com/startup), checked
2026-10-06.

| Tier | Credits | Who qualifies |
| --- | --- | --- |
| Start | up to $2,000 | Founded in the last 24 months, a working MVP, a clear business model, no Google Cloud credits beyond a free trial |
| Scale | up to $100,000 in year one and 20% of up to $100,000 more in year two | Institutional equity funding from pre-seed to Series A; angel, friends-and-family, crowdfunding and grant money do not count |

Rule: apply for Start now, and create nothing on Google Cloud until the answer arrives. If it is
approved, Google Cloud is reasonable: the credits cover the database, Redis and the worker for
many months. If it is refused, or you do not want to wait, use Railway. The Dockerfile works on
both, and Google Cloud can build any target directly. Once credits are approved, tell me and I
will write the Cloud Run deploy workflow, which needs your project and cannot be tested before.

Recommendation: start on Railway Hobby with a spending limit, because the repository is already
configured for it and scaling is a plan change. Move to a Hetzner server when a customer asks for
a European provider, or when private-repo scanning needs a network-less sandbox. No option has a
free tier that keeps a worker and a database alive, so budget a few tens of euros a month.

## Steps on Railway

1. **You:** create a Railway account, add a payment method, and set a monthly spending limit.
2. **You:** create a project. Add Postgres and Redis from the plugin list. Pick an EU region for
   every service in its settings.
3. **You:** add a service from the GitHub repository for the web app. Nothing to configure: the
   root `railway.toml` sets the health check and the migration step. Railway builds the root
   Dockerfile, whose last stage is the web image.
4. **You:** add a second service from the same repository for the worker. In its settings set the
   config file to `/railway.worker.toml` and add the variable `ROLE=worker`.
5. **You:** set the variables below on both services (use shared variables).
6. **You:** give the web service a public domain, then set `QUANTSIV_API_URL` where CI runs the
   scanner. Tell me the address and I change the scanner's built-in default and the CI templates.
7. **You:** register the GitHub App (next section), then fill the five App variables.
8. Redeploy both services, then run the smoke test.

## Variables

| Name | Value | Notes |
| --- | --- | --- |
| `ENV` | `production` | Secure cookies, API docs off |
| `DATABASE_URL` | the Postgres plugin's URL | Both `postgres://` and `postgresql://` work |
| `REDIS_URL` | the Redis plugin's URL | |
| `SESSION_SECRET` | 48 random bytes | `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `GITHUB_WEBHOOK_SECRET` | a random string | Also entered in the GitHub App |
| `GITHUB_APP_ID` | from the App's settings page | |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | from the App's settings page | Used for sign-in |
| `GITHUB_APP_PRIVATE_KEY` | the downloaded `.pem`, whole file | Real newlines, or one line with literal `\n`; both work |
| `LOG_LEVEL` | `INFO` | INFO carries no account or repository names |
| `LEGAL_READY` | leave unset | Legal pages stay hidden until D4 and counsel |
| `STRIPE_*` | leave unset | Billing is not built |

The worker needs the same required variables as the web service, because both load one settings
class.

## Registering the GitHub App

**You**, once, from the account that will own it (GitHub, Settings, Developer settings, GitHub
Apps, New GitHub App). The values come from the code, not from the spec.

| Setting | Value |
| --- | --- |
| Homepage URL | your domain |
| Callback URL | `https://<domain>/auth/github/callback` |
| Webhook URL | `https://<domain>/webhook/github` |
| Webhook secret | the value of `GITHUB_WEBHOOK_SECRET` |
| Repository permissions | Contents: read-only. Metadata: read-only. Nothing else; the code asks for exactly these |
| Subscribe to events | Push (installation and authorization events arrive without a subscription) |
| Where can it be installed | Only on this account while you test, then any account |

Then generate a private key, and copy the App ID, client ID and a new client secret into the
variables. Do not request pull-request or check permissions yet; the check-run surface (roadmap
1.2) is where those come in.

## Smoke test

1. `https://<domain>/health` returns `{"status":"healthy"}`.
2. Sign in with GitHub; the dashboard shows the empty state.
3. Install the App on a test repository; the App's "Advanced" tab shows the webhook delivery
   with a 202, and the dashboard lists nothing wrong.
4. Start a scan of a public repository from the dashboard; it reaches "done" and shows findings
   with a CBOM download.
5. Create an API token at `/dashboard/tokens`; run the scanner in CI with `--upload`; the
   default-branch build is a baseline, a pull request is gated against it.
6. Add a domain at `/dashboard/domains`, publish the TXT record, verify, scan.

Step 4 is the first time the hosted path meets a real GitHub. Expect to fix small things.

## What I can and cannot do

| Me | You |
| --- | --- |
| Keep the images, migrations, workflows and this runbook working; fix what the smoke test finds if you give me the logs | Own the accounts and billing, choose the host and the domain |
| Change the scanner's default address and the CI templates once the domain exists | Register the GitHub App and hold its private key and secrets |
| Run the first dry release (see `release-scanner.md`) | Decide when anything becomes public |
