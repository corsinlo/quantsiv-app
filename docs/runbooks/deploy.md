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
| **Hetzner Cloud VPS** | None | Yes: one 2 vCPU, 4 GB server (about 5.5 euro a month) runs all four parts under Docker Compose | German and Finnish regions, the strongest EU story. You run backups, updates and TLS. It also allows a no-network scan sandbox, which hosted scanning of private repos would need later (D1) |

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
