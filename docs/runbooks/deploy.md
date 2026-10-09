# Deploying the control plane

Status on 2026-10-09: **nothing is deployed anywhere.** Every hosted path has been tested against
a fake GitHub only. The founder chose **Render** (Frankfurt) on 2026-10-09, and `render.yaml`
describes the whole stack. This runbook is the shortest route from the repository to a running
instance, and says who does each step.

## What runs

| Part | Image | Needs |
| --- | --- | --- |
| web (FastAPI, uvicorn) | `Dockerfile`, default stage (`web`) | Postgres, Redis, the GitHub App's secrets |
| worker (ARQ: webhooks, hosted scans, TLS probes) | `Dockerfile.worker`, the `worker` stage as its own file | the same variables as web |
| Postgres 16 | Render Postgres | durable storage, Frankfurt |
| Redis | Render Key Value (Redis-compatible) | the job queue; losing it loses queued jobs only |

Migrations run on separate compute before each web deploy (`render.yaml`, `preDeployCommand`).
Hosted scanning covers public repositories only (D1), so the missing network isolation on a PaaS
(`docs/hosted-scanning.md`) is accepted. The scanner itself runs in customers' CI, so load on this
service is small: CBOM uploads are kilobytes of JSON.

## Which host

Plans and prices below were checked from public summaries, not from the vendors' pricing pages
(the cloud sandbox cannot reach them). Render shows the exact monthly total before you confirm the
Blueprint; read it.

| Host | Free tier | Fits this app? | Notes |
| --- | --- | --- | --- |
| **Render (chosen)** | Free web service that sleeps after inactivity; free Postgres that expires after 30 days; free Key Value of 25 MB without persistence | Yes, on paid plans: about $31 a month for all four parts (table below). The free plans cannot keep a worker and a database alive | Frankfurt region. `render.yaml` is the Blueprint. Plans changed on 1 Aug 2026 (included bandwidth cut). Render is a US company, so say "hosted in the EU (Frankfurt)" and never "European provider" or "sovereign" |
| **Railway** | 30-day trial with a small credit and no card; then Hobby from $5 a month, billed by usage, and Pro at $20 per seat | Yes: `railway.toml` and `railway.worker.toml` exist | Kept as the alternative. It cannot choose a Dockerfile target, so its worker uses the `ROLE` variable (steps below). Usage-based, so set a spending limit |
| **Google Cloud** | Always Free covers Cloud Run for the web service within a monthly quota (2 million requests, 180,000 vCPU-seconds, 360,000 GiB-seconds). There is no free Postgres or Redis, and the free VM exists only in three US regions. New accounts get a trial credit | Only with credits. The smallest Cloud SQL PostgreSQL instance is about $8 a month and Memorystore Redis about $36 a month for 1 GB (US prices; check the EU region). An always-on worker uses about 2.6 million vCPU-seconds a month, against 180,000 free | EU regions exist. More setup: IAM, a VPC connection for Redis, Artifact Registry, a deploy workflow. Startup credits are below |
| **Hetzner Cloud VPS** | None | Yes: one 2 vCPU, 4 GB server (about 5.5 euro a month) runs all four parts under Docker Compose | German and Finnish regions, the strongest EU story. You run backups, updates and TLS. It also allows a no-network scan sandbox, which hosted scanning of private repos would need later (D1) |

### What Render costs

| Part | Plan in `render.yaml` | Monthly price |
| --- | --- | --- |
| web | `starter` | $7 |
| worker | `starter` | $7 |
| Key Value (queue) | `starter` | $10 |
| Postgres | `basic-256mb`, plus storage | $6, plus $0.30 per GB |
| **Total** | | **about $31** |

For a throwaway test, change the queue's `plan` to `free` (25 MB, nothing survives a restart, so
queued jobs would be lost) and save $10. Do not use the free Postgres: it expires after 30 days.
The web and worker plans are always-on, so the free tier's sleeping does not apply.

### Credits

- **Google for Startups Cloud Program** (cloud.google.com/startup), checked 2026-10-06. Start:
  up to $2,000 for a company founded in the last 24 months with a working MVP and no Google Cloud
  credits beyond a free trial. Scale: up to $100,000 in year one, and only for institutional
  equity funding from pre-seed to Series A. These credits apply to Google Cloud, not to Render.
  If you win them and want to use them, tell me and I write the Cloud Run deploy workflow; it
  needs your project and cannot be tested before.
- **Render** lists a startup programme (render.com/startups). I could not open the page from the
  cloud sandbox, and the summaries I found said access goes through partner organisations. Read
  the page before you apply, and do not wait for an answer: the test costs about $31 a month.

Moving later is a plan change, not a rewrite: the images are plain Dockerfiles that every host
here can build. Move to Hetzner when a customer asks for a European provider, or when private-repo
scanning needs a network-less sandbox.

## Steps on Render

1. **You:** create an account at render.com, add a payment method, and connect GitHub (Account
   Settings, GitHub). Give Render access to the `corsinlo/quantsiv-app` repository.
2. **You:** make the webhook secret on your machine and keep it:
   `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
3. **You:** in the Dashboard open Environment Groups, New Environment Group, and name it exactly
   `quantsiv-github`. Add these five variables. Use placeholders for the four that do not exist
   yet; the services refuse to start without them, and the GitHub App cannot be registered until
   Render has given you the address.

   | Variable | Value now |
   | --- | --- |
   | `GITHUB_WEBHOOK_SECRET` | the secret from step 2 (real) |
   | `GITHUB_APP_ID` | `0` |
   | `GITHUB_CLIENT_ID` | `placeholder` |
   | `GITHUB_CLIENT_SECRET` | `placeholder` |
   | `GITHUB_APP_PRIVATE_KEY` | `placeholder` |

4. **You:** New, Blueprint, pick the repository and the `main` branch. Render reads `render.yaml`,
   lists four resources (web, worker, Key Value, Postgres) and the monthly total. Apply it. The
   first build takes several minutes.
5. **You:** when `quantsiv-web` is live, copy its address from the service page (it ends in
   `.onrender.com`). `https://<address>/health` should return `{"status":"healthy"}`. If a build
   or a start fails, send me the log.
6. **You:** register the GitHub App with that address (next section). Then open the group
   `quantsiv-github` and replace the four placeholders with the real App values. Render should
   redeploy the services that use the group; if it does not, run Manual Deploy on both.
7. Run the smoke test.
8. **Later, you:** attach a custom domain to the web service (Settings, Custom Domains, then a
   CNAME at your DNS). Update the GitHub App's callback and webhook URLs, and set
   `QUANTSIV_API_URL` where CI runs the scanner. Tell me the address and I change the scanner's
   built-in default and the CI templates.

After this, every merge to `main` redeploys web and worker once CI is green
(`autoDeployTrigger: checksPass`).

## Variables

`render.yaml` sets everything except the GitHub App values, which live in the group.

| Name | Where | Value |
| --- | --- | --- |
| `ENV` | `render.yaml` | `production`: secure cookies, API docs off |
| `DATABASE_URL` | `render.yaml` | the database's internal connection string; both `postgres://` and `postgresql://` work |
| `REDIS_URL` | `render.yaml` | the Key Value instance's internal connection string |
| `SESSION_SECRET` | `render.yaml` | generated by Render for each service; only the web service uses it, and changing it signs everyone out |
| `LOG_LEVEL` | `render.yaml` | `INFO` carries no account or repository names |
| `GITHUB_WEBHOOK_SECRET` | group `quantsiv-github` | a random string, also entered in the GitHub App |
| `GITHUB_APP_ID` | group `quantsiv-github` | from the App's settings page |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | group `quantsiv-github` | from the App's settings page; used for sign-in |
| `GITHUB_APP_PRIVATE_KEY` | group `quantsiv-github` | the downloaded `.pem`, whole file; real newlines, or one line with literal `\n` (both work) |
| `LEGAL_READY` | not set | legal pages stay hidden until D4 and counsel |
| `STRIPE_*` | not set | billing is not built |

The worker needs the same required variables as the web service, because both load one settings
class. Both mount the group, so the five values are entered once. The database and the queue accept
connections from inside Render's network only (`ipAllowList: []`); to read the database with
`psql`, add your own address in the Dashboard.

## Registering the GitHub App

**You**, once, from the account that will own it (GitHub, Settings, Developer settings, GitHub
Apps, New GitHub App). The values come from the code, not from the spec.

| Setting | Value |
| --- | --- |
| Homepage URL | your website |
| Callback URL | `https://<address>/auth/github/callback` |
| Webhook URL | `https://<address>/webhook/github` |
| Webhook secret | the value of `GITHUB_WEBHOOK_SECRET` |
| Repository permissions | Contents: read-only. Metadata: read-only. Nothing else; the code asks for exactly these |
| Subscribe to events | Push (installation and authorization events arrive without a subscription) |
| Where can it be installed | Only on this account while you test, then any account |

`<address>` is the web service's address. Both URLs can be edited later, so registering with the
`onrender.com` address now and moving to your own domain afterwards costs nothing.

Then generate a private key, and copy the App ID, client ID and a new client secret into the
group's variables. Do not request pull-request or check permissions yet; the check-run surface
(roadmap 1.2) is where those come in.

## Smoke test

1. `https://<address>/health` returns `{"status":"healthy"}`.
2. Sign in with GitHub; the dashboard shows the empty state.
3. Install the App on a test repository; the App's "Advanced" tab shows the webhook delivery
   with a 202, and the dashboard lists nothing wrong.
4. Start a scan of a public repository from the dashboard; it reaches "done" and shows findings
   with a CBOM download.
5. Create an API token at `/dashboard/tokens`; run the scanner in CI with `--upload`; the
   default-branch build is a baseline, a pull request is gated against it.
6. Add a domain at `/dashboard/domains`, publish the TXT record, verify, scan.

Step 4 is the first time the hosted path meets a real GitHub. Expect to fix small things.

## Steps on Railway (the alternative)

1. **You:** create a Railway account, add a payment method, and set a monthly spending limit.
2. **You:** create a project. Add Postgres and Redis from the plugin list. Pick an EU region for
   every service in its settings.
3. **You:** add a service from the GitHub repository for the web app. Nothing to configure: the
   root `railway.toml` sets the health check and the migration step. Railway builds the root
   Dockerfile, whose last stage is the web image.
4. **You:** add a second service from the same repository for the worker. In its settings set the
   config file to `/railway.worker.toml` and add the variable `ROLE=worker`.
5. **You:** set the variables above on both services (Railway's shared variables), with `ENV`,
   `DATABASE_URL`, `REDIS_URL` and a generated `SESSION_SECRET` added by hand.
6. Give the web service a public domain, then follow Render steps 6 to 8 with that address.

## What I can and cannot do

| Me | You |
| --- | --- |
| Keep the images, migrations, workflows, `render.yaml` and this runbook working; fix what the smoke test finds if you give me the logs | Own the accounts and billing, choose the host and the domain |
| Change the scanner's default address and the CI templates once the domain exists | Register the GitHub App and hold its private key and secrets |
| Run the first dry release (see `release-scanner.md`) | Decide when anything becomes public |
