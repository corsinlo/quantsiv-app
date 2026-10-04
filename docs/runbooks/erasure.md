# Runbook: erasure of a person's or an organisation's data (GDPR Art. 17)

Erasure must happen without undue delay and within **one month** of the request
(Art. 12(3)); the law does not require a self-serve button. This is the manual procedure; the
worker's `delete_account` and `purge_installation` jobs perform the database steps in the same
order.

## When it runs

- A written request from the user or the organisation (verify the requester controls the
  GitHub account: ask them to open the request from that account, or sign in).
- The GitHub App is uninstalled (`installation` webhook, `action=deleted`): the worker purges
  that installation's data automatically.
- The user revokes the app's authorisation (`github_app_authorization`, `action=revoked`): the
  worker queues `delete_account` for that user.

## Steps

1. **Identify** the GitHub user id and the installations they own:
   `SELECT id, github_installation_id FROM installations WHERE user_id = (SELECT id FROM users WHERE github_user_id = :id);`
2. **Database** (the job does this; by hand, in this order, per installation):
   `findings`, `tls_scans`, `cbom_snapshots`, `share_links` (per scan), then `audit_events`,
   `scans`, `api_tokens`, `installations`; finally the `users` row.
   By hand: `python -c "import asyncio; from app import worker; ctx={}; asyncio.run(worker.startup(ctx)); print(asyncio.run(worker.delete_account(ctx, GITHUB_USER_ID)))"`
   with `DATABASE_URL` set.
3. **Billing** (once billing exists, D5): cancel the subscription and delete the customer at the
   payment provider. Invoices are kept under the statutory retention period (Art. 17(3)(b));
   the period depends on the entity's country (D4).
4. **E-mail provider** (once e-mail exists): remove the address from every list.
5. **Backups:** database backups age out on the hosting provider's schedule (D3); record the
   date after which no backup holds the data.
6. **Logs:** application logs carry ids, not names (A25); no action beyond their retention.
7. **Confirm** to the requester in writing, with the date, and keep the confirmation (not the
   data) as the record of the request.

## What is not deleted

- Invoices and payment records, for as long as tax law requires (D4 decides the country).
- Aggregate, non-personal statistics.
