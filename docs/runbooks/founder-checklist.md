# Founder checklist: what only you can do

Everything here needs your accounts, your domain or your secrets. Do the parts in order. Each
part says when it is done. The detailed settings are in `deploy.md` and `release-scanner.md`.

## Part 1. Decide the address (10 minutes)

1. Decide which domain you control and what the app's address will be, for example
   `app.<your-domain>`. The scanner's built-in default, `app.quantsiv.io`, is a placeholder.
2. Confirm you can create DNS records for it (a CNAME now, TXT records later).

Done when you can write the address down: `https://app.<your-domain>`.

## Part 2. Ask for Google Cloud credits (20 minutes, then wait)

1. Open cloud.google.com/startup and apply for the **Start** tier. You need your website, your
   company details and a Google account. Do not create Google Cloud resources yet.
2. Note the date. While you wait, do Parts 3 and 4.

Done when the application is sent. Approved means Google Cloud is the host; refused or no answer in
a week or so means Railway (see `deploy.md`, "Google Cloud and startup credits").

## Part 3. Create the signing key (15 minutes)

You do this on your own machine, so the private key never passes through anyone else.

1. Install cosign. macOS: `brew install cosign`. Windows: download `cosign-windows-amd64.exe` from
   github.com/sigstore/cosign/releases, rename it `cosign.exe`, and put it in a folder on your PATH.
2. In an empty folder outside the repository, run `cosign generate-key-pair`. Choose a strong
   password and keep it in a password manager. This writes `cosign.key` and `cosign.pub`.
3. In the GitHub repository, open Settings, Secrets and variables, Actions, New repository secret.
   Add `COSIGN_PRIVATE_KEY` with the whole contents of `cosign.key`, including the BEGIN and END
   lines. Add `COSIGN_PASSWORD` with your password.
   - Copy the key: macOS `pbcopy < cosign.key`; Windows PowerShell `Get-Content cosign.key -Raw | Set-Clipboard`.
4. Add `cosign.pub` to the repository as `release/cosign.pub` (GitHub: Add file, Upload files).
   A public key is meant to be shared.
5. Store `cosign.key` in your password manager, then delete it from the folder. Never commit it.

Done when the repository shows two secrets and a `release/cosign.pub` file. Then tell me, and I run
the first signed release.

## Part 4. Register the GitHub App (30 minutes)

Do this once you have the address from Part 1. The App is registered on GitHub, not on the host, so
it does not depend on Railway or Google Cloud.

1. GitHub: your profile photo, Settings, Developer settings, GitHub Apps, New GitHub App.
2. Name: `Quantsiv` (or `Quantsiv dev` if the name is taken). Homepage URL: your website.
3. Callback URL: `https://app.<your-domain>/auth/github/callback`.
4. Webhook: tick Active. Webhook URL: `https://app.<your-domain>/webhook/github`. Webhook secret:
   a random string; make one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`
   and keep it, because the host needs the same value.
5. Repository permissions: Contents: Read-only. Metadata: Read-only. Nothing else.
6. Subscribe to events: Push.
7. Where can this GitHub App be installed: Only on this account, for now.
8. Create GitHub App. On its page: note the **App ID** and the **Client ID**; Generate a new
   client secret and copy it; Generate a private key, which downloads a `.pem` file.

Done when you hold five values: App ID, client ID, client secret, the `.pem` file and the webhook
secret. Keep them in a password manager. Do not paste them anywhere except the host's variables.

## Part 5. Create the host (45 minutes)

Follow `deploy.md`, "Steps on Railway", with the five values from Part 4. If Google Cloud credits
were approved, tell me instead and I prepare the Google Cloud path.

Done when the web address answers `/health` and both services are running.

## Part 6. Smoke test (30 minutes)

Run the six checks in `deploy.md`, "Smoke test". Send me the logs of anything that fails; the first
real contact with GitHub is where small things surface.

## Part 7. The landing page (your local machine)

1. `git clone https://github.com/corsinlo/quantsiv-landing` (or `git fetch` in your clone), then
   `git switch claude/landing-claude-md`. It holds one new file, `CLAUDE.md`, and changes nothing
   else.
2. Open Claude in that folder. Ask it to apply the "Edits the current page needs" table, one row at
   a time, on a new branch. Review the page in a browser.
3. Merge to the default branch only when you are happy: GitHub Pages publishes it within minutes.
4. `CLAUDE.md` contains no strategy, pricing or competitor names, so it is safe to publish. If you
   would rather keep it off the public site, copy it into your clone and add `CLAUDE.md` to
   `.git/info/exclude`.
5. Decide the waitlist form: connect it to a real store, or say the waitlist is not open yet. It
   currently shows "recorded" and sends nothing.

## Part 8. Tidy up

Delete the stale branch `docs/audit-handover-2026-10-03` and any merged branches you no longer
need, in both repositories. The git proxy used by the cloud sessions cannot delete branches.
