# Founder checklist: what only you can do

Everything here needs your accounts, your domain or your secrets. Do the parts in order. Each
part says when it is done. The detailed settings are in `deploy.md` and `release-scanner.md`.
The host is Render (decision of 2026-10-09). To test the product you need Parts 1 to 3 only.

## Part 1. Create the stack on Render (45 minutes)

Follow `deploy.md`, "Steps on Render", steps 1 to 5:

1. Create the Render account, add a payment method, connect GitHub and give Render access to the
   repository.
2. Make the webhook secret on your machine
   (`python -c "import secrets; print(secrets.token_urlsafe(48))"`) and keep it in a password
   manager.
3. Create the environment group `quantsiv-github` with the five variables, using the placeholders
   the runbook lists for the four values that do not exist yet.
4. Create the Blueprint from the repository. Render lists four resources and about $31 a month.
   Apply it, and wait for the first build.

Done when `https://<address>/health` answers `{"status":"healthy"}`, where `<address>` is the web
service's `onrender.com` address. If a build fails, send me the log.

## Part 2. Register the GitHub App (30 minutes)

Do this once you have the address from Part 1. The App is registered on GitHub, not on the host.

1. GitHub: your profile photo, Settings, Developer settings, GitHub Apps, New GitHub App.
2. Name: `Quantsiv` (or `Quantsiv dev` if the name is taken). Homepage URL: your website.
3. Callback URL: `https://<address>/auth/github/callback`.
4. Webhook: tick Active. Webhook URL: `https://<address>/webhook/github`. Webhook secret: the
   secret from Part 1, step 2.
5. Repository permissions: Contents: Read-only. Metadata: Read-only. Nothing else.
6. Subscribe to events: Push.
7. Where can this GitHub App be installed: Only on this account, for now.
8. Create GitHub App. On its page: note the **App ID** and the **Client ID**; Generate a new
   client secret and copy it; Generate a private key, which downloads a `.pem` file.
9. In the Render group `quantsiv-github`, replace the four placeholders with the App ID, the
   client ID, the client secret and the whole contents of the `.pem` file. Wait for both services
   to redeploy (or run Manual Deploy on each).

Done when you hold the five values in your password manager and the services run with them. Do not
paste the values anywhere except the Render group.

## Part 3. Smoke test (30 minutes)

Run the six checks in `deploy.md`, "Smoke test". Send me the logs of anything that fails; the first
real contact with GitHub is where small things surface.

## Part 4. The landing page (your local machine)

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

## Part 5. Create the signing key (15 minutes, before the first public scanner image)

Nothing above needs this. Do it before anyone outside the team pulls the scanner container.
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

## Part 6. Optional, whenever you want

- **A custom domain.** Attach it to the web service in Render, then update the GitHub App's two
  URLs and tell me the address: the scanner's built-in default, `app.quantsiv.io`, is a placeholder.
  Needed before a customer sees the product, not before your own test.
- **Startup credits.** Google for Startups (cloud.google.com/startup) gives credits for Google
  Cloud only, and Render lists its own programme (render.com/startups). Neither is needed for the
  test; `deploy.md`, "Credits", says what I could and could not check.

## Part 7. Tidy up

Delete the stale branch `docs/audit-handover-2026-10-03` and any merged branches you no longer
need, in both repositories. The git proxy used by the cloud sessions cannot delete branches.
