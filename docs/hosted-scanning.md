# Hosted scanning: what runs on Quantsiv's servers

Decision D1 (confirmed 2026-10-04): scanning is local-first. The customer's own CI runs the
scanner (WP7) and only the CBOM and finding metadata reach Quantsiv. Hosted scanning, where
Quantsiv clones a repository onto its own servers, exists for public repositories and demos.

## Rules the code enforces (WP5)

- **Public repositories only.** `ScanPipeline` reads the repository's metadata first and refuses
  a private repository before anything is cloned ("Hosted scanning covers public repositories
  only.").
- **Size limit.** Repositories larger than `MAX_REPO_KB` (500 MB, from GitHub's `size` field) are
  refused before cloning.
- **Least-privilege token (A52).** The installation token is down-scoped to the one repository,
  with `contents: read` and `metadata: read`, and revoked (`DELETE /installation/token`) as soon
  as the clone finishes, before the engine runs, including when anything fails.
- **Hardened clone (A15, A16).** The token travels only in the child's environment
  (`GIT_CONFIG_*`), never in argv, the URL, `.git/config`, logs or user-visible errors. Shallow,
  single-branch, no tags, submodules, LFS, hooks or symlinks, https only. `.git` is deleted
  before scanning.
- **Limited engine process (A16).** The engine, `quantsiv_scanner` (decision D2), runs through
  `app.services.sandbox.run_limited`: timeout, CPU, memory and file-size limits, no core dumps
  and a minimal environment (no secrets; `PYTHONPATH` to the app only).
- **TLS scanning (A17).** Only for domains an installation has verified: the customer adds a
  domain on the "TLS domains" page and publishes `_quantsiv.<domain> TXT "quantsiv-verify=<token>"`
  (a random token per domain). `worker.scan_tls` checks the record again before every scan, so a
  domain that changed hands or lost its record is not contacted. The probe resolves through
  `app.services.ssrf.resolve_scan_target` (public addresses only, port 443 only, internal names
  refused) and connects to the vetted IP with SNI set to the domain. One handshake, no
  certificate validation, metadata only. Unverified domains are not contacted at all, which is
  stricter than the audit's "at most one lightweight handshake". Domains named in a repository's
  files are never scanned from the control plane.

## Why private repositories stay off

The limits above cannot cut the engine off from the network: dropping network access needs
container-level isolation that the current host (Railway) does not provide to a process. A
hostile repository could therefore make the engine talk to the network. For public code that
risk is accepted; for customers' private code it is not.

Hosted scanning of private repositories may be offered later as an opt-in (D1 note), once the
engine runs in a network-less sandbox (for example a separate container or microVM with no
network) and the compliance work (security certification, DPA, EU processing) is funded.
