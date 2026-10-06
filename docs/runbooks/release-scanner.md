# Releasing the scanner image

The scanner image is how customers run Quantsiv in their CI (decision D1). A release builds it,
pushes it to a **private** registry and signs it, so a design partner can check the image came
from this repository's build. Nothing becomes public until you change a package's visibility.

## What a signature is

A signature is a cryptographic proof attached to the image's exact digest. A partner who has our
public key can run one command and learn that the image is the one this build produced, and not a
swapped or altered copy. It says nothing about whether the code is good; it says who built it.

Signing uses a key pair we hold (cosign, no public transparency log). The public log used by
keyless signing would publish this repository's name, which stealth rules out. GitHub's own
build attestations are an alternative for private repositories, but a partner outside the
organisation cannot fetch them without access, so a key pair is simpler for now.

The cosign key is ECDSA P-256, a quantum-vulnerable algorithm. By our own narrative a signature
risks forgery rather than retroactive decryption, and the signature deadline is 31 Dec 2031
(EO 14412). Move to a post-quantum signature when cosign supports one.

## One-time setup (you)

1. On a trusted machine, run `cosign generate-key-pair`. It writes `cosign.key` (private,
   encrypted with the password you choose) and `cosign.pub`.
2. In the repository's Settings, Secrets and variables, Actions, add two secrets:
   `COSIGN_PRIVATE_KEY` (the whole contents of `cosign.key`) and `COSIGN_PASSWORD`.
3. Commit `cosign.pub` as `release/cosign.pub`. A public key is meant to be shared.
4. Never put `cosign.key` in the repository. `.gitignore` already blocks `*.key`.

## Each release

1. Actions, `release-scanner`, Run workflow. First leave **dry run** ticked: it builds the image,
   proves it scans the fixture offline, and pushes and signs nothing.
2. Run it again with dry run off and a version such as `0.1.0`. It pushes
   `ghcr.io/<owner>/quantsiv-scanner:0.1.0`, signs the digest, verifies the signature, and writes
   the verify command into the run summary.
3. The package is private. In GitHub, Packages, `quantsiv-scanner`, Package settings, add each
   design partner under "Manage access" with read access.

## What a partner does

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io -u <their-github-user> --password-stdin
cosign verify --key cosign.pub --insecure-ignore-tlog=true ghcr.io/<owner>/quantsiv-scanner@sha256:<digest>
```

Then they set `QUANTSIV_IMAGE` in their CI to that reference. `$GHCR_TOKEN` is a token with the
`read:packages` scope. Pin the digest, not the tag.

## The Marketplace action, at the stealth exit

GitHub lists an action only from a **public** repository that holds a single `action.yml` at its
root, contains no workflow files and has a unique name, and the publisher must have two-factor
authentication and accept the Marketplace terms. A listing would make the product name and the
image public, so it waits for the stealth exit (about Q2 2027 in the strategy).

Until then the CI templates in `ci/` do the same job with `docker run`. At the exit:

1. Make the scanner image public (package settings) and release the final version.
2. Create a GitHub organisation for the product, with two-factor authentication required.
3. Create a new public repository there containing only `action.yml`, a README and a licence.
   Do not copy anything else from this private repository.
4. `action.yml` is a composite action that runs the public image with the inputs the templates
   use. Sketch:

```yaml
name: Quantsiv scan
description: Cryptography inventory (CycloneDX CBOM) for your build
author: Quantsiv
branding: {icon: shield, color: blue}
inputs:
  image: {description: Scanner image, required: true}
  upload: {description: Upload the CBOM (needs QUANTSIV_TOKEN), default: "false"}
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        docker run --rm -e QUANTSIV_TOKEN -v "$PWD:/src" -w /src "${{ inputs.image }}" \
          scan /src --out /src/quantsiv-out
```

5. Publish a release in that repository and tick "Publish this Action to the GitHub
   Marketplace".

Test the action first in a throwaway private repository inside the same organisation.
