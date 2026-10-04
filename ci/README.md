# CI templates for `quantsiv scan`

Each template runs the same scanner container after your build, in your own CI. The scanner
writes `quantsiv-out/cbom.json` (CycloneDX 1.6), `findings.sarif`, `report.json` and
`report.md` **offline**: no account, token or network call is needed for that. Upload to the
Quantsiv control plane happens only when `QUANTSIV_TOKEN` is set, and then the step fails when
the control plane's gate finds *newly added* quantum-vulnerable cryptography compared with the
previous upload of the same repository (the delta, never the absolute count).

Optional but recommended for Java, Python and Go: run
[CBOMkit-action](https://github.com/PQCA/cbomkit-action) (Apache-2.0) first. The scanner
merges its `cbom/cbom.json` with its own findings and records CBOMkit as a source.

| Template | File |
| --- | --- |
| GitHub Actions | `github-actions/quantsiv.yml` |
| GitLab CI | `gitlab/quantsiv.gitlab-ci.yml` |
| Jenkins (declarative, container step) | `jenkins/Jenkinsfile.snippet` |
| Azure DevOps | `azure-devops/quantsiv.yml` |

**Image.** `QUANTSIV_IMAGE` names the scanner image. It is not published yet (the product is in
stealth): build it from this repository's `Dockerfile` with
`docker build --target scanner -t quantsiv-scanner .` and push it to your own registry. A
signed public image follows at the stealth exit.

**Secrets.** The token only ever travels in the `QUANTSIV_TOKEN` environment variable, never on
the command line. Create it at `/dashboard/tokens`; it belongs to one GitHub App installation.

**Time to value.** Set `QUANTSIV_STEP_STARTED` to the step's start time (the templates do) and
the report records the seconds from there to the first CBOM.
