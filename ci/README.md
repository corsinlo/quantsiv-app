# CI templates for `quantsiv scan`

Each template runs the same scanner container after your build, in your own CI. The scanner
writes `quantsiv-out/cbom.json` (CycloneDX 1.6), `findings.sarif`, `report.json` and
`report.md` **offline**: no account, token or network call is needed for that. Upload to the
Quantsiv control plane happens only when `QUANTSIV_TOKEN` is set, and then the step fails when
the control plane's gate finds *newly added* quantum-vulnerable cryptography compared with the
latest **default-branch** upload of the same repository (the delta, never the absolute count).

Optional but recommended for Java, Python and Go: run
[CBOMkit-action](https://github.com/PQCA/cbomkit-action) (Apache-2.0) first. The scanner
merges its `cbom/cbom.json` with its own findings and records CBOMkit as a source.

| Template | File |
| --- | --- |
| GitHub Actions | `github-actions/quantsiv.yml` |
| GitLab CI | `gitlab/quantsiv.gitlab-ci.yml` |
| Jenkins (declarative, container step) | `jenkins/Jenkinsfile.snippet` |
| Azure DevOps | `azure-devops/quantsiv.yml` |

**Baseline and policy (read this before relying on the gate).**
- Only a build that runs on the default branch and is not a pull or merge request becomes the
  baseline. Every other upload, including one whose branch is unknown, is a candidate: gated
  against the baseline, stored, never used as one. A failing pull request therefore fails again
  when CI re-runs.
- The templates pass `QUANTSIV_BRANCH`, `QUANTSIV_DEFAULT_BRANCH` and `QUANTSIV_CHANGE`.
  GitHub Actions and GitLab need nothing else. Azure DevOps and Jenkins need
  `QUANTSIV_DEFAULT_BRANCH` set by you. On any other CI, set the three variables or pass
  `--branch`, `--default-branch` and `--change`.
- The baseline's policy decides, so a pull request cannot add an exception or switch the gate
  off in its own `quantsiv.yml`. Edits to the policy are listed in the verdict and take effect
  after the change is merged and built on the default branch. To add an exception for code you
  are about to write, merge the exception first, then the code. Put `quantsiv.yml` under
  CODEOWNERS so that someone other than the author approves it.
- Limit: a pull request can edit the workflow file that runs this step, so the check is only as
  strong as your control over that file. A required check posted by the Quantsiv GitHub App
  (roadmap 1.2) removes that limit.
- The first upload of a repository has no baseline: every asset counts as new and its own policy
  applies, until a default-branch build is uploaded.

**Image.** `QUANTSIV_IMAGE` names the scanner image. It is not published yet (the product is in
stealth): build it from this repository's `Dockerfile` with
`docker build --target scanner -t quantsiv-scanner .` and push it to your own registry. A
signed public image follows at the stealth exit.

**Secrets.** The token only ever travels in the `QUANTSIV_TOKEN` environment variable, never on
the command line. Create it at `/dashboard/tokens`; it belongs to one GitHub App installation.

**Time to value.** Set `QUANTSIV_STEP_STARTED` to the step's start time (the templates do) and
the report records the seconds from there to the first CBOM.
