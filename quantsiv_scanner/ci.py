"""Which build is this? The branch, the default branch and whether it is a pull or merge request,
read from the CI environment (WP12).

The control plane compares a change with the latest default-branch upload, never with another
pull request, so it must know which kind of build uploaded. Anything this module cannot tell stays
unknown, and an upload with an unknown branch is stored as a candidate that cannot become the
baseline. Explicit `QUANTSIV_BRANCH`, `QUANTSIV_DEFAULT_BRANCH` and `QUANTSIV_CHANGE` always win,
for CI systems that are not recognised and for containers that receive only some variables.

A pull request can edit its own workflow file, so this is honest-CI plumbing, not enforcement
against a hostile author. Enforcement needs a required check that the pull request cannot edit.
"""

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass

MAX_EVENT_BYTES = 5 * 1024 * 1024
_TRUE = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class BuildContext:
    branch: str | None = None
    default_branch: str | None = None
    change: bool = False
    provider: str | None = None

    @property
    def can_be_baseline(self) -> bool:
        return not self.change and self.branch is not None and self.branch == self.default_branch


def _clean(value: str | None) -> str | None:
    value = (value or "").strip()
    return value or None


def _strip_ref(ref: str | None) -> str | None:
    ref = _clean(ref)
    return ref.removeprefix("refs/heads/") if ref else None


def _github_default_branch(env: Mapping[str, str]) -> str | None:
    path = env.get("GITHUB_EVENT_PATH")
    try:
        if not path or os.path.getsize(path) > MAX_EVENT_BYTES:
            return None
        with open(path, encoding="utf-8") as handle:
            return _clean(((json.load(handle).get("repository")) or {}).get("default_branch"))
    except (OSError, ValueError, AttributeError):
        return None


def _provider(env: Mapping[str, str]) -> BuildContext:
    if env.get("GITHUB_ACTIONS") == "true":
        change = env.get("GITHUB_EVENT_NAME", "") in {
            "pull_request",
            "pull_request_target",
            "merge_group",
        }
        branch = env.get("GITHUB_HEAD_REF") if change else env.get("GITHUB_REF_NAME")
        return BuildContext(_clean(branch), _github_default_branch(env), change, "github-actions")
    if env.get("GITLAB_CI") == "true":
        change = bool(env.get("CI_MERGE_REQUEST_IID"))
        branch = (
            env.get("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")
            if change
            else env.get("CI_COMMIT_BRANCH") or env.get("CI_COMMIT_REF_NAME")
        )
        return BuildContext(_clean(branch), _clean(env.get("CI_DEFAULT_BRANCH")), change, "gitlab")
    if env.get("TF_BUILD"):
        change = env.get("BUILD_REASON") == "PullRequest"
        branch = (
            env.get("SYSTEM_PULLREQUEST_SOURCEBRANCH") if change else env.get("BUILD_SOURCEBRANCH")
        )
        return BuildContext(_strip_ref(branch), None, change, "azure-devops")
    if env.get("JENKINS_URL"):
        change = bool(env.get("CHANGE_ID"))
        branch = env.get("CHANGE_BRANCH") if change else env.get("BRANCH_NAME")
        return BuildContext(_clean(branch), None, change, "jenkins")
    return BuildContext()


def detect(env: Mapping[str, str] | None = None) -> BuildContext:
    env = os.environ if env is None else env
    found = _provider(env)
    change = (
        env["QUANTSIV_CHANGE"].strip().lower() in _TRUE
        if "QUANTSIV_CHANGE" in env
        else found.change
    )
    return BuildContext(
        branch=_clean(env.get("QUANTSIV_BRANCH")) or found.branch,
        default_branch=_clean(env.get("QUANTSIV_DEFAULT_BRANCH")) or found.default_branch,
        change=change,
        provider=found.provider,
    )
