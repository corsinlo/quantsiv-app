"""Which build is this? Detection from the CI environment (WP12)."""

import json

import pytest

from quantsiv_scanner.ci import detect


def github(tmp_path, event, **extra):
    payload = tmp_path / "event.json"
    payload.write_text(json.dumps({"repository": {"default_branch": "trunk"}}))
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": event,
        "GITHUB_EVENT_PATH": str(payload),
        **extra,
    }


def test_github_default_branch_push_can_be_the_baseline(tmp_path):
    build = detect(github(tmp_path, "push", GITHUB_REF_NAME="trunk"))
    assert (build.branch, build.default_branch, build.change) == ("trunk", "trunk", False)
    assert build.can_be_baseline and build.provider == "github-actions"


def test_github_pull_request_is_a_change_on_its_source_branch(tmp_path):
    env = github(tmp_path, "pull_request", GITHUB_REF_NAME="12/merge", GITHUB_HEAD_REF="fix/kex")
    build = detect(env)
    assert (build.branch, build.change, build.can_be_baseline) == ("fix/kex", True, False)


def test_github_feature_branch_push_is_not_the_baseline(tmp_path):
    build = detect(github(tmp_path, "push", GITHUB_REF_NAME="feature"))
    assert build.can_be_baseline is False


def test_github_unreadable_event_leaves_the_default_branch_unknown(tmp_path):
    env = github(tmp_path, "push", GITHUB_REF_NAME="main", GITHUB_EVENT_PATH="/nonexistent")
    build = detect(env)
    assert build.default_branch is None and build.can_be_baseline is False


def test_gitlab_merge_request_and_branch_pipelines():
    mr = detect(
        {
            "GITLAB_CI": "true",
            "CI_MERGE_REQUEST_IID": "4",
            "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "fix",
            "CI_DEFAULT_BRANCH": "main",
        }
    )
    assert (mr.branch, mr.change, mr.can_be_baseline) == ("fix", True, False)
    push = detect({"GITLAB_CI": "true", "CI_COMMIT_BRANCH": "main", "CI_DEFAULT_BRANCH": "main"})
    assert push.can_be_baseline


def test_azure_devops_needs_the_default_branch_from_you():
    env = {
        "TF_BUILD": "True",
        "BUILD_SOURCEBRANCH": "refs/heads/main",
        "BUILD_REASON": "IndividualCI",
    }
    assert detect(env).can_be_baseline is False
    assert detect({**env, "QUANTSIV_DEFAULT_BRANCH": "main"}).can_be_baseline is True
    pr = detect(
        {
            "TF_BUILD": "True",
            "BUILD_REASON": "PullRequest",
            "SYSTEM_PULLREQUEST_SOURCEBRANCH": "refs/heads/fix",
            "QUANTSIV_DEFAULT_BRANCH": "main",
        }
    )
    assert (pr.branch, pr.change) == ("fix", True)


def test_jenkins_multibranch():
    env = {"JENKINS_URL": "https://ci", "BRANCH_NAME": "main", "QUANTSIV_DEFAULT_BRANCH": "main"}
    assert detect(env).can_be_baseline
    pr = detect({**env, "BRANCH_NAME": "PR-7", "CHANGE_ID": "7", "CHANGE_BRANCH": "fix"})
    assert (pr.branch, pr.change) == ("fix", True)


@pytest.mark.parametrize(
    "value,expected", [("true", True), ("1", True), ("false", False), ("", False)]
)
def test_explicit_variables_win(tmp_path, value, expected):
    env = github(tmp_path, "push", GITHUB_REF_NAME="trunk", QUANTSIV_CHANGE=value)
    assert detect(env).change is expected
    env = {**env, "QUANTSIV_BRANCH": "override", "QUANTSIV_DEFAULT_BRANCH": "override"}
    assert detect(env).branch == "override"


def test_an_unrecognised_ci_knows_nothing():
    build = detect({})
    assert (build.branch, build.default_branch, build.change, build.provider) == (
        None,
        None,
        False,
        None,
    )
    assert build.can_be_baseline is False
