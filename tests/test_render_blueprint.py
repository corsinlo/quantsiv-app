"""render.yaml stays consistent with the code it deploys (WP14).

Render's own validator needs the network and the Render CLI; these checks catch the mistakes that
break a first deploy: a dangling reference, a missing setting, a secret in the file, a worker
command that differs from the image's.
"""

import re
from pathlib import Path

import pytest
import yaml

from app.config import Settings

ROOT = Path(__file__).resolve().parents[1]
BLUEPRINT = yaml.safe_load((ROOT / "render.yaml").read_text())
SERVICES = {s["name"]: s for s in BLUEPRINT["services"]}
DATABASES = {d["name"]: d for d in BLUEPRINT["databases"]}
# The environment group the founder creates in the Dashboard (docs/runbooks/deploy.md)
GROUP = "quantsiv-github"
GROUP_KEYS = {
    "GITHUB_APP_ID",
    "GITHUB_APP_PRIVATE_KEY",
    "GITHUB_WEBHOOK_SECRET",
    "GITHUB_CLIENT_ID",
    "GITHUB_CLIENT_SECRET",
}
COMPUTE = [s for s in BLUEPRINT["services"] if s["type"] in ("web", "worker")]


def env_keys(service) -> set[str]:
    return {e["key"] for e in service.get("envVars", []) if "key" in e}


def test_names_are_unique_and_everything_is_in_frankfurt():
    names = [s["name"] for s in BLUEPRINT["services"]] + list(DATABASES)
    assert len(names) == len(set(names))
    regions = {s["region"] for s in BLUEPRINT["services"]} | {
        d["region"] for d in DATABASES.values()
    }
    assert regions == {"frankfurt"}  # one region, and the EU one; private networking needs it


@pytest.mark.parametrize("service", COMPUTE, ids=lambda s: s["name"])
def test_references_resolve(service):
    for env in service["envVars"]:
        if "fromDatabase" in env:
            assert env["fromDatabase"]["name"] in DATABASES
        if "fromService" in env:
            target = SERVICES[env["fromService"]["name"]]
            assert target["type"] == env["fromService"]["type"] == "keyvalue"
        if "fromGroup" in env:
            assert env["fromGroup"] == GROUP


@pytest.mark.parametrize("service", COMPUTE, ids=lambda s: s["name"])
def test_every_required_setting_is_provided(service):
    required = {
        name.upper() for name, field in Settings.model_fields.items() if field.is_required()
    }
    assert required <= env_keys(service) | GROUP_KEYS, required - env_keys(service) - GROUP_KEYS
    assert {"DATABASE_URL", "REDIS_URL", "ENV"} <= env_keys(service)


def test_no_secret_is_written_in_the_file():
    for service in COMPUTE:
        for env in service["envVars"]:
            key = env.get("key", "")
            if re.search(r"SECRET|KEY|TOKEN|PASSWORD", key):
                assert "value" not in env, f"{service['name']} writes {key} in the file"
    text = (ROOT / "render.yaml").read_text()
    assert "postgres://" not in text and "redis://" not in text


def test_the_web_service_migrates_and_is_health_checked():
    web = SERVICES["quantsiv-web"]
    assert web["healthCheckPath"] == "/health"
    assert web["preDeployCommand"] == "alembic upgrade head"
    assert "dockerCommand" not in web  # the image's CMD reads Render's PORT
    assert "preDeployCommand" not in SERVICES["quantsiv-worker"]


def instructions(text: str) -> list[str]:
    """Dockerfile instructions without comments, blank lines or line breaks."""
    joined = re.sub(r"\\\n", " ", text)
    lines = (" ".join(line.split()) for line in joined.splitlines())
    return [line for line in lines if line and not line.startswith("#")]


def test_the_worker_builds_from_its_own_file_which_matches_the_worker_stage():
    worker = SERVICES["quantsiv-worker"]
    assert SERVICES["quantsiv-web"]["dockerfilePath"] == "./Dockerfile"
    assert worker["dockerfilePath"] == "./Dockerfile.worker"
    assert "dockerCommand" not in worker  # the image's CMD starts ARQ
    main = (ROOT / "Dockerfile").read_text()
    stage_start = re.search(r"^FROM (\S+) AS worker$", main, re.MULTILINE)
    stage = main[stage_start.end() :].split("\nFROM ", 1)[0]
    own = instructions((ROOT / "Dockerfile.worker").read_text())
    assert own[0] == f"FROM {stage_start.group(1)}"
    assert own[1:] == instructions(stage), "Dockerfile.worker drifted from the worker stage"
    assert own[-1].startswith("CMD ") and "arq" in own[-1]


def test_the_queue_never_evicts_and_is_internal_only():
    queue = SERVICES["quantsiv-queue"]
    assert queue["maxmemoryPolicy"] == "noeviction"
    assert queue["ipAllowList"] == []
    assert DATABASES["quantsiv-db"]["ipAllowList"] == []


def test_the_runbook_names_the_group_and_its_keys():
    runbook = (ROOT / "docs" / "runbooks" / "deploy.md").read_text()
    assert GROUP in runbook
    for key in GROUP_KEYS:
        assert key in runbook
