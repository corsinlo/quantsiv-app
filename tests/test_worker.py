from app import worker


def test_worker_settings_register_the_jobs():
    names = {f.__name__ for f in worker.WorkerSettings.functions}
    assert names == {"scan_repository", "handle_github_event", "delete_account"}


async def test_placeholder_jobs_run():
    ctx: dict = {}
    assert await worker.scan_repository(ctx, 1, "o/r") is None
    assert await worker.handle_github_event(ctx, "ping", {}) is None
    assert await worker.delete_account(ctx, 1) is None
