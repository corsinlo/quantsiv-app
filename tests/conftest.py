import os

# Required settings must exist before anything imports app.config (A10)
for key, value in {
    "GITHUB_APP_ID": "1",
    "GITHUB_APP_PRIVATE_KEY": "test",
    "GITHUB_WEBHOOK_SECRET": "test-secret",
    "GITHUB_CLIENT_ID": "test-client",
    "GITHUB_CLIENT_SECRET": "test-client-secret",
    "SESSION_SECRET": "test",
}.items():
    os.environ.setdefault(key, value)
