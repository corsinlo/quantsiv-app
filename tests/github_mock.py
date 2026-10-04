"""A fake GitHub API for GitHubApp, recording every request."""

import httpx

from app.services.github import GitHubApp

TOKEN = "ghs_INSTALLATION_TOKEN_SECRET"


class FakeGitHub:
    def __init__(self, *, private=False, size_kb=100, token_status=201, installation=7):
        self.private = private
        self.size_kb = size_kb
        self.token_status = token_status
        self.installation = installation
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if request.method == "GET" and path.endswith("/installation"):
            if self.installation is None:
                return httpx.Response(404, json={"message": "Not Found"})
            return httpx.Response(200, json={"id": self.installation})
        if request.method == "POST" and path.endswith("/access_tokens"):
            return httpx.Response(self.token_status, json={"token": TOKEN})
        if request.method == "DELETE" and path == "/installation/token":
            return httpx.Response(204)
        if request.method == "GET" and path.startswith("/repos/"):
            return httpx.Response(200, json={"private": self.private, "size": self.size_kb})
        return httpx.Response(500)

    def app(self) -> GitHubApp:
        github = GitHubApp(httpx.MockTransport(self.handler))
        github.app_jwt = lambda: "app-jwt"  # the RS256 signing is tested separately
        return github

    def calls(self) -> list[tuple[str, str]]:
        return [(r.method, r.url.path) for r in self.requests]
