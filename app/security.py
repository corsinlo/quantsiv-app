"""Security headers (A20). The strict CSP works because every script and stylesheet is
self-hosted and nothing is inline (A19)."""

from starlette.requests import Request

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'"
)


async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # Swagger UI loads from a CDN; /docs only exists outside production (A04)
    if request.url.path != "/docs":
        response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response
