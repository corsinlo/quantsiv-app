from fastapi import HTTPException, Request


async def read_body(request: Request, limit: int) -> bytes:
    """The request body, refused with 413 past `limit` bytes (also for chunked bodies)."""
    if int(request.headers.get("content-length") or 0) > limit:
        raise HTTPException(413, "payload too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise HTTPException(413, "payload too large")
    return bytes(body)
