from typing import TypedDict

from shimpz import Context, power


class Report(TypedDict):
    token_length: int


@power(integrations=["cloudflare"])
async def run(*, ctx: Context) -> Report:
    return {"token_length": len(ctx.integrations.cloudflare.access_token)}
