from typing import TypedDict

from shimpz import Context, action


class Report(TypedDict):
    token_length: int


@action(integrations=["cloudflare"])
async def run(*, ctx: Context) -> Report:
    return {"token_length": len(ctx.integrations.cloudflare.access_token)}
