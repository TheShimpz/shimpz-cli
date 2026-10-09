from typing import TypedDict

from shimpz import Context, action


class Report(TypedDict):
    token_length: int


@action(description="Report the length of the Cloudflare access token.", integrations=["cloudflare"])
async def run(*, ctx: Context) -> Report:
    return {"token_length": len(ctx.integrations.cloudflare.access_token)}
