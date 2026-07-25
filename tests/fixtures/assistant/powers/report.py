from typing import TypedDict

from shimpz import Context, power


class Report(TypedDict):
    token_length: int


@power(accounts=["cloudflare"])
async def run(*, ctx: Context = None) -> Report:
    return {"token_length": len(ctx.accounts.cloudflare.access_token)}
