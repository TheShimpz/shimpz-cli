import os
from typing import TypedDict

from shimpz import Context, FetchError, action


class Report(TypedDict):
    outcome: str


@action(description="Ask for one provider call and report how it ended.", integrations=["cloudflare"])
async def run(url: str, *, ctx: Context) -> Report:
    # The CLI makes the call and adds the Integration bearer itself; the Action never holds a credential (ADR-0106).
    if any(name.startswith("SHIMPZ_INTEGRATION_") for name in os.environ):
        return {"outcome": "credential-exposed"}
    try:
        response = await ctx.fetch("GET", url)
    except FetchError as error:
        return {"outcome": error.code}
    return {"outcome": f"status {response.status}"}
