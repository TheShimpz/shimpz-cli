from typing import TypedDict

from shimpz import action


class Greeting(TypedDict):
    message: str


@action()
async def run(name: str) -> Greeting:
    return {"message": f"Hello, {name}"}
