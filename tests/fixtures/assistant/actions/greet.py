from typing import TypedDict

from shimpz import action


class Greeting(TypedDict):
    message: str


@action(description="Greet one person by name.")
async def run(name: str) -> Greeting:
    return {"message": f"Hello, {name}"}
