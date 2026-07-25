from typing import TypedDict

from shimpz import power


class Greeting(TypedDict):
    message: str


@power()
async def run(name: str) -> Greeting:
    return {"message": f"Hello, {name}"}
