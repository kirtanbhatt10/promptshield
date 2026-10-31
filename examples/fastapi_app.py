"""Run with: pip install fastapi uvicorn && uvicorn examples.fastapi_app:app"""

from fastapi import FastAPI

from promptshield import Policy, Scanner
from promptshield.integrations.asgi import PromptShieldMiddleware

app = FastAPI()
app.add_middleware(
    PromptShieldMiddleware,
    scanner=Scanner(Policy(block_threshold=50)),
    paths=("/chat",),
    field="message",
)


@app.post("/chat")
async def chat(payload: dict) -> dict:
    # Only reached when promptshield did not block the message.
    return {"reply": f"You said: {payload['message']}"}
