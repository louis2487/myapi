from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class UserRuntimePayload(BaseModel):
    user_id: str
    runtime_seconds: int

@app.post("/runtime/update")
def update_runtime(payload: UserRuntimePayload):
    print(f"{payload.user_id} → {payload.runtime_seconds}초")
    return {"status": "received"}
