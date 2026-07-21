from fastapi import APIRouter
from pydantic import BaseModel

from db.database import get_db

router = APIRouter()


class SetWebhookUrlRequest(BaseModel):
    url: str


async def get_config_value(db, key: str) -> str | None:
    cur = await db.execute("SELECT value FROM app_config WHERE key = ?", (key,))
    row = await cur.fetchone()
    return row["value"] if row else None


async def set_config_value(db, key: str, value: str) -> None:
    await db.execute(
        """
        INSERT INTO app_config (key, value, updated_at)
        VALUES (?, ?, datetime('now'))
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (key, value),
    )
    await db.commit()


@router.get("/config/webhook-url")
async def get_webhook_url():
    db = await get_db()
    url = await get_config_value(db, "webhook_url")
    return {"url": url}


@router.post("/config/webhook-url")
async def set_webhook_url(body: SetWebhookUrlRequest):
    db = await get_db()
    await set_config_value(db, "webhook_url", body.url)
    return {"url": body.url}
