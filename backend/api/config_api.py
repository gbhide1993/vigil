from fastapi import APIRouter, HTTPException
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


# ------------------------------------------------------------------ opt-in external timestamps (Stage 2)

class ExternalTimestampSettings(BaseModel):
    enabled: bool = False
    url: str = ""
    fallback_url: str = ""
    ca_pem: str = ""


def _clean_url(value: str, label: str) -> str:
    value = (value or "").strip()
    if value and (not value.lower().startswith(("http://", "https://")) or len(value) > 500 or " " in value):
        raise HTTPException(status_code=400, detail=f"{label} must be an http:// or https:// address")
    return value


async def _external_timestamp_view(db) -> dict:
    from core import external_timestamp as ts

    settings = await ts.load_settings(db)
    return {
        "enabled": settings["enabled"], "url": settings["url"], "fallback_url": settings["fallback_url"],
        "ca_pem": settings["ca_pem"], "active": ts.is_active(settings), "disclosure": ts.DISCLOSURE,
    }


@router.get("/config/external-timestamp")
async def get_external_timestamp():
    return await _external_timestamp_view(await get_db())


@router.post("/config/external-timestamp")
async def set_external_timestamp(body: ExternalTimestampSettings):
    """Off by default. Nothing is sent until enabled is true AND a url is set. Turning it on records the
    newest existing anchor as the first one to timestamp; older anchors are not back-filled."""
    from core import external_timestamp as ts

    url = _clean_url(body.url, "The timestamp service address")
    fallback = _clean_url(body.fallback_url, "The fallback address")
    if body.enabled and not url:
        raise HTTPException(status_code=400, detail="Set the timestamp service address before turning this on")
    ca_pem = (body.ca_pem or "").strip()
    if ca_pem:
        try:
            if not ts.load_ca_certificates(ca_pem):
                raise ValueError("no certificate")
        except Exception:
            raise HTTPException(status_code=400, detail="The certificate is not valid PEM") from None
    db = await get_db()
    was_active = ts.is_active(await ts.load_settings(db))
    await set_config_value(db, ts.CONFIG_URL, url)
    await set_config_value(db, ts.CONFIG_FALLBACK_URL, fallback)
    await set_config_value(db, ts.CONFIG_CA_PEM, ca_pem)
    await set_config_value(db, ts.CONFIG_ENABLED, "1" if body.enabled else "0")
    if body.enabled and not was_active:
        try:
            cur = await db.execute("SELECT COALESCE(MAX(anchor_seq), 1) AS m FROM evidence_anchors")
            await set_config_value(db, ts.CONFIG_SINCE_SEQ, str((await cur.fetchone())["m"]))
        except Exception:
            await set_config_value(db, ts.CONFIG_SINCE_SEQ, "1")
    return await _external_timestamp_view(db)
