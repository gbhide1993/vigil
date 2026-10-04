"""Read-only endpoints over the evidence chain (core/evidence_chain.py).
Never writes -- sealing happens only via the scheduled job in main.py."""

from fastapi import APIRouter

from core.evidence_chain import get_chain_head, verify_chain
from db.database import get_db

router = APIRouter()


@router.get("/evidence/chain/head")
async def chain_head():
    db = await get_db()
    return await get_chain_head(db)


@router.get("/evidence/chain/verify")
async def chain_verify():
    db = await get_db()
    return await verify_chain(db)
