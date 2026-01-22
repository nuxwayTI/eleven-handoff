import os
import time
import re
import logging
from typing import Optional, Any, Dict

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

# -----------------------------
# Logging (Render Logs)
# -----------------------------
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("eleven-handoff")

# -----------------------------
# ENV VARS
# -----------------------------
ELEVEN_SHARED_SECRET = os.getenv("ELEVEN_SHARED_SECRET")  # optional
DRY_RUN = os.getenv("DRY_RUN", "0") == "1"

PBX_DOMAIN = os.getenv("PBX_DOMAIN")  # e.g. nuxwaytechnology.use.ycmcloud.com
YEASTAR_API_PATH = os.getenv("YEASTAR_API_PATH", "openapi/v1.0")
YEASTAR_USER_AGENT = os.getenv("YEASTAR_USER_AGENT", "OpenAPI")  # required by Yeastar

YEASTAR_USERNAME = os.getenv("YEASTAR_USERNAME")
YEASTAR_PASSWORD = os.getenv("YEASTAR_PASSWORD")

# Your requested control vars:
CALLER = os.getenv("CALLER", "6200")               # IVR 6200
CALLEE_PREFIX = os.getenv("CALLEE_PREFIX", "98")   # outbound prefix 98
DIAL_PERMISSION = os.getenv("DIAL_PERMISSION", "4002")  # permission extension 4002

DEFAULT_AUTO_ANSWER = os.getenv("DEFAULT_AUTO_ANSWER", "no")  # keep 'no' for IVR/Queue flow


def _require_env(name: str, value: Optional[str]) -> str:
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def normalize_digits(value: str) -> str:
    value = (value or "").strip()
    value = value.replace("@c.us", "").replace("@s.whatsapp.net", "")
    return re.sub(r"\D", "", value)


def build_callee(number: str) -> str:
    digits = normalize_digits(number)
    prefix = normalize_digits(CALLEE_PREFIX)

    if not digits:
        return ""

    if prefix and digits.startswith(prefix):
        return digits

    return f"{prefix}{digits}" if prefix else digits


class YeastarClient:
    def __init__(self) -> None:
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

    @property
    def base_url(self) -> str:
        domain = _require_env("PBX_DOMAIN", PBX_DOMAIN)
        return f"https://{domain}"

    @property
    def api_base(self) -> str:
        return f"{self.base_url}/{YEASTAR_API_PATH}"

    async def get_token(self) -> str:
        url = f"{self.api_base}/get_token"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": YEASTAR_USER_AGENT,
        }
        payload = {
            "username": _require_env("YEASTAR_USERNAME", YEASTAR_USERNAME),
            "password": _require_env("YEASTAR_PASSWORD", YEASTAR_PASSWORD),
        }

        logger.info("Requesting Yeastar access token...")
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(url, headers=headers, json=payload)
            r.raise_for_status()
            data = r.json()

        if data.get("errcode") != 0:
            raise RuntimeError(f"Yeastar get_token failed: {data}")

        token = data["access_token"]
        expires_in = int(data.get("access_token_expire_time", 1800))

        self._token = token
        self._token_expiry = time.time() + max(0, expires_in - 30)

        logger.info(f"Yeastar token OK. Expires in ~{expires_in}s")
        return token

    async def access_token(self) -> str:
        if self._token and time.time() < self._token_expiry:
            return self._token
        return await self.get_token()

    async def dial(
        self,
        caller: str,
        callee: str,
        dial_permission: Optional[str],
        auto_answer: str,
    ) -> Dict[str, Any]:
        token = await self.access_token()

        url = f"{self.api_base}/call/dial"
        params = {"access_token": token}
        headers = {
            "Content-Type": "application/json",
            "User-Agent": YEASTAR_USER_AGENT,
        }

        payload: Dict[str, Any] = {"caller": caller, "callee": callee}
        if dial_permission:
            payload["dial_permission"] = dial_permission
        if auto_answer:
            payload["auto_answer"] = auto_answer

        logger.info(f"Calling Yeastar /call/dial payload={payload}")
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(url, headers=headers, params=params, json=payload)
            r.raise_for_status()
            return r.json()


yeastar = YeastarClient()
app = FastAPI(title="eleven-handoff")


class HandoffPayload(BaseModel):
    whatsapp_id: str = Field(..., description="User number/whatsapp id; server prefixes with CALLEE_PREFIX.")
    confirmed: bool = Field(..., description="True after user confirms.")
    reason: Optional[str] = Field(None, description="Optional context.")

    # Optional overrides per request
    caller: Optional[str] = None
    dial_permission: Optional[str] = None
    auto_answer: Optional[str] = None


@app.get("/health")
async def health():
    return {
        "ok": True,
        "service": "eleven-handoff",
        "dry_run": DRY_RUN,
        "caller": CALLER,
        "callee_prefix": CALLEE_PREFIX,
        "dial_permission": DIAL_PERMISSION,
    }


@app.get("/yeastar/ping")
async def yeastar_ping(x_admin_key: Optional[str] = Header(default=None)):
    if ELEVEN_SHARED_SECRET and x_admin_key != ELEVEN_SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Invalid admin key")

    token = await yeastar.access_token()
    return {"ok": True, "message": "Yeastar token obtained", "token_prefix": token[:6]}


@app.post("/tools/handoff_to_human")
async def handoff_to_human(payload: HandoffPayload, x_eleven_secret: Optional[str] = Header(default=None)):
    logger.info(">>> /tools/handoff_to_human HIT")
    logger.info(f"DRY_RUN={DRY_RUN}")
    logger.info(f"Payload received: {payload.model_dump()}")

    if ELEVEN_SHARED_SECRET and x_eleven_secret != ELEVEN_SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Invalid secret")

    if not payload.confirmed:
        return {"status": "ignored", "reason": "User not confirmed yet"}

    caller = (payload.caller or CALLER).strip()
    dial_permission = (payload.dial_permission or DIAL_PERMISSION).strip() if (payload.dial_permission or DIAL_PERMISSION) else None
    auto_answer = (payload.auto_answer or DEFAULT_AUTO_ANSWER).strip()

    callee = build_callee(payload.whatsapp_id)

    if not caller:
        raise HTTPException(status_code=500, detail="CALLER not set")
    if not callee:
        raise HTTPException(status_code=400, detail="Invalid whatsapp_id")

    logger.info(f"Prepared call -> caller={caller}, callee={callee}, dial_permission={dial_permission}, auto_answer={auto_answer}")

    if DRY_RUN:
        return {
            "status": "dry_run_ok",
            "would_call": {
                "caller": caller,
                "callee": callee,
                "dial_permission": dial_permission,
                "auto_answer": auto_answer,
                "reason": payload.reason,
            },
        }

    res = await yeastar.dial(
        caller=caller,
        callee=callee,
        dial_permission=dial_permission,
        auto_answer=auto_answer,
    )

    if res.get("errcode") != 0:
        raise HTTPException(status_code=502, detail={"yeastar": res})

    return {"status": "ok", "call_id": res.get("call_id"), "yeastar": res}
