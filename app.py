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
ELEVEN_SHARED_SECRET = os.getenv("ELEVEN_SHARED_SECRET")  # optional; protects endpoints if set
DRY_RUN = os.getenv("DRY_RUN", "0") == "1"  # if 1 -> no real calls

PBX_DOMAIN = os.getenv("PBX_DOMAIN")  # e.g. nuxwaytechnology.use.ycmcloud.com
YEASTAR_API_PATH = os.getenv("YEASTAR_API_PATH", "openapi/v1.0")
YEASTAR_USER_AGENT = os.getenv("YEASTAR_USER_AGENT", "OpenAPI")  # REQUIRED by Yeastar

YEASTAR_USERNAME = os.getenv("YEASTAR_USERNAME")  # Client ID
YEASTAR_PASSWORD = os.getenv("YEASTAR_PASSWORD")  # Client Secret

DEFAULT_CALLER = os.getenv("DEFAULT_CALLER", "")  # e.g. "4002"
DEFAULT_DIAL_PERMISSION = os.getenv("DEFAULT_DIAL_PERMISSION")  # optional
DEFAULT_AUTO_ANSWER = os.getenv("DEFAULT_AUTO_ANSWER", "no")  # yes/no


def _require_env(name: str, value: Optional[str]) -> str:
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def normalize_phone(value: str) -> str:
    """
    Accept:
      - +59170123456
      - 59170123456
      - 59170123456@c.us
      - 59170123456@s.whatsapp.net
    """
    value = (value or "").strip()
    value = value.replace("@c.us", "").replace("@s.whatsapp.net", "")
    if value.startswith("+"):
        return "+" + re.sub(r"\D", "", value)
    return re.sub(r"\D", "", value)


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
            "User-Agent": YEASTAR_USER_AGENT,  # REQUIRED
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
        dial_permission: Optional[str] = None,
        auto_answer: str = "no",
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

        logger.info("Calling Yeastar /call/dial ...")
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(url, headers=headers, params=params, json=payload)
            r.raise_for_status()
            return r.json()


yeastar = YeastarClient()
app = FastAPI(title="eleven-handoff")


class HandoffPayload(BaseModel):
    whatsapp_id: str = Field(..., description="User WhatsApp ID/number (E.164 or wa_id).")
    confirmed: bool = Field(..., description="True only after user confirms talking to a human.")
    reason: Optional[str] = Field(None, description="Optional context (for logs).")
    caller: Optional[str] = Field(None, description="Extension/Caller. If not provided uses DEFAULT_CALLER.")
    dial_permission: Optional[str] = Field(None, description="Optional if caller lacks outbound permission.")
    auto_answer: Optional[str] = Field(None, description="yes/no. If not provided uses DEFAULT_AUTO_ANSWER.")


@app.get("/health")
async def health():
    logger.info("Health check hit.")
    return {"ok": True, "service": "eleven-handoff", "dry_run": DRY_RUN}


@app.get("/yeastar/ping")
async def yeastar_ping(x_admin_key: Optional[str] = Header(default=None)):
    """
    Safe test: verifies Yeastar connectivity by obtaining token (no call).
    Protect it with ELEVEN_SHARED_SECRET using header X-Admin-Key.
    """
    if ELEVEN_SHARED_SECRET:
        if not x_admin_key or x_admin_key != ELEVEN_SHARED_SECRET:
            raise HTTPException(status_code=401, detail="Invalid admin key")

    try:
        token = await yeastar.access_token()
        return {"ok": True, "message": "Yeastar token obtained", "token_prefix": token[:6]}
    except Exception as e:
        logger.exception("Failed to obtain Yeastar token")
        raise HTTPException(status_code=502, detail=f"Failed to obtain Yeastar token: {str(e)}")


@app.post("/tools/handoff_to_human")
async def handoff_to_human(payload: HandoffPayload, x_eleven_secret: Optional[str] = Header(default=None)):
    logger.info(">>> /tools/handoff_to_human HIT")
    logger.info(f"DRY_RUN={DRY_RUN}")
    logger.info(f"Headers: X-Eleven-Secret present={bool(x_eleven_secret)}")

    # Optional security for Eleven webhook
    if ELEVEN_SHARED_SECRET:
        if not x_eleven_secret or x_eleven_secret != ELEVEN_SHARED_SECRET:
            logger.warning("Invalid secret provided.")
            raise HTTPException(status_code=401, detail="Invalid secret")

    logger.info(f"Payload received: {payload.model_dump()}")

    if not payload.confirmed:
        logger.info("User not confirmed yet -> ignoring.")
        return {"status": "ignored", "reason": "User not confirmed yet"}

    caller = payload.caller or DEFAULT_CALLER
    if not caller:
        raise HTTPException(status_code=500, detail="DEFAULT_CALLER not set and caller not provided")

    callee = normalize_phone(payload.whatsapp_id)
    if not callee:
        raise HTTPException(status_code=400, detail="Invalid whatsapp_id")

    dial_permission = payload.dial_permission or DEFAULT_DIAL_PERMISSION
    auto_answer = payload.auto_answer or DEFAULT_AUTO_ANSWER

    logger.info(f"Preparing call: caller={caller}, callee={callee}, dial_permission={dial_permission}, auto_answer={auto_answer}")

    if DRY_RUN:
        logger.info("DRY_RUN=1 -> Not calling Yeastar. Returning simulated OK.")
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

    try:
        res = await yeastar.dial(
            caller=caller,
            callee=callee,
            dial_permission=dial_permission,
            auto_answer=auto_answer,
        )
        logger.info(f"Yeastar response: {res}")
    except httpx.HTTPError as e:
        logger.exception("HTTP error calling Yeastar")
        raise HTTPException(status_code=502, detail=f"HTTP error calling Yeastar: {str(e)}")
    except Exception as e:
        logger.exception("Unexpected error calling Yeastar")
        raise HTTPException(status_code=502, detail=f"Error calling Yeastar: {str(e)}")

    if res.get("errcode") != 0:
        logger.error(f"Yeastar returned errcode != 0: {res}")
        raise HTTPException(status_code=502, detail={"yeastar": res})

    return {"status": "ok", "call_id": res.get("call_id"), "yeastar": res}

