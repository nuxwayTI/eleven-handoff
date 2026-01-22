import os
import time
import re
import logging
from typing import Optional, Any, Dict

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

# -----------------------------
# Logging (shows in Render Logs)
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
YEASTAR_USER_AGENT = os.getenv("YEASTAR_USER_AGENT", "OpenAPI")  # REQUIRED by Yeastar

YEASTAR_USERNAME = os.getenv("YEASTAR_USERNAME")  # Client ID
YEASTAR_PASSWORD = os.getenv("YEASTAR_PASSWORD")  # Client Secret

# NEW: Control variables (as you requested)
CALLER = os.getenv("CALLER", "6200")               # e.g. IVR 6200
CALLEE_PREFIX = os.getenv("CALLEE_PREFIX", "98")   # outbound prefix
DIAL_PERMISSION = os.getenv("DIAL_PERMISSION", "4002")  # permission extension

# We keep auto_answer default as "no" for IVR/Queue flows
DEFAULT_AUTO_ANSWER = os.getenv("DEFAULT_AUTO_ANSWER", "no")


def _require_env(name: str, value: Optional[str]) -> str:
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def normalize_digits(value: str) -> str:
    """
    Accept:
      - +59170770144
      - 59170770144
      - 70770144
      - 70770144@c.us
    Returns only digits.
    """
    value = (value or "").strip()
    value = value.replace("@c.us", "").replace("@s.whatsapp.net", "")
    return re.sub(r"\D", "", value)


def build_callee(number: str) -> str:
    """
    Ensures number starts with CALLEE_PREFIX (e.g. 98).
    If already starts with 98, keep it.
    """
    digits = normalize_digits(number)
    prefix = normalize_digits(CALLEE_PREFIX)

    if not digits:
        return ""

    if prefix and digits.startswith(prefix):
        return digits

    return f"{prefix}{digits}" if prefix else digits


# -----------------------------
# Yeastar API Client
# -----------------------------
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
        """
        POST /openapi/v1.0/get_token
        Headers MUST include: User-Agent: OpenAPI
        """
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
        dial_permission: Optional[str],
        auto_answer: str,
    ) -> Dict[str, Any]:
        """
        POST /openapi/v1.0/call/dial?access_token=...
        JSON body: caller, callee, dial_permission, auto_answer
        """
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


# -----------------------------
# Payload from ElevenLabs Tool
# -----------------------------
class HandoffPayload(BaseModel):
    whatsapp_id: str = Field(..., description="User number/whatsapp id. We will prefix it with CALLEE_PREFIX.")
    confirmed: bool = Field(..., description="True only after user confirms.")
    reason: Optional[str] = Field(None, description="Optional context for logs.")

    # Optional overrides per-request (if needed later)
    caller: Optional[str] = Field(None, description="Overrides env CALLER.")
    callee_prefix: Optional[str] = Field(None, description="Overrides env CALLEE_PREFIX.")
    dial_permission: Optional[str] = Field(None, description="Overrides env DIAL_PERMISSION.")
    auto_answer: Optional[str] = Field(None, description="yes/no. For IVR/Queue usually 'no'.")


@app.get("/health")
async def health():
    logger.info("Health check hit.")
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
    """
    Safe connectivity test: obtains token only (no call).
    If ELEVEN_SHARED_SECRET is set, protect with header X-Admin-Key.
    """
    if ELEVEN_SHARED_SECRET:
        if x_admin_key != ELEVEN_SHARED_SECRET:
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
    logger.info(f"Payload received: {payload.model_dump()}")

    # Optional security
    if ELEVEN_SHARED_SECRET:
        if x_eleven_secret != ELEVEN_SHARED_SECRET:
            logger.warning("Invalid secret provided.")
            raise HTTPException(status_code=401, detail="Invalid secret")

    if not payload.confirmed:
        return {"status": "ignored", "reason": "User not confirmed yet"}

    # Resolve config (env + optional request overrides)
    caller = (payload.caller or CALLER).strip()
    dial_permission = (payload.dial_permission or DIAL_PERMISSION).strip() if (payload.dial_permission or DIAL_PERMISSION) else None

    # allow overriding prefix in request if you ever want
    effective_prefix = payload.callee_prefix or CALLEE_PREFIX
    global CALLEE_PREFIX  # used by build_callee
    old_prefix = CALLEE_PREFIX
    CALLEE_PREFIX = effective_prefix

    try:
        callee = build_callee(payload.whatsapp_id)
    finally:
        CALLEE_PREFIX = old_prefix  # restore

    if not caller:
        raise HTTPException(status_code=500, detail="CALLER env var not set (and no caller provided).")

    if not callee:
        raise HTTPException(status_code=400, detail="Invalid whatsapp_id / could not build callee")

    auto_answer = (payload.auto_answer or DEFAULT_AUTO_ANSWER).strip()

    logger.info(f"Prepared call -> caller={caller}, callee={callee}, dial_permission={dial_permission}, auto_answer={auto_answer}")

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
