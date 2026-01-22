import os
import time
import re
from typing import Optional, Any, Dict

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field


# -----------------------------
# ENV VARS (Heroku/Render/etc.)
# -----------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

ELEVEN_SHARED_SECRET = os.getenv("ELEVEN_SHARED_SECRET")  # opcional

PBX_DOMAIN = os.getenv("PBX_DOMAIN")  # ej: tu-dominio.yeastarcloud.com
YEASTAR_API_PATH = os.getenv("YEASTAR_API_PATH", "openapi/v1.0")
YEASTAR_USER_AGENT = os.getenv("YEASTAR_USER_AGENT", "OpenAPI")  # requerido por Yeastar

YEASTAR_USERNAME = os.getenv("YEASTAR_USERNAME")  # Client ID
YEASTAR_PASSWORD = os.getenv("YEASTAR_PASSWORD")  # Client Secret

DEFAULT_CALLER = os.getenv("DEFAULT_CALLER", "")  # ej: "100"
DEFAULT_DIAL_PERMISSION = os.getenv("DEFAULT_DIAL_PERMISSION")  # opcional
DEFAULT_AUTO_ANSWER = os.getenv("DEFAULT_AUTO_ANSWER", "no")  # yes/no


def _require_env(name: str, value: Optional[str]) -> str:
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


# -----------------------------
# Helpers
# -----------------------------
def normalize_phone(value: str) -> str:
    """
    WhatsApp ID puede venir como:
      - +59170123456
      - 59170123456
      - 59170123456@c.us
    Dejamos solo dígitos y + inicial si existe.
    """
    value = value.strip()
    value = value.replace("@c.us", "").replace("@s.whatsapp.net", "")
    if value.startswith("+"):
        return "+" + re.sub(r"\D", "", value)
    return re.sub(r"\D", "", value)


# -----------------------------
# Yeastar API Client (minimal)
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
        # token endpoint: POST /openapi/v1.0/get_token
        url = f"{self.api_base}/get_token"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": YEASTAR_USER_AGENT,  # REQUIRED
        }
        payload = {
            "username": _require_env("YEASTAR_USERNAME", YEASTAR_USERNAME),
            "password": _require_env("YEASTAR_PASSWORD", YEASTAR_PASSWORD),
        }

        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(url, headers=headers, json=payload)
            r.raise_for_status()
            data = r.json()

        if data.get("errcode") != 0:
            raise RuntimeError(f"Yeastar get_token failed: {data}")

        token = data["access_token"]
        expires_in = int(data.get("access_token_expire_time", 1800))
        self._token = token
        self._token_expiry = time.time() + max(0, expires_in - 30)  # refresh early
        return token

    async def access_token(self) -> str:
        if self._token and time.time() < self._token_expiry:
            return self._token
        return await self.get_token()

    async def dial(self, caller: str, callee: str, dial_permission: Optional[str], auto_answer: str) -> Dict[str, Any]:
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

        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(url, headers=headers, params=params, json=payload)
            r.raise_for_status()
            return r.json()


yeastar = YeastarClient()
app = FastAPI(title="eleven-handoff")


# -----------------------------
# Payload que manda ElevenLabs
# -----------------------------
class HandoffPayload(BaseModel):
    whatsapp_id: str = Field(..., description="Número/ID del usuario (ideal E.164 o wa_id).")
    confirmed: bool = Field(..., description="True si el usuario confirmó hablar con humano.")
    caller: Optional[str] = Field(None, description="Extensión/Caller. Si no, usa DEFAULT_CALLER.")
    dial_permission: Optional[str] = Field(None, description="Opcional si caller no tiene permisos.")
    auto_answer: Optional[str] = Field(None, description="yes/no. Si no, usa DEFAULT_AUTO_ANSWER.")


@app.get("/health")
async def health():
    return {"ok": True}


@app.post("/tools/handoff_to_human")
async def handoff_to_human(payload: HandoffPayload, x_eleven_secret: Optional[str] = Header(default=None)):
    # Seguridad opcional
    if ELEVEN_SHARED_SECRET:
        if not x_eleven_secret or x_eleven_secret != ELEVEN_SHARED_SECRET:
            raise HTTPException(status_code=401, detail="Invalid secret")

    # Debe venir confirmado (tu agente pregunta primero)
    if not payload.confirmed:
        return {"status": "ignored", "reason": "User not confirmed yet"}

    caller = payload.caller or DEFAULT_CALLER
    if not caller:
        raise HTTPException(status_code=500, detail="DEFAULT_CALLER not set and caller not provided")

    callee = normalize_phone(payload.whatsapp_id)
    if not callee:
        raise HTTPException(status_code=400, detail="Invalid whatsapp_id")

    dial_permission = payload.dial_permission or DEFAULT_DIAL_PERMISSION
    auto_answer = payload.auto_answer or DEFAULT_AUTO_ANSWER

    try:
        res = await yeastar.dial(
            caller=caller,
            callee=callee,
            dial_permission=dial_permission,
            auto_answer=auto_answer,
        )
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"HTTP error calling Yeastar: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error calling Yeastar: {str(e)}")

    if res.get("errcode") != 0:
        raise HTTPException(status_code=502, detail={"yeastar": res})

    return {"status": "ok", "call_id": res.get("call_id"), "yeastar": res}

