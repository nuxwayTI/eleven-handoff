import os
import logging
from flask import Flask, request, jsonify, Response
from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

# =========================
# ENV
# =========================
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "").strip()

# Tu SIP Domain de Twilio
SIP_DOMAIN = os.getenv("SIP_DOMAIN", "nuxway.sip.twilio.com").strip()

# Cola/extensión destino
QUEUE_EXT = os.getenv("QUEUE_EXT", "6049").strip()

# URL pública del servicio (Render)
BASE_URL = os.getenv("BASE_URL", "").strip().rstrip("/")

# Caller SIP
TWILIO_FROM = os.getenv(
    "TWILIO_FROM",
    f"sip:ivr@{SIP_DOMAIN}"
).strip()

# (Opcional) token simple para proteger el webhook
WEBHOOK_TOKEN = os.getenv("WEBHOOK_TOKEN", "").strip()

twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

def abs_url(path: str) -> str:
    if not BASE_URL:
        raise RuntimeError("Falta BASE_URL en variables de entorno")
    if not path.startswith("/"):
        path = "/" + path
    return f"{BASE_URL}{path}"

@app.get("/")
def health():
    return "OK", 200

# =========================
# Webhook desde ElevenLabs
# =========================
@app.post("/elevenlabs/handoff")
def elevenlabs_handoff():

    # Seguridad opcional
    if WEBHOOK_TOKEN:
        token = request.headers.get("X-Webhook-Token", "").strip()
        if token != WEBHOOK_TOKEN:
            return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    logging.info(f"[ELEVENLABS] payload={data}")

    to_sip = f"sip:{QUEUE_EXT}@{SIP_DOMAIN}"

    try:
        call = twilio_client.calls.create(
            to=to_sip,
            from_=TWILIO_FROM,
            url=abs_url("/twiml/notify"),
            method="POST"
        )

        logging.warning(f"[TWILIO] call created SID={call.sid}")
        return jsonify({"ok": True, "call_sid": call.sid}), 200

    except Exception as e:
        logging.exception("[TWILIO] error creating call")
        return jsonify({"ok": False, "error": str(e)}), 500

# =========================
# TwiML mínimo
# =========================
@app.post("/twiml/notify")
def twiml_notify():
    vr = VoiceResponse()
    vr.say("Conectando con soporte. Por favor espere.", language="es-MX")
    return Response(str(vr), mimetype="text/xml")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)

