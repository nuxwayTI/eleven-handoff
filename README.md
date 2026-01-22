# eleven-handoff

Webhook receiver for ElevenLabs tools that triggers a Yeastar Cloud PBX callback.

## Endpoints
- GET /health
- POST /tools/handoff_to_human

## Environment Variables (Render)
Required:
- PBX_DOMAIN
- YEASTAR_USERNAME
- YEASTAR_PASSWORD
- DEFAULT_CALLER

Recommended:
- ELEVEN_SHARED_SECRET (then send header X-Eleven-Secret in ElevenLabs tool)
- DRY_RUN=1 for testing without calling Yeastar

Optional:
- DEFAULT_DIAL_PERMISSION
- DEFAULT_AUTO_ANSWER (yes/no)
- YEASTAR_API_PATH (default: openapi/v1.0)
- YEASTAR_USER_AGENT (default: OpenAPI)

## Example request
POST /tools/handoff_to_human
Headers:
- Content-Type: application/json
- X-Eleven-Secret: <secret> (optional)

Body:
```json
{
  "whatsapp_id": "+59170123456",
  "confirmed": true,
  "reason": "hablar con un asesor"
}
