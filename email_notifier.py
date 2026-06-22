"""
Notificador de alertas por correo electrónico (SMTP / Gmail con STARTTLS).

════════════════════════════════════════════════════════════════════
 CONFIGURACIÓN — variables de entorno requeridas
════════════════════════════════════════════════════════════════════

  SMTP_USER       Dirección de correo remitente
                  Ej: SMTP_USER=tu-cuenta@gmail.com

  SMTP_PASSWORD   Contraseña de aplicación (NO la contraseña de la cuenta).
                  En Gmail: Mi Cuenta → Seguridad → Verificación en dos pasos
                  → Contraseñas de aplicaciones → generar una nueva.
                  Ej: SMTP_PASSWORD="xxxx xxxx xxxx xxxx"

  ALERT_EMAIL_TO  Dirección(es) destinataria. Para varias, separar con coma.
                  Ej: ALERT_EMAIL_TO=admin@example.com

Variables opcionales (tienen defaults razonables):

  SMTP_HOST       Servidor SMTP   (default: smtp.gmail.com)
  SMTP_PORT       Puerto SMTP     (default: 587)

════════════════════════════════════════════════════════════════════
 Configuración en la Pi (OpenWrt)
════════════════════════════════════════════════════════════════════

Editá /etc/init.d/iot25 y agregá las variables antes del comando de inicio:

    export SMTP_USER="tu-cuenta@gmail.com"
    export SMTP_PASSWORD="xxxx xxxx xxxx xxxx"
    export ALERT_EMAIL_TO="tu@correo.com"

O usá /etc/profile para que persistan en todas las sesiones.

════════════════════════════════════════════════════════════════════
 Comportamiento si las variables NO están definidas
════════════════════════════════════════════════════════════════════

El módulo queda deshabilitado silenciosamente. El resto del sistema
funciona con normalidad: las alertas se crean en la DB igual.

El nivel mínimo de severidad que dispara correo se configura en la
tabla settings con la key 'email_min_severity' (valores: medium /
high / critical; default 'high').
"""

import logging
import os
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from database import get_db

logger = logging.getLogger(__name__)

_TZ_AR = timezone(timedelta(hours=-3))

# Orden numérico de severidades para comparación >= .
_SEV_ORDER: dict[str, int] = {"medium": 0, "high": 1, "critical": 2}


# ── helpers ───────────────────────────────────────────────────────────────────

def is_smtp_configured() -> bool:
    """True si las credenciales SMTP (SMTP_USER y SMTP_PASSWORD) están en env vars.
    No requiere ALERT_EMAIL_TO porque el destinatario puede venir de settings."""
    return bool(os.getenv("SMTP_USER") and os.getenv("SMTP_PASSWORD"))


def _get_email_to() -> str:
    """Destino: settings['email_to'] si está definido, si no la env var ALERT_EMAIL_TO."""
    db_to = _get_setting("email_to", "").strip()
    if db_to:
        return db_to
    return os.getenv("ALERT_EMAIL_TO", "").strip()


def _get_setting(key: str, default: str) -> str:
    try:
        row = get_db().execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else default
    except Exception:
        return default


def _fmt_local(iso_ts: str | None) -> str:
    """Convierte un timestamp ISO UTC a hora Argentina (UTC-3) en formato legible."""
    if not iso_ts:
        return "—"
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return dt.astimezone(_TZ_AR).strftime("%d/%m/%Y %H:%M:%S")
    except (ValueError, AttributeError):
        return iso_ts


def _build_alert_message(alert: dict, to: str) -> EmailMessage:
    severity   = (alert.get("severity") or "medium").upper()
    device     = alert.get("device_label") or f"dispositivo #{alert.get('device_id', '?')}"
    body_text  = alert.get("message") or "Sin detalle."
    rec        = alert.get("recommendations") or ""
    ts_display = _fmt_local(alert.get("timestamp"))
    alert_type = alert.get("type", "anomaly_iforest")

    rec_block = f"\nAcción sugerida:\n{rec}\n" if rec else ""

    body = (
        f"IoT25 — Alerta de Seguridad\n"
        f"{'=' * 44}\n\n"
        f"Dispositivo : {device}\n"
        f"Severidad   : {severity}\n"
        f"Tipo        : {alert_type}\n"
        f"Hora        : {ts_display} (hora Argentina, UTC-3)\n\n"
        f"Detalle:\n{body_text}\n"
        f"{rec_block}\n"
        f"{'─' * 44}\n"
        f"Mensaje generado automáticamente por IoT25.\n"
    )

    msg = EmailMessage()
    msg["Subject"] = f"[IoT25] Alerta {severity}: {device}"
    msg["From"]    = os.environ["SMTP_USER"]
    msg["To"]      = to
    msg.set_content(body)
    return msg


def _send_via_smtp(msg: EmailMessage) -> None:
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.environ["SMTP_USER"]
    pwd  = os.environ["SMTP_PASSWORD"]

    with smtplib.SMTP(host, port, timeout=15) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        smtp.login(user, pwd)
        smtp.send_message(msg)


# ── API pública ───────────────────────────────────────────────────────────────

def send_alert_email(alert: dict) -> bool:
    """
    Envía un correo para la alerta dada.

    Verifica en orden:
      1. Credenciales SMTP presentes (env vars SMTP_USER/SMTP_PASSWORD).
      2. email_enabled = 'true' en settings (interruptor global).
      3. Destinatario configurado (settings['email_to'] o env var ALERT_EMAIL_TO).
      4. Severidad de la alerta >= email_min_severity de settings.

    Retorna True si se envió. Cualquier fallo se loguea pero NO se propaga.

    Parámetros esperados en `alert`:
        device_id, device_label, type, severity, message, recommendations, timestamp
    """
    if not is_smtp_configured():
        logger.debug("Email omitido: credenciales SMTP no configuradas.")
        return False

    if _get_setting("email_enabled", "false").lower() != "true":
        logger.debug("Email omitido: email_enabled = false.")
        return False

    to = _get_email_to()
    if not to:
        logger.debug("Email omitido: sin destinatario configurado.")
        return False

    min_sev   = _get_setting("email_min_severity", "high")
    alert_sev = alert.get("severity", "medium")
    if _SEV_ORDER.get(alert_sev, 0) < _SEV_ORDER.get(min_sev, 1):
        logger.debug(
            "Email omitido: severidad %s por debajo del mínimo %s.", alert_sev, min_sev
        )
        return False

    try:
        msg = _build_alert_message(alert, to)
        _send_via_smtp(msg)
        logger.info(
            "Email de alerta enviado — device=%s severity=%s to=%s",
            alert.get("device_label"), alert_sev, to,
        )
        return True
    except Exception as exc:
        logger.error("Error al enviar email de alerta: %s", exc)
        return False


def send_test_email() -> dict:
    """
    Envía un correo de prueba para verificar la configuración SMTP.
    Ignora intencionalmente email_enabled (es una prueba manual).
    Retorna {'ok': bool, 'detail': str}.
    """
    if not is_smtp_configured():
        return {
            "ok": False,
            "detail": (
                "Credenciales SMTP no configuradas en el servidor. "
                "Definí SMTP_USER y SMTP_PASSWORD como variables de entorno."
            ),
        }

    to = _get_email_to()
    if not to:
        return {
            "ok": False,
            "detail": (
                "Sin destinatario configurado. "
                "Guardá un email en la sección Notificaciones o definí ALERT_EMAIL_TO."
            ),
        }

    user = os.environ["SMTP_USER"]
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))

    msg = EmailMessage()
    msg["Subject"] = "[IoT25] Correo de prueba — configuración SMTP OK"
    msg["From"]    = user
    msg["To"]      = to
    msg.set_content(
        "Este es un correo de prueba generado por IoT25.\n\n"
        "Si recibiste este mensaje, la configuración SMTP está funcionando correctamente.\n\n"
        f"Servidor : {host}:{port}\n"
        f"Destino  : {to}\n"
    )

    try:
        _send_via_smtp(msg)
        logger.info("Correo de prueba enviado a %s", to)
        return {"ok": True, "detail": f"Correo enviado correctamente a {to}."}
    except Exception as exc:
        logger.error("Error en correo de prueba: %s", exc)
        return {"ok": False, "detail": str(exc)}
