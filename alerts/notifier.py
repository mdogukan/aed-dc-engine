import asyncio
import httpx
import logging
from datetime import datetime

logger = logging.getLogger("AED-DC.Notifier")

class ThreatNotifier:
    """
    Saldırı ve tecrit olaylarını Telegram veya Webhook üzerinden dış sistemlere aktarır.
    """
    def __init__(self, telegram_token: str = None, telegram_chat_id: str = None, webhook_url: str = None):
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.webhook_url = webhook_url

    async def send_telegram(self, ip: str, port: int, protocol: str, reason: str):
        if not self.telegram_token or not self.telegram_chat_id:
            return

        text = (
            f"🚨 *[AED-DC ENGINE ALARM]* 🚨\n\n"
            f"⚡ *Durum:* Saldırgan Tespit Edildi & Tecrit Edildi\n"
            f"🌐 *Saldırgan IP:* `{ip}`\n"
            f"🎯 *Hedef Port:* `{port}` ({protocol})\n"
            f"🛡️ *Eylem:* nftables DROP\n"
            f"📝 *Detay:* {reason}\n"
            f"⏱️ *Zaman:* `{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}`"
        )
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {"chat_id": self.telegram_chat_id, "text": text, "parse_mode": "Markdown"}

        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(url, json=payload)
                logger.info(f"[*] Telegram alarmı gönderildi: {ip}")
        except Exception as e:
            logger.warning(f"Telegram alarm hatası: {e}")

    async def send_webhook(self, data: dict):
        if not self.webhook_url:
            return
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(self.webhook_url, json=data)
                logger.info("[*] Webhook alarmı fırlatıldı.")
        except Exception as e:
            logger.warning(f"Webhook hatası: {e}")

    async def broadcast_containment(self, ip: str, port: int, protocol: str, reason: str):
        data = {
            "event": "ATTACKER_ISOLATED",
            "source_ip": ip,
            "target_port": port,
            "protocol": protocol,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
        await asyncio.gather(
            self.send_telegram(ip, port, protocol, reason),
            self.send_webhook(data),
            return_exceptions=True
        )

# Global alarm nesnesi
notifier_engine = ThreatNotifier()
