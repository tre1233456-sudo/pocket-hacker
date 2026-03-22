"""Pocket Flipper - Runner script for deployment."""
import asyncio
import logging
import signal
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from config import Config
from telegram_bot import TelegramBot


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    logger = logging.getLogger(__name__)

    config = Config.from_env()
    if not config.telegram_token:
        logger.error("TELEGRAM_TOKEN not set!")
        return
    if not config.groq_key:
        logger.error("GROQ_API_KEY not set!")
        return

    bot = TelegramBot(config)

    railway_url = os.environ.get("RAILWAY_PUBLIC_DOMAIN") or os.environ.get("RAILWAY_URL")

    if railway_url:
        # Webhook mode on Railway
        from aiohttp import web

        async def webhook_handler(request):
            import json
            data = await request.read()
            update = bot.app.update_queue
            from telegram import Update as TGUpdate
            upd = TGUpdate.de_json(json.loads(data), bot.app.bot)
            await bot.app.process_update(upd)
            return web.Response(text="ok")

        async def health(request):
            return web.Response(text="Pocket Flipper is running")

        async def run_webhook():
            await bot.start()
            logger.info("Pocket Flipper is LIVE (webhook mode)")

            app_web = web.Application()
            app_web.router.add_post("/webhook", webhook_handler)
            app_web.router.add_get("/", health)

            port = int(os.environ.get("PORT", 8080))
            runner = web.AppRunner(app_web)
            await runner.setup()
            site = web.TCPSite(runner, "0.0.0.0", port)
            await site.start()
            logger.info(f"Webhook server listening on port {port}")

            stop_event = asyncio.Event()
            def _signal_handler():
                stop_event.set()
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, _signal_handler)
                except NotImplementedError:
                    pass
            await stop_event.wait()
            await runner.cleanup()
            await bot.stop()

        try:
            asyncio.run(run_webhook())
        except KeyboardInterrupt:
            logger.info("Shutting down...")
    else:
        # Polling mode for local dev
        async def run():
            await bot.start()
            logger.info("Pocket Flipper is LIVE (polling mode)")
            stop_event = asyncio.Event()

            def _signal_handler():
                stop_event.set()

            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, _signal_handler)
                except NotImplementedError:
                    pass

            await stop_event.wait()
            await bot.stop()

        try:
            asyncio.run(run())
        except KeyboardInterrupt:
            logger.info("Shutting down...")


if __name__ == "__main__":
    main()
