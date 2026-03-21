"""Pocket Hacker - Runner script for deployment."""
import asyncio
import logging
import signal
import os
import sys

# Fix imports - add current dir to path
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

    async def run():
        await bot.start()
        logger.info("Pocket Hacker is LIVE")
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
