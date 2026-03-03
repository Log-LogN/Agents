import uvicorn
import logging
import signal
import sys

from shared.config import settings

# =========================================================
# Logging
# =========================================================

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger("supervisor-launcher")


def run():
    logger.info("Starting Supervisor API on port 9000...")

    uvicorn.run(
        "agent.supervisor.api:app",
        host="0.0.0.0",
        port=9000,
        reload=False,
        log_level=settings.LOG_LEVEL.lower(),
    )


def handle_signal(signum, frame):
    logger.info("Received signal %s. Shutting down supervisor...", signum)
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    run()