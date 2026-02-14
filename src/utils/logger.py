import atexit
import logging
import logging.handlers
import os
import queue
import sys
from typing import Optional

from pythonjsonlogger import jsonlogger

from src.utils.middleware import request_id_ctx

_log_queue: queue.Queue = queue.Queue(-1)
_listener: Optional[logging.handlers.QueueListener] = None
_initialized: bool = False

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(request_id)s %(message)s"


class RequestIDFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get("")
        return True


def setup_logging(log_dir: str = "logs", log_level: str = "DEBUG") -> None:
    """Initialize logging infrastructure once. Safe to call multiple times."""
    global _listener, _initialized
    if _initialized:
        return

    # Create log directory
    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError as e:
        print(f"Error creating log directory: {e}", file=sys.stderr)
        log_dir = None  # Fall back to console-only

    json_formatter = jsonlogger.JsonFormatter(
        LOG_FORMAT,
        rename_fields={
            "levelname": "level",
            "asctime": "timestamp",
            "request_id": "request_id",
        },
    )

    handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(json_formatter)
    console_handler.setLevel(logging.DEBUG)
    handlers.append(console_handler)

    # File handler (only if log dir exists)
    if log_dir:
        file_handler = logging.handlers.TimedRotatingFileHandler(
            filename=os.path.join(log_dir, "app.log"),
            when="midnight",
            backupCount=7,
            encoding="utf-8",
            delay=True,
        )
        file_handler.setFormatter(json_formatter)
        file_handler.setLevel(logging.INFO)
        handlers.append(file_handler)

    # Start the queue listener
    _listener = logging.handlers.QueueListener(
        _log_queue, *handlers, respect_handler_level=True
    )
    _listener.start()
    atexit.register(_listener.stop)

    _initialized = True


def get_logger(name: str = __name__) -> logging.Logger:
    """Get a logger that writes through the async queue."""
    setup_logging()  # Ensure logging is initialized

    logger = logging.getLogger(name)
    if not logger.hasHandlers():
        queue_handler = logging.handlers.QueueHandler(_log_queue)
        logger.addHandler(queue_handler)
        logger.addFilter(RequestIDFilter())
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

    return logger
