"""
Logging utilities for the input preparation module.

Provides structured logging with request IDs and timing information.
"""

import logging
import sys
from typing import Optional
from datetime import datetime
from app.config import settings


# Color codes for terminal output
class LogColors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color coding for different log levels."""
    
    COLORS = {
        logging.DEBUG: LogColors.GRAY,
        logging.INFO: LogColors.GREEN,
        logging.WARNING: LogColors.YELLOW,
        logging.ERROR: LogColors.RED,
        logging.CRITICAL: LogColors.MAGENTA,
    }
    
    def format(self, record):
        """Format log record with color coding."""
        color = self.COLORS.get(record.levelno, LogColors.RESET)
        record.levelname = f"{color}{record.levelname}{LogColors.RESET}"
        return super().format(record)


def setup_logging(log_level: Optional[str] = None) -> None:
    """
    Configure logging for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    level = log_level or settings.LOG_LEVEL
    
    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    
    # Create formatter
    formatter = ColoredFormatter(
        fmt='%(asctime)s | %(levelname)s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(handler)
    
    # Reduce noise from third-party libraries
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("fastapi").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (typically __name__)
    
    Returns:
        Configured logger instance
    
    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Processing request")
    """
    return logging.getLogger(name)


class RequestLogger:
    """Context manager for logging request processing with timing."""
    
    def __init__(self, request_id: str, logger: logging.Logger):
        """
        Initialize request logger.
        
        Args:
            request_id: Unique request identifier
            logger: Logger instance to use
        """
        self.request_id = request_id
        self.logger = logger
        self.start_time: Optional[datetime] = None
        self.step_times: dict[str, float] = {}
    
    def __enter__(self):
        """Start timing the request."""
        self.start_time = datetime.now()
        self.logger.info(f"[{self.request_id}] Starting request processing")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Log completion and total time."""
        if self.start_time:
            elapsed = (datetime.now() - self.start_time).total_seconds() * 1000
            if exc_type:
                self.logger.error(
                    f"[{self.request_id}] Request failed after {elapsed:.2f}ms: {exc_val}"
                )
            else:
                self.logger.info(
                    f"[{self.request_id}] Request completed in {elapsed:.2f}ms"
                )
    
    def log_step(self, step_name: str, duration_ms: float):
        """
        Log timing for a specific processing step.
        
        Args:
            step_name: Name of the processing step
            duration_ms: Duration in milliseconds
        """
        self.step_times[step_name] = duration_ms
        self.logger.debug(
            f"[{self.request_id}] Step '{step_name}' completed in {duration_ms:.2f}ms"
        )
    
    def get_step_times(self) -> dict[str, float]:
        """Get dictionary of all step timings."""
        return self.step_times.copy()

