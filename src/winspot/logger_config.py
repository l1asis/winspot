import logging
import sys

from . import logger


class CustomFormatter(logging.Formatter):
    """Custom logging formatter with colors based on log level."""

    dim = "\x1b[2m"
    cyan = "\x1b[36;21m"
    green = "\x1b[32;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    FORMATTERS = {
        logging.INFO: logging.Formatter(f"{green}[%(levelname)s]{reset} %(message)s"),
        logging.DEBUG: logging.Formatter(
            f"{cyan}[%(levelname)s]{reset} {dim}%(asctime)s - %(filename)s:%(lineno)d{reset} %(message)s"
        ),
        logging.WARNING: logging.Formatter(
            f"{yellow}[%(levelname)s]{reset} %(message)s"
        ),
        logging.ERROR: logging.Formatter(f"{red}[%(levelname)s]{reset} %(message)s"),
        logging.CRITICAL: logging.Formatter(
            f"{bold_red}[%(levelname)s]{reset} %(message)s"
        ),
    }

    def format(self, record: logging.LogRecord) -> str:
        formatter = self.FORMATTERS.get(record.levelno)
        if formatter is not None:
            return formatter.format(record)
        return super().format(record)


def setup_logging(verbose: bool = False, quiet: bool = False, silent: bool = False):
    """Configures the package logger."""

    if logger.hasHandlers():
        logger.handlers.clear()

    if silent:
        logger.addHandler(logging.NullHandler())
        logger.propagate = False
        return

    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    else:
        level = logging.INFO

    logger.setLevel(level)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(CustomFormatter())
    logger.addHandler(console_handler)

    logger.propagate = False
