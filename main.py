import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from pwdp.client import PWDPClient

logger = logging.getLogger(__name__)


if __name__ == "__main__":
    # Logger setup
    time = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"{time}_run.log"
    # Define and create directory for logging
    log_dpath = os.environ.get("LOGS_DIR")
    if log_dpath:
        log_directory = Path(log_dpath)
    else:
        log_directory = Path.cwd() / "logs"
    log_directory.mkdir(exist_ok=True)

    # Setup file and sys.stdout logging
    file_handler = logging.FileHandler(filename=log_directory / log_filename)
    stdout_handler = logging.StreamHandler(stream=sys.stdout)
    handlers = [file_handler, stdout_handler]

    logging.basicConfig(
        format="%(asctime)s %(message)s",
        datefmt="%m/%d/%Y %H:%M:%S",
        level=logging.INFO,
        handlers=handlers,
    )
    # Run app
    try:
        app: PWDPClient = PWDPClient.from_inbuilt_config()
        logger.info("Application initialized.")
        logger.info("Starting ...")
        app.run()
        logger.info("Application finished successfully.")
    except Exception as e:
        logger.info(f"Caught:\n{e}")
        logger.info("Application failed.")
