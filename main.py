import logging
from datetime import datetime
from pathlib import Path

from pwdp.client import PWDPClient

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    # Logger setup
    time = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"{time}_run.log"
    # Define and create directory for logging
    log_directory = Path.cwd() / "logs"
    log_directory.mkdir(exist_ok=True)

    logging.basicConfig(
        filename=log_directory / log_filename,
        format="%(asctime)s %(message)s",
        datefmt="%m/%d/%Y %H:%M:%S",
        level=logging.INFO,
    )

    # Run app
    app = PWDPClient.from_inbuilt_config()
    logger.info("Application initialized.")
    logger.info("Starting ...")
    app.run()
    logger.info("Application finished successfully.")
