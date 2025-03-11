import glob
import logging
import shutil
import time
from configparser import ConfigParser
from pathlib import Path
from typing import Self

import requests

from pwdp import config_loader

logger = logging.getLogger(__name__)


class UploadError(Exception):
    pass


class PWDPClient:
    def __init__(self, config: ConfigParser) -> None:
        # Extract data from Config
        self.file_format = config["General"]["file_format"]
        self.source_path = Path(config["Paths"]["source_path"])
        self.sent_path = Path(config["Paths"]["sent_dir_path"])
        self.failed_path = Path(config["Paths"]["failed_dir_path"])
        self.scanning_mode = config["General"]["scanning_mode"]
        self.delay_in_seconds = int(config["General"]["delay_in_seconds"])
        self.upload_endpoint = config["General"]["upload_endpoint"]
        self.oauth2_endpoint = config["General"]["oauth2_endpoint"]
        self.user = config["Credentials"]["user"]
        self.secret = config["Credentials"]["secret"]
        self.permission = config["Credentials"]["permission"]

        self.refresh_token_expiration_time = None
        self.access_token = None
        self.refresh_token = None

    @staticmethod
    def from_inbuilt_config() -> Self:
        config = config_loader.load_config()
        logger.info("Config file loaded.")
        return PWDPClient(config)

    def check_token_expiration_time(self, time_since_last_update: int) -> bool:
        current_time = time.time()
        return (
            current_time - (time_since_last_update + self.refresh_token_expiration_time)
            > -1800
        )

    def setup_processing_directories(self) -> None:
        self.sent_path.mkdir(parents=True, exist_ok=True)
        self.failed_path.mkdir(parents=True, exist_ok=True)
        if not self.source_path.exists() and self.source_path.is_dir():
            logger.error("Source directory does not exist.")
            raise FileNotFoundError()

    def run_once(self) -> None:
        files = self.scan_for_files()
        self.upload_and_sort_files(files)

    def run_continuously(self) -> None:
        time_since_last_token_update = time.time()
        while True:
            self.run_once()
            time.sleep(5)
            if self.check_token_expiration_time(time_since_last_token_update):
                self.refresh_rpt_tokens()
                time_since_last_token_update = time.time()

    def run(self) -> None:
        self.setup_processing_directories()
        self.authenticate()
        if self.scanning_mode == "one-time":
            self.run_once()
        elif self.scanning_mode == "loop":
            self.run_continuously()
        else:
            logger.error("Unknown 'scanning_mode' provided.")

    def scan_for_files(self, file_format: str | None = None) -> list[str]:
        """
        Scan for new files with given format.
        By default use one specified in config.
        """
        if file_format is None:
            file_format = self.file_format

        files = glob.glob(pathname=f"*{file_format}", root_dir=self.source_path)
        if files:
            logger.info(f'Found files: {", ".join(files)}')
        files.sort()
        return files

    @staticmethod
    def _retrieve_tokens_from_response(response: requests.Response) -> tuple[str, str]:
        # Try decoding response as JSON
        try:
            r = response.json()
        except requests.JSONDecodeError as e:
            logger.error(e)
            raise
        # Try retrieving tokens from JSON
        try:
            access_token = r["access_token"]
            refresh_token = r["refresh_token"]
            refresh_expiration_time = r["refresh_expires_in"]
        except KeyError:
            logger.error("Access and refresh tokens are not present in response.")
            raise
        return (access_token, refresh_token, refresh_expiration_time)

    def _request_initial_tokens(self) -> tuple[str, str]:
        logger.info(f"Requesting inital tokens from {self.oauth2_endpoint} ...")
        response = requests.post(
            url=self.oauth2_endpoint,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "client_id": "frontend-ppb",
                "grant_type": "password",
                "username": self.user,
                "password": self.secret,
            },
            verify=False,
        )
        (
            access_token,
            refresh_token,
            refresh_expiration_time,
        ) = self._retrieve_tokens_from_response(response)
        logger.info("Initial tokens fetched successfully.")
        return (access_token, refresh_token, refresh_expiration_time)

    def _request_rpt_tokens(self, initial_access_token: str) -> tuple[str, str]:
        "Obtain requesting party token (RPT) in the UMA protocol"
        logger.info(f"Requesting RPT tokens from {self.oauth2_endpoint} ...")
        response = requests.post(
            url=self.oauth2_endpoint,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {initial_access_token}",
            },
            data={
                "permission": self.permission,
                "audience": "pwdp2",
                "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
            },
            verify=False,
        )
        (
            access_token,
            refresh_token,
            refresh_expiration_time,
        ) = self._retrieve_tokens_from_response(response)
        logger.info("RPT tokens fetched successfully.")
        return (access_token, refresh_token, refresh_expiration_time)

    def authenticate(self) -> None:
        # Get initial access token in OAuth 2.0
        initial_access_token, _, __ = self._request_initial_tokens()
        # Get RPT token in the UMA
        (
            rpt_access_token,
            rpt_refresh_token,
            rpt_expiration_time,
        ) = self._request_rpt_tokens(initial_access_token)
        self.access_token = rpt_access_token
        self.refresh_token = rpt_refresh_token
        self.refresh_token_expiration_time = rpt_expiration_time

    def refresh_rpt_tokens(self) -> None:
        logger.info("Refreshing RPT token...")
        response = requests.post(
            self.oauth2_endpoint,
            data={
                "client_id": "frontend-ppb",
                "refresh_token": self.refresh_token,
                "grant_type": "refresh_token",
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "partnercode": self.permission,
            },
            verify=False,
        )
        (
            access_token,
            refresh_token,
            rpt_expiration_time,
        ) = self._retrieve_tokens_from_response(response)
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.refresh_token_expiration_time = rpt_expiration_time
        logger.info("RPT token refreshed successfully.")

    def upload_file(self, filename: str) -> requests.Response:
        logger.info(f"Attempting to upload: {filename} to: {self.upload_endpoint} ...")
        response = requests.post(
            url=self.upload_endpoint,
            headers={
                "Resource": self.permission,
                "Authorization": "Bearer " + self.access_token,
            },
            files={"file": (filename, open(f"{self.source_path / filename}", "rb"))},
            verify=False,
        )
        return response

    def upload_file_with_retry(self, filename: str) -> None:
        """
        Uploads file. If it fails, refreshes RPT token and tries uploading again.
        If this also fails, raise UploadError.
        """
        time.sleep(self.delay_in_seconds)
        response = self.upload_file(filename)
        if response.ok:
            logger.info(f"{filename} upload was successful.")
            return

        logger.warning("File upload failed. Refreshing RPT token and retrying...")
        self.refresh_rpt_tokens()
        response = self.upload_file(filename)

        if response.ok:
            logger.info(f"{filename} upload was successful.")
            return
        try:
            error_description = response.json()
        except requests.JSONDecodeError:
            if response.text:
                error_description = response.text
            else:
                error_description = "Unknown reason - unable to parse JSON response."
        raise UploadError(
            f"Upload of file: {filename} failed due to: {error_description}"
        )

    def upload_and_sort_files(self, filenames: list[str]) -> None:
        for filename in filenames:
            try:
                self.upload_file_with_retry(filename)
                self.move_file(filename, self.sent_path)
            except UploadError as error:
                logger.error(error)
                self.write_error_file(filename, error)
                self.move_file(filename, self.failed_path)
            # Delay next upload to avoid server overload
            time.sleep(self.delay_in_seconds)

    def write_error_file(self, filename: str, error: UploadError) -> None:
        error_filename = f"failed_{filename}.err"
        with open(self.failed_path / error_filename, "w") as f:
            f.write(str(error))

    def move_file(self, filename: str, destination_path: str) -> None:
        try:
            shutil.move(
                self.source_path / filename,
                destination_path / filename,
            )
            logger.info(f"Moved {filename} to: {destination_path}")
        except shutil.Error:
            logger.error(f"Failed to move: {filename} to: " f"{destination_path}")
