import glob
import io
import logging
import shutil
import time
from configparser import ConfigParser
from pathlib import Path
from typing import Self
from zipfile import BadZipFile, ZipFile

import requests
from exchangelib import DELEGATE, Account, Configuration, Credentials, FileAttachment

from pwdp import config_loader

logger = logging.getLogger(__name__)


class UploadError(Exception):
    pass


class ExchangeError(Exception):
    pass


class PWDPClient:
    def __init__(self, config: ConfigParser) -> None:
        # Extract data from Config
        self.source_path = Path(config["Paths"]["source_path"])
        self.sent_path = Path(config["Paths"]["sent_dir_path"])
        self.failed_path = Path(config["Paths"]["failed_dir_path"])

        self.file_format = config["General"]["file_format"]
        self.scanning_mode = config["General"]["scanning_mode"]
        self.delay_in_seconds = int(config["General"]["delay_in_seconds"])
        self.consecutive_runs_interval = int(
            config["General"]["consecutive_runs_interval"]
        )
        self.upload_endpoint = config["General"]["upload_endpoint"]
        self.oauth2_endpoint = config["General"]["oauth2_endpoint"]

        self.user = config["Credentials"]["user"]
        self.secret = config["Credentials"]["secret"]
        self.permission = config["Credentials"]["permission"]
        self.email_username = config["Credentials"]["email_username"]
        self.email_password = config["Credentials"]["email_password"]
        proxy = config["Proxy"].get("proxy")
        if proxy:
            self.proxy = {"http": proxy, "https": proxy}
        else:
            self.proxy = None
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
            time.sleep(self.consecutive_runs_interval)
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
            logger.error(
                "Unknown 'scanning_mode' provided. 'one-time' or 'loop' are vaild."
            )

    def _connect_to_email(self) -> Account:
        credentials = Credentials(
            username=self.email_username,
            password=self.email_password,
        )
        config = Configuration(server="poczta.pse.pl", credentials=credentials)
        account = Account(
            primary_smtp_address=self.email_username,
            config=config,
            autodiscover=False,
            access_type=DELEGATE,
        )
        return account

    def fetch_attachments_to_upload(self, file_format: str, account: Account) -> None:
        unread_mails = account.inbox.filter(is_read=False)
        # Save attachments to local file system for future upload
        for mail in unread_mails:
            if mail.has_attachments:
                logger.info(f"Found email '{mail.subject}' with attachments.")
                for attachment in mail.attachments:
                    # TODO - tar and tar.gz?
                    if attachment.name.split(".")[-1].lower() == "zip":
                        logger.info(
                            f"Attachment '{attachment.name}' is probably an archive."
                        )
                        self.fetch_valid_files_from_archive_attachment(
                            file_format, attachment
                        )
                    elif "." + attachment.name.split(".")[-1].lower() == file_format:
                        with open(self.source_path / attachment.name, "wb") as f:
                            f.write(attachment.content)
                            logger.info(
                                f"Successfuly saved attachment: {attachment.name} "
                                "to local filesystem."
                            )
            # Mark email as read, delete it entirely and update account
            mail.is_read = True
            mail.save()
            mail.delete()

        logger.info(f"Finished fetching {file_format} files from Inbox.")

    def fetch_valid_files_from_archive_attachment(
        self, file_format: str, attachment: FileAttachment
    ) -> None:
        try:
            archive_file = ZipFile(io.BytesIO(attachment.content))
        except BadZipFile as e:
            logger.error(f"{attachment.name} {e}")
            return

        if archive_file.testzip() is not None:
            logger.error(
                f"Archive attachment '{attachment.name}' "
                "failed integrity test, skipping its parsing...."
            )
            return
        logger.info(f"Attachment '{attachment.name}' seems to be vaild.")
        for filename in archive_file.namelist():
            if filename.endswith(file_format):
                logger.info(f"Found {filename} in archive: {attachment.name}")
                with open(self.source_path / filename, "wb") as f:
                    f.write(archive_file.read(filename))
                logger.info(f"Successfuly saved {filename} to local filesystem.")

    def scan_for_files(self, file_format: str | None = None) -> list[str]:
        """
        Scan for new files with given format.
        By default use one specified in config.
        Sort output to ensure alphabetic processing.
        """
        # Connect to email
        try:
            account = self._connect_to_email()
            logger.info("Connected to EWS account.")
        except ExchangeError as e:
            logger.error(f"Error while connecting to Exchange account: {e}")
            raise
        # Refresh info about Account
        try:
            account.inbox.refresh()
            logger.info("Refreshed Inbox.")
        except ExchangeError as e:
            logger.error(f"Unable to refresh Inbox - Unexpected error: {e}")
            raise

        if file_format is None:
            file_format = self.file_format

        try:
            self.fetch_attachments_to_upload(file_format, account)
        except ExchangeError as e:
            logger.warning(f"Failed to fetch file(s) to upload: {e}")

        files = glob.glob(pathname=f"*{file_format}", root_dir=self.source_path)
        if files:
            logger.info(f'Found files: {", ".join(files)}')
        else:
            logger.info("No vaild files to upload.")
        return files

    @staticmethod
    def _retrieve_tokens_from_response(response: requests.Response) -> tuple[str, str]:
        # Try decoding response as JSON
        try:
            r = response.json()
        except requests.JSONDecodeError as e:
            logger.error(e)
            raise
        if not response.ok:
            error = r.get("error", "Not available")
            error_description = r.get("error_description", "Not available")
            logger.error(
                f"Request failed with HTTP status: {response.status_code}. "
                f"Reason: {error}. Details: {error_description}."
            )

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
            verify=True,
            timeout=(5, 5),
            proxies=self.proxy,
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
            verify=True,
            timeout=(5, 5),
            proxies=self.proxy,
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
            verify=True,
            timeout=(5, 5),
            proxies=self.proxy,
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
            verify=True,
            timeout=(100, 120),
            proxies=self.proxy,
        )
        return response

    def upload_file_with_retry(self, filename: str) -> None:
        """
        Uploads file. If it fails, refreshes RPT token and tries uploading again.
        If this also fails, raise UploadError.
        """
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
