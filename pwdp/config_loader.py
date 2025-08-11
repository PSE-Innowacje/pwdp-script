# Copyright (c) 2024 by PSE Innowacje sp. z o.o.
# This file is licensed under the MIT License.
# See the LICENSE file in the project root for full license information.
import importlib.resources
from configparser import ConfigParser

DEFAULT_CONFIG_ANCHOR = "pwdp.config"


def read_asset(asset_name: str, assets_anchor: str = DEFAULT_CONFIG_ANCHOR) -> bytes:
    "Read asset as binary file and return as bytes"
    resource = importlib.resources.files(assets_anchor).joinpath(asset_name)
    return resource.read_bytes()


def load_config_from_ini(filename: str) -> ConfigParser:
    config_content = read_asset(filename)
    config_parser = ConfigParser(interpolation=None)
    config_parser.read_string(config_content.decode("utf-8"))
    return config_parser


def load_config() -> ConfigParser:
    return load_config_from_ini("config.ini")
