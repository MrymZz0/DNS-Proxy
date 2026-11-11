import os
import re
from collections import namedtuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = "config.txt"
LOG_FILE = "log.txt"
PROMPT = "Enter domain (or exit): "

Result = namedtuple("Result", "domain source status ip ttl")

DOMAIN_RE = re.compile(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.?")
IPV4_RE = re.compile(r"([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})")
UINT_RE = re.compile(r"[0-9]+")


class ConfigError(Exception):
    pass
