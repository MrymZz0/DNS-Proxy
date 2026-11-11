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

def out(text=""):
    print(text, flush=True)

def is_ipv4(s):
    m = IPV4_RE.fullmatch(s)
    return bool(m) and all(0 <= int(g) <= 255 for g in m.groups())

def is_valid_domain(s):
    return DOMAIN_RE.fullmatch(s) is not None

def normalize(name):
    name = name.lower()
    return name[:-1] if name.endswith(".") else name

def in_list(name, entries):
    labels = name.split(".")
    for i in range(len(labels)):
        if ".".join(labels[i:]) in entries:
            return True
    return False

def _parse_bool(key, value):
    v = value.lower()
    if v not in ("true", "false"):
        raise ConfigError(f"'{key}' must be true or false (got '{value}')")
    return v == "true"

def _parse_uint(key, value, minimum=0, maximum=None):
    if not UINT_RE.fullmatch(value):
        raise ConfigError(f"'{key}' must be an integer (got '{value}')")
    n = int(value)
    if n < minimum or (maximum is not None and n > maximum):
        raise ConfigError(f"'{key}' out of range (got '{value}')")
    return n

def _parse_ip(key, value):
    if not is_ipv4(value):
        raise ConfigError(f"'{key}' must be an IPv4 address (got '{value}')")
    return value