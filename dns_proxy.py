import os
import re
import socket
import struct
import time
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

def load_config():
    path = os.path.join(BASE_DIR, CONFIG_FILE)
    try:
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        raise ConfigError(f"{CONFIG_FILE} not found")
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"cannot read {CONFIG_FILE}: {e}")

    raw = {}
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigError(f"{CONFIG_FILE} line {n}: expected key=value")
        key, value = line.split("=", 1)
        raw[key.strip()] = value.strip()

    for key in ("upstream_ip", "upstream_port", "sinkhole_ip", "proxy_ip",
                "ad_list_file", "sanction_list_file"):
        if not raw.get(key):
            raise ConfigError(f"missing required key '{key}'")

    try:
        timeout = float(raw.get("upstream_timeout_sec", "2"))
    except ValueError:
        raise ConfigError(f"'upstream_timeout_sec' must be a number (got '{raw['upstream_timeout_sec']}')")
    if timeout <= 0:
        raise ConfigError("'upstream_timeout_sec' must be greater than 0")

    real = raw.get("enabled_dns_real", raw.get("real_dns_enabled", "false"))
    cfg = {
        "upstream_ip": _parse_ip("upstream_ip", raw["upstream_ip"]),
        "upstream_port": _parse_uint("upstream_port", raw["upstream_port"], 1, 65535),
        "upstream_timeout_sec": timeout,
        "sinkhole_ip": _parse_ip("sinkhole_ip", raw["sinkhole_ip"]),
        "proxy_ip": _parse_ip("proxy_ip", raw["proxy_ip"]),
        "local_ttl": _parse_uint("local_ttl", raw.get("local_ttl", "60")),
        "ad_list_file": raw["ad_list_file"],
        "sanction_list_file": raw["sanction_list_file"],
        "cache_enabled": _parse_bool("cache_enabled", raw.get("cache_enabled", "true")),
        "entries_max_cache": (_parse_uint("entries_max_cache", raw["entries_max_cache"], 1)
                              if raw.get("entries_max_cache") else None),
        "dns_real": _parse_bool("enabled_dns_real", real),
    }
    return cfg

def load_list(path_str):
    path = path_str if os.path.isabs(path_str) else os.path.join(BASE_DIR, path_str)
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        raise ConfigError(f"list file not found: {path_str}")
    except OSError as e:
        raise ConfigError(f"cannot read list file {path_str}: {e}")

    entries, warnings = set(), []
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if is_valid_domain(line):
            entries.add(normalize(line))
        else:
            warnings.append(f"Warning: bad line {n} in {path_str}: {line}")
    return entries, warnings

def build_dns_query(name, qid):
    msg = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        b = label.encode("ascii")
        if not 1 <= len(b) <= 63:
            raise ValueError("bad label length")
        msg += bytes([len(b)]) + b
    return msg + b"\x00" + struct.pack(">HH", 1, 1)

def _skip_name(data, off):
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length

def parse_dns_response(data):
    if len(data) < 12:
        raise ValueError("short packet")
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    if not flags & 0x8000:
        raise ValueError("not a response")
    rcode = flags & 0x0F
    if rcode == 3:
        return ("NOT_FOUND",)
    if rcode != 0:
        raise ValueError(f"rcode {rcode}")
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    for _ in range(an):
        off = _skip_name(data, off)
        if off + 10 > len(data):
            raise ValueError("truncated record")
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if off + rdlen > len(data):
            raise ValueError("truncated rdata")
        if rtype == 1 and rclass == 1 and rdlen == 4:
            return ("OK", ".".join(str(b) for b in data[off:off + 4]), ttl)
        off += rdlen
    if flags & 0x0200 and an == 0:
        raise ValueError("truncated response")
    return ("NOT_FOUND",)

class DnsProxy:
    def __init__(self, cfg):
        self.cfg = cfg
        self.ad_set, self.sanction_set = set(), set()
        self.cache = {}
        self.stats = {"Total": 0, "AD_BLOCK": 0, "SANCTION": 0,
                      "CACHE": 0, "UPSTREAM": 0, "ERRORS": 0}
    def load_lists(self):
        ads, w1 = load_list(self.cfg["ad_list_file"])
        sanc, w2 = load_list(self.cfg["sanction_list_file"])
        self.ad_set, self.sanction_set = ads, sanc
        for w in w1 + w2:
            out(w)

    @staticmethod
    def _remaining(entry):
        return entry[1] - int(time.monotonic() - entry[2])

    def cache_get(self, name):
        entry = self.cache.get(name)
        if entry is None:
            return None
        rem = self._remaining(entry)
        if rem >= 1:
            return entry[0], rem
        del self.cache[name]
        return None

    def cache_put(self, name, ip, ttl):
        self.cache.pop(name, None)
        limit = self.cfg["entries_max_cache"]
        if limit:
            while len(self.cache) >= limit:
                self.cache.pop(next(iter(self.cache)))
        self.cache[name] = (ip, ttl, time.monotonic())

    def query_upstream(self, name):
        addr = (self.cfg["upstream_ip"], self.cfg["upstream_port"])
        timeout = self.cfg["upstream_timeout_sec"]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if self.cfg["dns_real"]:
                return self._query_real(sock, name, addr, timeout)
            sock.settimeout(timeout)
            sock.sendto(f"QUERY {name}".encode("utf-8"), addr)
            data, _ = sock.recvfrom(4096)
            parts = data.decode("utf-8").split()
        except (OSError, UnicodeDecodeError, ValueError, struct.error):
            return ("SERVER_ERROR",)
        finally:
            sock.close()
        if parts == ["NOT_FOUND"]:
            return ("NOT_FOUND",)
        if (len(parts) == 3 and parts[0] == "OK" and is_ipv4(parts[1])
                and UINT_RE.fullmatch(parts[2])):
            return ("OK", parts[1], int(parts[2]))
        return ("SERVER_ERROR",)
