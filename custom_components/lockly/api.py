"""Lockly API — all crypto + HTTP for the Lockly cloud API."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import datetime
from typing import Any

import aiohttp

from .const import API_BASE, API_USER_AGENT, COMMON_BODY, SENDDATA_TIMEOUT

_LOGGER = logging.getLogger(__name__)

# ── Lazy crypto imports (pycryptodome) ────────────────────────────────────────

def _aes():
    from Crypto.Cipher import AES
    return AES

def _des3():
    from Crypto.Cipher import DES3
    return DES3

def _rsa():
    from Crypto.PublicKey import RSA
    return RSA


# ── Embedded RSA keys (extracted from libkey.so in Lockly APK 3.2.9) ─────────
# RSA-1024, NoPadding. Keys are DER-encoded, base64-stored.
# Re-extract if Lockly updates their APK's RSA keys.

_PUB_KEY_DER_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZtiijnvRo5EEI0n2I7shxljMX"
    "b7mZ/FpjuS98MHGWuYYUrsiJQVgfPn29lmI/MDkhVc7oVTsg5BIyC0TUpZKTgxyF"
    "DZw08AdWKe9JZvzyGB00AGkRxcem2J64xJJ04o9FW6PDLF0gSvblZAvUdHU1YyfB"
    "7DgJhikP7lPrFNdGwwIDAQAB"
)
_PRIV_KEY_DER_B64 = (
    "MIICWwIBAAKBgQDAWboNKfQkSLGSPqN6zI9XZSrewBOdkJeOHUoFb2k1Wd2Vgdr0"
    "abwPNHBf0EF1Wzg4GlN8Q9GU5HhmOhD95UGsS8Bm0Atca3y5eK1STwbdqpNBLUk"
    "Le9vazmAczCUqdK+XzzJlQz6IKd53jJRYT9sRZZKfssvobG5L15rE/ZKWYwIDAQAB"
    "AoGAMtHCASZbdZarK6tW/+O532pAOFfhFtkT4Z1FaEg2ML1MeOq1Eaw53n6JThc0"
    "pC/0m4YBFqzIW6E9WizvPlVq0whdwS9gTytPhtEBmIfJeeqpNHcqCYgM+kLrODkp"
    "cqTTtNVSGRoTX2smJT41Za2bQ0U2RdZD251I3FMBCrKx13ECQQDmW4+M6KZmE3we"
    "8RbG8j/yu5zDkRIwDS4pYntRZJfEWfMUkcHc+rO69VcdyblGW8MsjTBtuzTvrWYH"
    "bxdLt6bJAkEA1cMWFMrhfoiB/SGtqkNXNQJeXyAQVGPKOwU+Lb4i6UBIy9pWXiQb"
    "5UUcwsomWSEkfil6vCHePjilaYsehaAtywJAfc9J4mp53swLgRapGvTZiid/IaxMo6"
    "O/L2kS8sweu2VpBjXpDFh76sLt1l4C63NYcC+YYIXbDn/EdpDsxzTBSQJAO8YfqJ"
    "TK1W0qnDQMse2+tw4Aga0fo9l7tWFT78qZTIwzTv2w5QZH3qai0j1g18+Susyyi2"
    "UVFmUUrBzA3jDaXQJAdQgL6YM1bfzmGxr1AwyvVRWyraazdIchcbml/6WGkC/Ic+"
    "5fsJErwHepUIDZVuai32KINOl1HsazhUbzIyITJg=="
)

_PUB_KEY_OBJ = None
_PRIV_KEY_OBJ = None


def _get_pub_key():
    global _PUB_KEY_OBJ
    if _PUB_KEY_OBJ is None:
        RSA = _rsa()
        der = base64.b64decode(_PUB_KEY_DER_B64)
        _PUB_KEY_OBJ = RSA.import_key(der)
    return _PUB_KEY_OBJ


def _get_priv_key():
    global _PRIV_KEY_OBJ
    if _PRIV_KEY_OBJ is None:
        RSA = _rsa()
        der = base64.b64decode(_PRIV_KEY_DER_B64)
        _PRIV_KEY_OBJ = RSA.import_key(der)
    return _PRIV_KEY_OBJ


# ── RSA NoPadding crypto ───────────────────────────────────────────────────────

def rsa_encrypt_para(json_str: str) -> str:
    """RSA-1024 NoPadding encrypt for API para field."""
    pub = _get_pub_key()
    msg = json_str.encode("utf-8")
    key_size = (pub.n.bit_length() + 7) // 8
    padded = b"\x00" * (key_size - len(msg)) + msg
    c = pow(int.from_bytes(padded, "big"), pub.e, pub.n)
    return base64.b64encode(c.to_bytes(key_size, "big")).decode("ascii")


def rsa_decrypt_key(key_b64: str) -> str:
    """RSA-1024 NoPadding decrypt server key field → 32-char ASCII string."""
    priv = _get_priv_key()
    ct = base64.b64decode(key_b64 + "==")
    m = pow(int.from_bytes(ct, "big"), priv.d, priv.n)
    pt = m.to_bytes((priv.n.bit_length() + 7) // 8, "big")
    return pt.lstrip(b"\x00").decode("ascii")


# ── DES3 crypto ───────────────────────────────────────────────────────────────

def des3_key_from_server_key(server_key_str: str) -> bytes:
    """base64-decode the 32-char server key → 24-byte DES3 key."""
    return base64.b64decode(server_key_str)[:24]


def des3_encrypt(des3_key: bytes, plaintext: str) -> str:
    """DES3/ECB encrypt with PKCS7 padding → base64 output."""
    DES3 = _des3()
    data = plaintext.encode("utf-8")
    pad_len = 8 - (len(data) % 8)
    data += bytes([pad_len] * pad_len)
    return base64.b64encode(DES3.new(des3_key, DES3.MODE_ECB).encrypt(data)).decode("ascii")


def des3_decrypt(des3_key: bytes, b64_data: str) -> bytes:
    """DES3/ECB decrypt base64 ciphertext → bytes (PKCS7 stripped)."""
    DES3 = _des3()
    ct = base64.b64decode(b64_data + "==")
    pt = DES3.new(des3_key, DES3.MODE_ECB).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 8 and all(b == pad for b in pt[-pad:]):
        pt = pt[:-pad]
    return pt


# ── BLE crypto helpers ────────────────────────────────────────────────────────

def derive_aes_key(master_code: str, uuid: str) -> bytes:
    """DataUtils.m86653h: 16-byte AES key from masterCode + device UUID."""
    expanded_hex = "".join("0" + c for c in str(master_code))
    mc_bytes = bytes.fromhex(expanded_hex)
    uuid_bytes = bytes.fromhex(uuid)
    result = bytearray(16)
    mc_len = len(str(master_code))
    for i in range(mc_len):
        result[i] = uuid_bytes[i % len(uuid_bytes)] ^ mc_bytes[i]
    for i in range(8, 12):
        result[i] = uuid_bytes[i] ^ mc_bytes[i - 8]
    for i in range(12, 16):
        result[i] = uuid_bytes[i - 12]
    return bytes(result)


def encrypt_master_code(master_code: str, uuid: str) -> str:
    """HexUtils.m86806g: XOR digit-bytes of masterCode with UUID bytes → hex."""
    mc_bytes = bytes([int(c) for c in str(master_code)])
    uuid_bytes = bytes.fromhex(uuid)
    return bytes([mc_bytes[i] ^ uuid_bytes[i % len(uuid_bytes)] for i in range(len(mc_bytes))]).hex().upper()


_CRC8_LUT = [0, 49, 98, 83, 196, 245, 166, 151, 185, 136, 219, 234, 125, 76, 31, 46]


def crc8_lockly(data: bytes) -> int:
    crc = 0
    for byte in data:
        s4 = ((crc << 4) & 0xFF) ^ _CRC8_LUT[(crc >> 4) ^ (byte >> 4)]
        crc = ((s4 << 4) & 0xFF) ^ _CRC8_LUT[(s4 >> 4) ^ (byte & 0x0F)]
    return crc & 0xFF


def build_ble_frame(payload: bytes, type_byte: int) -> bytes:
    HEAD = bytes([0xA1, 0xB2, 0xC3, 0xD4])
    total_len = len(payload) + 8
    frame_no_crc = HEAD + bytes([total_len % 256, total_len // 256]) + payload + bytes([type_byte])
    return frame_no_crc + bytes([crc8_lockly(frame_no_crc)])


def _build_cmd_hex(cmd_code: str, master_code: str, uuid: str, extra_fields: str = "") -> str:
    """Build an AES-encrypted BLE command hex string.

    Command content (NewUnlockCmd AES path):
      cmd_code + mc_len + enc_mc + "02" + pwd_id("0100") + extra_fields + time_hex + "01"
    """
    AES = _aes()
    enc_mc = encrypt_master_code(master_code, uuid)
    mc_len = f"{len(enc_mc) // 2:02x}"
    aes_key = derive_aes_key(master_code, uuid)

    now = datetime.now()
    time_str = now.strftime("%y%m%d%H%M%S")
    time_hex = "".join(f"{int(time_str[i:i+2]):02x}" for i in range(0, 12, 2))

    raw = cmd_code + mc_len + enc_mc + "02" + "0100" + extra_fields + time_hex + "01"
    byte_len = len(raw) // 2
    remainder = byte_len % 16
    padding = "" if remainder == 0 else "00" * (16 - remainder)
    padded = raw + padding

    encrypted = AES.new(aes_key, AES.MODE_ECB).encrypt(bytes.fromhex(padded))
    pad_byte_count = len(padding) // 2
    type_byte_val = f"{pad_byte_count:X}5"
    if len(type_byte_val) % 2:
        type_byte_val = "0" + type_byte_val
    type_byte = bytes.fromhex(type_byte_val)[0]
    return build_ble_frame(encrypted, type_byte).hex().upper()


def build_query_status_cmd(master_code: str, uuid: str) -> str:
    """Build QueryLockStatus BLE command hex string for senddata 'cmd' field."""
    AES = _aes()
    enc_mc = encrypt_master_code(master_code, uuid)
    mc_len = f"{len(enc_mc) // 2:02x}"
    aes_key = derive_aes_key(master_code, uuid)

    now = datetime.now()
    time_str = now.strftime("%y%m%d%H%M%S")
    time_hex = "".join(f"{int(time_str[i:i+2]):02x}" for i in range(0, 12, 2))

    # CMD_NEW_QUERY_LOCK_STATUS = "1E"
    raw = "1E" + mc_len + enc_mc + time_hex + "01"
    byte_len = len(raw) // 2
    remainder = byte_len % 16
    padding = "" if remainder == 0 else "00" * (16 - remainder)
    padded = raw + padding

    encrypted = AES.new(aes_key, AES.MODE_ECB).encrypt(bytes.fromhex(padded))
    pad_byte_count = len(padding) // 2
    type_byte_val = f"{pad_byte_count:X}5"
    if len(type_byte_val) % 2:
        type_byte_val = "0" + type_byte_val
    type_byte = bytes.fromhex(type_byte_val)[0]
    return build_ble_frame(encrypted, type_byte).hex().upper()


def build_unlock_cmd(master_code: str, uuid: str) -> str:
    """Build NewUnlock BLE command hex (cmd_code "22", unlock type "02")."""
    return _build_cmd_hex("22", master_code, uuid)


def build_lock_cmd(master_code: str, uuid: str) -> str:
    """Build NewLock BLE command hex (same frame as unlock; directive "L" signals intent).

    NewLockCmd uses the same "22" command frame as NewUnlockCmd per APK analysis.
    The server/hub interprets the directive field to determine lock vs unlock.
    """
    return _build_cmd_hex("22", master_code, uuid)


def parse_ack(ack_hex: str, master_code: str, uuid: str) -> dict[str, Any]:
    """Parse ACK field from senddata response.

    Response BLE frame: HEAD(4)+LEN(2)+CMD_TYPE(2)+AES_PAYLOAD(32)+CRC(1) = 41 bytes
    AES payload = ack_hex[16:-2]
    """
    AES = _aes()
    h = ack_hex.upper()
    payload_hex = h[16:-2]
    aes_key = derive_aes_key(master_code, uuid)

    try:
        payload = bytes.fromhex(payload_hex)
        if len(payload) % 16 != 0:
            _LOGGER.warning("ACK payload not AES-aligned: %d bytes", len(payload))
            return {}
        decrypted = AES.new(aes_key, AES.MODE_ECB).decrypt(payload)
        d = decrypted.rstrip(b"\x00").hex()

        if len(d) < 10:
            _LOGGER.warning("Decrypted ACK too short: %s", d)
            return {}

        status_byte = int(d[8:10], 16)
        result: dict[str, Any] = {
            "firmware_version": d[0:8],
            "is_locked": not bool((status_byte >> 1) & 1),
            "door_sensor_open": bool((status_byte >> 2) & 1),
            "wired_door_sensor_connected": bool(status_byte & 1),
            "battery_invalid": bool((status_byte >> 4) & 1),
        }
        if len(d) >= 14:
            result["wakeup_voltage"] = int(d[10:12], 16) + int(d[12:14], 16) * 256
        if len(d) >= 18:
            result["start_voltage"] = int(d[14:16], 16) + int(d[16:18], 16) * 256
        if len(d) >= 36:
            result["auto_unlock_delay_s"] = int(d[32:34], 16) + int(d[34:36], 16) * 256
        return result
    except Exception:
        _LOGGER.exception("Failed to parse ACK: %s", ack_hex[:60])
        return {}


# ── Cached status bit masks (HubCacheStatusData) ─────────────────────────────
# bit 0 (=1)  LOCK_STATUS_BIT  : 0=locked, 1=unlocked
# bit 1 (=2)  HAS_WIRED_DS_BIT : wired door sensor present
# bit 2 (=4)  WIRED_DS_STATUS  : wired door sensor open
# bit 3 (=8)  HAS_RF_DS_BIT    : RF door sensor present
# bit 4 (=16) HAS_RF_STATUS    : RF door sensor open
# bit 7 (=128) LOW_BAT_BIT     : low battery


def parse_cached_status(sts: int) -> dict[str, Any]:
    """Parse the `sts` integer from lock/cachedstatus/get response."""
    return {
        "is_locked": not bool(sts & 1),
        "low_battery": bool(sts & 128),
        "door_sensor_open": bool(sts & 4) if (sts & 2) else None,
    }


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def sha256_hex(password: str) -> str:
    """SHA256Util.m87491b: SHA-256 of password string → lowercase hex."""
    return hashlib.sha256(password.encode()).hexdigest()


def _headers(jwt: str | None = None) -> dict:
    h = {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": API_USER_AGENT,
        "Accept-Encoding": "gzip",
    }
    if jwt:
        h["Authorization"] = f"Bearer {jwt}"
    return h


# ── HTTP API calls ─────────────────────────────────────────────────────────────

async def api_login(session: aiohttp.ClientSession, email: str, password: str) -> str | None:
    """Login and return JWT token, or None on failure.

    Password is SHA-256 hashed before sending (per LoginActivity line 587).
    JWT returned in HTTP response Authorization header (TokenRenewInterceptor).
    """
    req_json = json.dumps({"acct": email, "pw": sha256_hex(password)}, separators=(",", ":"))
    para = rsa_encrypt_para(req_json)
    try:
        async with session.post(
            API_BASE + "login",
            json={**COMMON_BODY, "para": para},
            headers=_headers(),
        ) as resp:
            body = await resp.json(content_type=None)
            if str(body.get("cod")) != "200":
                _LOGGER.error("Login failed: cod=%s", body.get("cod"))
                return None
            jwt = resp.headers.get("Authorization", "")
            if jwt.startswith("Bearer "):
                jwt = jwt[7:]
            if not jwt:
                _LOGGER.error("Login succeeded but no JWT in response headers")
                return None
            return jwt
    except Exception:
        _LOGGER.exception("Login request failed")
        return None


async def api_get_devices(
    session: aiohttp.ClientSession, jwt: str, email: str
) -> tuple[list[dict], bytes | None]:
    """Fetch device list and DES3 key via qrylknew.

    Returns (locks_list, des3_key_bytes) or ([], None) on failure.
    """
    req_json = json.dumps({"acct": email}, separators=(",", ":"))
    para = rsa_encrypt_para(req_json)
    try:
        async with session.post(
            API_BASE + "qrylknew",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
        ) as resp:
            body = await resp.json(content_type=None)
            if str(body.get("cod")) != "200":
                _LOGGER.error("qrylknew failed: cod=%s", body.get("cod"))
                return [], None

            server_key_str = rsa_decrypt_key(body["key"])
            des3_key = des3_key_from_server_key(server_key_str)

            locks = []
            for dl_entry in body.get("dl", []):
                try:
                    pt = des3_decrypt(des3_key, dl_entry)
                    lock = json.loads(pt.rstrip(b"\x00"))
                    locks.append(lock)
                except Exception:
                    _LOGGER.exception("Failed to decrypt lock entry")

            return locks, des3_key
    except Exception:
        _LOGGER.exception("qrylknew request failed")
        return [], None


async def api_cached_status(
    session: aiohttp.ClientSession,
    jwt: str,
    des3_key: bytes,
    email: str,
    lock: dict,
) -> dict[str, Any] | None:
    """Query lock status from the server cache — NO physical device contact, NO beep.

    POST lock/cachedstatus/get  →  {"data": {"addr": "...", "sts": <int>, "time": <long>}}
    Status bits parsed via parse_cached_status().

    Parameters are DES3-encrypted in the 'para' field, matching the pattern used by
    all other post-auth endpoints (senddata, getstatus, etc.).
    """
    lock_id = lock["ID"]
    req = {"acct": email, "dv": lock_id}
    para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
    try:
        async with session.post(
            API_BASE + "lock/cachedstatus/get",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
        ) as resp:
            body = await resp.json(content_type=None)
            if str(body.get("cod")) != "200":
                _LOGGER.warning("cachedstatus failed: cod=%s lock=%s", body.get("cod"), lock_id)
                return None
            data = body.get("data") or {}
            sts = data.get("sts")
            if sts is None:
                _LOGGER.warning("cachedstatus: no 'sts' in data for lock %s", lock_id)
                return None
            return {**parse_cached_status(int(sts)), "cache_time": data.get("time")}
    except Exception:
        _LOGGER.exception("cachedstatus request failed for lock %s", lock_id)
        return None


async def api_query_lock_status(
    session: aiohttp.ClientSession,
    jwt: str,
    email: str,
    des3_key: bytes,
    lock: dict,
) -> dict[str, Any] | None:
    """Query lock status via senddata. Returns parsed status dict or None."""
    mc = str(lock["mc"])
    uuid = lock["ID"]
    cmd_hex = build_query_status_cmd(mc, uuid)

    req = {
        "acct": email,
        "hubid": lock.get("hubid", ""),
        "dv": lock["ID"],
        "cmd": cmd_hex,
        "mdna": lock.get("iotdm", ""),
    }
    para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
    try:
        async with session.post(
            API_BASE + "senddata",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
            timeout=aiohttp.ClientTimeout(total=SENDDATA_TIMEOUT),
        ) as resp:
            body = await resp.json(content_type=None)
            if str(body.get("cod")) != "200" or "ACK" not in body:
                _LOGGER.warning(
                    "senddata failed: cod=%s lock=%s", body.get("cod"), lock.get("blename")
                )
                return None
            return parse_ack(body["ACK"], mc, uuid)
    except Exception:
        _LOGGER.exception("senddata request failed for lock %s", lock.get("blename"))
        return None


async def _api_send_directive(
    session: aiohttp.ClientSession,
    jwt: str,
    email: str,
    des3_key: bytes,
    lock: dict,
    directive: str,
    cmd_hex: str,
) -> bool:
    """Send lock/unlock directive via senddata. Returns True if cod=200."""
    req = {
        "acct": email,
        "hubid": lock.get("hubid", ""),
        "dv": lock["ID"],
        "cmd": cmd_hex,
        "mdna": lock.get("iotdm", ""),
        "directive": directive,
    }
    para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
    try:
        async with session.post(
            API_BASE + "senddata",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
            timeout=aiohttp.ClientTimeout(total=SENDDATA_TIMEOUT),
        ) as resp:
            body = await resp.json(content_type=None)
            cod = str(body.get("cod"))
            _LOGGER.debug(
                "senddata directive=%s cod=%s lock=%s", directive, cod, lock.get("blename")
            )
            return cod == "200"
    except Exception:
        _LOGGER.exception(
            "senddata directive=%s failed for lock %s", directive, lock.get("blename")
        )
        return False


async def api_unlock(
    session: aiohttp.ClientSession,
    jwt: str,
    email: str,
    des3_key: bytes,
    lock: dict,
) -> bool:
    """Send unlock command. Returns True if server acknowledged."""
    mc = str(lock["mc"])
    return await _api_send_directive(
        session, jwt, email, des3_key, lock, "U", build_unlock_cmd(mc, lock["ID"])
    )


async def api_lock(
    session: aiohttp.ClientSession,
    jwt: str,
    email: str,
    des3_key: bytes,
    lock: dict,
) -> bool:
    """Send lock command. Returns True if server acknowledged."""
    mc = str(lock["mc"])
    return await _api_send_directive(
        session, jwt, email, des3_key, lock, "L", build_lock_cmd(mc, lock["ID"])
    )
